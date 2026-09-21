"""Atomic parent/child creation, retry receipts and concurrent SQLite writers."""
from __future__ import annotations

import copy
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from openkapsel.context_store import ContextStore
from openkapsel.context_plans import PlanRequestConflict, normalize_plan_request


class PlanCreationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ContextStore(self.root)
        self.body = {
            "type": "plan", "taskname": "batch", "content": "Implement one feature",
            "scope_paths": ["src"], "memory_tags": ["feature"],
            "subplans": [
                {"ref": "code", "content": "Implement the code"},
                {"ref": "tests", "content": "Test it", "taskname": "batch-tests"},
                {"content": "Review the result", "status": "cancelled"},
            ],
        }

    def create(self, body=None, actor="actor-a", store=None):
        return (store or self.store).create_plans(self.body if body is None else body, actor_id=actor)

    def count(self):
        return self.store.query(limit=200)[1]

    def test_parent_children_ids_refs_and_inherited_taskname(self):
        result = self.create()
        self.assertEqual(4, self.count())
        self.assertNotIn("request_id", result)
        self.assertIsNone(result["plan_id"])
        children = result["subplans"]
        self.assertEqual([0, 1, 2], [c["index"] for c in children])
        self.assertEqual(["batch", "batch-tests", "batch"], [c["taskname"] for c in children])
        self.assertEqual(["code", "tests", None], [c.get("ref") for c in children])
        self.assertEqual(["in_progress", "in_progress", "cancelled"], [c["status"] for c in children])
        self.assertTrue(all(c["plan_id"] == result["id"] for c in children))
        self.assertTrue(all("content" not in c and "related_memory" not in c for c in children))
        plans = self.store.plan_tree(result["id"])["plans"]
        self.assertEqual([result["id"], *(c["id"] for c in children)], [p["id"] for p in plans])
        self.assertEqual([0, 1, 1, 1], [p["depth"] for p in plans])
        self.assertTrue(all(p["actor_id"] == "actor-a" for p in plans))
        self.assertEqual("code", plans[1]["request"]["ref"])
        self.assertEqual(result["id"], self.store.query(path="src")[0][0]["id"])

    def test_existing_parent_and_single_plan_remain_supported(self):
        parent = self.store.add("plan", "Existing root", taskname="existing")
        body = dict(self.body, plan_id=parent)
        result = self.create(body)
        self.assertEqual(parent, result["plan_id"])
        self.assertEqual(5, len(self.store.plan_tree(parent)["plans"]))
        for children in ({}, {"subplans": []}):
            one = self.create({"content": "Singleton", "taskname": "single", **children})
            self.assertEqual([], one["subplans"])
        self.assertEqual(7, self.count())

    def test_invalid_children_metadata_and_payload_are_all_or_nothing(self):
        malformed = [None, {}, ["child"], [{"content": " "}], [{"content": "x", "taskname": "x" * 33}],
                     [{"content": "x", "status": []}], [{"content": "x", "ref": ""}],
                     [{"content": "x", "plan_id": 10}], [{"content": "x", "subplans": []}],
                     [{"content": "x", "ref": "same"}, {"content": "y", "ref": "same"}],
                     [{"content": "x", "scope_paths": ["../escape"]}],
                     [{"content": "x", "memory_tags": [None]}],
                     [{"content": "x", "scope_paths": None}], [{"content": "x", "memory_tags": None}],
                     [{"content": "x"}] * 65, [{"content": "x" * 32769}],
                     [{"content": "x\x00y"}], [{"content": "\ud800"}]]
        for children in malformed:
            with self.subTest(children=str(children)[:100]):
                with self.assertRaises(ValueError):
                    self.create(dict(self.body, subplans=children))
                self.assertEqual(0, self.count())
        oversized = dict(self.body, subplans=[{"content": "x" * 32768}] * 9)
        with self.assertRaisesRegex(ValueError, "combined"):
            self.create(oversized)
        invalid_union = dict(self.body, subplans=[{"content": str(i), "memory_tags": ["tag" + str(i)]} for i in range(32)])
        with self.assertRaises(ValueError):
            self.create(invalid_union)
        self.assertEqual(0, self.count())

    def test_invalid_parent_does_not_leave_root_or_children(self):
        note = self.store.add("note", "Not a plan", taskname="note")
        for parent in (True, 0, -1, "1", note, 123456, 2**80):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                self.create(dict(self.body, plan_id=parent))
            self.assertEqual(1, self.count())

    def test_mid_insert_failure_rolls_back_root_children_indexes_and_retry_key(self):
        # Inject a real SQLite constraint failure on the second child. Validation
        # succeeds; this exercises rollback after earlier INSERTs actually ran.
        with closing(self.store._connect()) as connection, connection:
            connection.execute("CREATE TRIGGER injected_failure BEFORE INSERT ON context_entries "
                               "WHEN NEW.content = 'Test it' BEGIN SELECT RAISE(ABORT, 'injected'); END")
        body = dict(self.body, request_id="transaction-1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(body)
        self.assertEqual(0, self.count())
        with closing(self.store._connect()) as connection, connection:
            for table in ("context_entry_paths", "context_plan_requests"):
                self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0])
            connection.execute("DROP TRIGGER injected_failure")
        result = self.create(body)
        self.assertFalse(result["replayed"])
        self.assertEqual(4, self.count())

    def test_replay_after_reopen_uses_same_ids_and_does_not_revert_edits(self):
        body = dict(self.body, request_id="retry-1")
        before = copy.deepcopy(body)
        first = self.create(body)
        self.assertEqual(before, body)
        self.store.update_plan(first["id"], taskname="updated", content="New current content", plan_status="cancelled")
        reopened = ContextStore(self.root)
        replay = self.create(body, store=reopened)
        self.assertEqual({**first, "replayed": True}, replay)
        self.assertEqual(4, self.count())
        current = self.store.query(entry_id=first["id"])[0][0]
        self.assertEqual("New current content", current["content"])
        self.assertEqual("cancelled", current["status"])

    def test_same_key_conflicts_on_changed_children_refs_scope_or_parent(self):
        first = self.create(dict(self.body, request_id="retry-conflict"))
        changes = [{"content": "Changed root"}, {"taskname": "other"}, {"subplans": []},
                   {"scope_paths": ["other"]}, {"memory_tags": ["other"]}, {"plan_id": first["id"]}]
        different_ref = copy.deepcopy(self.body["subplans"])
        different_ref[0]["ref"] = "changed"
        changes.append({"subplans": different_ref})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(PlanRequestConflict) as error:
                self.create(dict(self.body, request_id="retry-conflict", **change))
            self.assertEqual("context_request_conflict", error.exception.code)
        self.assertEqual(4, self.count())

    def test_semantically_identical_defaults_are_retryable(self):
        body = dict(self.body, request_id="normalized")
        first = self.create(body)
        explicit = copy.deepcopy(body)
        explicit.update(status="in_progress", plan_id=None)
        explicit["subplans"][0].update(taskname="batch", status="in_progress", scope_paths=[], memory_tags=[])
        replay = self.create(explicit)
        self.assertEqual(first["id"], replay["id"])
        self.assertTrue(replay["replayed"])

    def test_retries_are_scoped_to_actor_and_workspace(self):
        body = dict(self.body, request_id="same-key")
        a = self.create(body)
        b = self.create(body, actor="actor-b")
        self.assertNotEqual(a["id"], b["id"])
        other = self.root / "another-workspace"
        other.mkdir()
        fresh = self.create(body, store=ContextStore(other))
        self.assertFalse(fresh["replayed"])
        self.assertEqual(8, self.count())

    def test_concurrent_writers_with_separate_stores_create_one_batch(self):
        body = dict(self.body, request_id="concurrent")
        stores = [ContextStore(self.root) for _ in range(6)]
        gate = threading.Barrier(len(stores))
        def run(store):
            gate.wait(timeout=10)
            return self.create(body, store=store)
        with ThreadPoolExecutor(max_workers=len(stores)) as executor:
            results = list(executor.map(run, stores))
        self.assertEqual(1, sum(not r["replayed"] for r in results))
        self.assertEqual(1, len({r["id"] for r in results}))
        self.assertEqual(1, len({tuple(c["id"] for c in r["subplans"]) for r in results}))
        self.assertEqual(4, self.count())

    def test_concurrent_changed_request_has_one_winner_and_one_conflict(self):
        other = ContextStore(self.root)
        gate = threading.Barrier(2)
        def run(pair):
            store, content = pair
            gate.wait(timeout=10)
            try:
                return self.create(dict(self.body, content=content, request_id="collision"), store=store)
            except PlanRequestConflict as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(run, [(self.store, "First"), (other, "Second")]))
        self.assertEqual(1, sum(isinstance(r, dict) for r in results))
        self.assertIn("context_request_conflict", results)
        self.assertEqual(4, self.count())

    def test_trim_protects_new_batch_and_pruned_keys_are_not_reused(self):
        with patch("openkapsel.context_store.MAX_CONTEXT_ENTRIES", 2), patch("openkapsel.context_store.CONTEXT_TRIM_ENTRIES", 100):
            self.store.add("note", "Old note", taskname="old")
            result = self.create(dict(self.body, request_id="retained-key"))
            self.assertEqual(4, self.count())
            self.assertEqual(4, len(self.store.plan_tree(result["id"])["plans"]))
            self.store.add("note", "Trigger later pruning", taskname="later")
        count = self.count()
        with self.assertRaises(PlanRequestConflict) as error:
            self.create(dict(self.body, request_id="retained-key"))
        self.assertEqual("context_request_gone", error.exception.code)
        self.assertEqual(count, self.count())

    def test_bounded_request_ledger_keeps_existing_replays(self):
        with patch("openkapsel.context_plans.MAX_PLAN_REQUESTS", 1):
            body = dict(self.body, request_id="first")
            first = self.create(body)
            with self.assertRaises(PlanRequestConflict) as error:
                self.create(dict(self.body, request_id="second"))
            self.assertEqual("context_request_limit", error.exception.code)
            self.assertEqual(first["id"], self.create(body)["id"])
            self.assertEqual(4, self.count())

    def test_maximum_batch_returns_all_65_unique_plan_ids(self):
        body = dict(self.body, subplans=[{"ref": f"part-{i}", "content": f"Part {i}"} for i in range(64)])
        result = self.create(body)
        ids = [result["id"], *(c["id"] for c in result["subplans"])]
        self.assertEqual(65, len(set(ids)))
        self.assertEqual(65, self.count())
        self.assertEqual(65, len(self.store.plan_tree(result["id"])["plans"]))

    def test_receipt_insert_failure_rolls_back_the_complete_plan_batch(self):
        with closing(self.store._connect()) as connection, connection:
            connection.execute("CREATE TRIGGER injected_receipt_failure BEFORE INSERT ON context_plan_requests "
                               "BEGIN SELECT RAISE(ABORT, 'receipt failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(dict(self.body, request_id="receipt-failure"))
        self.assertEqual(0, self.count())
        with closing(self.store._connect()) as connection:
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM context_entry_paths").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM context_plan_requests").fetchone()[0])

    def test_invalid_request_ids_and_note_requests_are_rejected(self):
        for key in (None, "", "white space", "-leading", "x" * 129, 123):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.create(dict(self.body, request_id=key))
        with self.assertRaises(ValueError):
            self.create(dict(self.body, request_id="actor-required"), actor=None)
        with self.assertRaises(ValueError):
            normalize_plan_request(dict(self.body, type="note"))
        self.assertEqual(0, self.count())


if __name__ == "__main__":
    unittest.main()

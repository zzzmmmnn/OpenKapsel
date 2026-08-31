from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.context_store import ContextStore


class ContextStoreTests(unittest.TestCase):
    def test_operation_messages_and_tasknames_have_short_hard_limits(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = ContextStore(Path(raw))
            plan_id = store.add("plan", "Limit test", taskname="short-task")
            with self.assertRaises(ValueError):
                store.add(
                    "operation",
                    "x" * 201,
                    taskname="short-task",
                    operation="fs.write",
                    plan_id=plan_id,
                )
            with self.assertRaises(ValueError):
                store.add("plan", "Too long task name", taskname="x" * 33)

    def test_unfinished_root_plan_hints_are_compact_and_exclude_subplans(self) -> None:
        with tempfile.TemporaryDirectory() as raw, patch(
            "openkapsel.context_store.MAX_UNFINISHED_ROOT_PLAN_HINTS", 1
        ), patch("openkapsel.context_store.MAX_PLAN_HINT_CONTENT_CHARS", 8):
            store = ContextStore(Path(raw))
            older_root = store.add(
                "plan",
                "A long root plan description",
                taskname="older-root",
            )
            store.add(
                "plan",
                "Sub-plan",
                taskname="sub-plan",
                plan_id=older_root,
            )
            completed_root = store.add(
                "plan",
                "Already done",
                taskname="completed-root",
            )
            store.update_plan(
                completed_root,
                taskname="completed-root",
                plan_status="completed",
                debrief={
                    "summary": "Completed without retained Memory.",
                    "outcome": "succeeded",
                    "memory_refs": [],
                },
            )
            newest_root = store.add(
                "plan",
                "Newest unfinished root",
                taskname="newest-root",
            )

            hints = store.unfinished_root_plan_hints(exclude_plan_id=newest_root)
            self.assertEqual(1, hints["total"])
            self.assertFalse(hints["truncated"])
            self.assertEqual([older_root], [item["id"] for item in hints["plans"]])
            self.assertEqual("A long r", hints["plans"][0]["content_preview"])
            self.assertTrue(hints["plans"][0]["content_truncated"])
            self.assertIsNone(hints["plans"][0]["plan_id"])

    def test_add_finish_query_and_workspace_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            store = ContextStore(workspace)
            plan_id = store.add(
                "plan",
                "Implement context history",
                taskname="context-feature",
                actor_id="actor",
            )
            operation_id = store.add(
                "operation",
                "Write the implementation",
                taskname="context-feature",
                actor_id="actor",
                operation="fs.write",
                status="running",
                plan_id=plan_id,
                request={"path": "app.py"},
            )
            store.finish_operation(
                operation_id,
                succeeded=True,
                result_summary="fs.write succeeded with HTTP 200: app.py",
                result={"path": "app.py", "bytes_written": 12},
            )

            self.assertTrue(
                (workspace / ".openkapsel" / "context" / "context.sqlite3").is_file()
            )
            self.assertEqual(
                0o600,
                (workspace / ".openkapsel" / "context" / "context.sqlite3").stat().st_mode
                & 0o777,
            )
            entries, total = store.query(query="app.py", limit=200)
            self.assertEqual(1, total)
            self.assertEqual(operation_id, entries[0]["id"])
            self.assertEqual("succeeded", entries[0]["status"])
            self.assertEqual({"path": "app.py"}, entries[0]["request"])
            by_actor, total = store.query(actor_id="actor")
            self.assertEqual(2, total)
            self.assertEqual({plan_id, operation_id}, {item["id"] for item in by_actor})
            by_path, total = store.query(path="./app.py")
            self.assertEqual(1, total)
            self.assertEqual(operation_id, by_path[0]["id"])
            moved_id = store.add(
                "operation",
                "Move the implementation",
                taskname="context-feature",
                actor_id="other-actor",
                operation="fs.move",
                status="running",
                plan_id=plan_id,
                request={"source": "app.py", "destination": "src/app.py"},
            )
            combined, total = store.query(actor_id="other-actor", path="src/app.py")
            self.assertEqual(1, total)
            self.assertEqual(moved_id, combined[0]["id"])
            exact, total = store.query(entry_id=plan_id)
            self.assertEqual(1, total)
            self.assertEqual("plan", exact[0]["type"])
            self.assertEqual("context-feature", exact[0]["taskname"])
            self.assertEqual("in_progress", exact[0]["status"])
            updated = store.update_plan(
                plan_id,
                taskname="context-feature",
                content="Implement and verify context history",
                plan_status="completed",
                debrief={
                    "summary": "Context history was implemented and verified.",
                    "outcome": "succeeded",
                    "memory_refs": [{"memory_id": "mem_example", "revision": 1}],
                },
                actor_id="actor",
            )
            self.assertEqual(plan_id, updated["id"])
            self.assertEqual("completed", updated["status"])
            completed, total = store.query(
                entry_type="plan",
                entry_status="completed",
                taskname="context-feature",
            )
            self.assertEqual(1, total)
            self.assertEqual(plan_id, completed[0]["id"])
            self.assertEqual("succeeded", completed[0]["debrief"]["outcome"])
            debrief = store.plan_debrief(plan_id)
            self.assertIsNotNone(debrief)
            self.assertEqual("succeeded", debrief["outcome"])
            self.assertEqual("mem_example", debrief["memory_refs"][0]["memory_id"])
            note_id = store.add(
                "note",
                "Initial finding",
                taskname="context-feature",
                plan_id=plan_id,
            )
            replacement = store.replace_note(
                note_id,
                taskname="context-feature",
                content="Updated finding",
                plan_id=plan_id,
            )
            self.assertGreater(replacement["id"], note_id)
            removed, total = store.query(entry_id=note_id)
            self.assertEqual(([], 0), (removed, total))
            grouped, total = store.query(taskname="context-feature", limit=200)
            self.assertEqual(4, total)
            self.assertEqual(replacement["id"], grouped[0]["id"])
            child_plan_id = store.add(
                "plan",
                "Implement the API layer",
                taskname="context-feature",
                plan_id=plan_id,
            )
            child_operation_id = store.add(
                "operation",
                "Write the API layer",
                taskname="context-feature",
                actor_id="actor",
                operation="fs.write",
                status="running",
                plan_id=child_plan_id,
                request={"path": "api.py"},
            )
            direct, total = store.query(plan_id=child_plan_id)
            self.assertEqual(1, total)
            self.assertEqual(child_operation_id, direct[0]["id"])
            tree = store.plan_tree(plan_id, max_depth=8, limit=200)
            self.assertEqual([plan_id, child_plan_id], [item["id"] for item in tree["plans"]])
            self.assertEqual([0, 1], [item["depth"] for item in tree["plans"]])
            self.assertIn(
                child_operation_id,
                {item["id"] for item in tree["entries"]},
            )
            with self.assertRaisesRegex(ValueError, "cycle"):
                store.update_plan(
                    plan_id,
                    taskname="context-feature",
                    plan_id=child_plan_id,
                )
            with self.assertRaises(ValueError):
                store.query(limit=201)
            with self.assertRaises(ValueError):
                store.query(actor_id=" ")
            with self.assertRaises(ValueError):
                store.query(path=" ")

    def test_over_capacity_deletes_oldest_batch(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "openkapsel.context_store.MAX_CONTEXT_ENTRIES", 5
        ), patch("openkapsel.context_store.CONTEXT_TRIM_ENTRIES", 2):
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            store = ContextStore(workspace)
            ids = [
                store.add("note", f"note {index}", taskname="capacity-test")
                for index in range(6)
            ]
            entries, total = store.query(limit=200)
            self.assertEqual(4, total)
            self.assertEqual(ids[2:], sorted(item["id"] for item in entries))

    def test_capacity_trim_preserves_referenced_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "openkapsel.context_store.MAX_CONTEXT_ENTRIES", 5
        ), patch("openkapsel.context_store.CONTEXT_TRIM_ENTRIES", 2):
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            store = ContextStore(workspace)
            plan_id = store.add("plan", "Long-running plan", taskname="capacity-plan")
            operation_ids = [
                store.add(
                    "operation",
                    f"operation {index}",
                    taskname="capacity-plan",
                    operation="fs.write",
                    status="running",
                    plan_id=plan_id,
                )
                for index in range(5)
            ]
            plan, total = store.query(entry_id=plan_id)
            self.assertEqual(1, total)
            self.assertEqual("plan", plan[0]["type"])
            remaining, total = store.query(plan_id=plan_id, limit=200)
            self.assertEqual(operation_ids[2:], sorted(item["id"] for item in remaining))
            self.assertEqual(3, total)

    def test_deleted_context_directory_is_recreated_before_next_insert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            store = ContextStore(workspace)
            store.add(
                "note",
                "This record will be removed with the database",
                taskname="recreate-test",
            )
            shutil.rmtree(workspace / ".openkapsel")

            new_id = store.add(
                "note",
                "Context storage was recreated",
                taskname="recreate-test",
            )
            entries, total = store.query(limit=200)
            self.assertEqual(1, total)
            self.assertEqual(new_id, entries[0]["id"])
            self.assertEqual("Context storage was recreated", entries[0]["content"])

    def test_legacy_database_adds_taskname_plan_status_and_plan_id_columns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            context = workspace / ".openkapsel" / "context"
            context.mkdir(parents=True)
            database = context / "context.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE context_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    entry_type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    operation TEXT,
                    status TEXT,
                    result_summary TEXT,
                    actor_id TEXT,
                    request_json TEXT,
                    result_json TEXT
                );
                INSERT INTO context_entries (
                    created_at, updated_at, entry_type, content
                ) VALUES ('now', 'now', 'plan', 'Legacy plan');
                INSERT INTO context_entries (
                    created_at, updated_at, entry_type, content, operation,
                    actor_id, request_json
                ) VALUES (
                    'now', 'now', 'operation', 'Legacy write', 'fs.write',
                    'legacy-actor', '{"path":"legacy.txt"}'
                );
                """
            )
            connection.commit()
            connection.close()

            store = ContextStore(workspace)
            migrated_connection = sqlite3.connect(database)
            migrated_columns = {
                row[1]
                for row in migrated_connection.execute(
                    "PRAGMA table_info(context_entries)"
                )
            }
            migrated_connection.close()
            self.assertTrue({"taskname", "plan_status", "plan_id"} <= migrated_columns)
            entries, total = store.query(limit=200)
            self.assertEqual(2, total)
            plan = next(item for item in entries if item["type"] == "plan")
            self.assertIsNone(plan["taskname"])
            self.assertEqual("in_progress", plan["status"])
            self.assertIsNone(plan["plan_id"])
            migrated, total = store.query(
                actor_id="legacy-actor",
                path="legacy.txt",
            )
            self.assertEqual(1, total)
            self.assertEqual("Legacy write", migrated[0]["content"])
            store.add("note", "New note", taskname="migrated-workspace")


if __name__ == "__main__":
    unittest.main()

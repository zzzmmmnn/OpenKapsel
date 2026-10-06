"""Append-only Conversation model and atomic Plan integration."""
from __future__ import annotations

import re
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from openkapsel.context.context_store import ContextStore


class ConversationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ContextStore(self.root)

    @staticmethod
    def initial_entries(label: str = "conversation") -> list[dict[str, str]]:
        return [
            {"role": "user", "content": f"User starts {label}."},
            {"role": "ai", "content": f"AI acknowledges {label}."},
        ]

    def next_conversation_id(self) -> int:
        return self.store.conversation_query(limit=1)[2]

    def create_conversation(self, label: str = "conversation") -> dict:
        return self.store.create_conversation(
            self.next_conversation_id(),
            self.initial_entries(label),
        )

    def create_plan(self, conversation: dict, **overrides) -> dict:
        body = {
            "type": "plan",
            "taskname": "conversation-plan",
            "content": "Implement the requested change.",
            "subplans": [],
            "conversation_id": conversation["conversation_id"],
            "writer_nonce": conversation["writer_nonce"],
            "conversation_entries": [
                {"role": "ai", "content": "AI creates the implementation Plan."}
            ],
        }
        body.update(overrides)
        return self.store.create_plans(body, actor_id="actor")

    def test_create_requires_sequential_id_and_stores_plaintext_writer_nonce(self) -> None:
        created = self.create_conversation()
        self.assertEqual(0, created["conversation_id"])
        self.assertRegex(created["writer_nonce"], r"^@[A-Za-z0-9]{4}@$")
        self.assertEqual(1, self.next_conversation_id())
        self.assertIn("next_conversation_id", created["instructions"])
        self.assertIn("8192", created["instructions"])
        self.assertIn("original wording verbatim", created["instructions"])
        self.assertIn("does not need extra compression", created["instructions"])
        self.assertIn("must compress that range", created["instructions"])
        with closing(sqlite3.connect(self.store.database)) as connection:
            stored = connection.execute(
                "SELECT writer_nonce FROM conversations WHERE id = ?",
                (created["conversation_id"],),
            ).fetchone()[0]
        self.assertEqual(created["writer_nonce"], stored)
        self.assertEqual(["user", "ai"], [item["role"] for item in created["entries"]])
        self.assertEqual([1, 2], [item["sub_id"] for item in created["entries"]])
        self.assertIn("conversation_append", created["instructions"])

        queried, total, next_id = self.store.conversation_query(
            conversation_id=created["conversation_id"],
            full=True,
        )
        self.assertEqual(2, total)
        self.assertEqual(1, next_id)
        self.assertEqual([2, 1], [item["sub_id"] for item in queried])
        self.assertTrue(all("writer_nonce" not in item for item in queried))

        with self.assertRaisesRegex(ValueError, "next_conversation_id 1"):
            self.store.create_conversation(2, self.initial_entries("skipped id"))
        with self.assertRaisesRegex(ValueError, "next_conversation_id 1"):
            self.store.create_conversation(0, self.initial_entries("duplicate id"))

        with self.assertRaises(ValueError):
            self.store.create_conversation(
                self.next_conversation_id(),
                [
                    {"role": "ai", "content": "wrong first role"},
                    {"role": "user", "content": "wrong second role"},
                ]
            )
        with self.assertRaises(ValueError):
            self.store.create_conversation(
                self.next_conversation_id(),
                [{"role": "user", "content": "only one record"}]
            )
        with self.assertRaises(ValueError):
            self.store.create_conversation(
                self.next_conversation_id(),
                [
                    {"role": "user", "content": "ok"},
                    {"role": "ai", "content": "x" * 1001},
                ]
            )

    def test_concurrent_create_accepts_only_the_current_next_id_once(self) -> None:
        other = ContextStore(self.root)
        self.assertEqual(0, self.store.conversation_query(limit=1)[2])
        self.assertEqual(0, other.conversation_query(limit=1)[2])
        barrier = threading.Barrier(2)

        def attempt(store: ContextStore, label: str):
            barrier.wait()
            try:
                return ("ok", store.create_conversation(0, self.initial_entries(label)))
            except ValueError as exc:
                return ("error", str(exc))

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda args: attempt(*args),
                    ((self.store, "first contender"), (other, "second contender")),
                )
            )
        self.assertEqual(1, sum(kind == "ok" for kind, _ in results))
        self.assertEqual(1, sum(kind == "error" for kind, _ in results))
        rejected = next(value for kind, value in results if kind == "error")
        self.assertIn("next_conversation_id 1", rejected)
        entries, total, next_id = self.store.conversation_query(full=True, limit=100)
        self.assertEqual(2, total)
        self.assertEqual(1, next_id)
        self.assertEqual({0}, {item["conversation_id"] for item in entries})

    def test_append_requires_matching_formatted_writer_nonce(self) -> None:
        created = self.create_conversation()
        result = self.store.append_conversation(
            conversation_id=created["conversation_id"],
            writer_nonce=created["writer_nonce"],
            entries=[{"role": "user", "content": "User changes one requirement."}],
        )
        self.assertEqual(3, result["entries"][0]["sub_id"])

        for writer_nonce in ("abcd", "@abc@", "@abc!@", "@ABCDE@", "@0000x", "@zzzz@"):
            if writer_nonce == created["writer_nonce"]:
                continue
            with self.subTest(writer_nonce=writer_nonce):
                with self.assertRaises((ValueError, PermissionError)):
                    self.store.append_conversation(
                        conversation_id=created["conversation_id"],
                        writer_nonce=writer_nonce,
                        entries=[{"role": "ai", "content": "must not append"}],
                    )
        entries, total, _ = self.store.conversation_query(
            conversation_id=created["conversation_id"],
            full=True,
        )
        self.assertEqual(3, total)
        self.assertEqual([3, 2, 1], [item["sub_id"] for item in entries])

    def test_summary_is_prompted_after_forty_and_required_after_forty_nine(self) -> None:
        created = self.create_conversation("summary cadence")
        conversation_id = created["conversation_id"]
        writer_nonce = created["writer_nonce"]
        self.assertEqual(2, created["summary_status"]["user_ai_since_summary"])
        self.assertFalse(created["summary_status"]["recommended"])

        prompted = self.store.append_conversation(
            conversation_id=conversation_id,
            writer_nonce=writer_nonce,
            entries=[
                {"role": "user" if index % 2 else "ai", "content": f"record {index}"}
                for index in range(3, 41)
            ],
        )
        self.assertEqual(40, prompted["summary_status"]["user_ai_since_summary"])
        self.assertTrue(prompted["summary_status"]["recommended"])
        self.assertFalse(
            prompted["summary_status"]["required_before_next_user_ai"]
        )
        self.assertEqual(1, prompted["summary_status"]["source_start_sub_id"])
        self.assertEqual(40, prompted["summary_status"]["source_end_sub_id"])
        self.assertIn("sub_id 1 through 40", prompted["summary_status"]["instruction"])

        summary = self.store.append_conversation(
            conversation_id=conversation_id,
            writer_nonce=writer_nonce,
            entries=[{"role": "summary", "content": "S" * 8192}],
        )
        self.assertEqual(41, summary["entries"][0]["sub_id"])
        self.assertEqual(0, summary["summary_status"]["user_ai_since_summary"])
        self.assertFalse(summary["summary_status"]["recommended"])
        self.assertEqual(41, summary["summary_status"]["source_start_sub_id"])
        with self.assertRaisesRegex(ValueError, "8192"):
            self.store.append_conversation(
                conversation_id=conversation_id,
                writer_nonce=writer_nonce,
                entries=[{"role": "summary", "content": "S" * 8193}],
            )

        required = self.store.append_conversation(
            conversation_id=conversation_id,
            writer_nonce=writer_nonce,
            entries=[
                {"role": "user" if index % 2 else "ai", "content": f"window {index}"}
                for index in range(1, 50)
            ],
        )
        self.assertEqual(90, required["entries"][-1]["sub_id"])
        self.assertEqual(49, required["summary_status"]["user_ai_since_summary"])
        self.assertTrue(required["summary_status"]["recommended"])
        self.assertTrue(
            required["summary_status"]["required_before_next_user_ai"]
        )
        self.assertEqual(41, required["summary_status"]["source_start_sub_id"])
        self.assertEqual(90, required["summary_status"]["source_end_sub_id"])
        self.assertIn("required", required["summary_status"]["instruction"])
        self.assertIn("sub_id 41 through 90", required["summary_status"]["instruction"])

        with self.assertRaisesRegex(ValueError, "summary is required"):
            self.store.append_conversation(
                conversation_id=conversation_id,
                writer_nonce=writer_nonce,
                entries=[{"role": "ai", "content": "must summarize first"}],
            )

        resumed = self.store.append_conversation(
            conversation_id=conversation_id,
            writer_nonce=writer_nonce,
            entries=[
                {"role": "summary", "content": "Compressed dynamic window."},
                {"role": "ai", "content": "AI continues after the summary."},
            ],
        )
        self.assertEqual([91, 92], [item["sub_id"] for item in resumed["entries"]])
        self.assertEqual(1, resumed["summary_status"]["user_ai_since_summary"])
        self.assertFalse(resumed["summary_status"]["recommended"])
        self.assertEqual(91, resumed["summary_status"]["source_start_sub_id"])

    def test_cross_conversation_query_defaults_to_latest_summary_window(self) -> None:
        first = self.create_conversation("first")
        self.store.append_conversation(
            conversation_id=first["conversation_id"],
            writer_nonce=first["writer_nonce"],
            entries=[
                {"role": "ai" if index % 2 else "user", "content": f"old first {index}"}
                for index in range(3, 30)
            ]
            + [
                {"role": "summary", "content": "latest first summary"},
                {"role": "ai", "content": "new first decision"},
            ],
        )
        second = self.create_conversation("second")
        self.store.append_conversation(
            conversation_id=second["conversation_id"],
            writer_nonce=second["writer_nonce"],
            entries=[{"role": "user", "content": "second has no summary yet"}],
        )

        recent, recent_total, next_id = self.store.conversation_query(limit=100)
        first_rows = [
            item for item in recent if item["conversation_id"] == first["conversation_id"]
        ]
        second_rows = [
            item for item in recent if item["conversation_id"] == second["conversation_id"]
        ]
        self.assertEqual([31, 30], [item["sub_id"] for item in first_rows])
        self.assertEqual({1, 2, 3}, {item["sub_id"] for item in second_rows})
        self.assertEqual(5, recent_total)
        self.assertEqual(2, next_id)

        full, full_total, full_next_id = self.store.conversation_query(full=True, limit=100)
        self.assertEqual(34, full_total)
        self.assertEqual(2, full_next_id)
        self.assertEqual(31, len([x for x in full if x["conversation_id"] == first["conversation_id"]]))

        ranged, ranged_total, ranged_next_id = self.store.conversation_query(
            conversation_id=first["conversation_id"],
            start_sub_id=28,
            end_sub_id=31,
            limit=100,
        )
        self.assertEqual(4, ranged_total)
        self.assertEqual(2, ranged_next_id)
        self.assertEqual([31, 30, 29, 28], [item["sub_id"] for item in ranged])

        with self.assertRaises(ValueError):
            self.store.conversation_query(start_sub_id=2)
        with self.assertRaises(ValueError):
            self.store.conversation_query(limit=101)

    def test_plan_creation_and_conversation_append_are_atomic(self) -> None:
        conversation = self.create_conversation("plan create")
        before, before_total, _ = self.store.conversation_query(
            conversation_id=conversation["conversation_id"],
            full=True,
        )
        plan = self.create_plan(conversation)
        self.assertEqual(conversation["conversation_id"], plan["conversation_id"])
        self.assertEqual(3, plan["conversation_entries"][0]["sub_id"])
        self.assertEqual(1, self.store.query(entry_type="plan")[1])

        entries, total, _ = self.store.conversation_query(
            conversation_id=conversation["conversation_id"],
            full=True,
        )
        self.assertEqual(before_total + 1, total)

        with self.assertRaises(PermissionError):
            self.store.create_plans(
                {
                    "type": "plan",
                    "taskname": "bad-owner",
                    "content": "Must roll back.",
                    "subplans": [],
                    "conversation_id": conversation["conversation_id"],
                    "writer_nonce": "@zzzz@"
                    if conversation["writer_nonce"] != "@zzzz@"
                    else "@yyyy@",
                    "conversation_entries": [
                        {"role": "ai", "content": "This must not be appended."}
                    ],
                },
                actor_id="actor",
            )
        self.assertEqual(1, self.store.query(entry_type="plan")[1])
        self.assertEqual(
            total,
            self.store.conversation_query(
                conversation_id=conversation["conversation_id"],
                full=True,
            )[1],
        )

    def test_plan_update_rolls_back_when_conversation_append_fails(self) -> None:
        conversation = self.create_conversation("plan update")
        plan = self.create_plan(conversation)

        updated = self.store.update_plan(
            plan["id"],
            expected_revision=plan["revision"],
            taskname="conversation-plan",
            content="Updated Plan content.",
            conversation_id=conversation["conversation_id"],
            writer_nonce=conversation["writer_nonce"],
            conversation_entries=[
                {"role": "user", "content": "User changed the requested behavior."}
            ],
            require_conversation=True,
        )
        self.assertEqual(2, updated["revision"])
        self.assertEqual("Updated Plan content.", updated["content"])

        # Fill to 49 user/ai entries since no summary exists. Creation used 1-2, Plan create 3, update 4.
        self.store.append_conversation(
            conversation_id=conversation["conversation_id"],
            writer_nonce=conversation["writer_nonce"],
            entries=[
                {"role": "ai" if index % 2 else "user", "content": f"fill {index}"}
                for index in range(5, 50)
            ],
        )
        with self.assertRaisesRegex(ValueError, "summary is required"):
            self.store.update_plan(
                plan["id"],
                expected_revision=updated["revision"],
                taskname="conversation-plan",
                content="Must not commit.",
                conversation_id=conversation["conversation_id"],
                writer_nonce=conversation["writer_nonce"],
                conversation_entries=[
                    {"role": "ai", "content": "Must summarize before another ordinary entry."}
                ],
                require_conversation=True,
            )
        current = self.store.query(entry_id=plan["id"])[0][0]
        self.assertEqual(2, current["revision"])
        self.assertEqual("Updated Plan content.", current["content"])
        self.assertEqual(
            49,
            self.store.conversation_query(
                conversation_id=conversation["conversation_id"],
                full=True,
                limit=100,
            )[1],
        )

    def test_plan_completion_requires_ai_entry_atomically(self) -> None:
        conversation = self.create_conversation("completion")
        plan = self.create_plan(conversation)
        debrief = {
            "items": [],
            "outcome": "succeeded",
            "memory_refs": [],
            "memory_feedback": [],
            "memory_conflicts": [],
        }
        with self.assertRaisesRegex(ValueError, "role=ai"):
            self.store.update_plan(
                plan["id"],
                expected_revision=plan["revision"],
                taskname="conversation-plan",
                plan_status="completed",
                debrief=debrief,
                conversation_id=conversation["conversation_id"],
                writer_nonce=conversation["writer_nonce"],
                conversation_entries=[
                    {"role": "user", "content": "Only user context is not enough to complete."}
                ],
                require_conversation=True,
            )
        current = self.store.query(entry_id=plan["id"])[0][0]
        self.assertEqual("in_progress", current["status"])
        self.assertEqual(plan["revision"], current["revision"])
        self.assertEqual(
            3,
            self.store.conversation_query(
                conversation_id=conversation["conversation_id"],
                full=True,
            )[1],
        )

        completed = self.store.update_plan(
            plan["id"],
            expected_revision=plan["revision"],
            taskname="conversation-plan",
            plan_status="completed",
            debrief=debrief,
            actor_id="actor",
            conversation_id=conversation["conversation_id"],
            writer_nonce=conversation["writer_nonce"],
            conversation_entries=[
                {"role": "ai", "content": "AI records the completed Plan result."}
            ],
            require_conversation=True,
        )
        self.assertEqual("completed", completed["status"])
        self.assertEqual(2, completed["revision"])
        self.assertEqual("ai", completed["conversation_entries"][0]["role"])

    def test_cancel_only_needs_no_conversation_owner_but_cancel_plus_edit_does(self) -> None:
        conversation = self.create_conversation("cancellation")
        plan = self.create_plan(conversation)

        with self.assertRaisesRegex(ValueError, "conversation_id"):
            self.store.update_plan(
                plan["id"],
                expected_revision=plan["revision"],
                taskname="conversation-plan",
                content="Edit while cancelling.",
                plan_status="cancelled",
                require_conversation=True,
            )
        unchanged = self.store.query(entry_id=plan["id"])[0][0]
        self.assertEqual("in_progress", unchanged["status"])
        self.assertEqual(plan["revision"], unchanged["revision"])

        cancelled = self.store.update_plan(
            plan["id"],
            expected_revision=plan["revision"],
            taskname="other-session-close",
            plan_status="cancelled",
            require_conversation=True,
        )
        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual(2, cancelled["revision"])
        self.assertEqual("conversation-plan", cancelled["taskname"])
        self.assertNotIn("conversation_entries", cancelled)

    def test_parent_plan_cannot_cross_conversation(self) -> None:
        first = self.create_conversation("first owner")
        second = self.create_conversation("second owner")
        parent = self.create_plan(first)
        before = self.store.conversation_query(
            conversation_id=second["conversation_id"],
            full=True,
        )[1]
        with self.assertRaisesRegex(ValueError, "different conversation"):
            self.create_plan(second, plan_id=parent["id"])
        self.assertEqual(1, self.store.query(entry_type="plan")[1])
        self.assertEqual(
            before,
            self.store.conversation_query(
                conversation_id=second["conversation_id"],
                full=True,
            )[1],
        )


if __name__ == "__main__":
    unittest.main()

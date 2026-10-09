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
        return self.store.conversation_query()[2]

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

    def test_create_request_id_replays_nonce_across_store_restart(self) -> None:
        from openkapsel.context.conversation import ConversationRequestConflict
        entries = self.initial_entries("idempotent")
        first = self.store.create_conversation(0, entries, request_id="retry-a", actor_id="actor-a")
        self.assertFalse(first["replayed"])
        restarted = ContextStore(self.root)
        replay = restarted.create_conversation(0, entries, request_id="retry-a", actor_id="actor-a")
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["writer_nonce"], replay["writer_nonce"])
        self.assertEqual(first["entries"], replay["entries"])
        self.assertEqual(1, restarted.conversation_query()[2])
        with self.assertRaises(ConversationRequestConflict) as conflict:
            restarted.create_conversation(0, self.initial_entries("changed"), request_id="retry-a", actor_id="actor-a")
        self.assertEqual("context_request_conflict", conflict.exception.code)
        with self.assertRaises(ValueError):
            restarted.create_conversation(0, entries, request_id="retry-a", actor_id="actor-b")
        with self.assertRaises(ValueError):
            restarted.create_conversation(1, entries, request_id="invalid key", actor_id="actor-a")
        with self.assertRaises(ValueError):
            restarted.create_conversation(1, entries, request_id="retry-b")
        with closing(sqlite3.connect(restarted.database)) as connection:
            connection.execute("DELETE FROM conversations WHERE id = 0")
            connection.commit()
        with self.assertRaises(ConversationRequestConflict) as gone:
            restarted.create_conversation(0, entries, request_id="retry-a", actor_id="actor-a")
        self.assertEqual("context_request_gone", gone.exception.code)

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
        )
        self.assertEqual(2, total)
        self.assertEqual(1, next_id)
        self.assertEqual(1, len(queried))
        self.assertEqual(created["conversation_id"], queried[0]["conversation_id"])
        self.assertEqual([1, 2], [item["sub_id"] for item in queried[0]["entries"]])
        self.assertTrue(all("writer_nonce" not in item for item in queried[0]["entries"]))

        with self.assertRaisesRegex(ValueError, "Call conversation_query"):
            self.store.create_conversation(2, self.initial_entries("skipped id"))
        with self.assertRaisesRegex(ValueError, "Call conversation_query"):
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
        self.assertEqual(0, self.store.conversation_query()[2])
        self.assertEqual(0, other.conversation_query()[2])
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
        self.assertIn("Call conversation_query", rejected)
        entries, total, next_id = self.store.conversation_query(conversation_id=0)
        self.assertEqual(2, total)
        self.assertEqual(1, next_id)
        self.assertEqual([0], [item["conversation_id"] for item in entries])

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
        )
        self.assertEqual(3, total)
        self.assertEqual([1, 2, 3], [item["sub_id"] for item in entries[0]["entries"]])

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

    def test_conversation_query_orders_by_last_update_pages_and_formats_time(self) -> None:
        conversations = [self.create_conversation(f"conversation {index}") for index in range(5)]
        second_page_first = conversations[2]
        self.store.append_conversation(
            conversation_id=second_page_first["conversation_id"],
            writer_nonce=second_page_first["writer_nonce"],
            entries=[
                {"role": "summary", "content": "checkpoint"},
                {"role": "user", "content": "after checkpoint user"},
                {"role": "ai", "content": "after checkpoint ai"},
            ],
        )
        oldest_kept = conversations[0]
        with closing(sqlite3.connect(self.store.database)) as connection:
            connection.executemany(
                "UPDATE conversation_entries SET created_at = ? WHERE conversation_id = ? AND sub_id = ?",
                [
                    ("2026-03-29T09:00:10+00:00", 0, 1),
                    ("2026-03-29T09:01:20+00:00", 0, 2),
                    ("2026-03-31T10:00:05+00:00", 1, 1),
                    ("2026-03-31T10:01:06+00:00", 1, 2),
                    ("2026-03-30T10:00:01+00:00", 2, 1),
                    ("2026-03-30T10:01:02+00:00", 2, 2),
                    ("2026-03-30T11:00:03+00:00", 2, 3),
                    ("2026-03-31T00:01:12+00:00", 2, 4),
                    ("2026-03-31T00:02:13+00:00", 2, 5),
                    ("2026-04-01T08:00:01+00:00", 3, 1),
                    ("2026-04-01T08:01:02+00:00", 3, 2),
                    ("2026-03-28T07:00:01+00:00", 4, 1),
                    ("2026-03-28T07:01:02+00:00", 4, 2),
                ],
            )
            connection.executemany(
                "INSERT INTO conversation_entries (conversation_id, sub_id, created_at, role, content) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        oldest_kept["conversation_id"],
                        sub_id,
                        ("2026-03-28T09:30:23+00:00" if sub_id == 23 else f"2026-03-29T09:30:{sub_id % 60:02d}+00:00"),
                        "ai",
                        f"bulk {sub_id}",
                    )
                    for sub_id in range(3, 123)
                ],
            )
            connection.execute(
                "INSERT INTO conversations (id, created_at, writer_nonce) VALUES (?, ?, ?)",
                (5, "2026-04-02T00:00:00+00:00", "@e000@"),
            )
            connection.commit()

        first_page, total_conversations, next_id = self.store.conversation_query()
        self.assertEqual(5, total_conversations)
        self.assertEqual(6, next_id)
        self.assertEqual([3, 1], [item["conversation_id"] for item in first_page])
        self.assertEqual(["2026-04-01", "2026-03-31"], [item["date"] for item in first_page])
        self.assertTrue(all(re.fullmatch(r"\d{2}:\d{2}", entry["time"]) for group in first_page for entry in group["entries"]))

        second_page, second_total, _ = self.store.conversation_query(page=2)
        self.assertEqual(5, second_total)
        self.assertEqual([2, 0], [item["conversation_id"] for item in second_page])
        self.assertEqual([3, 4, 5], [item["sub_id"] for item in second_page[0]["entries"]])
        self.assertEqual("2026-03-30 11:00", second_page[0]["entries"][0]["time"])

        third_page, _, _ = self.store.conversation_query(page=3)
        self.assertEqual([4], [item["conversation_id"] for item in third_page])
        with self.assertRaises(ValueError):
            self.store.conversation_query(page=11)
        with self.assertRaises(ValueError):
            self.store.conversation_query(conversation_id=0, page=2)

        latest, latest_total, latest_next = self.store.conversation_query(conversation_id=0)
        self.assertEqual(122, latest_total)
        self.assertEqual(6, latest_next)
        self.assertEqual(1, len(latest))
        self.assertEqual(list(range(23, 123)), [item["sub_id"] for item in latest[0]["entries"]])
        self.assertEqual("2026-03-28 09:30", latest[0]["entries"][0]["time"])
        self.assertEqual("2026-03-29", latest[0]["date"])

        ranged, ranged_total, ranged_next_id = self.store.conversation_query(
            conversation_id=0,
            start_sub_id=10,
            end_sub_id=120,
        )
        self.assertEqual(111, ranged_total)
        self.assertEqual(6, ranged_next_id)
        self.assertEqual(list(range(21, 121)), [item["sub_id"] for item in ranged[0]["entries"]])
        self.assertTrue(all(
            re.fullmatch(r"(?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}:\d{2}", item["time"])
            for item in ranged[0]["entries"]
        ))

        with self.assertRaises(ValueError):
            self.store.conversation_query(start_sub_id=2)

    def test_plan_creation_and_conversation_append_are_atomic(self) -> None:
        conversation = self.create_conversation("plan create")
        before, before_total, _ = self.store.conversation_query(
            conversation_id=conversation["conversation_id"],
        )
        plan = self.create_plan(conversation)
        self.assertEqual(conversation["conversation_id"], plan["conversation_id"])
        self.assertEqual(3, plan["conversation_entries"][0]["sub_id"])
        self.assertEqual(1, self.store.query(entry_type="plan")[1])

        entries, total, _ = self.store.conversation_query(
            conversation_id=conversation["conversation_id"],
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
        )[1]
        with self.assertRaisesRegex(ValueError, "different conversation"):
            self.create_plan(second, plan_id=parent["id"])
        self.assertEqual(1, self.store.query(entry_type="plan")[1])
        self.assertEqual(
            before,
            self.store.conversation_query(
                conversation_id=second["conversation_id"],
                )[1],
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openkapsel.memory_store import MemoryStore


class MemoryStoreTests(unittest.TestCase):
    def test_revisioned_memory_tag_path_search_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            store = MemoryStore(workspace)
            created = store.create(
                category="known_issue",
                key="auth/form-reset",
                title="Login form reset race",
                content="Resetting the form before the async request completes loses state.",
                severity="high",
                tags=["auth", "frontend"],
                paths=["frontend/auth"],
                plan_id=7,
                actor_id="actor-a",
                message="Record reusable login failure",
            )
            self.assertTrue(created["memory_id"].startswith("mem_"))
            self.assertEqual(1, created["revision"])
            self.assertEqual("open", created["status"])
            self.assertTrue((workspace / ".context" / "memory.sqlite3").is_file())

            by_tag, total = store.query(tag="auth")
            self.assertEqual(1, total)
            self.assertEqual(created["memory_id"], by_tag[0]["memory_id"])
            by_path, total = store.query(path="frontend/auth/login.js")
            self.assertEqual(1, total)
            self.assertEqual(created["memory_id"], by_path[0]["memory_id"])

            related = store.related(
                "Fix login",
                ["frontend/auth/login.js"],
                ["auth"],
            )
            self.assertEqual(created["memory_id"], related[0]["memory_id"])
            self.assertEqual(["auth"], related[0]["matched_tags"])
            self.assertEqual(["frontend/auth"], related[0]["matched_paths"])

            updated = store.update(
                created["memory_id"],
                changes={"status": "resolved", "content": "Wait for the request, then reset."},
                expected_revision=1,
                plan_id=8,
                actor_id="actor-b",
                message="Record the verified fix",
            )
            self.assertEqual(2, updated["revision"])
            self.assertEqual(8, updated["resolution_plan_id"])
            revisions = store.revisions(created["memory_id"])
            self.assertEqual([2, 1], [item["revision"] for item in revisions])

            with self.assertRaises(RuntimeError):
                store.update(
                    created["memory_id"],
                    changes={"title": "stale update"},
                    expected_revision=1,
                    plan_id=8,
                    actor_id="actor-b",
                    message="Reject stale revision",
                )

            archived = store.archive(
                created["memory_id"],
                expected_revision=2,
                plan_id=8,
                actor_id="actor-b",
                message="Archive obsolete issue",
            )
            self.assertEqual(3, archived["revision"])
            active, total = store.query()
            self.assertEqual(([], 0), (active, total))
            archived_items, total = store.query(include_archived=True)
            self.assertEqual(1, total)
            self.assertIsNotNone(archived_items[0]["archived_at"])

    def test_memory_validates_tags_paths_and_unique_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = MemoryStore(Path(raw))
            store.create(
                category="overview",
                key="project",
                title="Project overview",
                content="A test project.",
                tags=["project"],
                plan_id=1,
                message="Create project overview",
            )
            with self.assertRaises(ValueError):
                store.create(
                    category="overview",
                    key="project",
                    title="Duplicate overview",
                    content="Duplicate.",
                    plan_id=1,
                    message="Reject duplicate key",
                )
            with self.assertRaises(ValueError):
                store.create(
                    category="decision",
                    title="Unsafe path",
                    content="Invalid path.",
                    paths=["../outside"],
                    plan_id=1,
                    message="Reject path escape",
                )


if __name__ == "__main__":
    unittest.main()

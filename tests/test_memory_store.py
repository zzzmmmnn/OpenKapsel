from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from openkapsel.context.memory_store import MemoryStore
from openkapsel.context.memory_handlers import MemoryHandlersMixin


class MemoryStoreTests(unittest.TestCase):
    def test_revisioned_memory_tag_path_search_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            store = MemoryStore(workspace)
            created = store.create(
                content="Reset only after the async login request completes.",
                tags=["auth", "frontend", "login", "lifecycle"],
                path="server:frontend/auth",
                plan_id=7,
                actor_id="actor-a",
                message="Record reusable login fact",
            )
            self.assertTrue(created["memory_id"].startswith("mem_"))
            self.assertEqual(1, created["revision"])
            self.assertEqual(
                {"path", "content", "tags"} <= set(created),
                True,
            )
            self.assertNotIn("category", created)
            self.assertNotIn("title", created)
            self.assertEqual("server:frontend/auth", created["path"])
            self.assertTrue(
                (workspace / ".openkapsel" / "context" / "memory.sqlite3").is_file()
            )

            by_tag, total = store.query(tag="auth")
            self.assertEqual(1, total)
            self.assertEqual(created["memory_id"], by_tag[0]["memory_id"])
            by_path, total = store.query(path="server:frontend/auth/login.js")
            self.assertEqual(1, total)
            self.assertEqual(created["memory_id"], by_path[0]["memory_id"])

            related = store.related(
                "Fix login",
                ["server:frontend/auth/login.js"],
                ["auth"],
            )
            self.assertEqual(created["memory_id"], related[0]["memory_id"])
            self.assertEqual(["auth"], related[0]["matched_tags"])
            self.assertEqual("server:frontend/auth", related[0]["matched_path"])

            updated = store.update(
                created["memory_id"],
                changes={"content": "Wait for login completion, then reset the form."},
                expected_revision=1,
                plan_id=8,
                actor_id="actor-b",
                message="Record the verified fix",
            )
            self.assertEqual(2, updated["revision"])
            self.assertEqual(
                "Wait for login completion, then reset the form.",
                updated["content"],
            )
            revisions = store.revisions(created["memory_id"])
            self.assertEqual([2, 1], [item["revision"] for item in revisions])
            self.assertNotIn("category", revisions[0]["snapshot"])

            with self.assertRaises(RuntimeError):
                store.update(
                    created["memory_id"],
                    changes={"tags": ["stale"]},
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
                message="Archive obsolete Memory",
            )
            self.assertEqual(3, archived["revision"])
            active, total = store.query()
            self.assertEqual(([], 0), (active, total))
            archived_items, total = store.query(include_archived=True)
            self.assertEqual(1, total)
            self.assertIsNotNone(archived_items[0]["archived_at"])

    def test_memory_requires_tags_and_content_is_capped_at_256(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = MemoryStore(Path(raw))
            with self.assertRaisesRegex(ValueError, "at least one tag"):
                store.create(
                    content="This should be rejected.",
                    tags=[],
                    plan_id=1,
                    message="Reject empty tags",
                )
            accepted = store.create(
                content="x" * 256,
                tags=["memory", "limit", "content", "validation"],
                plan_id=1,
                message="Accept boundary content",
            )
            self.assertEqual(256, len(accepted["content"]))
            with self.assertRaisesRegex(ValueError, "256 characters"):
                store.create(
                    content="x" * 257,
                    tags=["memory"],
                    plan_id=1,
                    message="Reject overlong content",
                )
            with self.assertRaises(ValueError):
                store.create(
                    content="Invalid path.",
                    tags=["paths"],
                    path="server:../outside",
                    plan_id=1,
                    message="Reject path escape",
                )

    def test_memory_path_namespaces_and_global_root_overlap(self) -> None:
        self.assertTrue(
            MemoryStore._paths_overlap(
                "server:src/auth/login.py",
                "server:src/auth",
            )
        )
        self.assertTrue(
            MemoryStore._paths_overlap(
                "mapping:win:C:/Repo/src/a.py",
                "mapping:win:c:/repo/src",
            )
        )
        self.assertFalse(
            MemoryStore._paths_overlap(
                "mapping:win-a:C:/repo",
                "mapping:win-b:C:/repo",
            )
        )
        self.assertFalse(
            MemoryStore._paths_overlap(
                "storage:p1:docs",
                "server:docs",
            )
        )
        self.assertTrue(
            MemoryStore._paths_overlap(
                "mapping:win:.",
                "mapping:win:C:/repo/src",
            )
        )
        self.assertTrue(
            MemoryStore._paths_overlap(
                "storage:p1:.",
                "storage:p1:docs/reports",
            )
        )
        self.assertTrue(
            MemoryStore._paths_overlap(
                "server:.",
                "mapping:win:C:/repo/src",
            )
        )
        self.assertTrue(
            MemoryStore._paths_overlap(
                "server:.",
                "storage:p1:docs",
            )
        )

    def test_common_memory_scope_respects_target_namespaces(self) -> None:
        self.assertEqual(
            "server:src/auth",
            MemoryHandlersMixin._common_memory_scope(
                ["server:src/auth/login", "server:src/auth/session"]
            ),
        )
        self.assertEqual(
            "mapping:win:C:/Repo/src",
            MemoryHandlersMixin._common_memory_scope(
                ["mapping:win:C:/Repo/src/auth", "mapping:win:c:/repo/src/api"]
            ),
        )
        self.assertEqual(
            "server:.",
            MemoryHandlersMixin._common_memory_scope(
                ["mapping:win-a:C:/repo", "mapping:win-b:C:/repo"]
            ),
        )
        self.assertEqual(
            "server:.",
            MemoryHandlersMixin._common_memory_scope(
                ["storage:p1:docs", "storage:p2:docs"]
            ),
        )
        self.assertEqual(
            "server:.",
            MemoryHandlersMixin._common_memory_scope(
                ["server:src", "mapping:win:C:/repo"]
            ),
        )
        self.assertEqual(
            "mapping:unix:/home/app",
            MemoryHandlersMixin._common_memory_scope(
                ["mapping:unix:/home/app/api", "mapping:unix:/home/app/jobs"]
            ),
        )
        self.assertEqual(
            "storage:p1:/docs",
            MemoryHandlersMixin._common_memory_scope(
                ["storage:p1:/docs/a", "storage:p1:/docs/b"]
            ),
        )

    def test_plan_memory_paths_use_only_shell_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw).resolve()

            class FakeContext:
                @staticmethod
                def query(**_kwargs):
                    return ([{
                        "operation": "shell.exec",
                        "status": "succeeded",
                        "request": {"cwd": "src/tools", "path": "ignored/request.txt"},
                        "result": {"path": "ignored/result.txt"},
                    }], 1)

            class FakeMappings:
                @staticmethod
                def at_path(_path):
                    return None

            class FakeStorage:
                @staticmethod
                def mapping_at_path(_path):
                    return None

            class FakeServer:
                mappings = FakeMappings()
                storage_providers = FakeStorage()

                @staticmethod
                def context_for(_root):
                    return FakeContext()

            class Handler(MemoryHandlersMixin):
                pass

            handler = Handler()
            handler.server = FakeServer()
            handler.token_scope_root = workspace
            self.assertEqual("server:src/tools", handler._plan_memory_path(7))

    def test_plan_memory_path_paginates_all_operations(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw).resolve()
            entries = [
                {
                    "id": entry_id,
                    "operation": "shell.exec",
                    "status": "succeeded",
                    "request": {"cwd": "src/tools" if entry_id > 1 else "docs"},
                    "result": {},
                }
                for entry_id in range(201, 0, -1)
            ]

            class FakeContext:
                @staticmethod
                def query(**kwargs):
                    before_id = kwargs.get("before_id")
                    candidates = entries
                    if before_id is not None:
                        candidates = [item for item in candidates if item["id"] < before_id]
                    limit = kwargs["limit"]
                    page = candidates[:limit]
                    return page, len(candidates)

            class FakeMappings:
                @staticmethod
                def at_path(_path):
                    return None

            class FakeStorage:
                @staticmethod
                def mapping_at_path(_path):
                    return None

            class FakeServer:
                mappings = FakeMappings()
                storage_providers = FakeStorage()

                @staticmethod
                def context_for(_root):
                    return FakeContext()

            class Handler(MemoryHandlersMixin):
                pass

            handler = Handler()
            handler.server = FakeServer()
            handler.token_scope_root = workspace
            self.assertEqual("server:.", handler._plan_memory_path(7))

    def test_legacy_multi_paths_expose_one_common_path_until_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = MemoryStore(Path(raw))
            created = store.create(
                content="Legacy path compatibility.",
                tags=["memory", "legacy", "path", "compatibility"],
                path="server:src/a",
                plan_id=1,
                message="Create seed Memory",
            )
            legacy_paths = ["server:src/a", "server:src/b"]
            connection = sqlite3.connect(store.database)
            connection.execute(
                "UPDATE memories SET paths_json = ? WHERE id = ?",
                (MemoryStore._encode(legacy_paths), created["memory_id"]),
            )
            connection.commit()
            connection.close()

            self.assertEqual("server:src", store.get(created["memory_id"])["path"])
            updated = store.update(
                created["memory_id"],
                changes={"tags": ["memory", "legacy", "path", "preserved"]},
                expected_revision=1,
                plan_id=2,
                actor_id="actor",
                message="Retag legacy paths",
            )
            self.assertEqual("server:src", updated["path"])
            connection = sqlite3.connect(store.database)
            stored = connection.execute(
                "SELECT paths_json FROM memories WHERE id = ?",
                (created["memory_id"],),
            ).fetchone()[0]
            connection.close()
            self.assertEqual(legacy_paths, MemoryStore._decode(stored))

            rewritten = store.update(
                created["memory_id"],
                changes={"path": "server:src/new"},
                expected_revision=2,
                plan_id=3,
                actor_id="actor",
                message="Rewrite to singular path",
            )
            self.assertEqual("server:src/new", rewritten["path"])

    def test_preflight_actions_simulates_ordered_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = MemoryStore(Path(raw))
            created = store.create(
                content="Ordered action preflight.",
                tags=["memory", "preflight", "revision", "actions"],
                path="server:src",
                plan_id=1,
                message="Create ordered action seed",
            )
            store.preflight_actions([
                {
                    "action": "update",
                    "memory_id": created["memory_id"],
                    "expected_revision": 1,
                    "content": "First simulated revision.",
                },
                {
                    "action": "update",
                    "memory_id": created["memory_id"],
                    "expected_revision": 2,
                    "content": "Second simulated revision.",
                },
                {
                    "action": "archive",
                    "memory_id": created["memory_id"],
                    "expected_revision": 3,
                },
            ])
            with self.assertRaises(KeyError):
                store.preflight_actions([
                    {
                        "action": "archive",
                        "memory_id": created["memory_id"],
                        "expected_revision": 1,
                    },
                    {
                        "action": "update",
                        "memory_id": created["memory_id"],
                        "expected_revision": 2,
                        "content": "Cannot update after simulated archive.",
                    },
                ])

    def test_legacy_long_content_is_preserved_until_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = MemoryStore(Path(raw))
            created = store.create(
                content="short",
                tags=["legacy", "memory", "migration", "content"],
                plan_id=1,
                message="Create seed Memory",
            )
            legacy_content = "L" * 600
            connection = sqlite3.connect(store.database)
            connection.execute(
                "UPDATE memories SET content = ?, title = ? WHERE id = ?",
                (legacy_content, legacy_content[:256], created["memory_id"]),
            )
            connection.commit()
            connection.close()

            legacy = store.get(created["memory_id"])
            self.assertEqual(600, len(legacy["content"]))
            tag_update = store.update(
                created["memory_id"],
                changes={"tags": ["legacy", "preserved", "tags", "migration"]},
                expected_revision=1,
                plan_id=2,
                actor_id="actor",
                message="Retag legacy Memory",
            )
            self.assertEqual(legacy_content, tag_update["content"])
            with self.assertRaisesRegex(ValueError, "256 characters"):
                store.update(
                    created["memory_id"],
                    changes={"content": "N" * 257},
                    expected_revision=2,
                    plan_id=3,
                    actor_id="actor",
                    message="Reject long rewrite",
                )

    def test_helpful_feedback_affects_relevance_without_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = MemoryStore(Path(raw))
            first = store.create(
                content="Reconnect uses a versioned WebSocket handshake.",
                tags=["client", "websocket", "reconnect", "handshake"],
                plan_id=1,
                message="Record reconnect architecture",
            )
            second = store.create(
                content="Reconnect may retry transport setup.",
                tags=["client", "websocket", "reconnect", "fallback"],
                plan_id=1,
                message="Record reconnect fallback",
            )
            validated = store.validate_helpful_feedback(
                [{"memory_id": first["memory_id"], "revision": 1}]
            )
            store.record_helpful_feedback(
                plan_id=2,
                feedback=validated,
                actor_id="actor-a",
            )
            used = store.get(first["memory_id"])
            self.assertEqual(1, used["revision"])
            self.assertEqual(1, used["helpful_count"])
            self.assertIsNotNone(used["last_helpful_at"])

            store.record_helpful_feedback(
                plan_id=2,
                feedback=validated,
                actor_id="actor-a",
            )
            self.assertEqual(1, store.get(first["memory_id"])["helpful_count"])
            store.record_helpful_feedback(
                plan_id=3,
                feedback=validated,
                actor_id="actor-b",
            )
            self.assertEqual(2, store.get(first["memory_id"])["helpful_count"])

            related = store.related("Reconnect client WebSocket", memory_tags=["client"])
            first_row = next(item for item in related if item["memory_id"] == first["memory_id"])
            second_row = next(item for item in related if item["memory_id"] == second["memory_id"])
            self.assertGreater(first_row["relevance_score"], second_row["relevance_score"])
            self.assertEqual(["client"], first_row["matched_tags"])


if __name__ == "__main__":
    unittest.main()

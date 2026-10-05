from __future__ import annotations

import sqlite3
import tempfile
import threading
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

    def test_concurrent_updates_reject_stale_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            seed_store = MemoryStore(workspace)
            created = seed_store.create(
                content="Initial concurrent Memory value.",
                tags=["memory", "revision", "concurrency", "cas"],
                plan_id=1,
                actor_id="seed",
                message="Create concurrency seed",
            )
            stores = [MemoryStore(workspace), MemoryStore(workspace)]
            barrier = threading.Barrier(2)
            outcomes: list[tuple[str, object, object]] = []
            outcomes_lock = threading.Lock()

            def writer(store: MemoryStore, content: str, actor_id: str) -> None:
                barrier.wait()
                try:
                    result = store.update(
                        created["memory_id"],
                        changes={"content": content},
                        expected_revision=1,
                        plan_id=2,
                        actor_id=actor_id,
                        message="Race the same Memory revision",
                    )
                except Exception as exc:
                    outcome: tuple[str, object, object] = (
                        "error",
                        type(exc).__name__,
                        str(exc),
                    )
                else:
                    outcome = ("ok", result["revision"], result["content"])
                with outcomes_lock:
                    outcomes.append(outcome)

            threads = [
                threading.Thread(
                    target=writer,
                    args=(stores[0], "Concurrent writer A won.", "writer-a"),
                ),
                threading.Thread(
                    target=writer,
                    args=(stores[1], "Concurrent writer B won.", "writer-b"),
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())

            successes = [item for item in outcomes if item[0] == "ok"]
            failures = [item for item in outcomes if item[0] == "error"]
            self.assertEqual(1, len(successes))
            self.assertEqual(1, len(failures))
            self.assertEqual(2, successes[0][1])
            self.assertEqual("RuntimeError", failures[0][1])
            self.assertIn("revision", str(failures[0][2]))

            current = seed_store.get(created["memory_id"])
            self.assertEqual(2, current["revision"])
            self.assertEqual(successes[0][2], current["content"])
            self.assertEqual(
                [2, 1],
                [item["revision"] for item in seed_store.revisions(created["memory_id"])],
            )

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

    def test_legacy_database_is_migrated_to_singular_path_schema(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            context = workspace / ".openkapsel" / "context"
            context.mkdir(parents=True)
            database = context / "memory.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE memories (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    category TEXT NOT NULL,
                    memory_key TEXT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT,
                    tags_json TEXT NOT NULL,
                    paths_json TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    source_plan_id INTEGER,
                    last_updated_plan_id INTEGER,
                    resolution_plan_id INTEGER,
                    helpful_count INTEGER NOT NULL DEFAULT 0,
                    last_helpful_at TEXT,
                    actor_id TEXT,
                    archived_at TEXT
                );
                CREATE TABLE memory_tags (
                    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                    tag TEXT NOT NULL,
                    PRIMARY KEY (memory_id, tag)
                );
                CREATE TABLE memory_paths (
                    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    PRIMARY KEY (memory_id, path)
                );
                CREATE TABLE memory_revisions (
                    memory_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    changed_at TEXT NOT NULL,
                    actor_id TEXT,
                    plan_id INTEGER,
                    message TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    PRIMARY KEY (memory_id, revision)
                );
                CREATE TABLE memory_feedback (
                    plan_id INTEGER NOT NULL,
                    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                    memory_revision INTEGER NOT NULL,
                    actor_id TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (plan_id, memory_id)
                );
                """
            )
            legacy_paths = ["server:src/a", "server:src/b"]
            tags = ["memory", "legacy", "path", "migration"]
            connection.execute(
                """
                INSERT INTO memories (
                    id, created_at, updated_at, category, memory_key, title,
                    content, status, severity, tags_json, paths_json, revision,
                    source_plan_id, last_updated_plan_id, resolution_plan_id,
                    helpful_count, last_helpful_at, actor_id, archived_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "mem_legacy", "2026-01-01T00:00:00+00:00",
                    "2026-01-02T00:00:00+00:00", "architecture", "old/key",
                    "Old title", "Legacy path migration.", "current", "high",
                    MemoryStore._encode(tags), MemoryStore._encode(legacy_paths),
                    1, 7, 7, None, 2, "2026-01-03T00:00:00+00:00",
                    "actor", None,
                ),
            )
            connection.executemany(
                "INSERT INTO memory_tags(memory_id, tag) VALUES (?, ?)",
                (("mem_legacy", tag) for tag in tags),
            )
            connection.executemany(
                "INSERT INTO memory_paths(memory_id, path) VALUES (?, ?)",
                (("mem_legacy", path) for path in legacy_paths),
            )
            legacy_snapshot = {
                "id": "mem_legacy",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
                "category": "architecture",
                "title": "Old title",
                "content": "Legacy path migration.",
                "tags": tags,
                "paths": legacy_paths,
                "revision": 1,
                "source_plan_id": 7,
                "last_updated_plan_id": 7,
                "actor_id": "actor",
                "archived_at": None,
            }
            connection.execute(
                "INSERT INTO memory_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "mem_legacy", 1, "2026-01-02T00:00:00+00:00", "actor", 7,
                    "Legacy revision", MemoryStore._encode(legacy_snapshot),
                ),
            )
            connection.execute(
                "INSERT INTO memory_feedback VALUES (?, ?, ?, ?, ?)",
                (
                    9, "mem_legacy", 1, "actor",
                    "2026-01-03T00:00:00+00:00",
                ),
            )
            prune_cases = [
                ("mem_outdated", "outdated", None),
                ("mem_superseded", "superseded", None),
                ("mem_resolved", "resolved", None),
                ("mem_wontfix", "wontfix", None),
                ("mem_archived", "current", "2026-01-04T00:00:00+00:00"),
                ("mem_suspected", "suspected_stale", None),
            ]
            for index, (memory_id, status, archived_at) in enumerate(prune_cases, 20):
                case_tags = ["legacy", "migration", status, "prune"]
                case_paths = [f"server:legacy/{status}/a", f"server:legacy/{status}/b"]
                connection.execute(
                    """
                    INSERT INTO memories (
                        id, created_at, updated_at, category, memory_key, title,
                        content, status, severity, tags_json, paths_json, revision,
                        source_plan_id, last_updated_plan_id, resolution_plan_id,
                        helpful_count, last_helpful_at, actor_id, archived_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        memory_id, "2026-01-01T00:00:00+00:00",
                        "2026-01-02T00:00:00+00:00", "known_issue", memory_id,
                        f"Legacy {status}", f"Legacy {status} content.", status, "low",
                        MemoryStore._encode(case_tags), MemoryStore._encode(case_paths),
                        1, 7, 7, None, 1, "2026-01-03T00:00:00+00:00",
                        "actor", archived_at,
                    ),
                )
                connection.executemany(
                    "INSERT INTO memory_tags(memory_id, tag) VALUES (?, ?)",
                    ((memory_id, tag) for tag in case_tags),
                )
                connection.executemany(
                    "INSERT INTO memory_paths(memory_id, path) VALUES (?, ?)",
                    ((memory_id, path) for path in case_paths),
                )
                case_snapshot = {
                    "id": memory_id,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-02T00:00:00+00:00",
                    "category": "known_issue",
                    "title": f"Legacy {status}",
                    "content": f"Legacy {status} content.",
                    "status": status,
                    "tags": case_tags,
                    "paths": case_paths,
                    "revision": 1,
                    "source_plan_id": 7,
                    "last_updated_plan_id": 7,
                    "actor_id": "actor",
                    "archived_at": archived_at,
                }
                connection.execute(
                    "INSERT INTO memory_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        memory_id, 1, "2026-01-02T00:00:00+00:00", "actor", 7,
                        "Legacy revision", MemoryStore._encode(case_snapshot),
                    ),
                )
                connection.execute(
                    "INSERT INTO memory_feedback VALUES (?, ?, ?, ?, ?)",
                    (
                        index, memory_id, 1, "actor",
                        "2026-01-03T00:00:00+00:00",
                    ),
                )
            connection.commit()
            connection.close()

            store = MemoryStore(workspace)
            migrated = store.get("mem_legacy")
            self.assertEqual("server:src", migrated["path"])
            self.assertEqual(tags, migrated["tags"])
            self.assertEqual(2, migrated["helpful_count"])
            suspected = store.get("mem_suspected")
            self.assertEqual("server:legacy/suspected_stale", suspected["path"])
            for memory_id in (
                "mem_outdated",
                "mem_superseded",
                "mem_resolved",
                "mem_wontfix",
                "mem_archived",
            ):
                with self.assertRaises(KeyError):
                    store.get(memory_id)

            connection = sqlite3.connect(store.database)
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(memories)")
            }
            self.assertEqual(
                {
                    "id", "created_at", "updated_at", "content", "tags_json",
                    "path", "revision", "source_plan_id", "last_updated_plan_id",
                    "helpful_count", "last_helpful_at", "actor_id", "archived_at",
                },
                columns,
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertNotIn("memory_paths", tables)
            self.assertEqual(2, connection.execute("PRAGMA user_version").fetchone()[0])
            feedback = connection.execute(
                "SELECT memory_revision, actor_id FROM memory_feedback "
                "WHERE plan_id = 9 AND memory_id = 'mem_legacy'"
            ).fetchone()
            self.assertEqual((1, "actor"), feedback)
            retained_ids = {"mem_legacy", "mem_suspected"}
            self.assertEqual(
                retained_ids,
                {
                    row[0]
                    for row in connection.execute("SELECT id FROM memories")
                },
            )
            for table in ("memory_tags", "memory_revisions", "memory_feedback"):
                self.assertEqual(
                    retained_ids,
                    {
                        row[0]
                        for row in connection.execute(
                            f"SELECT DISTINCT memory_id FROM {table}"
                        )
                    },
                )
            self.assertEqual([], connection.execute("PRAGMA foreign_key_check").fetchall())
            connection.close()

            history = store.revisions("mem_legacy")
            snapshot = history[0]["snapshot"]
            self.assertEqual("server:src", snapshot["path"])
            self.assertEqual("mem_legacy", snapshot["memory_id"])
            self.assertNotIn("paths", snapshot)
            self.assertNotIn("category", snapshot)
            self.assertNotIn("title", snapshot)

            updated = store.update(
                "mem_legacy",
                changes={"path": "server:src/new"},
                expected_revision=1,
                plan_id=8,
                actor_id="actor",
                message="Use migrated singular path",
            )
            self.assertEqual("server:src/new", updated["path"])

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
                "UPDATE memories SET content = ? WHERE id = ?",
                (legacy_content, created["memory_id"]),
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

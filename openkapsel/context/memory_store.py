"""Project-level long-term memory stored beside the context event log."""

from __future__ import annotations

import json
import os
import posixpath
import re
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openkapsel.random_ids import token_urlsafe_alnum
from openkapsel.workspace.workspace_layout import CONTEXT_DIRECTORY, ensure_workspace_directory, ensure_workspace_layout


MEMORY_DATABASE = "memory.sqlite3"
MAX_MEMORY_QUERY_LIMIT = 200
MAX_MEMORY_REVISION_LIMIT = 200
MAX_MEMORY_RELATED_CANDIDATES = 2_000
MAX_MEMORY_CONTENT_CHARS = 256
MAX_MEMORY_TITLE_CHARS = 256
MAX_MEMORY_TAGS = 32
MAX_MEMORY_SCOPE_PATHS = 64
MAX_MEMORY_TAG_CHARS = 64
MAX_MEMORY_PATH_CHARS = 4_096
MAX_MEMORY_CHANGE_MESSAGE_CHARS = 200
MAX_MEMORY_FEEDBACK_REFS = 20


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MemoryStore:
    """Mutable, revisioned project memory for exactly one workspace."""

    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve(strict=True)
        self.directory = ensure_workspace_layout(self.workspace).context
        self.database = self.directory / MEMORY_DATABASE
        self._lock = threading.RLock()
        self._initialize()

    def _prepare_storage(self) -> None:
        self.directory = ensure_workspace_directory(self.workspace, CONTEXT_DIRECTORY)
        if self.database.is_symlink():
            raise ValueError("Workspace memory database must not be a symlink")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._lock:
            self._prepare_storage()
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("PRAGMA journal_mode = WAL")
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS memories (
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
                        )
                        """
                    )
                    memory_columns = {
                        row["name"]
                        for row in connection.execute("PRAGMA table_info(memories)").fetchall()
                    }
                    if "helpful_count" not in memory_columns:
                        connection.execute(
                            "ALTER TABLE memories ADD COLUMN helpful_count INTEGER NOT NULL DEFAULT 0"
                        )
                    if "last_helpful_at" not in memory_columns:
                        connection.execute(
                            "ALTER TABLE memories ADD COLUMN last_helpful_at TEXT"
                        )
                    connection.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS memories_active_key "
                        "ON memories(category, memory_key) "
                        "WHERE memory_key IS NOT NULL AND archived_at IS NULL"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS memories_category_status_updated "
                        "ON memories(category, status, updated_at DESC)"
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS memory_tags (
                            memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                            tag TEXT NOT NULL,
                            PRIMARY KEY (memory_id, tag)
                        )
                        """
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS memory_tags_tag_memory "
                        "ON memory_tags(tag, memory_id)"
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS memory_paths (
                            memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                            path TEXT NOT NULL,
                            PRIMARY KEY (memory_id, path)
                        )
                        """
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS memory_paths_path_memory "
                        "ON memory_paths(path, memory_id)"
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS memory_revisions (
                            memory_id TEXT NOT NULL,
                            revision INTEGER NOT NULL,
                            changed_at TEXT NOT NULL,
                            actor_id TEXT,
                            plan_id INTEGER,
                            message TEXT NOT NULL,
                            snapshot_json TEXT NOT NULL,
                            PRIMARY KEY (memory_id, revision)
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS memory_feedback (
                            plan_id INTEGER NOT NULL,
                            memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                            memory_revision INTEGER NOT NULL,
                            actor_id TEXT,
                            created_at TEXT NOT NULL,
                            PRIMARY KEY (plan_id, memory_id)
                        )
                        """
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS memory_feedback_memory_created "
                        "ON memory_feedback(memory_id, created_at DESC)"
                    )
                    self._backfill_indexes(connection)
            os.chmod(self.database, 0o600)

    def _ensure_available(self) -> None:
        self._prepare_storage()
        if not self.database.exists():
            self._initialize()

    @staticmethod
    def _required_text(value: Any, name: str, maximum: int) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"memory {name} must be a non-empty string")
        result = value.strip()
        if len(result) > maximum:
            raise ValueError(f"memory {name} exceeds {maximum} characters")
        return result

    @classmethod
    def _validate_tags(cls, value: Any, *, required: bool = False) -> list[str]:
        if value is None:
            if required:
                raise ValueError("memory tags must contain at least one tag")
            return []
        if not isinstance(value, list) or len(value) > MAX_MEMORY_TAGS:
            raise ValueError(
                f"memory tags must be an array of 1 to {MAX_MEMORY_TAGS} strings"
                if required
                else f"memory tags must be an array of at most {MAX_MEMORY_TAGS} strings"
            )
        tags: list[str] = []
        for item in value:
            tag = cls._required_text(item, "tag", MAX_MEMORY_TAG_CHARS)
            if tag not in tags:
                tags.append(tag)
        if required and not tags:
            raise ValueError("memory tags must contain at least one tag")
        return tags

    @staticmethod
    def _normalize_path(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("memory path must be a non-empty string")
        raw = value.strip()
        kind = "server"
        target_id: str | None = None
        path_value = raw
        if raw.startswith("server:"):
            path_value = raw[len("server:"):]
        elif raw.startswith("mapping:"):
            kind = "mapping"
            rest = raw[len("mapping:"):]
            target_id, sep, path_value = rest.partition(":")
            if not sep or not target_id:
                raise ValueError("mapping memory paths require mapping:<mapping_id>:<path>")
        elif raw.startswith("storage:"):
            kind = "storage"
            rest = raw[len("storage:"):]
            target_id, sep, path_value = rest.partition(":")
            if not sep or not target_id:
                raise ValueError("storage memory paths require storage:<provider_id>:<path>")

        path_value = path_value.replace("\\", "/") or "."
        path = posixpath.normpath(path_value)
        if kind == "server":
            path = path.lstrip("/") or "."
            if path == ".." or path.startswith("../"):
                raise ValueError("server memory paths must stay inside the workspace root")
        elif not path.startswith("/") and not re.match(r"^[A-Za-z]:/", path):
            if path == ".." or path.startswith("../"):
                raise ValueError(f"{kind} memory paths must stay inside their target root")

        prefix = f"{kind}:" if target_id is None else f"{kind}:{target_id}:"
        normalized = prefix + path
        if len(normalized) > MAX_MEMORY_PATH_CHARS:
            raise ValueError(f"memory path exceeds {MAX_MEMORY_PATH_CHARS} characters")
        return normalized

    @classmethod
    def _path_parts(cls, scope: str) -> tuple[str, str | None, str]:
        normalized = cls._normalize_path(scope)
        if normalized.startswith("mapping:") or normalized.startswith("storage:"):
            kind, rest = normalized.split(":", 1)
            target_id, path = rest.split(":", 1)
            return kind, target_id, path
        return "server", None, normalized[len("server:"):]

    @staticmethod
    def _path_anchor(path: str) -> tuple[str, list[str]]:
        if path == ".":
            return ".", []
        drive = re.match(r"^([A-Za-z]:)/(.*)$", path)
        if drive:
            return drive.group(1), [part for part in drive.group(2).split("/") if part]
        if path.startswith("//"):
            return "//", [part for part in path[2:].split("/") if part]
        if path.startswith("/"):
            return "/", [part for part in path[1:].split("/") if part]
        return "", [part for part in path.split("/") if part]

    @classmethod
    def _common_path(cls, scopes: list[str]) -> str:
        if not scopes:
            return "server:."
        parsed = [cls._path_parts(scope) for scope in scopes]
        identities = {(kind, target_id) for kind, target_id, _path in parsed}
        if len(identities) != 1:
            return "server:."
        kind, target_id = next(iter(identities))
        prefix = f"{kind}:" if target_id is None else f"{kind}:{target_id}:"
        paths = [path for _kind, _target_id, path in parsed]
        if any(path == "." for path in paths):
            return prefix + "."

        anchored = [cls._path_anchor(path) for path in paths]
        anchors = [anchor for anchor, _parts in anchored]
        folded = [anchor.casefold() if kind == "mapping" else anchor for anchor in anchors]
        if any(anchor != folded[0] for anchor in folded[1:]):
            return prefix + "."

        common: list[str] = []
        for values in zip(*(parts for _anchor, parts in anchored)):
            reference = values[0].casefold() if kind == "mapping" else values[0]
            if all((value.casefold() if kind == "mapping" else value) == reference for value in values[1:]):
                common.append(values[0])
            else:
                break

        anchor = anchors[0]
        if anchor == "/":
            path = "/" + "/".join(common) if common else "/"
        elif anchor == "//":
            path = "//" + "/".join(common) if common else "//"
        elif anchor:
            path = anchor + ("/" + "/".join(common) if common else "/")
        else:
            path = "/".join(common) or "."
        return prefix + path

    @classmethod
    def _validate_scope_paths(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > MAX_MEMORY_SCOPE_PATHS:
            raise ValueError(
                f"memory scope paths must be an array of at most {MAX_MEMORY_SCOPE_PATHS} strings"
            )
        paths: list[str] = []
        for item in value:
            path = cls._normalize_path(item)
            if path not in paths:
                paths.append(path)
        return paths

    @staticmethod
    def _validate_plan_id(value: Any, *, required: bool = True) -> int | None:
        if value is None and not required:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("memory plan_id must be a positive integer")
        return value

    @staticmethod
    def _validate_revision(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("memory revision must be a positive integer")
        return value

    @staticmethod
    def _encode(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _decode(value: str) -> Any:
        return json.loads(value)

    @classmethod
    def _backfill_indexes(cls, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT id, tags_json, paths_json FROM memories"
        ).fetchall()
        for row in rows:
            try:
                tags = cls._decode(row["tags_json"])
                paths = cls._decode(row["paths_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(tags, list):
                connection.executemany(
                    "INSERT OR IGNORE INTO memory_tags(memory_id, tag) VALUES (?, ?)",
                    ((row["id"], tag) for tag in tags if isinstance(tag, str)),
                )
            if isinstance(paths, list):
                connection.executemany(
                    "INSERT OR IGNORE INTO memory_paths(memory_id, path) VALUES (?, ?)",
                    ((row["id"], path) for path in paths if isinstance(path, str)),
                )

    @classmethod
    def _stored_paths(cls, row: sqlite3.Row) -> list[str]:
        try:
            raw = cls._decode(row["paths_json"])
        except (TypeError, json.JSONDecodeError):
            return []
        if not isinstance(raw, list):
            return []
        paths: list[str] = []
        for item in raw:
            try:
                path = cls._normalize_path(item)
            except ValueError:
                continue
            if path not in paths:
                paths.append(path)
        return paths

    @classmethod
    def _serialize(cls, row: sqlite3.Row, *, excerpt: bool = False) -> dict[str, Any]:
        content = str(row["content"])
        if excerpt and len(content) > 500:
            content = content[:500] + "…"
        return {
            "memory_id": row["id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "content" if not excerpt else "excerpt": content,
            "tags": cls._decode(row["tags_json"]),
            "path": cls._common_path(cls._stored_paths(row)),
            "revision": int(row["revision"]),
            "source_plan_id": row["source_plan_id"],
            "last_updated_plan_id": row["last_updated_plan_id"],
            "helpful_count": int(row["helpful_count"]),
            "last_helpful_at": row["last_helpful_at"],
            "actor_id": row["actor_id"],
            "archived_at": row["archived_at"],
        }

    @classmethod
    def _snapshot(cls, row: sqlite3.Row) -> str:
        snapshot = cls._serialize(row)
        snapshot.pop("helpful_count", None)
        snapshot.pop("last_helpful_at", None)
        return cls._encode(snapshot)

    @classmethod
    def _deserialize_snapshot(cls, value: str) -> dict[str, Any]:
        snapshot = cls._decode(value)
        if not isinstance(snapshot, dict):
            return {}
        if "memory_id" not in snapshot and "id" in snapshot:
            snapshot["memory_id"] = snapshot.pop("id")
        if "path" not in snapshot and isinstance(snapshot.get("paths"), list):
            snapshot["path"] = cls._common_path(snapshot["paths"])
        allowed = {
            "memory_id", "created_at", "updated_at", "content", "tags", "path",
            "revision", "source_plan_id", "last_updated_plan_id", "actor_id", "archived_at",
        }
        result = {key: item for key, item in snapshot.items() if key in allowed}
        if "path" in result:
            result["path"] = cls._normalize_path(result["path"])
        return result

    def create(
        self,
        *,
        content: Any,
        tags: Any,
        path: Any = None,
        plan_id: Any = None,
        actor_id: str | None = None,
        message: str = "create memory",
    ) -> dict[str, Any]:
        content = self._required_text(content, "content", MAX_MEMORY_CONTENT_CHARS)
        tags = self._validate_tags(tags, required=True)
        path = self._normalize_path("server:." if path is None else path)
        paths = [path]
        plan_id = self._validate_plan_id(plan_id, required=False)
        message = self._required_text(
            message,
            "change message",
            MAX_MEMORY_CHANGE_MESSAGE_CHARS,
        )
        now = _utc_now()
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                for _ in range(8):
                    memory_id = "mem_" + token_urlsafe_alnum(12)
                    try:
                        connection.execute(
                            """
                            INSERT INTO memories (
                                id, created_at, updated_at, category, memory_key,
                                title, content, status, severity, tags_json,
                                paths_json, revision, source_plan_id,
                                last_updated_plan_id, resolution_plan_id, actor_id
                            ) VALUES (?, ?, ?, 'overview', NULL, ?, ?, 'current', NULL, ?, ?, 1, ?, ?, NULL, ?)
                            """,
                            (
                                memory_id, now, now, content, content,
                                self._encode(tags), self._encode(paths),
                                plan_id, plan_id, actor_id,
                            ),
                        )
                        break
                    except sqlite3.IntegrityError as exc:
                        if "memories.id" not in str(exc):
                            connection.rollback()
                            raise ValueError("memory could not be created") from None
                else:
                    connection.rollback()
                    raise RuntimeError("unable to allocate memory id")
                row = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
                assert row is not None
                connection.executemany(
                    "INSERT INTO memory_tags(memory_id, tag) VALUES (?, ?)",
                    ((memory_id, tag) for tag in tags),
                )
                connection.executemany(
                    "INSERT INTO memory_paths(memory_id, path) VALUES (?, ?)",
                    ((memory_id, path) for path in paths),
                )
                connection.execute(
                    "INSERT INTO memory_revisions VALUES (?, 1, ?, ?, ?, ?, ?)",
                    (memory_id, now, actor_id, plan_id, message, self._snapshot(row)),
                )
                connection.commit()
        return self._serialize(row)

    def get(self, memory_id: str, *, include_archived: bool = False) -> dict[str, Any]:
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                row = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        if row is None or (row["archived_at"] is not None and not include_archived):
            raise KeyError("memory does not exist")
        return self._serialize(row)

    def preflight_actions(self, actions: Any) -> None:
        """Validate completion Memory mutations before any debrief side effects."""
        if not isinstance(actions, list):
            raise ValueError("memory actions must be an array")
        simulated: dict[str, tuple[int, bool]] = {}
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                for index, item in enumerate(actions):
                    if not isinstance(item, dict):
                        raise ValueError(f"memory action {index} must be an object")
                    action = item.get("action")
                    memory_id = item.get("memory_id")
                    if not isinstance(memory_id, str) or not memory_id:
                        raise ValueError(f"memory action {index} requires memory_id")
                    expected_revision = self._validate_revision(item.get("expected_revision"))
                    state = simulated.get(memory_id)
                    if state is None:
                        row = connection.execute(
                            "SELECT revision, archived_at FROM memories WHERE id = ?", (memory_id,)
                        ).fetchone()
                        if row is None or row["archived_at"] is not None:
                            raise KeyError("memory does not exist")
                        state = (int(row["revision"]), False)
                    current_revision, archived = state
                    if archived:
                        raise KeyError("memory does not exist")
                    if current_revision != expected_revision:
                        raise RuntimeError(
                            f"memory revision is {current_revision}, not {expected_revision}"
                        )

                    if action == "update":
                        allowed = {"action", "memory_id", "expected_revision", "content", "tags", "path"}
                        unknown = set(item) - allowed
                        if unknown:
                            raise ValueError(
                                "unknown memory action fields: " + ", ".join(sorted(unknown))
                            )
                        changes = {
                            key: value
                            for key, value in item.items()
                            if key not in {"action", "memory_id", "expected_revision"}
                        }
                        if not changes:
                            raise ValueError("memory update requires content, tags, or path")
                        if "content" in changes:
                            self._required_text(
                                changes["content"], "content", MAX_MEMORY_CONTENT_CHARS
                            )
                        if "tags" in changes:
                            self._validate_tags(changes["tags"], required=True)
                        if "path" in changes:
                            self._normalize_path(changes["path"])
                        simulated[memory_id] = (current_revision + 1, False)
                    elif action == "archive":
                        unknown = set(item) - {"action", "memory_id", "expected_revision"}
                        if unknown:
                            raise ValueError(
                                "unknown memory action fields: " + ", ".join(sorted(unknown))
                            )
                        simulated[memory_id] = (current_revision + 1, True)
                    else:
                        raise ValueError("memory action must be update or archive")

    def update(
        self,
        memory_id: str,
        *,
        changes: dict[str, Any],
        expected_revision: Any,
        plan_id: Any,
        actor_id: str | None,
        message: str,
    ) -> dict[str, Any]:
        expected_revision = self._validate_revision(expected_revision)
        plan_id = self._validate_plan_id(plan_id)
        message = self._required_text(
            message,
            "change message",
            MAX_MEMORY_CHANGE_MESSAGE_CHARS,
        )
        allowed = {"content", "tags", "path"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError("unknown memory fields: " + ", ".join(sorted(unknown)))
        if not changes:
            raise ValueError("memory update requires content, tags, or path")
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
                if row is None or row["archived_at"] is not None:
                    connection.rollback()
                    raise KeyError("memory does not exist")
                if int(row["revision"]) != expected_revision:
                    connection.rollback()
                    raise RuntimeError(f"memory revision is {row['revision']}, not {expected_revision}")
                content = (
                    self._required_text(changes["content"], "content", MAX_MEMORY_CONTENT_CHARS)
                    if "content" in changes
                    else str(row["content"])
                )
                tags = self._validate_tags(
                    changes.get("tags", self._decode(row["tags_json"])), required=True
                )
                stored_paths = self._decode(row["paths_json"])
                paths = stored_paths if isinstance(stored_paths, list) else []
                if "path" in changes:
                    paths = [self._normalize_path(changes["path"])]
                revision = expected_revision + 1
                now = _utc_now()
                connection.execute(
                    """
                    UPDATE memories SET updated_at = ?, title = ?, content = ?, tags_json = ?,
                        paths_json = ?, revision = ?, last_updated_plan_id = ?, actor_id = ?
                    WHERE id = ?
                    """,
                    (
                        now, content[:MAX_MEMORY_TITLE_CHARS], content,
                        self._encode(tags), self._encode(paths), revision, plan_id,
                        actor_id, memory_id,
                    ),
                )
                updated = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
                assert updated is not None
                connection.execute("DELETE FROM memory_tags WHERE memory_id = ?", (memory_id,))
                connection.execute("DELETE FROM memory_paths WHERE memory_id = ?", (memory_id,))
                connection.executemany(
                    "INSERT INTO memory_tags(memory_id, tag) VALUES (?, ?)",
                    ((memory_id, tag) for tag in tags),
                )
                connection.executemany(
                    "INSERT INTO memory_paths(memory_id, path) VALUES (?, ?)",
                    ((memory_id, path) for path in paths),
                )
                connection.execute(
                    "INSERT INTO memory_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (memory_id, revision, now, actor_id, plan_id, message, self._snapshot(updated)),
                )
                connection.commit()
        return self._serialize(updated)

    def archive(
        self,
        memory_id: str,
        *,
        expected_revision: Any,
        plan_id: Any,
        actor_id: str | None,
        message: str,
    ) -> dict[str, Any]:
        expected_revision = self._validate_revision(expected_revision)
        plan_id = self._validate_plan_id(plan_id)
        message = self._required_text(
            message,
            "change message",
            MAX_MEMORY_CHANGE_MESSAGE_CHARS,
        )
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
                if row is None or row["archived_at"] is not None:
                    connection.rollback()
                    raise KeyError("memory does not exist")
                if int(row["revision"]) != expected_revision:
                    connection.rollback()
                    raise RuntimeError(f"memory revision is {row['revision']}, not {expected_revision}")
                now = _utc_now()
                revision = expected_revision + 1
                connection.execute(
                    "UPDATE memories SET updated_at = ?, archived_at = ?, revision = ?, "
                    "last_updated_plan_id = ?, actor_id = ? WHERE id = ?",
                    (now, now, revision, plan_id, actor_id, memory_id),
                )
                archived = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
                assert archived is not None
                connection.execute(
                    "INSERT INTO memory_revisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (memory_id, revision, now, actor_id, plan_id, message, self._snapshot(archived)),
                )
                connection.commit()
        return self._serialize(archived)

    def validate_helpful_feedback(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            raise ValueError("memory feedback must be an array")
        if len(value) > MAX_MEMORY_FEEDBACK_REFS:
            raise ValueError(
                f"memory feedback cannot contain more than {MAX_MEMORY_FEEDBACK_REFS} items"
            )
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                for index, item in enumerate(value):
                    if not isinstance(item, dict):
                        raise ValueError(f"memory feedback {index} must be an object")
                    memory_id = item.get("memory_id")
                    if not isinstance(memory_id, str) or not memory_id:
                        raise ValueError(f"memory feedback {index} requires memory_id")
                    revision = self._validate_revision(item.get("revision"))
                    if memory_id in seen:
                        raise ValueError(f"memory feedback duplicates {memory_id}")
                    seen.add(memory_id)
                    row = connection.execute(
                        "SELECT archived_at FROM memories WHERE id = ?", (memory_id,)
                    ).fetchone()
                    if row is None or row["archived_at"] is not None:
                        raise KeyError("memory does not exist")
                    exists = connection.execute(
                        "SELECT 1 FROM memory_revisions WHERE memory_id = ? AND revision = ?",
                        (memory_id, revision),
                    ).fetchone()
                    if exists is None:
                        raise ValueError(
                            f"memory feedback revision {revision} does not exist for {memory_id}"
                        )
                    normalized.append({"memory_id": memory_id, "revision": revision})
        return normalized

    def record_helpful_feedback(
        self,
        *,
        plan_id: Any,
        feedback: list[dict[str, Any]],
        actor_id: str | None,
    ) -> list[dict[str, Any]]:
        plan_id = self._validate_plan_id(plan_id)
        if len(feedback) > MAX_MEMORY_FEEDBACK_REFS:
            raise ValueError(
                f"memory feedback cannot contain more than {MAX_MEMORY_FEEDBACK_REFS} items"
            )
        results: list[dict[str, Any]] = []
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                for item in feedback:
                    memory_id = item["memory_id"]
                    revision = self._validate_revision(item["revision"])
                    existing = connection.execute(
                        "SELECT memory_revision, created_at FROM memory_feedback "
                        "WHERE plan_id = ? AND memory_id = ?",
                        (plan_id, memory_id),
                    ).fetchone()
                    if existing is not None:
                        if int(existing["memory_revision"]) != revision:
                            connection.rollback()
                            raise ValueError(
                                f"plan {plan_id} already recorded a different revision for {memory_id}"
                            )
                        results.append(
                            {
                                "memory_id": memory_id,
                                "revision": revision,
                                "helpful_at": existing["created_at"],
                            }
                        )
                        continue
                    exists = connection.execute(
                        "SELECT 1 FROM memories WHERE id = ?", (memory_id,)
                    ).fetchone()
                    if exists is None:
                        connection.rollback()
                        raise KeyError("memory does not exist")
                    now = _utc_now()
                    connection.execute(
                        "INSERT INTO memory_feedback("
                        "plan_id, memory_id, memory_revision, actor_id, created_at"
                        ") VALUES (?, ?, ?, ?, ?)",
                        (plan_id, memory_id, revision, actor_id, now),
                    )
                    connection.execute(
                        "UPDATE memories SET helpful_count = helpful_count + 1, "
                        "last_helpful_at = ? WHERE id = ?",
                        (now, memory_id),
                    )
                    results.append(
                        {
                            "memory_id": memory_id,
                            "revision": revision,
                            "helpful_at": now,
                        }
                    )
                connection.commit()
        return results

    def revisions(self, memory_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= MAX_MEMORY_REVISION_LIMIT:
            raise ValueError(
                f"memory revision limit must be between 1 and {MAX_MEMORY_REVISION_LIMIT}"
            )
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                exists = connection.execute("SELECT 1 FROM memories WHERE id = ?", (memory_id,)).fetchone()
                if exists is None:
                    raise KeyError("memory does not exist")
                rows = connection.execute(
                    "SELECT * FROM memory_revisions WHERE memory_id = ? ORDER BY revision DESC LIMIT ?",
                    (memory_id, limit),
                ).fetchall()
        return [
            {
                "memory_id": row["memory_id"],
                "revision": int(row["revision"]),
                "changed_at": row["changed_at"],
                "actor_id": row["actor_id"],
                "plan_id": row["plan_id"],
                "message": row["message"],
                "snapshot": self._deserialize_snapshot(row["snapshot_json"]),
            }
            for row in rows
        ]

    def query(
        self,
        *,
        query: str = "",
        tag: str | None = None,
        path: str | None = None,
        include_archived: bool = False,
        limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        if not 1 <= limit <= MAX_MEMORY_QUERY_LIMIT:
            raise ValueError(f"memory limit must be between 1 and {MAX_MEMORY_QUERY_LIMIT}")
        normalized_query = query.strip()
        if len(normalized_query) > 1_000:
            raise ValueError("memory query exceeds 1000 characters")
        normalized_path = self._normalize_path(path) if path is not None else None
        clauses = [] if include_archived else ["archived_at IS NULL"]
        values: list[Any] = []
        if tag is not None:
            tag = self._required_text(tag, "tag", MAX_MEMORY_TAG_CHARS)
            clauses.append(
                "EXISTS (SELECT 1 FROM memory_tags WHERE memory_tags.memory_id = memories.id AND memory_tags.tag = ?)"
            )
            values.append(tag)
        if normalized_query:
            escaped = normalized_query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            clauses.append("content LIKE ? ESCAPE '\\'")
            values.append(pattern)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT * FROM memories" + where + " ORDER BY "
                    "CASE WHEN last_helpful_at IS NOT NULL AND last_helpful_at > updated_at "
                    "THEN last_helpful_at ELSE updated_at END DESC",
                    values,
                ).fetchall()
        items = [self._serialize(row) for row in rows]
        if normalized_path is not None:
            items = [
                item for item in items
                if self._paths_overlap(normalized_path, item["path"])
            ]
        total = len(items)
        return items[:limit], total

    @classmethod
    def _paths_overlap(cls, left: str, right: str) -> bool:
        left = cls._normalize_path(left)
        right = cls._normalize_path(right)
        if left == "server:." or right == "server:.":
            return True

        def split(value: str) -> tuple[str, str | None, str]:
            if value.startswith("mapping:") or value.startswith("storage:"):
                kind, rest = value.split(":", 1)
                target, path_value = rest.split(":", 1)
                return kind, target, path_value
            return "server", None, value[len("server:"):]

        left_kind, left_target, left_path = split(left)
        right_kind, right_target, right_path = split(right)
        if (left_kind, left_target) != (right_kind, right_target):
            return False
        if left_path == "." or right_path == ".":
            return True
        if left_kind == "mapping":
            left_path = left_path.casefold()
            right_path = right_path.casefold()
        return (
            left_path == right_path
            or left_path.startswith(right_path.rstrip("/") + "/")
            or right_path.startswith(left_path.rstrip("/") + "/")
        )

    @staticmethod
    def _keywords(value: str) -> set[str]:
        lowered = value.lower()
        words = set(re.findall(r"[a-z0-9_.-]{2,}", lowered))
        for sequence in re.findall(r"[\u3400-\u9fff]+", lowered):
            if len(sequence) <= 4:
                words.add(sequence)
            else:
                words.update(sequence[index:index + 2] for index in range(len(sequence) - 1))
        return words

    def related(
        self,
        content: str,
        scope_paths: list[str] | None = None,
        memory_tags: list[str] | None = None,
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        paths = self._validate_scope_paths(scope_paths)
        requested_tags = set(self._validate_tags(memory_tags))
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT * FROM memories WHERE archived_at IS NULL ORDER BY "
                    "CASE WHEN last_helpful_at IS NOT NULL AND last_helpful_at > updated_at "
                    "THEN last_helpful_at ELSE updated_at END DESC LIMIT ?",
                    (MAX_MEMORY_RELATED_CANDIDATES,),
                ).fetchall()
        items = [self._serialize(row) for row in rows]
        query_words = self._keywords(content)
        ranked: list[tuple[int, dict[str, Any], str | None, list[str]]] = []
        for item in items:
            matched_path = (
                item["path"]
                if any(self._paths_overlap(scope, item["path"]) for scope in paths)
                else None
            )
            matched_tags = sorted(requested_tags & set(item["tags"]))
            haystack = " ".join([item["content"], *item["tags"]])
            word_matches = len(query_words & self._keywords(haystack))
            score = word_matches * 2 + (12 if matched_path is not None else 0) + len(matched_tags) * 10
            score += min(3, int(item["helpful_count"]))
            if score > 0:
                ranked.append((score, item, matched_path, matched_tags))
        ranked.sort(
            key=lambda row: (
                row[0],
                max(row[1]["updated_at"], row[1]["last_helpful_at"] or ""),
            ),
            reverse=True,
        )
        result: list[dict[str, Any]] = []
        for score, item, matched_path, matched_tags in ranked[:limit]:
            compact = dict(item)
            content_value = compact.pop("content")
            compact["excerpt"] = content_value[:500] + ("…" if len(content_value) > 500 else "")
            compact["relevance_score"] = score
            compact["matched_path"] = matched_path
            compact["matched_tags"] = matched_tags
            result.append(compact)
        return result

    def project(self) -> dict[str, Any]:
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                total = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM memories WHERE archived_at IS NULL"
                    ).fetchone()[0]
                )
                rows = connection.execute(
                    """
                    SELECT * FROM memories
                    WHERE archived_at IS NULL
                    ORDER BY
                        CASE WHEN last_helpful_at IS NOT NULL AND last_helpful_at > updated_at
                             THEN last_helpful_at ELSE updated_at END DESC
                    LIMIT 50
                    """
                ).fetchall()
        memories = [self._serialize(row, excerpt=True) for row in rows]
        return {"memories": memories, "total": total, "truncated": total > len(memories)}

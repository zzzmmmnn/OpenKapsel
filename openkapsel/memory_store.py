"""Project-level long-term memory stored beside the context event log."""

from __future__ import annotations

import json
import os
import posixpath
import re
import secrets
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MEMORY_DATABASE = "memory.sqlite3"
MEMORY_CATEGORIES = {
    "overview",
    "architecture",
    "convention",
    "decision",
    "known_issue",
}
MEMORY_STATUSES = {
    "current",
    "suspected_stale",
    "outdated",
    "active",
    "superseded",
    "open",
    "resolved",
    "wontfix",
}
MEMORY_SEVERITIES = {"high", "medium", "low"}
MAX_MEMORY_QUERY_LIMIT = 200
MAX_MEMORY_CONTENT_CHARS = 32_768
MAX_MEMORY_TITLE_CHARS = 256
MAX_MEMORY_KEY_CHARS = 256
MAX_MEMORY_TAGS = 32
MAX_MEMORY_PATHS = 64
MAX_MEMORY_TAG_CHARS = 64
MAX_MEMORY_PATH_CHARS = 4_096
MAX_MEMORY_CHANGE_MESSAGE_CHARS = 200


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_status(category: str) -> str:
    if category == "known_issue":
        return "open"
    if category == "decision":
        return "active"
    return "current"


class MemoryStore:
    """Mutable, revisioned project memory for exactly one workspace."""

    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve(strict=True)
        self.directory = self.workspace / ".context"
        self.database = self.directory / MEMORY_DATABASE
        self._lock = threading.RLock()
        self._initialize()

    def _prepare_storage(self) -> None:
        if self.directory.is_symlink() or (
            self.directory.exists() and not self.directory.is_dir()
        ):
            raise ValueError("Workspace .context must be a real directory")
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.directory.chmod(0o700)
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
                            actor_id TEXT,
                            archived_at TEXT
                        )
                        """
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
    def _optional_key(cls, value: Any) -> str | None:
        if value is None:
            return None
        return cls._required_text(value, "key", MAX_MEMORY_KEY_CHARS)

    @staticmethod
    def _validate_category(value: Any) -> str:
        if not isinstance(value, str) or value not in MEMORY_CATEGORIES:
            raise ValueError("invalid memory category")
        return value

    @staticmethod
    def _validate_status(category: str, value: Any) -> str:
        status = _default_status(category) if value is None else value
        if not isinstance(status, str) or status not in MEMORY_STATUSES:
            raise ValueError("invalid memory status")
        if category == "known_issue" and status not in {"open", "resolved", "wontfix"}:
            raise ValueError("known_issue status must be open, resolved, or wontfix")
        if category != "known_issue" and status in {"open", "resolved", "wontfix"}:
            raise ValueError("open, resolved, and wontfix are only valid for known_issue")
        return status

    @staticmethod
    def _validate_severity(category: str, value: Any) -> str | None:
        if value is None:
            return None
        if category != "known_issue":
            raise ValueError("severity is only valid for known_issue")
        if not isinstance(value, str) or value not in MEMORY_SEVERITIES:
            raise ValueError("memory severity must be high, medium, or low")
        return value

    @classmethod
    def _validate_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > MAX_MEMORY_TAGS:
            raise ValueError(f"memory tags must be an array of at most {MAX_MEMORY_TAGS} strings")
        tags: list[str] = []
        for item in value:
            tag = cls._required_text(item, "tag", MAX_MEMORY_TAG_CHARS)
            if tag not in tags:
                tags.append(tag)
        return tags

    @staticmethod
    def _normalize_path(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("memory path must be a non-empty string")
        raw = value.strip().replace("\\", "/")
        if raw.startswith("/"):
            raise ValueError("memory paths must be relative to the workspace")
        path = posixpath.normpath(raw)
        if path == ".." or path.startswith("../"):
            raise ValueError("memory paths must stay inside the workspace")
        if len(path) > MAX_MEMORY_PATH_CHARS:
            raise ValueError(f"memory path exceeds {MAX_MEMORY_PATH_CHARS} characters")
        return path

    @classmethod
    def _validate_paths(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > MAX_MEMORY_PATHS:
            raise ValueError(f"memory paths must be an array of at most {MAX_MEMORY_PATHS} strings")
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
    def _serialize(cls, row: sqlite3.Row, *, excerpt: bool = False) -> dict[str, Any]:
        content = str(row["content"])
        if excerpt and len(content) > 500:
            content = content[:500] + "…"
        return {
            "memory_id": row["id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "category": row["category"],
            "key": row["memory_key"],
            "title": row["title"],
            "content" if not excerpt else "excerpt": content,
            "status": row["status"],
            "severity": row["severity"],
            "tags": cls._decode(row["tags_json"]),
            "paths": cls._decode(row["paths_json"]),
            "revision": int(row["revision"]),
            "source_plan_id": row["source_plan_id"],
            "last_updated_plan_id": row["last_updated_plan_id"],
            "resolution_plan_id": row["resolution_plan_id"],
            "actor_id": row["actor_id"],
            "archived_at": row["archived_at"],
        }

    @classmethod
    def _snapshot(cls, row: sqlite3.Row) -> str:
        return cls._encode(cls._serialize(row))

    @classmethod
    def _deserialize_snapshot(cls, value: str) -> dict[str, Any]:
        snapshot = cls._decode(value)
        if isinstance(snapshot, dict) and "memory_id" not in snapshot and "id" in snapshot:
            snapshot["memory_id"] = snapshot.pop("id")
        return snapshot

    def create(
        self,
        *,
        category: Any,
        title: Any,
        content: Any,
        key: Any = None,
        status: Any = None,
        severity: Any = None,
        tags: Any = None,
        paths: Any = None,
        plan_id: Any = None,
        actor_id: str | None = None,
        message: str = "create memory",
    ) -> dict[str, Any]:
        category = self._validate_category(category)
        title = self._required_text(title, "title", MAX_MEMORY_TITLE_CHARS)
        content = self._required_text(content, "content", MAX_MEMORY_CONTENT_CHARS)
        key = self._optional_key(key)
        status = self._validate_status(category, status)
        severity = self._validate_severity(category, severity)
        tags = self._validate_tags(tags)
        paths = self._validate_paths(paths)
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
                    memory_id = "mem_" + secrets.token_urlsafe(12)
                    try:
                        connection.execute(
                            """
                            INSERT INTO memories (
                                id, created_at, updated_at, category, memory_key,
                                title, content, status, severity, tags_json,
                                paths_json, revision, source_plan_id,
                                last_updated_plan_id, resolution_plan_id, actor_id
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                            """,
                            (
                                memory_id, now, now, category, key, title, content,
                                status, severity, self._encode(tags), self._encode(paths),
                                plan_id, plan_id,
                                plan_id if category == "known_issue" and status != "open" else None,
                                actor_id,
                            ),
                        )
                        break
                    except sqlite3.IntegrityError as exc:
                        if key is not None or "memories.id" not in str(exc):
                            connection.rollback()
                            raise ValueError("an active memory with this category and key already exists") from None
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
        allowed = {"category", "key", "title", "content", "status", "severity", "tags", "paths"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError("unknown memory fields: " + ", ".join(sorted(unknown)))
        if not changes:
            raise ValueError("memory update requires at least one changed field")
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
                category = self._validate_category(changes.get("category", row["category"]))
                key = self._optional_key(changes.get("key", row["memory_key"]))
                title = self._required_text(changes.get("title", row["title"]), "title", MAX_MEMORY_TITLE_CHARS)
                content = self._required_text(changes.get("content", row["content"]), "content", MAX_MEMORY_CONTENT_CHARS)
                status = self._validate_status(category, changes.get("status", row["status"]))
                severity = self._validate_severity(category, changes.get("severity", row["severity"]))
                tags = self._validate_tags(changes.get("tags", self._decode(row["tags_json"])))
                paths = self._validate_paths(changes.get("paths", self._decode(row["paths_json"])))
                revision = expected_revision + 1
                now = _utc_now()
                try:
                    connection.execute(
                        """
                        UPDATE memories SET updated_at = ?, category = ?, memory_key = ?,
                            title = ?, content = ?, status = ?, severity = ?, tags_json = ?,
                            paths_json = ?, revision = ?, last_updated_plan_id = ?,
                            resolution_plan_id = ?, actor_id = ? WHERE id = ?
                        """,
                        (
                            now, category, key, title, content, status, severity,
                            self._encode(tags), self._encode(paths), revision, plan_id,
                            plan_id if category == "known_issue" and status in {"resolved", "wontfix"} else row["resolution_plan_id"],
                            actor_id, memory_id,
                        ),
                    )
                except sqlite3.IntegrityError:
                    connection.rollback()
                    raise ValueError("an active memory with this category and key already exists") from None
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

    def revisions(self, memory_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= MAX_MEMORY_QUERY_LIMIT:
            raise ValueError(f"memory revision limit must be between 1 and {MAX_MEMORY_QUERY_LIMIT}")
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
        category: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        tag: str | None = None,
        path: str | None = None,
        include_archived: bool = False,
        limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        if not 1 <= limit <= MAX_MEMORY_QUERY_LIMIT:
            raise ValueError(f"memory limit must be between 1 and {MAX_MEMORY_QUERY_LIMIT}")
        if category is not None:
            category = self._validate_category(category)
        if status is not None and status not in MEMORY_STATUSES:
            raise ValueError("invalid memory status")
        if severity is not None and severity not in MEMORY_SEVERITIES:
            raise ValueError("invalid memory severity")
        normalized_query = query.strip()
        if len(normalized_query) > 1_000:
            raise ValueError("memory query exceeds 1000 characters")
        normalized_path = self._normalize_path(path) if path is not None else None
        clauses = [] if include_archived else ["archived_at IS NULL"]
        values: list[Any] = []
        for column, value in (("category", category), ("status", status), ("severity", severity)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        if tag is not None:
            tag = self._required_text(tag, "tag", MAX_MEMORY_TAG_CHARS)
            clauses.append(
                "EXISTS (SELECT 1 FROM memory_tags WHERE memory_tags.memory_id = memories.id AND memory_tags.tag = ?)"
            )
            values.append(tag)
        if normalized_query:
            escaped = normalized_query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            clauses.append("(title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\' OR COALESCE(memory_key, '') LIKE ? ESCAPE '\\')")
            values.extend([pattern, pattern, pattern])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT * FROM memories" + where + " ORDER BY updated_at DESC",
                    values,
                ).fetchall()
        items = [self._serialize(row) for row in rows]
        if normalized_path is not None:
            items = [item for item in items if any(self._paths_overlap(normalized_path, candidate) for candidate in item["paths"])]
        total = len(items)
        return items[:limit], total

    @staticmethod
    def _paths_overlap(left: str, right: str) -> bool:
        return left == right or left.startswith(right.rstrip("/") + "/") or right.startswith(left.rstrip("/") + "/")

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
        paths = self._validate_paths(scope_paths)
        requested_tags = set(self._validate_tags(memory_tags))
        items, _ = self.query(limit=MAX_MEMORY_QUERY_LIMIT)
        query_words = self._keywords(content)
        ranked: list[tuple[int, dict[str, Any], list[str]]] = []
        for item in items:
            matched_paths = [
                candidate
                for candidate in item["paths"]
                if any(self._paths_overlap(scope, candidate) for scope in paths)
            ]
            matched_tags = sorted(requested_tags & set(item["tags"]))
            haystack = " ".join(
                [item["title"], item["content"], item.get("key") or "", *item["tags"]]
            )
            word_matches = len(query_words & self._keywords(haystack))
            score = word_matches * 2 + len(matched_paths) * 12 + len(matched_tags) * 10
            if item["category"] == "overview":
                score += 2
            if item["category"] == "known_issue" and item["status"] == "open":
                score += {"high": 8, "medium": 4, "low": 2, None: 1}[item["severity"]]
            if score > 0:
                ranked.append((score, item, matched_paths))
        ranked.sort(key=lambda row: (row[0], row[1]["updated_at"]), reverse=True)
        result: list[dict[str, Any]] = []
        for score, item, matched_paths in ranked[:limit]:
            compact = dict(item)
            content_value = compact.pop("content")
            compact["excerpt"] = content_value[:500] + ("…" if len(content_value) > 500 else "")
            compact["relevance_score"] = score
            compact["matched_paths"] = matched_paths
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
                        CASE
                            WHEN category = 'overview' THEN 0
                            WHEN category = 'architecture' THEN 1
                            WHEN category = 'known_issue' AND status = 'open'
                                 AND severity = 'high' THEN 2
                            WHEN category = 'known_issue' AND status = 'open' THEN 3
                            WHEN category = 'convention' THEN 4
                            WHEN category = 'decision' THEN 5
                            ELSE 6
                        END ASC,
                        updated_at DESC
                    LIMIT 50
                    """
                ).fetchall()
        memories = [self._serialize(row) for row in rows]
        return {"memories": memories, "total": total, "truncated": total > len(memories)}

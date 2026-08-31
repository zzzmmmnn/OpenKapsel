"""Per-workspace append-oriented context and operation records."""

from __future__ import annotations

import json
import os
import posixpath
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .workspace_layout import CONTEXT_DIRECTORY, ensure_workspace_directory, ensure_workspace_layout


CONTEXT_DATABASE = "context.sqlite3"
CONTEXT_TYPES = {"operation", "plan", "note"}
OPERATION_STATUSES = {"running", "succeeded", "failed"}
PLAN_STATUSES = {"in_progress", "completed", "cancelled"}
MAX_CONTEXT_ENTRIES = 100_000
CONTEXT_TRIM_ENTRIES = 1_000
MAX_CONTEXT_QUERY_LIMIT = 200
MAX_CONTEXT_CONTENT_CHARS = 32_768
MAX_CONTEXT_OPERATION_MESSAGE_CHARS = 200
MAX_CONTEXT_TASKNAME_CHARS = 32
MAX_CONTEXT_ACTOR_ID_CHARS = 256
MAX_CONTEXT_PATH_CHARS = 4_096
CONTEXT_PATH_KEYS = {"path", "source", "destination", "cwd"}
MAX_PLAN_TREE_DEPTH = 32
MAX_UNFINISHED_ROOT_PLAN_HINTS = 20
MAX_PLAN_HINT_CONTENT_CHARS = 256
_UNSET = object()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ContextStore:
    """SQLite context history owned by exactly one workspace directory."""

    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve(strict=True)
        self.directory = ensure_workspace_layout(self.workspace).context
        self.database = self.directory / CONTEXT_DATABASE
        self._lock = threading.RLock()
        self._initialize()

    def _prepare_storage(self) -> None:
        self.directory = ensure_workspace_directory(self.workspace, CONTEXT_DIRECTORY)
        if self.database.is_symlink():
            raise ValueError("Workspace context database must not be a symlink")

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
                        CREATE TABLE IF NOT EXISTS context_entries (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            entry_type TEXT NOT NULL CHECK (
                                entry_type IN ('operation', 'plan', 'note')
                            ),
                            content TEXT NOT NULL,
                            operation TEXT,
                            status TEXT CHECK (
                                status IS NULL OR status IN ('running', 'succeeded', 'failed')
                            ),
                            result_summary TEXT,
                            actor_id TEXT,
                            request_json TEXT,
                            result_json TEXT,
                            taskname TEXT,
                            plan_status TEXT CHECK (
                                plan_status IS NULL OR plan_status IN (
                                    'in_progress', 'completed', 'cancelled'
                                )
                            ),
                            plan_id INTEGER
                        )
                        """
                    )
                    columns = {
                        row["name"]
                        for row in connection.execute(
                            "PRAGMA table_info(context_entries)"
                        ).fetchall()
                    }
                    if "taskname" not in columns:
                        connection.execute(
                            "ALTER TABLE context_entries ADD COLUMN taskname TEXT"
                        )
                    if "plan_status" not in columns:
                        connection.execute(
                            "ALTER TABLE context_entries ADD COLUMN plan_status TEXT "
                            "CHECK (plan_status IS NULL OR plan_status IN "
                            "('in_progress', 'completed', 'cancelled'))"
                        )
                    if "plan_id" not in columns:
                        connection.execute(
                            "ALTER TABLE context_entries ADD COLUMN plan_id INTEGER"
                        )
                    connection.execute(
                        "UPDATE context_entries SET plan_status = 'in_progress' "
                        "WHERE entry_type = 'plan' AND plan_status IS NULL"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS context_entries_type_id "
                        "ON context_entries(entry_type, id DESC)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS context_entries_taskname_id "
                        "ON context_entries(taskname, id DESC)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS context_entries_actor_id_id "
                        "ON context_entries(actor_id, id DESC)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS context_entries_plan_id_id "
                        "ON context_entries(plan_id, id DESC)"
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS context_entry_paths (
                            entry_id INTEGER NOT NULL REFERENCES context_entries(id)
                                ON DELETE CASCADE,
                            path TEXT NOT NULL,
                            PRIMARY KEY (entry_id, path)
                        )
                        """
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS context_entry_paths_path_id "
                        "ON context_entry_paths(path, entry_id DESC)"
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS plan_debriefs (
                            plan_id INTEGER PRIMARY KEY REFERENCES context_entries(id)
                                ON DELETE CASCADE,
                            created_at TEXT NOT NULL,
                            actor_id TEXT,
                            summary TEXT NOT NULL,
                            outcome TEXT NOT NULL,
                            memory_refs_json TEXT NOT NULL
                        )
                        """
                    )
                    self._backfill_paths(connection)
            os.chmod(self.database, 0o600)

    def _ensure_available(self) -> None:
        self._prepare_storage()
        if not self.database.exists():
            self._initialize()

    @staticmethod
    def _validate_content(content: str) -> str:
        if not isinstance(content, str) or not content.strip():
            raise ValueError("context content must be a non-empty string")
        value = content.strip()
        if len(value) > MAX_CONTEXT_CONTENT_CHARS:
            raise ValueError(
                f"context content exceeds {MAX_CONTEXT_CONTENT_CHARS} characters"
            )
        return value

    @staticmethod
    def _validate_taskname(taskname: str) -> str:
        if not isinstance(taskname, str) or not taskname.strip():
            raise ValueError("context taskname must be a non-empty string")
        value = taskname.strip()
        if len(value) > MAX_CONTEXT_TASKNAME_CHARS:
            raise ValueError(
                f"context taskname exceeds {MAX_CONTEXT_TASKNAME_CHARS} characters"
            )
        return value

    @staticmethod
    def _encode_json(value: dict[str, Any] | None) -> str | None:
        if value is None:
            return None
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _validate_actor_id(actor_id: str) -> str:
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise ValueError("context actor_id must be a non-empty string")
        value = actor_id.strip()
        if len(value) > MAX_CONTEXT_ACTOR_ID_CHARS:
            raise ValueError(
                f"context actor_id exceeds {MAX_CONTEXT_ACTOR_ID_CHARS} characters"
            )
        return value

    @staticmethod
    def _normalize_path(path: str) -> str:
        if not isinstance(path, str) or not path.strip():
            raise ValueError("context path must be a non-empty string")
        value = posixpath.normpath(path.strip())
        if len(value) > MAX_CONTEXT_PATH_CHARS:
            raise ValueError(
                f"context path exceeds {MAX_CONTEXT_PATH_CHARS} characters"
            )
        return value

    @classmethod
    def _extract_paths(cls, value: dict[str, Any] | None) -> set[str]:
        if not isinstance(value, dict):
            return set()
        paths: set[str] = set()
        for key in CONTEXT_PATH_KEYS:
            candidate = value.get(key)
            candidates = candidate if isinstance(candidate, list) else [candidate]
            for item in candidates:
                if not isinstance(item, str) or not item.strip():
                    continue
                try:
                    paths.add(cls._normalize_path(item))
                except ValueError:
                    continue
        return paths

    @classmethod
    def _backfill_paths(cls, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT id, request_json, result_json FROM context_entries "
            "WHERE request_json IS NOT NULL OR result_json IS NOT NULL"
        ).fetchall()
        for row in rows:
            paths: set[str] = set()
            for field in ("request_json", "result_json"):
                encoded = row[field]
                if not encoded:
                    continue
                try:
                    paths.update(cls._extract_paths(json.loads(encoded)))
                except (TypeError, json.JSONDecodeError):
                    continue
            connection.executemany(
                "INSERT OR IGNORE INTO context_entry_paths(entry_id, path) VALUES (?, ?)",
                ((int(row["id"]), path) for path in paths),
            )

    @classmethod
    def _insert_paths(
        cls,
        connection: sqlite3.Connection,
        entry_id: int,
        value: dict[str, Any] | None,
    ) -> None:
        connection.executemany(
            "INSERT OR IGNORE INTO context_entry_paths(entry_id, path) VALUES (?, ?)",
            ((entry_id, path) for path in cls._extract_paths(value)),
        )

    @staticmethod
    def _validate_plan_id_value(plan_id: Any) -> int:
        if isinstance(plan_id, bool) or not isinstance(plan_id, int) or plan_id < 1:
            raise ValueError("plan_id must be a positive integer")
        return plan_id

    @classmethod
    def _require_plan(
        cls,
        connection: sqlite3.Connection,
        plan_id: Any,
    ) -> sqlite3.Row:
        plan_id = cls._validate_plan_id_value(plan_id)
        row = connection.execute(
            "SELECT * FROM context_entries WHERE id = ?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise ValueError("plan_id does not exist")
        if row["entry_type"] != "plan":
            raise ValueError("plan_id must reference a plan")
        return row

    @classmethod
    def _validate_plan_parent(
        cls,
        connection: sqlite3.Connection,
        plan_id: Any,
        *,
        child_id: int | None = None,
    ) -> int:
        plan_id = cls._validate_plan_id_value(plan_id)
        cls._require_plan(connection, plan_id)
        if child_id is not None and plan_id == child_id:
            raise ValueError("a plan cannot be its own parent")
        current: int | None = plan_id
        visited: set[int] = set()
        while current is not None:
            if child_id is not None and current == child_id:
                raise ValueError("plan parent would create a cycle")
            if current in visited:
                raise ValueError("existing plan hierarchy contains a cycle")
            visited.add(current)
            row = connection.execute(
                "SELECT plan_id FROM context_entries WHERE id = ? AND entry_type = 'plan'",
                (current,),
            ).fetchone()
            if row is None:
                break
            current = row["plan_id"]
        return plan_id

    def add(
        self,
        entry_type: str,
        content: str,
        *,
        taskname: str,
        actor_id: str | None = None,
        operation: str | None = None,
        status: str | None = None,
        plan_status: str | None = None,
        plan_id: int | None = None,
        request: dict[str, Any] | None = None,
    ) -> int:
        if entry_type not in CONTEXT_TYPES:
            raise ValueError("context type must be operation, plan, or note")
        if status is not None and status not in OPERATION_STATUSES:
            raise ValueError("invalid context operation status")
        if entry_type != "operation" and status is not None:
            raise ValueError("only operation context can have an operation status")
        if entry_type == "operation" and plan_status is not None:
            raise ValueError("operation context cannot have a plan status")
        if entry_type == "plan":
            plan_status = plan_status or "in_progress"
            if plan_status not in PLAN_STATUSES:
                raise ValueError("plan status must be in_progress, completed, or cancelled")
        elif plan_status is not None:
            raise ValueError("only plan context can have a plan status")
        content = self._validate_content(content)
        if entry_type == "operation" and len(content) > MAX_CONTEXT_OPERATION_MESSAGE_CHARS:
            raise ValueError(
                f"context operation message exceeds {MAX_CONTEXT_OPERATION_MESSAGE_CHARS} characters"
            )
        taskname = self._validate_taskname(taskname)
        if actor_id is not None:
            actor_id = self._validate_actor_id(actor_id)
        now = _utc_now()
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if plan_id is not None:
                    if entry_type == "plan":
                        plan_id = self._validate_plan_parent(connection, plan_id)
                    else:
                        plan_id = self._validate_plan_id_value(plan_id)
                        self._require_plan(connection, plan_id)
                cursor = connection.execute(
                    """
                    INSERT INTO context_entries (
                        created_at, updated_at, entry_type, content, operation,
                        status, actor_id, request_json, taskname, plan_status,
                        plan_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        now,
                        entry_type,
                        content,
                        operation,
                        status,
                        actor_id,
                        self._encode_json(request),
                        taskname,
                        plan_status,
                        plan_id,
                    ),
                )
                entry_id = int(cursor.lastrowid)
                self._insert_paths(connection, entry_id, request)
                self._trim_if_needed(connection)
                connection.commit()
        return entry_id

    @staticmethod
    def _trim_if_needed(connection: sqlite3.Connection) -> None:
        count = int(
            connection.execute("SELECT COUNT(*) FROM context_entries").fetchone()[0]
        )
        if count > MAX_CONTEXT_ENTRIES:
            connection.execute(
                """
                DELETE FROM context_entries
                WHERE id IN (
                    SELECT candidate.id
                    FROM context_entries AS candidate
                    WHERE candidate.entry_type != 'plan'
                       OR NOT EXISTS (
                            SELECT 1
                            FROM context_entries AS dependent
                            WHERE dependent.plan_id = candidate.id
                       )
                    ORDER BY candidate.id ASC
                    LIMIT ?
                )
                """,
                (CONTEXT_TRIM_ENTRIES,),
            )

    def update_plan(
        self,
        entry_id: int,
        *,
        taskname: str,
        content: str | None = None,
        plan_status: str | None = None,
        plan_id: int | None | object = _UNSET,
        debrief: dict[str, Any] | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        taskname = self._validate_taskname(taskname)
        if content is None and plan_status is None and plan_id is _UNSET and debrief is None:
            raise ValueError("plan update requires content, status, or plan_id")
        if content is not None:
            content = self._validate_content(content)
        if plan_status is not None and plan_status not in PLAN_STATUSES:
            raise ValueError("plan status must be in_progress, completed, or cancelled")
        if debrief is not None:
            if plan_status != "completed":
                raise ValueError("plan debrief is only valid when status is completed")
            if not isinstance(debrief, dict):
                raise ValueError("plan debrief must be an object")
            summary = self._validate_content(debrief.get("summary"))
            outcome = debrief.get("outcome")
            if outcome not in {"succeeded", "partial", "no_change"}:
                raise ValueError("plan debrief outcome must be succeeded, partial, or no_change")
            memory_refs = debrief.get("memory_refs", [])
            if not isinstance(memory_refs, list):
                raise ValueError("plan debrief memory_refs must be an array")
            if actor_id is not None:
                actor_id = self._validate_actor_id(actor_id)
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM context_entries WHERE id = ?",
                    (entry_id,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    raise KeyError("context entry does not exist")
                if row["entry_type"] != "plan":
                    connection.rollback()
                    raise ValueError("context entry is not a plan")
                if debrief is not None:
                    existing_debrief = connection.execute(
                        "SELECT 1 FROM plan_debriefs WHERE plan_id = ?",
                        (entry_id,),
                    ).fetchone()
                    if existing_debrief is not None:
                        connection.rollback()
                        raise ValueError("plan already has a completion debrief")
                next_plan_id = row["plan_id"]
                if plan_id is not _UNSET:
                    next_plan_id = (
                        None
                        if plan_id is None
                        else self._validate_plan_parent(
                            connection,
                            plan_id,
                            child_id=entry_id,
                        )
                    )
                connection.execute(
                    """
                    UPDATE context_entries
                    SET updated_at = ?, taskname = ?, content = ?, plan_status = ?,
                        plan_id = ?
                    WHERE id = ?
                    """,
                    (
                        _utc_now(),
                        taskname,
                        content if content is not None else row["content"],
                        plan_status
                        if plan_status is not None
                        else (row["plan_status"] or "in_progress"),
                        next_plan_id,
                        entry_id,
                    ),
                )
                if debrief is not None:
                    connection.execute(
                        "INSERT INTO plan_debriefs VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            entry_id,
                            _utc_now(),
                            actor_id,
                            summary,
                            outcome,
                            self._encode_json({"items": memory_refs}) or "{}",
                        ),
                    )
                updated = connection.execute(
                    "SELECT * FROM context_entries WHERE id = ?",
                    (entry_id,),
                ).fetchone()
                connection.commit()
        assert updated is not None
        return self._serialize(updated)

    def plan_debrief(self, plan_id: int) -> dict[str, Any] | None:
        plan_id = self._validate_plan_id_value(plan_id)
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM plan_debriefs WHERE plan_id = ?",
                    (plan_id,),
                ).fetchone()
        if row is None:
            return None
        return self._serialize_debrief(row)

    def replace_note(
        self,
        entry_id: int,
        *,
        taskname: str,
        content: str,
        actor_id: str | None = None,
        plan_id: int | None | object = _UNSET,
    ) -> dict[str, Any]:
        taskname = self._validate_taskname(taskname)
        content = self._validate_content(content)
        if actor_id is not None:
            actor_id = self._validate_actor_id(actor_id)
        now = _utc_now()
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT entry_type, plan_id FROM context_entries WHERE id = ?",
                    (entry_id,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    raise KeyError("context entry does not exist")
                if row["entry_type"] != "note":
                    connection.rollback()
                    raise ValueError("context entry is not a note")
                next_plan_id = row["plan_id"]
                if plan_id is not _UNSET:
                    if plan_id is None:
                        raise ValueError("notes must reference a plan_id")
                    next_plan_id = self._validate_plan_id_value(plan_id)
                    self._require_plan(connection, next_plan_id)
                cursor = connection.execute(
                    """
                    INSERT INTO context_entries (
                        created_at, updated_at, entry_type, content, actor_id,
                        taskname, plan_id
                    ) VALUES (?, ?, 'note', ?, ?, ?, ?)
                    """,
                    (now, now, content, actor_id, taskname, next_plan_id),
                )
                new_id = int(cursor.lastrowid)
                connection.execute(
                    "DELETE FROM context_entries WHERE id = ?",
                    (entry_id,),
                )
                self._trim_if_needed(connection)
                replacement = connection.execute(
                    "SELECT * FROM context_entries WHERE id = ?",
                    (new_id,),
                ).fetchone()
                connection.commit()
        assert replacement is not None
        return self._serialize(replacement)

    def finish_operation(
        self,
        entry_id: int,
        *,
        succeeded: bool,
        result_summary: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        summary = self._validate_content(result_summary)
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                with connection:
                    cursor = connection.execute(
                        """
                        UPDATE context_entries
                        SET updated_at = ?, status = ?, result_summary = ?, result_json = ?
                        WHERE id = ? AND entry_type = 'operation'
                        """,
                        (
                            _utc_now(),
                            "succeeded" if succeeded else "failed",
                            summary,
                            self._encode_json(result),
                            entry_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise KeyError("context operation does not exist")
                    self._insert_paths(connection, entry_id, result)

    def query(
        self,
        *,
        entry_id: int | None = None,
        exclude_entry_id: int | None = None,
        query: str | None = None,
        entry_type: str | None = None,
        entry_status: str | None = None,
        taskname: str | None = None,
        actor_id: str | None = None,
        path: str | None = None,
        plan_id: int | None = None,
        root_plans: bool = False,
        before_id: int | None = None,
        limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        if not 1 <= limit <= MAX_CONTEXT_QUERY_LIMIT:
            raise ValueError(f"context limit must be between 1 and {MAX_CONTEXT_QUERY_LIMIT}")
        if entry_id is not None and entry_id < 1:
            raise ValueError("context id must be positive")
        if exclude_entry_id is not None and exclude_entry_id < 1:
            raise ValueError("excluded context id must be positive")
        if before_id is not None and before_id < 1:
            raise ValueError("before_id must be positive")
        if plan_id is not None:
            plan_id = self._validate_plan_id_value(plan_id)
        if root_plans and plan_id is not None:
            raise ValueError("root_plans and plan_id filters cannot be combined")
        if entry_type is not None and entry_type not in CONTEXT_TYPES:
            raise ValueError("context type must be operation, plan, or note")
        if entry_status is not None:
            if entry_status not in OPERATION_STATUSES | PLAN_STATUSES:
                raise ValueError("invalid context status filter")
            if entry_type == "plan" and entry_status not in PLAN_STATUSES:
                raise ValueError("invalid plan status filter")
            if entry_type == "operation" and entry_status not in OPERATION_STATUSES:
                raise ValueError("invalid operation status filter")
            if entry_type == "note":
                raise ValueError("note context has no status")
        normalized_taskname = (taskname or "").strip()
        if taskname is not None:
            normalized_taskname = self._validate_taskname(taskname)
        normalized_actor_id = (actor_id or "").strip()
        if actor_id is not None:
            normalized_actor_id = self._validate_actor_id(actor_id)
        normalized_path = (path or "").strip()
        if path is not None:
            normalized_path = self._normalize_path(path)
        normalized_query = (query or "").strip()
        if len(normalized_query) > 1_000:
            raise ValueError("context query exceeds 1000 characters")
        clauses: list[str] = []
        values: list[Any] = []
        if entry_id is not None:
            clauses.append("id = ?")
            values.append(entry_id)
        if exclude_entry_id is not None:
            clauses.append("id != ?")
            values.append(exclude_entry_id)
        if entry_type is not None:
            clauses.append("entry_type = ?")
            values.append(entry_type)
        if entry_status is not None:
            if entry_type == "plan":
                clauses.append("plan_status = ?")
            elif entry_type == "operation":
                clauses.append("status = ?")
            else:
                clauses.append("COALESCE(plan_status, status) = ?")
            values.append(entry_status)
        if normalized_taskname:
            clauses.append("taskname = ?")
            values.append(normalized_taskname)
        if normalized_actor_id:
            clauses.append("actor_id = ?")
            values.append(normalized_actor_id)
        if normalized_path:
            clauses.append(
                "EXISTS (SELECT 1 FROM context_entry_paths "
                "WHERE context_entry_paths.entry_id = context_entries.id "
                "AND context_entry_paths.path = ?)"
            )
            values.append(normalized_path)
        if plan_id is not None:
            clauses.append("plan_id = ?")
            values.append(plan_id)
        if root_plans:
            clauses.append("entry_type = 'plan' AND plan_id IS NULL")
        if before_id is not None:
            clauses.append("id < ?")
            values.append(before_id)
        if normalized_query:
            escaped = (
                normalized_query.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{escaped}%"
            clauses.append(
                "(content LIKE ? ESCAPE '\\' OR "
                "COALESCE(result_summary, '') LIKE ? ESCAPE '\\' OR "
                "COALESCE(operation, '') LIKE ? ESCAPE '\\' OR "
                "COALESCE(taskname, '') LIKE ? ESCAPE '\\')"
            )
            values.extend([pattern, pattern, pattern, pattern])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                total = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM context_entries" + where,
                        values,
                    ).fetchone()[0]
                )
                rows = connection.execute(
                    "SELECT * FROM context_entries"
                    + where
                    + " ORDER BY id DESC LIMIT ?",
                    [*values, limit],
                ).fetchall()
                serialized = [self._serialize(row) for row in rows]
                self._attach_debriefs(connection, serialized)
        return serialized, total

    def unfinished_root_plan_hints(
        self,
        *,
        exclude_plan_id: int | None = None,
    ) -> dict[str, Any]:
        """Return compact reminders for the newest unfinished root plans."""
        entries, total = self.query(
            exclude_entry_id=exclude_plan_id,
            entry_type="plan",
            entry_status="in_progress",
            root_plans=True,
            limit=MAX_UNFINISHED_ROOT_PLAN_HINTS,
        )
        plans: list[dict[str, Any]] = []
        for entry in entries:
            content = entry["content"]
            plans.append(
                {
                    "id": entry["id"],
                    "taskname": entry["taskname"],
                    "content_preview": content[:MAX_PLAN_HINT_CONTENT_CHARS],
                    "content_truncated": len(content) > MAX_PLAN_HINT_CONTENT_CHARS,
                    "status": entry["status"],
                    "plan_id": None,
                    "created_at": entry["created_at"],
                    "updated_at": entry["updated_at"],
                }
            )
        return {
            "plans": plans,
            "total": total,
            "truncated": len(plans) < total,
        }

    def plan_tree(
        self,
        plan_id: int,
        *,
        max_depth: int = 8,
        limit: int = 200,
    ) -> dict[str, Any]:
        plan_id = self._validate_plan_id_value(plan_id)
        if not 0 <= max_depth <= MAX_PLAN_TREE_DEPTH:
            raise ValueError(
                f"plan tree max_depth must be between 0 and {MAX_PLAN_TREE_DEPTH}"
            )
        if not 1 <= limit <= MAX_CONTEXT_QUERY_LIMIT:
            raise ValueError(f"plan tree limit must be between 1 and {MAX_CONTEXT_QUERY_LIMIT}")
        with self._lock:
            self._ensure_available()
            with closing(self._connect()) as connection:
                self._require_plan(connection, plan_id)
                plan_rows = connection.execute(
                    """
                    WITH RECURSIVE plan_tree(id, depth, visited) AS (
                        SELECT id, 0, printf('/%d/', id)
                        FROM context_entries
                        WHERE id = ? AND entry_type = 'plan'
                        UNION ALL
                        SELECT child.id, parent.depth + 1,
                               parent.visited || child.id || '/'
                        FROM context_entries AS child
                        JOIN plan_tree AS parent ON child.plan_id = parent.id
                        WHERE child.entry_type = 'plan'
                          AND parent.depth < ?
                          AND instr(parent.visited, printf('/%d/', child.id)) = 0
                    )
                    SELECT entry.*, plan_tree.depth AS tree_depth
                    FROM plan_tree
                    JOIN context_entries AS entry ON entry.id = plan_tree.id
                    ORDER BY plan_tree.depth ASC, entry.id ASC
                    LIMIT ?
                    """,
                    (plan_id, max_depth, limit + 1),
                ).fetchall()
                plans_truncated = len(plan_rows) > limit
                selected_plans = plan_rows[:limit]
                selected_ids = [int(row["id"]) for row in selected_plans]
                linked_rows: list[sqlite3.Row] = []
                entries_truncated = False
                if selected_ids:
                    placeholders = ",".join("?" for _ in selected_ids)
                    linked_rows = connection.execute(
                        "SELECT * FROM context_entries "
                        f"WHERE entry_type != 'plan' AND plan_id IN ({placeholders}) "
                        "ORDER BY id DESC LIMIT ?",
                        [*selected_ids, limit + 1],
                    ).fetchall()
                    entries_truncated = len(linked_rows) > limit
                    linked_rows = linked_rows[:limit]
                serialized_entries = [self._serialize(row) for row in linked_rows]
                plans = []
                for row in selected_plans:
                    item = self._serialize(row)
                    item["depth"] = int(row["tree_depth"])
                    plans.append(item)
                self._attach_debriefs(connection, plans)
        return {
            "root_plan_id": plan_id,
            "max_depth": max_depth,
            "limit": limit,
            "plans": plans,
            "entries": serialized_entries,
            "plans_truncated": plans_truncated,
            "entries_truncated": entries_truncated,
        }

    @classmethod
    def _attach_debriefs(
        cls,
        connection: sqlite3.Connection,
        entries: list[dict[str, Any]],
    ) -> None:
        plan_ids = [entry["id"] for entry in entries if entry["type"] == "plan"]
        if not plan_ids:
            return
        placeholders = ",".join("?" for _ in plan_ids)
        rows = connection.execute(
            f"SELECT * FROM plan_debriefs WHERE plan_id IN ({placeholders})",
            plan_ids,
        ).fetchall()
        debriefs = {int(row["plan_id"]): cls._serialize_debrief(row) for row in rows}
        for entry in entries:
            if entry["type"] == "plan" and entry["id"] in debriefs:
                entry["debrief"] = debriefs[entry["id"]]

    @staticmethod
    def _serialize_debrief(row: sqlite3.Row) -> dict[str, Any]:
        encoded_refs = json.loads(row["memory_refs_json"])
        return {
            "created_at": row["created_at"],
            "actor_id": row["actor_id"],
            "summary": row["summary"],
            "outcome": row["outcome"],
            "memory_refs": encoded_refs.get("items", []),
        }

    @staticmethod
    def _serialize(row: sqlite3.Row) -> dict[str, Any]:
        payload = {
            "id": int(row["id"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "type": row["entry_type"],
            "taskname": row["taskname"],
            "content": row["content"],
            "operation": row["operation"],
            "status": (
                row["plan_status"]
                if row["entry_type"] == "plan"
                else row["status"]
            ),
            "result_summary": row["result_summary"],
            "actor_id": row["actor_id"],
            "plan_id": row["plan_id"],
        }
        if row["entry_type"] == "operation":
            payload["message"] = row["content"]
        for source, destination in (
            ("request_json", "request"),
            ("result_json", "result"),
        ):
            value = row[source]
            payload[destination] = json.loads(value) if value else None
        return payload

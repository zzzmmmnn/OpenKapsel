"""Persistent public metadata for server-managed storage providers."""

from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from openkapsel.random_ids import token_urlsafe_alnum


PROVIDER_KINDS = (
    "google_drive",
    "dropbox",
    "pcloud",
    "onedrive",
    "webdav",
    "s3",
    "sftp",
    "smb",
)
DEFAULT_CACHE_MAX_BYTES = 1 * 1024 * 1024 * 1024
MIN_CACHE_MAX_BYTES = 256 * 1024 * 1024
MAX_CACHE_MAX_BYTES = 1024 * 1024 * 1024 * 1024
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


class StorageProviderStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.db() as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("""CREATE TABLE IF NOT EXISTS storage_providers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                remote_path TEXT NOT NULL,
                comment TEXT NOT NULL,
                writable INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                cache_max_bytes INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS storage_provider_mappings (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL REFERENCES storage_providers(id) ON DELETE CASCADE,
                workspace TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(workspace, name)
            )""")
        os.chmod(path, 0o600)

    @contextmanager
    def db(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            try:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys=ON")
                with db:
                    yield db
            finally:
                db.close()

    @staticmethod
    def validate_name(name: str, *, label: str = "name") -> str:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise ValueError(f"{label} must contain 1-64 ASCII letters, digits, '-' or '_' and start with a letter or digit")
        return name

    @staticmethod
    def validate_provider_name(name: str) -> str:
        if not isinstance(name, str):
            raise ValueError("provider name must contain 1-64 printable characters")
        name = name.strip()
        if not 1 <= len(name) <= 64 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
            raise ValueError("provider name must contain 1-64 printable characters")
        return name

    @staticmethod
    def validate_kind(kind: str) -> str:
        if kind not in PROVIDER_KINDS:
            raise ValueError(
                "storage provider kind must be google_drive, dropbox, pcloud, onedrive, "
                "webdav, s3, sftp, or smb"
            )
        return kind

    @staticmethod
    def validate_remote_path(value: str) -> str:
        if not isinstance(value, str) or "\x00" in value or "\r" in value or "\n" in value or len(value) > 2048:
            raise ValueError("remote path must be a single line containing at most 2048 characters")
        return value

    @staticmethod
    def validate_comment(value: str) -> str:
        if not isinstance(value, str) or len(value) > 200:
            raise ValueError("comment must contain at most 200 characters")
        return value

    @staticmethod
    def validate_cache_max_bytes(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not MIN_CACHE_MAX_BYTES <= value <= MAX_CACHE_MAX_BYTES:
            raise ValueError("VFS cache limit must be between 256 MiB and 1 TiB")
        return value

    @staticmethod
    def public(row: dict) -> dict:
        row["writable"] = bool(row["writable"])
        row["enabled"] = bool(row["enabled"])
        return row

    def list(self) -> list[dict]:
        with self.db() as db:
            rows = db.execute("SELECT * FROM storage_providers ORDER BY name")
            return [self.public(dict(row)) for row in rows]

    def get(self, provider_id: str) -> dict:
        with self.db() as db:
            row = db.execute("SELECT * FROM storage_providers WHERE id=?", (provider_id,)).fetchone()
            if row is None:
                raise KeyError("storage provider does not exist")
            return self.public(dict(row))

    def create(
        self,
        name: str,
        kind: str,
        *,
        remote_path: str = "",
        comment: str = "",
        writable: bool = False,
        cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES,
    ) -> dict:
        name = self.validate_provider_name(name)
        kind = self.validate_kind(kind)
        remote_path = self.validate_remote_path(remote_path)
        comment = self.validate_comment(comment)
        cache_max_bytes = self.validate_cache_max_bytes(cache_max_bytes)
        provider_id = token_urlsafe_alnum(18)
        now = time.time()
        with self.db() as db:
            db.execute(
                """INSERT INTO storage_providers
                   (id,name,kind,remote_path,comment,writable,enabled,cache_max_bytes,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (provider_id, name, kind, remote_path, comment, bool(writable), 1, cache_max_bytes, now, now),
            )
        return self.get(provider_id)

    def update(
        self,
        provider_id: str,
        *,
        name: str | None = None,
        remote_path: str | None = None,
        comment: str | None = None,
        writable: bool | None = None,
        enabled: bool | None = None,
        cache_max_bytes: int | None = None,
    ) -> dict:
        self.get(provider_id)
        values = {}
        if name is not None:
            values["name"] = self.validate_provider_name(name)
        if remote_path is not None:
            values["remote_path"] = self.validate_remote_path(remote_path)
        if comment is not None:
            values["comment"] = self.validate_comment(comment)
        if writable is not None:
            values["writable"] = bool(writable)
        if enabled is not None:
            values["enabled"] = bool(enabled)
        if cache_max_bytes is not None:
            values["cache_max_bytes"] = self.validate_cache_max_bytes(cache_max_bytes)
        if values:
            values["updated_at"] = time.time()
            with self.db() as db:
                for key, value in values.items():
                    db.execute(f"UPDATE storage_providers SET {key}=? WHERE id=?", (value, provider_id))
        return self.get(provider_id)

    def delete(self, provider_id: str) -> None:
        with self.db() as db:
            cursor = db.execute("DELETE FROM storage_providers WHERE id=?", (provider_id,))
            if cursor.rowcount != 1:
                raise KeyError("storage provider does not exist")

    def mappings(self, *, provider_id: str | None = None, workspace: str | None = None) -> list[dict]:
        where, values = [], []
        if provider_id is not None:
            where.append("provider_id=?")
            values.append(provider_id)
        if workspace is not None:
            where.append("workspace=?")
            values.append(workspace)
        query = "SELECT * FROM storage_provider_mappings"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY workspace,name"
        with self.db() as db:
            return [dict(row) for row in db.execute(query, tuple(values))]

    def mapping(self, mapping_id: str) -> dict:
        with self.db() as db:
            row = db.execute("SELECT * FROM storage_provider_mappings WHERE id=?", (mapping_id,)).fetchone()
            if row is None:
                raise KeyError("storage provider mapping does not exist")
            return dict(row)

    def add_mapping(self, provider_id: str, workspace: str, name: str) -> dict:
        self.get(provider_id)
        self.validate_name(name, label="mapping directory name")
        if not isinstance(workspace, str) or not _NAME_RE.fullmatch(workspace):
            raise ValueError("workspace must be an existing workspace name")
        mapping_id = token_urlsafe_alnum(18)
        with self.db() as db:
            db.execute(
                "INSERT INTO storage_provider_mappings(id,provider_id,workspace,name,created_at) VALUES(?,?,?,?,?)",
                (mapping_id, provider_id, workspace, name, time.time()),
            )
        return self.mapping(mapping_id)

    def delete_mapping(self, mapping_id: str) -> None:
        with self.db() as db:
            cursor = db.execute("DELETE FROM storage_provider_mappings WHERE id=?", (mapping_id,))
            if cursor.rowcount != 1:
                raise KeyError("storage provider mapping does not exist")

    def reserved(self, workspace: str, name: str) -> bool:
        with self.db() as db:
            row = db.execute(
                "SELECT 1 FROM storage_provider_mappings WHERE workspace=? AND name=?",
                (workspace, name),
            ).fetchone()
            return row is not None

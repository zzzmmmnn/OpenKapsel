"""Persistent provider identities, deliberately independent of REST credentials."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from openkapsel.random_ids import token_urlsafe_alnum


class MappingStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS mappings (
                id TEXT PRIMARY KEY, workspace TEXT NOT NULL, name TEXT NOT NULL,
                comment TEXT NOT NULL, secret_hash TEXT NOT NULL,
                writable INTEGER NOT NULL, allow_exec INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL,
                last_seen REAL, UNIQUE(workspace, name))""")
        os.chmod(path, 0o600)

    @contextmanager
    def db(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            try:
                db.row_factory = sqlite3.Row
                with db:
                    yield db
            finally:
                db.close()

    def list(self, workspace=None):
        with self.db() as db:
            if workspace is None:
                rows = db.execute("SELECT * FROM mappings ORDER BY workspace,name")
            else:
                rows = db.execute("SELECT * FROM mappings WHERE workspace=? ORDER BY name", (workspace,))
            return [self.public(dict(row)) for row in rows]

    @staticmethod
    def public(row):
        row.pop("secret_hash", None)
        for key in ("writable", "allow_exec", "enabled"):
            row[key] = bool(row[key])
        return row

    def get(self, mid):
        with self.db() as db:
            row = db.execute("SELECT * FROM mappings WHERE id=?", (mid,)).fetchone()
            if row is None:
                raise KeyError("mapping does not exist")
            return self.public(dict(row))

    @staticmethod
    def validate_name(name):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("mapping name must contain 1-64 ASCII letters, digits, '-' or '_'")

    def create(self, workspace, name, *, comment="", writable=False, allow_exec=False):
        self.validate_name(name)
        if not isinstance(comment, str) or len(comment) > 200:
            raise ValueError("comment must contain at most 200 characters")
        mid, secret = token_urlsafe_alnum(18), token_urlsafe_alnum(32)
        with self.db() as db:
            db.execute("INSERT INTO mappings(id,workspace,name,comment,secret_hash,writable,allow_exec,created_at) VALUES(?,?,?,?,?,?,?,?)",
                       (mid, workspace, name, comment, self.digest(secret), bool(writable), bool(allow_exec), time.time()))
        return self.get(mid), secret

    @staticmethod
    def digest(secret):
        return hashlib.sha256(secret.encode()).hexdigest()

    def authenticate(self, mid, secret):
        with self.db() as db:
            row = db.execute("SELECT * FROM mappings WHERE id=?", (mid,)).fetchone()
            if row is None or not row["enabled"] or not hmac.compare_digest(row["secret_hash"], self.digest(secret)):
                raise PermissionError("invalid mapping credential")
            return self.public(dict(row))

    def update(self, mid, *, workspace=None, name=None, comment=None, writable=None, allow_exec=None, enabled=None, rotate=False):
        self.get(mid)
        if name is not None:
            self.validate_name(name)
        if comment is not None and (not isinstance(comment, str) or len(comment) > 200):
            raise ValueError("comment must contain at most 200 characters")
        secret = token_urlsafe_alnum(32) if rotate else None
        with self.db() as db:
            for key, value in {"workspace": workspace, "name": name, "comment": comment, "writable": writable, "allow_exec": allow_exec,
                               "enabled": enabled, "secret_hash": self.digest(secret) if secret else None}.items():
                if value is not None:
                    db.execute(f"UPDATE mappings SET {key}=? WHERE id=?", (value, mid))
        return self.get(mid), secret

    def seen(self, mid):
        with self.db() as db:
            db.execute("UPDATE mappings SET last_seen=? WHERE id=?", (time.time(), mid))

    def delete(self, mid):
        with self.db() as db:
            db.execute("DELETE FROM mappings WHERE id=?", (mid,))

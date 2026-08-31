"""Safe Workspace database lookup backed by SQLAlchemy."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session


_DATABASE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_engines: dict[str, object] = {}


def _path(database_id: str) -> Path:
    if not _DATABASE_ID.fullmatch(database_id):
        raise ValueError("database id must use 1-64 letters, numbers, '_' or '-'")
    workspace = Path(os.environ.get("OPENKAPSEL_WORKSPACE", "/workspace"))
    configured_storage = os.environ.get("OPENKAPSEL_SQL_ROOT")
    if configured_storage:
        storage = Path(configured_storage)
    else:
        internal = workspace / ".openkapsel"
        if internal.is_symlink() or (internal.exists() and not internal.is_dir()):
            raise ValueError("workspace private storage must be a real directory")
        internal.mkdir(mode=0o700, exist_ok=True)
        internal.chmod(0o700)
        storage = internal / "sql"
    if storage.is_symlink() or (storage.exists() and not storage.is_dir()):
        raise ValueError("workspace database storage must be a real directory")
    storage.mkdir(mode=0o700, exist_ok=True)
    storage.chmod(0o700)
    return storage / f"{database_id}.sqlite3"


def engine(database_id: str = "main"):
    existing = _engines.get(database_id)
    if existing is not None:
        return existing
    value = create_engine(f"sqlite:///{_path(database_id)}", connect_args={"timeout": 5})

    @event.listens_for(value, "connect")
    def configure(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    _engines[database_id] = value
    return value


@contextmanager
def session(database_id: str = "main"):
    with Session(engine(database_id)) as value:
        try:
            yield value
            value.commit()
        except Exception:
            value.rollback()
            raise

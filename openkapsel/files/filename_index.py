"""Shared, private SQLite filename index for Linux and Windows native roots.

The index is a cache, never an authority for filesystem access.  Callers must
continue to check access and lstat results when presenting a candidate.
"""
from __future__ import annotations

import ctypes
from functools import lru_cache
import fnmatch
import logging
import os
import queue
import re
import sqlite3
import stat
import sys
import threading
import time
from pathlib import Path

from openkapsel.files.file_support import FileOperationSupportMixin

_RECONCILE_SECONDS = 600
_NANOSECONDS = 1_000_000_000
_STATX_BASIC_STATS = 0x07FF
_STATX_BTIME = 0x0800


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("seconds", ctypes.c_int64),
        ("nanoseconds", ctypes.c_uint32),
        ("reserved", ctypes.c_int32),
    ]


class _Statx(ctypes.Structure):
    """Linux statx ABI (256 bytes), providing birth time when supported."""

    _fields_ = [
        ("mask", ctypes.c_uint32),
        ("block_size", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64),
        ("nlink", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("spare0", ctypes.c_uint16),
        ("inode", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64),
        ("attributes_mask", ctypes.c_uint64),
        ("atime", _StatxTimestamp),
        ("btime", _StatxTimestamp),
        ("ctime", _StatxTimestamp),
        ("mtime", _StatxTimestamp),
        ("rdev_major", ctypes.c_uint32),
        ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32),
        ("dev_minor", ctypes.c_uint32),
        ("mount_id", ctypes.c_uint64),
        ("dio_mem_align", ctypes.c_uint32),
        ("dio_offset_align", ctypes.c_uint32),
        ("spare3", ctypes.c_uint64 * 12),
    ]


@lru_cache(maxsize=1)
def _statx_function():
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        statx = getattr(libc, "statx", None)
        if statx is None:
            return None
        statx.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint,
            ctypes.POINTER(_Statx),
        ]
        statx.restype = ctypes.c_int
        return statx
    except (AttributeError, OSError):
        return None


def _linux_statx(path: Path) -> tuple[int, int, int, int, int | None] | None:
    """Return (device, mode, size, mtime_utc_ns, birth_utc_ns) with no symlink follow.

    Missing/unsupported statx falls back to lstat; birth time stays NULL when
    unavailable. Linux ctime is *not* a creation timestamp.
    """
    statx = _statx_function()
    if statx is None:
        return None
    try:
        result = _Statx()
        if statx(-100, os.fsencode(path), 0x100 | 0x800,
                 _STATX_BASIC_STATS | _STATX_BTIME, ctypes.byref(result)):
            return None
        if result.mask & _STATX_BASIC_STATS != _STATX_BASIC_STATS:
            return None
        modified = result.mtime.seconds * _NANOSECONDS + result.mtime.nanoseconds
        created = (result.btime.seconds * _NANOSECONDS + result.btime.nanoseconds
                   if result.mask & _STATX_BTIME else None)
        return (os.makedev(result.dev_major, result.dev_minor), result.mode,
                result.size, modified, created)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _metadata(path: Path) -> tuple[int, int, int, int, int | None]:
    """Portable lstat metadata, with statx for native Linux birth timestamps."""
    indexed = _linux_statx(path)
    if indexed is not None:
        return indexed
    info = path.lstat()
    created = getattr(info, "st_birthtime_ns", None)
    if created is None:
        birth = getattr(info, "st_birthtime", None)
        created = int(birth * _NANOSECONDS) if birth is not None else None
    if created is None and os.name == "nt":
        # Windows exposes creation time as st_ctime_ns on older Python
        # versions; never use POSIX ctime (inode metadata-change time).
        created = info.st_ctime_ns
    return info.st_dev, info.st_mode, info.st_size, info.st_mtime_ns, created


def watcher_available() -> bool:
    try:
        import watchfiles  # noqa: F401
    except ImportError:
        return False
    return True


def private_database(root: Path, db_path: Path) -> Path:
    root = Path(root).resolve()
    db_path = Path(db_path).expanduser().resolve()
    if db_path == root or root in db_path.parents:
        raise ValueError("filename index database must be outside the exported root")
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(db_path.parent, 0o700)
    # Windows uses the enclosing user's profile/config-directory ACLs;
    # chmod does not implement Unix permissions on NTFS.
    return db_path


def _literal_run(pattern: str, glob: bool) -> str:
    if not glob:
        return pattern
    # A bracket class consumes its closing ], not a literal hint substring.
    chunks = []
    chunk = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char in "*?[":
            if chunk:
                chunks.append("".join(chunk))
                chunk.clear()
            if char == "[":
                closing = pattern.find("]", i + 1)
                if closing < 0:
                    # An unmatched [ is literal to fnmatch, but scanning
                    # without a hint is safer than filtering it incorrectly.
                    return ""
                i = closing
        else:
            chunk.append(char)
        i += 1
    if chunk:
        chunks.append("".join(chunk))
    return max(chunks, key=len, default="")


class FilenameIndex:
    """One index per native filesystem root, usable by both sides.

    An initial scan is required on each process start; search falls back until
    the watcher is registered and the snapshot (plus queued deltas) is ready.
    """

    def __init__(self, root: Path, db_path: Path):
        self.root = Path(root).resolve(strict=True)
        self.database = private_database(self.root, db_path)
        self._device = os.stat(self.root).st_dev
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._watch_ready = threading.Event()
        self._events = queue.Queue(maxsize=4096)
        self._overflow = threading.Event()
        self._worker = None
        self._watcher = None
        self._closed = False
        self._db = sqlite3.connect(self.database, timeout=10, check_same_thread=False)
        if os.name != "nt":
            os.chmod(self.database, 0o600)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL, folded TEXT NOT NULL, kind TEXT NOT NULL,
            created_utc_ns INTEGER, modified_utc_ns INTEGER, size_bytes INTEGER)""")
        self._db.execute("CREATE INDEX IF NOT EXISTS entries_path ON entries(path)")
        self._db.execute("CREATE INDEX IF NOT EXISTS entries_name_order ON entries(name,path)")
        self._db.execute("CREATE INDEX IF NOT EXISTS entries_size_order ON entries(size_bytes,path)")
        self._db.execute("CREATE INDEX IF NOT EXISTS entries_modified_order ON entries(modified_utc_ns,path)")
        self._fts = False
        try:
            self._db.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS entry_grams "
                "USING fts5(folded, content='entries', content_rowid='id', tokenize='trigram')"
            )
            self._db.executescript("""
                CREATE TRIGGER IF NOT EXISTS entry_insert AFTER INSERT ON entries BEGIN
                    INSERT INTO entry_grams(rowid, folded) VALUES(new.id,new.folded);
                END;
                CREATE TRIGGER IF NOT EXISTS entry_delete AFTER DELETE ON entries BEGIN
                    INSERT INTO entry_grams(entry_grams,rowid,folded)
                    VALUES('delete',old.id,old.folded);
                END;
            """)
            self._fts = True
        except sqlite3.OperationalError:
            self._fts = False
        self._db.commit()

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and not self._closed

    def start(self) -> bool:
        if not watcher_available() or self._worker is not None:
            return self.ready
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True,
                                         name="openkapsel-index-watch")
        self._worker = threading.Thread(target=self._worker_loop, daemon=True,
                                        name="openkapsel-index-build")
        self._watcher.start()
        self._worker.start()
        return True

    def _watch_loop(self):
        from watchfiles import watch
        try:
            for changes in watch(
                self.root, stop_event=self._stop, recursive=True,
                debounce=100, step=50, rust_timeout=500, yield_on_timeout=True,
                ignore_permission_denied=True,
            ):
                self._watch_ready.set()
                if self._stop.is_set():
                    break
                if changes:
                    try:
                        self._events.put_nowait(changes)
                    except queue.Full:
                        self._overflow.set()
                        self._ready.clear()
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Filename index watcher stopped for %s; using recursive search: %s",
                self.root, exc,
            )
            self._ready.clear()
        finally:
            self._watch_ready.set()
            # If full, the worker will eventually drain the queue.
            while True:
                try:
                    self._events.put(None, timeout=1)
                    break
                except queue.Full:
                    if self._stop.is_set():
                        break

    def _worker_loop(self):
        try:
            if not self._watch_ready.wait(timeout=5) or self._stop.is_set():
                return
            self.rebuild()
            # Apply modifications observed while the initial scan was running.
            while True:
                try:
                    changes = self._events.get_nowait()
                except queue.Empty:
                    break
                if changes is None:
                    return
                self.apply(changes)
            if self._overflow.is_set():
                self._overflow.clear()
                self.rebuild()
            self._ready.set()
            last_reconcile = time.monotonic()
            while not self._stop.is_set():
                try:
                    changes = self._events.get(timeout=1)
                except queue.Empty:
                    changes = ()
                if changes is None:
                    break
                if changes:
                    self.apply(changes)
                if self._overflow.is_set() or time.monotonic() - last_reconcile >= _RECONCILE_SECONDS:
                    self._ready.clear()
                    self._overflow.clear()
                    self.rebuild()
                    last_reconcile = time.monotonic()
                    if not self._overflow.is_set():
                        self._ready.set()
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Filename index builder stopped for %s; using recursive search: %s",
                self.root, exc,
            )
            self._ready.clear()
        finally:
            self._ready.clear()

    @staticmethod
    def _ignored(name: str) -> bool:
        protected_name = name.casefold() if os.name == "nt" else name
        return (protected_name in {".openkapsel", ".recycle"}
                or FileOperationSupportMixin._is_internal_transfer_name(name))

    def _entries(self, path: Path):
        stack = [path]
        while stack and not self._stop.is_set():
            current = stack.pop()
            try:
                device, mode, size, modified, created = _metadata(current)
            except OSError:
                continue
            if device != self._device or not (
                stat.S_ISREG(mode) or stat.S_ISDIR(mode)
            ):
                continue
            if os.name == "nt":
                # Junctions and other reparse-point directories must never
                # be followed or indexed, even if they share the same device.
                try:
                    if getattr(current.lstat(), "st_file_attributes", 0) & 0x400:
                        continue
                except OSError:
                    continue
            if current != self.root and self._ignored(current.name):
                continue
            relative = current.relative_to(self.root).as_posix()
            if current != self.root:
                yield (relative, current.name, current.name.casefold(),
                       "directory" if stat.S_ISDIR(mode) else "file",
                       created, modified, size)
            if stat.S_ISDIR(mode):
                try:
                    with os.scandir(current) as iterator:
                        children = [Path(item.path) for item in iterator
                                    if not item.is_symlink() and not self._ignored(item.name)]
                    stack.extend(children)
                except OSError:
                    continue

    def rebuild(self):
        """Reconcile the complete native tree; never cross symlinks/mounts."""
        with self._lock:
            with self._db:
                self._db.execute("DELETE FROM entries")
                batch = []
                for item in self._entries(self.root):
                    batch.append(item)
                    if len(batch) >= 1000:
                        self._db.executemany(
                            "INSERT INTO entries(path,name,folded,kind,created_utc_ns,modified_utc_ns,size_bytes) VALUES(?,?,?,?,?,?,?)",
                            batch,
                        )
                        batch.clear()
                if batch:
                    self._db.executemany(
                        "INSERT INTO entries(path,name,folded,kind,created_utc_ns,modified_utc_ns,size_bytes) VALUES(?,?,?,?,?,?,?)",
                        batch,
                    )

    def apply(self, changes):
        """Apply watcher changes. Directory moves reindex their entire subtree."""
        paths = {Path(raw).resolve(strict=False) for _change, raw in changes}
        with self._lock:
            with self._db:
                for path in paths:
                    try:
                        relative = path.relative_to(self.root)
                    except ValueError:
                        continue
                    if not relative.parts or any(self._ignored(p) for p in relative.parts):
                        continue
                    key = relative.as_posix()
                    self._db.execute(
                        "DELETE FROM entries WHERE path=? OR substr(path,1,?)=?",
                        (key, len(key)+1, key+"/"),
                    )
                    self._db.executemany(
                        "INSERT INTO entries(path,name,folded,kind,created_utc_ns,modified_utc_ns,size_bytes) VALUES(?,?,?,?,?,?,?)",
                        self._entries(path),
                    )

    def search(self, scope: Path, query: str, *, glob: bool = False,
               case_sensitive: bool = False, offset: int = 0, limit: int = 50,
               timeout_seconds: float = 5.0, accept=None,
               sort_by: str = "path", sort_order: str = "asc",
               file_type: str = "all",
               excluded_roots=()) -> dict | None:
        if not self.ready:
            return None
        scope = Path(scope).resolve(strict=False)
        try:
            scope_rel = scope.relative_to(self.root)
        except ValueError:
            return None
        prefix = scope_rel.as_posix()
        pattern = query if case_sensitive else query.casefold()
        hint = _literal_run(pattern, glob).casefold()
        # FTS5's trigram LIKE optimization needs >=3 literal chars and no
        # ESCAPE clause. Percent/underscore hints use the safe full scan.
        fast = self._fts and len(hint) >= 3 and not any(c in hint for c in "%_")
        if sort_by not in {"name", "path", "size", "modified"} or sort_order not in {"asc", "desc"}:
            raise ValueError("invalid index sorting")
        if file_type not in {"all", "file", "directory"}:
            raise ValueError("invalid indexed file type")
        base = ("SELECT e.path,e.name,e.folded,e.kind,e.created_utc_ns,e.modified_utc_ns,e.size_bytes FROM entries e "
                "JOIN entry_grams f ON f.rowid=e.id WHERE f.folded LIKE ?"
                if fast else "SELECT e.path,e.name,e.folded,e.kind,e.created_utc_ns,e.modified_utc_ns,e.size_bytes FROM entries e WHERE 1=1")
        args = ["%" + hint + "%"] if fast else []
        if prefix != ".":
            base += " AND e.path >= ? AND e.path < ?"
            args.extend([prefix + "/", prefix + "/\U0010ffff"])
        if file_type != "all":
            base += " AND e.kind = ?"
            args.append(file_type)
        # Mount roots, including unmounted registration placeholders, are
        # excluded in SQL before sorting/limiting to preserve native Top N.
        for mount in excluded_roots:
            mount = Path(mount)
            try:
                relative_mount = mount.relative_to(self.root).as_posix()
            except ValueError:
                continue
            base += (" AND e.path != ? AND NOT "
                     "(e.path >= ? AND e.path < ?)")
            args.extend([relative_mount, relative_mount + "/",
                         relative_mount + "/\U0010ffff"])
        order_col = {"name": "name", "path": "path", "size": "size_bytes",
                     "modified": "modified_utc_ns"}[sort_by]
        direction = "DESC" if sort_order == "desc" else "ASC"
        base += f" ORDER BY e.{order_col} {direction}, e.path {direction}"
        deadline = time.monotonic() + timeout_seconds
        matches = []
        count = 0
        timed_out = False
        with self._lock:
            self._db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            try:
                for relative, name, folded, kind, created, modified, size in self._db.execute(base, args):
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    text = name if case_sensitive else folded
                    matched = (fnmatch.fnmatchcase(text, pattern) if glob
                               else pattern in text)
                    if not matched:
                        continue
                    path = self.root / relative
                    item = (accept(path, kind) if accept else {"path": relative, "type": kind})
                    if item is None:
                        continue
                    item.update(size_bytes=size, modified_utc_ns=modified,
                                created_utc_ns=created)
                    if count >= offset:
                        matches.append(item)
                    count += 1
                    if len(matches) > limit:
                        break
            except sqlite3.OperationalError as exc:
                if "interrupted" not in str(exc):
                    raise
                timed_out = True
            finally:
                self._db.set_progress_handler(None, 0)
        truncated = len(matches) > limit or timed_out
        return {"backend": "sqlite_watch", "results": matches[:limit],
                "result_count": min(limit, len(matches)), "truncated": truncated,
                "timed_out": timed_out,
                "next_offset": offset + min(limit, len(matches)) if truncated else None}

    def close(self):
        self._closed = True
        self._ready.clear()
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=4)
        if self._watcher is not None:
            self._watcher.join(timeout=4)
        with self._lock:
            self._db.close()

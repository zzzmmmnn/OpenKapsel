"""Versioned, private SQLite filename metadata and asynchronous trigram index.

A cache, never a filesystem access authority. Callers must still validate
access and lstat when presenting a candidate.
"""
from __future__ import annotations

from openkapsel.auth.path_access import is_private_name

import ctypes
from functools import lru_cache
import fnmatch
import logging
from contextlib import closing
import os
import queue
import re
# Keep the newer SQLite isolated to the filename index. AlmaLinux 8 ships
# SQLite 3.26 through Python's stdlib, which lacks FTS5's trigram tokenizer.
# pysqlite3-binary bundles newer SQLite without replacing system libsqlite3.
try:
    import pysqlite3 as sqlite3
except ImportError:
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
    """Persistent Linux filename metadata and asynchronous contentless trigram index.

    Filesystem reconciliation changes only differing rows.  The pending table
    preserves the old indexed text until the FTS transaction commits.  Readers
    include pending names so async indexing never hides new/renamed files.
    """

    SCHEMA_VERSION = 2

    def __init__(self, root: Path, db_path: Path):
        self.root = Path(root).resolve(strict=True)
        self.database = private_database(self.root, db_path)
        self._device = os.stat(self.root).st_dev
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._watch_ready = threading.Event()
        self._pending_event = threading.Event()
        self._events = queue.Queue(maxsize=4096)
        self._overflow = threading.Event()
        self._worker = None
        self._watcher = None
        self._indexer = None
        self._closed = False

        # A version mismatch is the ONLY reason to discard a stored index.
        # A new database has no schema, and is initialized without deletion.
        existed = self.database.exists()
        if existed:
            try:
                with closing(sqlite3.connect(
                    self.database.as_uri() + "?mode=ro", uri=True
                )) as old:
                    version = old.execute("PRAGMA user_version").fetchone()[0]
            except sqlite3.DatabaseError:
                # A corrupt database is not a schema-version mismatch.
                raise
            if version != self.SCHEMA_VERSION:
                for suffix in ("", "-wal", "-shm"):
                    Path(str(self.database) + suffix).unlink(missing_ok=True)

        self._db = sqlite3.connect(self.database, timeout=10, check_same_thread=False)
        if os.name != "nt":
            os.chmod(self.database, 0o600)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE NOT NULL,
                parent TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                created_utc_ns INTEGER,
                modified_utc_ns INTEGER,
                size_bytes INTEGER,
                visible INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS entries_parent ON entries(parent,path);
            CREATE INDEX IF NOT EXISTS entries_name_order ON entries(name,path);
            CREATE INDEX IF NOT EXISTS entries_size_order ON entries(size_bytes,path);
            CREATE INDEX IF NOT EXISTS entries_modified_order ON entries(modified_utc_ns,path);
            CREATE TABLE IF NOT EXISTS pending_index (
                entry_id INTEGER PRIMARY KEY REFERENCES entries(id),
                old_folded TEXT
            );
        """)
        had_fts = self._db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='entry_grams'"
        ).fetchone() is not None
        self._fts = False
        try:
            self._db.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS entry_grams "
                "USING fts5(folded, content='', tokenize='trigram', "
                "detail='none', columnsize=0)"
            )
            self._fts = True
            if not had_fts:
                # The FTS table is newly empty; even existing pending records
                # cannot refer to indexed old terms in this new table.
                self._db.execute("UPDATE pending_index SET old_folded=NULL "
                                 "WHERE old_folded IS NOT NULL")
                self._db.execute(
                    "INSERT OR IGNORE INTO pending_index(entry_id,old_folded) "
                    "SELECT id,NULL FROM entries WHERE visible=1"
                )
        except sqlite3.OperationalError:
            self._fts = False
        self._db.execute(f"PRAGMA user_version={self.SCHEMA_VERSION}")
        self._db.commit()
        if self._db.execute("SELECT 1 FROM pending_index LIMIT 1").fetchone():
            self._pending_event.set()

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and not self._closed

    def start(self) -> bool:
        # Never retain Windows directory handles, even from a direct caller.
        if os.name == "nt":
            return False
        if not watcher_available() or self._worker is not None:
            return self.ready
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True,
                                         name="openkapsel-index-watch")
        self._worker = threading.Thread(target=self._worker_loop, daemon=True,
                                        name="openkapsel-index-scan")
        self._indexer = threading.Thread(target=self._indexer_loop, daemon=True,
                                         name="openkapsel-index-fts")
        self._watcher.start()
        self._indexer.start()
        self._worker.start()
        return True

    @staticmethod
    def _ignored(name: str) -> bool:
        protected_name = name.casefold()
        return (protected_name == ".recycle" or is_private_name(name)
                or FileOperationSupportMixin._is_internal_transfer_name(name))

    def _watch_directories(self):
        """Enumerate watchable same-device directories, excluding mounts."""
        paths = [self.root]
        for relative, _name, _folded, kind, *_ in self._entries(self.root):
            if kind == "directory":
                directory = self.root / relative
                if os.access(directory, os.R_OK | os.X_OK):
                    paths.append(directory)
        return paths

    def _watch_loop(self):
        from watchfiles import Change, watch
        try:
            while not self._stop.is_set():
                directories = self._watch_directories()
                with closing(watch(
                    *directories, stop_event=self._stop, recursive=False,
                    debounce=100, step=50, rust_timeout=500,
                    yield_on_timeout=True, ignore_permission_denied=True,
                )) as changes_stream:
                    for changes in changes_stream:
                        self._watch_ready.set()
                        if self._stop.is_set():
                            break
                        if changes:
                            try:
                                self._events.put_nowait(changes)
                            except queue.Full:
                                self._overflow.set()
                                self._ready.clear()
                            if any(
                                change == Change.added
                                and Path(path).is_dir()
                                and not Path(path).is_symlink()
                                for change, path in changes
                            ):
                                self._overflow.set()
                                self._ready.clear()
                                break
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Filename index watcher stopped for %s; using recursive search: %s",
                self.root, exc,
            )
            self._ready.clear()
        finally:
            self._watch_ready.set()
            while True:
                try:
                    self._events.put(None, timeout=1)
                    break
                except queue.Full:
                    if self._stop.is_set():
                        break

    def _worker_loop(self):
        try:
            # Watcher must be registered before scanning so no updates are lost.
            while not self._watch_ready.wait(timeout=1):
                if self._stop.is_set() or not self._watcher.is_alive():
                    return
            if self._stop.is_set():
                return
            self.reconcile()
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
                self.reconcile()
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
                if (self._overflow.is_set()
                        or time.monotonic() - last_reconcile >= _RECONCILE_SECONDS):
                    self._ready.clear()
                    self._overflow.clear()
                    self.reconcile()
                    last_reconcile = time.monotonic()
                    if not self._overflow.is_set():
                        self._ready.set()
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Filename index scan stopped for %s; using recursive search: %s",
                self.root, exc,
            )
            self._ready.clear()
        finally:
            self._ready.clear()

    def _indexer_loop(self):
        try:
            while not self._stop.is_set():
                self._pending_event.wait(timeout=1)
                if self._stop.is_set():
                    return
                self._pending_event.clear()
                while not self._stop.is_set() and self._flush_pending(limit=1000):
                    pass
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Filename FTS worker stopped for %s: %s", self.root, exc,
            )
            self._ready.clear()

    def _entries(self, path: Path):
        """Legacy iterator used to enumerate directories for watcher setup."""
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

    def _queue_index(self, entry_id: int, old_name: str | None) -> None:
        # Keep the OLD indexed text on repeated changes until it is removed.
        self._db.execute(
            "INSERT OR IGNORE INTO pending_index(entry_id,old_folded) VALUES(?,?)",
            (entry_id, old_name.casefold() if old_name is not None else None),
        )
        self._pending_event.set()

    def _upsert(self, relative: str, kind: str, created: int | None,
                modified: int, size: int) -> None:
        name = relative.rsplit("/", 1)[-1]
        parent = relative.rpartition("/")[0] or "."
        old = self._db.execute(
            "SELECT id,name,kind,created_utc_ns,modified_utc_ns,size_bytes,visible "
            "FROM entries WHERE path=?", (relative,),
        ).fetchone()
        if old is None:
            cursor = self._db.execute(
                "INSERT INTO entries(path,parent,name,kind,created_utc_ns,"
                "modified_utc_ns,size_bytes,visible) VALUES(?,?,?,?,?,?,?,1)",
                (relative, parent, name, kind, created, modified, size),
            )
            self._queue_index(cursor.lastrowid, None)
        elif (old[1], old[2], old[3], old[4], old[5], old[6]) != (
                name, kind, created, modified, size, 1):
            if old[1] != name or not old[6]:
                self._queue_index(old[0], old[1])
            if old[2] == "directory" and kind != "directory":
                self._retire(relative, descendants_only=True)
            self._db.execute(
                "UPDATE entries SET name=?,kind=?,created_utc_ns=?,"
                "modified_utc_ns=?,size_bytes=?,visible=1 WHERE id=?",
                (name, kind, created, modified, size, old[0]),
            )

    def _retire(self, relative: str, *, descendants_only=False) -> None:
        """Tombstone a deleted subtree without losing the old FTS term."""
        prefix = relative + "/"
        if descendants_only:
            sql = ("SELECT id,name FROM entries WHERE visible=1 AND "
                   "path>=? AND path<?")
            params = (prefix, prefix + "\U0010ffff")
        else:
            sql = ("SELECT id,name FROM entries WHERE visible=1 AND "
                   "(path=? OR (path>=? AND path<?))")
            params = (relative, prefix, prefix + "\U0010ffff")
        rows = self._db.execute(sql, params).fetchall()
        for entry_id, name in rows:
            self._queue_index(entry_id, name)
            self._db.execute(
                "UPDATE entries SET visible=0 WHERE id=?", (entry_id,),
            )

    def _reconcile_tree(self, start: Path):
        """Compare direct children directory-by-directory; never erase unseen trees.

        A failed scandir leaves all cached children untouched, avoiding false
        deletions for temporarily unreadable directories.
        """
        stack = [start]
        if start != self.root:
            try:
                device, mode, size, modified, created = _metadata(start)
                if (device != self._device or
                        not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)) or
                        start.is_symlink()):
                    raise OSError("unsupported filesystem entry")
                if os.name == "nt" and getattr(start.lstat(), "st_file_attributes", 0) & 0x400:
                    raise OSError("reparse point")
            except OSError:
                with self._lock, self._db:
                    self._retire(start.relative_to(self.root).as_posix())
                return
            relative = start.relative_to(self.root).as_posix()
            with self._lock, self._db:
                self._upsert(relative, "directory" if stat.S_ISDIR(mode) else "file",
                             created, modified, size)
            if stat.S_ISREG(mode):
                return
        while stack and not self._stop.is_set():
            current = stack.pop()
            relative_dir = current.relative_to(self.root).as_posix()
            found = []
            descend = []
            seen = set()
            try:
                with os.scandir(current) as iterator:
                    for item in iterator:
                        if self._ignored(item.name):
                            continue
                        child = Path(item.path)
                        relative = child.relative_to(self.root).as_posix()
                        try:
                            if item.is_symlink():
                                continue
                            device, mode, size, modified, created = _metadata(child)
                            if (device != self._device
                                    or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                                continue
                            if os.name == "nt" and getattr(child.lstat(), "st_file_attributes", 0) & 0x400:
                                continue
                        except OSError:
                            # Cannot stat a child: do not treat it as deleted.
                            seen.add(relative)
                            continue
                        seen.add(relative)
                        kind = "directory" if stat.S_ISDIR(mode) else "file"
                        found.append((relative, kind, created, modified, size))
                        if kind == "directory":
                            descend.append(child)
            except OSError:
                continue
            with self._lock, self._db:
                for relative, kind, created, modified, size in found:
                    self._upsert(relative, kind, created, modified, size)
                old_children = self._db.execute(
                    "SELECT path FROM entries WHERE parent=? AND visible=1",
                    (relative_dir,),
                ).fetchall()
                for (old_path,) in old_children:
                    if old_path not in seen:
                        self._retire(old_path)
            stack.extend(descend)

    def reconcile(self) -> None:
        """Full filesystem check, but database and FTS updates are incremental."""
        self._reconcile_tree(self.root)

    def rebuild(self) -> None:
        """Compatibility entrypoint; reconcile changes, never clear stored rows."""
        self.reconcile()
        # Explicit rebuild callers expect search results immediately.
        while self._flush_pending(limit=1000):
            pass

    def apply(self, changes) -> None:
        """Update only changed paths and affected directory subtrees."""
        # Keep the lexical path: resolving symlinks could turn a deleted/changed
        # symlink into a different path and leave a stale indexed entry behind.
        paths = {Path(raw).parent.resolve(strict=False) / Path(raw).name
                 for _change, raw in changes}
        for path in paths:
            if self._stop.is_set():
                break
            try:
                relative = path.relative_to(self.root)
            except ValueError:
                continue
            if not relative.parts or any(self._ignored(p) for p in relative.parts):
                continue
            self._reconcile_tree(path)

    def _flush_pending(self, limit=1000) -> bool:
        """Synchronize pending mutations and FTS atomically; safe after crashes."""
        # On SQLite without a trigram tokenizer, the same durable queue
        # still cleans up tombstones. Only FTS postings are omitted; searches
        # use the metadata table and a future FTS installation backfills it.
        with self._lock:
            rows = self._db.execute(
                "SELECT p.entry_id,p.old_folded,e.name,e.visible "
                "FROM pending_index p JOIN entries e ON e.id=p.entry_id "
                "ORDER BY p.entry_id LIMIT ?", (limit,),
            ).fetchall()
            if not rows:
                return False
            with self._db:
                for entry_id, old_folded, name, visible in rows:
                    if self._fts and old_folded is not None:
                        self._db.execute(
                            "INSERT INTO entry_grams(entry_grams,rowid,folded) "
                            "VALUES('delete',?,?)", (entry_id, old_folded),
                        )
                    if visible:
                        if self._fts:
                            self._db.execute(
                                "INSERT INTO entry_grams(rowid,folded) VALUES(?,?)",
                                (entry_id, name.casefold()),
                            )
                    else:
                        self._db.execute("DELETE FROM entries WHERE id=?", (entry_id,))
                    self._db.execute(
                        "DELETE FROM pending_index WHERE entry_id=?", (entry_id,),
                    )
            return True

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
        # The contentless FTS5 table cannot serve LIKE (its text is NULL).
        # MATCH one complete trigram, and confirm the full name in Python.
        fast = self._fts and len(hint) >= 3
        if sort_by not in {"name", "path", "size", "modified"} or sort_order not in {"asc", "desc"}:
            raise ValueError("invalid index sorting")
        if file_type not in {"all", "file", "directory"}:
            raise ValueError("invalid indexed file type")
        cols = "e.path,e.name,e.kind,e.created_utc_ns,e.modified_utc_ns,e.size_bytes"
        if fast:
            # Exclude pending rows from the old index, then add their current
            # metadata directly, including new names awaiting indexing.
            match = '"' + hint[:3].replace('"', '""') + '"'
            base = (
                f"SELECT * FROM (SELECT {cols} FROM entries e "
                "JOIN entry_grams ON entry_grams.rowid=e.id "
                "WHERE entry_grams MATCH ? AND e.visible=1 AND NOT EXISTS "
                "(SELECT 1 FROM pending_index p WHERE p.entry_id=e.id) "
                f"UNION ALL SELECT {cols} FROM entries e "
                "JOIN pending_index p ON p.entry_id=e.id "
                "WHERE e.visible=1) e WHERE 1=1"
            )
            args = [match]
        else:
            base = f"SELECT {cols} FROM entries e WHERE e.visible=1"
            args = []
        if prefix != ".":
            base += " AND e.path >= ? AND e.path < ?"
            args.extend([prefix + "/", prefix + "/\U0010ffff"])
        if file_type != "all":
            base += " AND e.kind = ?"
            args.append(file_type)
        for mount in excluded_roots:
            mount = Path(mount)
            try:
                relative_mount = mount.relative_to(self.root).as_posix()
            except ValueError:
                continue
            base += " AND e.path != ? AND NOT (e.path >= ? AND e.path < ?)"
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
                for relative, name, kind, created, modified, size in self._db.execute(base, args):
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    text = name if case_sensitive else name.casefold()
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
        self._pending_event.set()
        if self._worker is not None:
            self._worker.join(timeout=4)
        if self._watcher is not None:
            self._watcher.join(timeout=4)
        if self._indexer is not None:
            self._indexer.join(timeout=4)
        with self._lock:
            self._db.close()

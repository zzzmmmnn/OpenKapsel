"""Short-lived, ID-addressed file and directory sharing between workspaces."""

from __future__ import annotations

import errno
import ctypes
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path, PurePosixPath
from typing import Any

from .workspace_layout import INTERNAL_DIRECTORY


SHARE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{22}")
RESERVED_NAMES = {INTERNAL_DIRECTORY}
DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class ShareError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


@dataclass(frozen=True)
class ShareRecord:
    id: str
    owner_id: str
    created_at: float
    expires_at: float
    name: str
    kind: str
    size_bytes: int
    file_count: int

    def public(self) -> dict[str, Any]:
        return {
            "share_id": self.id,
            "name": self.name,
            "type": self.kind,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "created_at": _timestamp(self.created_at),
            "expires_at": _timestamp(self.expires_at),
        }


class ShareStore:
    """An immutable, bounded share store backed by directories plus SQLite metadata."""

    def __init__(
        self,
        root: Path,
        *,
        ttl_seconds: int = 24 * 60 * 60,
        max_entries: int = 10,
        max_bytes: int = 256 * 1024 * 1024,
        max_depth: int = 32,
        max_query_nodes: int = 5000,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.max_query_nodes = max_query_nodes
        self._lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self._staging = self.root / ".staging"
        self._staging.mkdir(exist_ok=True, mode=0o700)
        os.chmod(self._staging, 0o700)
        self._database = self.root / "index.sqlite3"
        self._initialize_database()
        with self._lock:
            self._cleanup_locked(time.time())

    def create(self, source_fd: int, name: str, owner_id: str) -> tuple[ShareRecord, str | None]:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ShareError(HTTPStatus.BAD_REQUEST, "invalid_share_source", "source name is invalid")
        if name in RESERVED_NAMES or name.startswith(".openkapsel-"):
            raise ShareError(
                HTTPStatus.FORBIDDEN,
                "reserved_path",
                "workspace internal paths cannot be shared",
            )
        with self._lock:
            now = time.time()
            self._cleanup_locked(now)
            share_id = self._new_id_locked()
            stage = self._staging / f"{share_id}-{secrets.token_hex(6)}"
            payload = stage / "payload"
            stage.mkdir(mode=0o700)
            payload.mkdir(mode=0o700)
            try:
                source_stat = os.fstat(source_fd)
                state = {"bytes": 0, "files": 0}
                if stat.S_ISREG(source_stat.st_mode):
                    kind = "file"
                    self._copy_file_fd(source_fd, payload / name, source_stat, state)
                elif stat.S_ISDIR(source_stat.st_mode):
                    kind = "directory"
                    destination = payload / name
                    destination.mkdir(mode=self._safe_mode(source_stat.st_mode, directory=True))
                    self._copy_directory_fd(source_fd, destination, 0, state)
                    self._apply_times(destination, source_stat)
                elif stat.S_ISLNK(source_stat.st_mode):
                    raise ShareError(
                        HTTPStatus.BAD_REQUEST,
                        "unsupported_share_type",
                        "symbolic links cannot be shared",
                    )
                else:
                    raise ShareError(
                        HTTPStatus.BAD_REQUEST,
                        "unsupported_share_type",
                        "only regular files and directories can be shared",
                    )
                expires_at = now + self.ttl_seconds
                record = ShareRecord(
                    share_id,
                    owner_id,
                    now,
                    expires_at,
                    name,
                    kind,
                    state["bytes"],
                    state["files"],
                )
                os.rename(stage, self.root / share_id)
                try:
                    with closing(self._connect()) as connection, connection:
                        connection.execute(
                            "INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                record.id,
                                record.owner_id,
                                record.created_at,
                                record.expires_at,
                                record.name,
                                record.kind,
                                record.size_bytes,
                                record.file_count,
                            ),
                        )
                except Exception:
                    self._remove_tree(self.root / share_id)
                    raise
                evicted = self._trim_locked()
                return record, evicted
            except Exception:
                self._remove_tree(stage)
                raise

    def inspect(self, share_id: str, relative_path: str, depth: int) -> dict[str, Any]:
        with self._lock:
            record = self._get_locked(share_id)
            relative = self._parse_relative_path(relative_path)
            target = self.root / record.id / "payload"
            for part in relative.parts:
                target /= part
            self._assert_inside_payload(record, target)
            try:
                details = target.lstat()
            except FileNotFoundError:
                raise ShareError(HTTPStatus.NOT_FOUND, "share_path_not_found", "shared path does not exist") from None
            if stat.S_ISLNK(details.st_mode):
                raise ShareError(HTTPStatus.NOT_FOUND, "share_path_not_found", "shared path does not exist")
            entries: list[dict[str, Any]] = []
            state = {"count": 0, "truncated": False}
            if stat.S_ISDIR(details.st_mode):
                self._list_directory(target, relative, depth, 0, entries, state)
            else:
                entries.append(self._entry(target, relative))
            return {
                **record.public(),
                "path": relative.as_posix() if relative.parts else "",
                "depth": depth,
                "entries": entries,
                "truncated": state["truncated"],
            }

    def import_into(
        self,
        share_id: str,
        parent_fd: int,
        destination_name: str,
    ) -> ShareRecord:
        with self._lock:
            record = self._get_locked(share_id)
            try:
                os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ShareError(
                    HTTPStatus.CONFLICT,
                    "destination_exists",
                    "destination already exists; shared imports do not overwrite",
                )
            temp_name = f".openkapsel-share-{secrets.token_hex(12)}"
            source = self.root / record.id / "payload" / record.name
            try:
                source_stat = source.lstat()
                state = {"bytes": 0, "files": 0}
                if record.kind == "file":
                    source_fd = os.open(source, FILE_FLAGS)
                    try:
                        self._copy_file_to_parent(
                            source_fd,
                            parent_fd,
                            temp_name,
                            source_stat,
                            state,
                        )
                    finally:
                        os.close(source_fd)
                else:
                    os.mkdir(
                        temp_name,
                        mode=self._safe_mode(source_stat.st_mode, directory=True),
                        dir_fd=parent_fd,
                    )
                    destination_fd = os.open(temp_name, DIRECTORY_FLAGS, dir_fd=parent_fd)
                    source_fd = os.open(source, DIRECTORY_FLAGS)
                    try:
                        self._copy_directory_between_fds(source_fd, destination_fd, 0, state)
                    finally:
                        os.close(source_fd)
                        os.close(destination_fd)
                self._rename_noreplace(parent_fd, temp_name, destination_name)
                return record
            except OSError as exc:
                self._remove_at(parent_fd, temp_name)
                if exc.errno == errno.EEXIST:
                    raise ShareError(
                        HTTPStatus.CONFLICT,
                        "destination_exists",
                        "destination already exists; shared imports do not overwrite",
                    ) from None
                if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}:
                    raise ShareError(
                        HTTPStatus.INSUFFICIENT_STORAGE,
                        "share_destination_full",
                        "destination workspace does not have enough free space",
                    ) from None
                raise
            except Exception:
                self._remove_at(parent_fd, temp_name)
                raise

    def delete(self, share_id: str, owner_id: str) -> None:
        with self._lock:
            record = self._get_locked(share_id)
            if not secrets.compare_digest(record.owner_id, owner_id):
                raise ShareError(HTTPStatus.NOT_FOUND, "share_not_found", "share does not exist")
            self._delete_locked(record.id)

    def _initialize_database(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS shares (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    file_count INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS shares_created_at ON shares(created_at, id)"
            )
        os.chmod(self._database, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _get_locked(self, share_id: str) -> ShareRecord:
        self._validate_id(share_id)
        self._cleanup_locked(time.time())
        with closing(self._connect()) as connection, connection:
            row = connection.execute("SELECT * FROM shares WHERE id = ?", (share_id,)).fetchone()
        if row is None or not (self.root / share_id / "payload").is_dir():
            if row is not None:
                self._delete_locked(share_id)
            raise ShareError(HTTPStatus.NOT_FOUND, "share_not_found", "share does not exist")
        return self._row(row)

    def _cleanup_locked(self, now: float) -> None:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT id FROM shares WHERE expires_at <= ?", (now,)
            ).fetchall()
        for row in rows:
            self._delete_locked(str(row["id"]))
        with closing(self._connect()) as connection, connection:
            known_rows = connection.execute("SELECT id FROM shares").fetchall()
        known = {str(row["id"]) for row in known_rows}
        for item in self.root.iterdir():
            if item.name in {"index.sqlite3", "index.sqlite3-wal", "index.sqlite3-shm", ".staging"}:
                continue
            if item.is_dir() and item.name not in known:
                self._remove_tree(item)
        for item in self._staging.iterdir():
            self._remove_tree(item)

    def _trim_locked(self) -> str | None:
        evicted: str | None = None
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT id FROM shares ORDER BY created_at ASC, id ASC"
            ).fetchall()
        while len(rows) > self.max_entries:
            evicted = str(rows.pop(0)["id"])
            self._delete_locked(evicted)
        return evicted

    def _delete_locked(self, share_id: str) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("DELETE FROM shares WHERE id = ?", (share_id,))
        self._remove_tree(self.root / share_id)

    def _new_id_locked(self) -> str:
        with closing(self._connect()) as connection, connection:
            while True:
                share_id = secrets.token_urlsafe(16)
                if len(share_id) == 22 and connection.execute(
                    "SELECT 1 FROM shares WHERE id = ?", (share_id,)
                ).fetchone() is None:
                    return share_id

    @staticmethod
    def _validate_id(share_id: str) -> None:
        if not SHARE_ID_PATTERN.fullmatch(share_id):
            raise ShareError(HTTPStatus.NOT_FOUND, "share_not_found", "share does not exist")

    @staticmethod
    def _parse_relative_path(value: str) -> PurePosixPath:
        if not value:
            return PurePosixPath()
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ShareError(HTTPStatus.BAD_REQUEST, "invalid_share_path", "path must be relative and cannot contain '..'")
        return path

    def _assert_inside_payload(self, record: ShareRecord, target: Path) -> None:
        payload = (self.root / record.id / "payload").resolve()
        try:
            target.resolve(strict=False).relative_to(payload)
        except ValueError:
            raise ShareError(HTTPStatus.BAD_REQUEST, "invalid_share_path", "path escapes shared content") from None

    def _copy_directory_fd(
        self,
        source_fd: int,
        destination: Path,
        depth: int,
        state: dict[str, int],
    ) -> None:
        if depth >= self.max_depth:
            raise ShareError(HTTPStatus.BAD_REQUEST, "share_too_deep", "shared directory exceeds the recursion depth limit")
        with os.scandir(source_fd) as iterator:
            entries = sorted(iterator, key=lambda item: item.name.casefold())
        for entry in entries:
            self._validate_child_name(entry.name)
            details = entry.stat(follow_symlinks=False)
            target = destination / entry.name
            if stat.S_ISREG(details.st_mode):
                child_fd = os.open(entry.name, FILE_FLAGS, dir_fd=source_fd)
                try:
                    self._copy_file_fd(child_fd, target, details, state)
                finally:
                    os.close(child_fd)
            elif stat.S_ISDIR(details.st_mode):
                child_fd = os.open(entry.name, DIRECTORY_FLAGS, dir_fd=source_fd)
                target.mkdir(mode=self._safe_mode(details.st_mode, directory=True))
                try:
                    self._copy_directory_fd(child_fd, target, depth + 1, state)
                finally:
                    os.close(child_fd)
                self._apply_times(target, details)
            else:
                raise ShareError(HTTPStatus.BAD_REQUEST, "unsupported_share_type", f"unsupported entry in shared directory: {entry.name}")

    def _copy_file_fd(
        self,
        source_fd: int,
        destination: Path,
        details: os.stat_result,
        state: dict[str, int],
    ) -> None:
        output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, self._safe_mode(details.st_mode))
        try:
            self._copy_bytes(source_fd, output_fd, state)
            os.fchmod(output_fd, self._safe_mode(details.st_mode))
            os.utime(output_fd, ns=(details.st_atime_ns, details.st_mtime_ns))
        finally:
            os.close(output_fd)

    def _copy_file_to_parent(
        self,
        source_fd: int,
        parent_fd: int,
        name: str,
        details: os.stat_result,
        state: dict[str, int],
    ) -> None:
        output_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            self._safe_mode(details.st_mode),
            dir_fd=parent_fd,
        )
        try:
            self._copy_bytes(source_fd, output_fd, state)
            os.fchmod(output_fd, self._safe_mode(details.st_mode))
            os.utime(output_fd, ns=(details.st_atime_ns, details.st_mtime_ns))
        finally:
            os.close(output_fd)

    def _copy_directory_between_fds(
        self,
        source_fd: int,
        destination_fd: int,
        depth: int,
        state: dict[str, int],
    ) -> None:
        if depth >= self.max_depth:
            raise ShareError(HTTPStatus.CONFLICT, "share_corrupt", "shared directory exceeds configured depth")
        with os.scandir(source_fd) as iterator:
            entries = sorted(iterator, key=lambda item: item.name.casefold())
        for entry in entries:
            self._validate_child_name(entry.name)
            details = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(details.st_mode):
                child_fd = os.open(entry.name, FILE_FLAGS, dir_fd=source_fd)
                try:
                    self._copy_file_to_parent(child_fd, destination_fd, entry.name, details, state)
                finally:
                    os.close(child_fd)
            elif stat.S_ISDIR(details.st_mode):
                os.mkdir(entry.name, self._safe_mode(details.st_mode, directory=True), dir_fd=destination_fd)
                source_child = os.open(entry.name, DIRECTORY_FLAGS, dir_fd=source_fd)
                destination_child = os.open(entry.name, DIRECTORY_FLAGS, dir_fd=destination_fd)
                try:
                    self._copy_directory_between_fds(source_child, destination_child, depth + 1, state)
                finally:
                    os.close(source_child)
                    os.close(destination_child)
            else:
                raise ShareError(HTTPStatus.CONFLICT, "share_corrupt", "shared content contains an unsupported entry")

    def _copy_bytes(self, source_fd: int, destination_fd: int, state: dict[str, int]) -> None:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            state["bytes"] += len(chunk)
            if state["bytes"] > self.max_bytes:
                raise ShareError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "share_too_large",
                    f"shared content exceeds the {self.max_bytes}-byte limit",
                )
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        state["files"] += 1

    def _list_directory(
        self,
        directory: Path,
        relative: PurePosixPath,
        max_depth: int,
        current_depth: int,
        entries: list[dict[str, Any]],
        state: dict[str, Any],
    ) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            raise ShareError(HTTPStatus.CONFLICT, "share_corrupt", "shared content cannot be read") from None
        for child in children:
            if state["count"] >= self.max_query_nodes:
                state["truncated"] = True
                return
            child_relative = relative / child.name
            item = self._entry(child, child_relative)
            entries.append(item)
            state["count"] += 1
            if item["type"] == "directory" and current_depth < max_depth:
                self._list_directory(child, child_relative, max_depth, current_depth + 1, entries, state)
                if state["truncated"]:
                    return

    @staticmethod
    def _entry(path: Path, relative: PurePosixPath) -> dict[str, Any]:
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode):
            kind = "directory"
        elif stat.S_ISREG(details.st_mode):
            kind = "file"
        else:
            raise ShareError(HTTPStatus.CONFLICT, "share_corrupt", "shared content contains an unsupported entry")
        return {
            "name": path.name,
            "path": relative.as_posix(),
            "type": kind,
            "size_bytes": details.st_size,
            "modified_at": _timestamp(details.st_mtime),
        }

    @staticmethod
    def _validate_child_name(name: str) -> None:
        if name in RESERVED_NAMES or name.startswith(".openkapsel-"):
            raise ShareError(HTTPStatus.FORBIDDEN, "reserved_path", "workspace internal paths cannot be shared")

    @staticmethod
    def _safe_mode(mode: int, *, directory: bool = False) -> int:
        permissions = stat.S_IMODE(mode) & 0o777
        return permissions or (0o700 if directory else 0o600)

    @staticmethod
    def _apply_times(path: Path, details: os.stat_result) -> None:
        os.utime(path, ns=(details.st_atime_ns, details.st_mtime_ns), follow_symlinks=False)

    @staticmethod
    def _row(row: sqlite3.Row) -> ShareRecord:
        return ShareRecord(
            str(row["id"]),
            str(row["owner_id"]),
            float(row["created_at"]),
            float(row["expires_at"]),
            str(row["name"]),
            str(row["kind"]),
            int(row["size_bytes"]),
            int(row["file_count"]),
        )

    @staticmethod
    def _remove_tree(path: Path) -> None:
        try:
            details = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            for child in path.iterdir():
                ShareStore._remove_tree(child)
            path.rmdir()
        else:
            path.unlink()

    @staticmethod
    def _remove_at(parent_fd: int, name: str) -> None:
        try:
            details = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            child_fd = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
            try:
                with os.scandir(child_fd) as iterator:
                    children = [entry.name for entry in iterator]
                for child in children:
                    ShareStore._remove_at(child_fd, child)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=parent_fd)
        else:
            os.unlink(name, dir_fd=parent_fd)

    @staticmethod
    def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
        """Publish a staged import without replacing a concurrently created target."""
        if sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = getattr(libc, "renameat2", None)
            if renameat2 is not None:
                renameat2.argtypes = (
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_uint,
                )
                renameat2.restype = ctypes.c_int
                result = renameat2(
                    parent_fd,
                    os.fsencode(source),
                    parent_fd,
                    os.fsencode(destination),
                    1,  # RENAME_NOREPLACE
                )
                if result == 0:
                    return
                error = ctypes.get_errno()
                if error not in {errno.ENOSYS, errno.EINVAL}:
                    raise OSError(error, os.strerror(error), destination)
        # Portable fallback. ShareStore serializes its own imports; platforms
        # without renameat2 cannot make the final existence check kernel-atomic.
        try:
            os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, destination, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            return
        raise FileExistsError(errno.EEXIST, "destination already exists", destination)


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()

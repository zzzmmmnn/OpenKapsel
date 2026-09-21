"""Guarded local/remote file streams. No method in this module mounts FUSE.

Remote descriptors remain bound to one provider generation. A lost response is
never replayed, and metadata comes from the open descriptor, not a later path
lookup. Server paths are only presentation; providers receive relative paths.
"""

from __future__ import annotations

import base64
import errno
import io
import os
import stat
from pathlib import Path
from types import SimpleNamespace

from .mapping_transport import CHUNK_SIZE
from .safe_paths import SafePathAccess


def remote_stat(value):
    required = ("st_mode", "st_size", "st_ino", "st_dev", "st_mtime_ns", "st_atime_ns", "st_ctime_ns")
    if not isinstance(value, dict) or any(type(value.get(k)) is not int for k in required):
        raise OSError(errno.ENOSYS, "update the mapping client for descriptor metadata support")
    if value["st_size"] < 0 or not (stat.S_ISREG(value["st_mode"]) or stat.S_ISDIR(value["st_mode"])):
        raise OSError(errno.EIO, "invalid mapping metadata")
    result = dict(value)
    for field in ("st_mtime", "st_atime", "st_ctime"):
        result[field] = result[field + "_ns"] / 1_000_000_000
    return SimpleNamespace(**result)


def stream_stat(stream):
    """fstat for ordinary streams and buffered/text-wrapped RemoteFile streams."""
    current = stream
    while True:
        if isinstance(current, RemoteFile):
            return current.stat()
        child = getattr(current, "buffer", None) or getattr(current, "raw", None)
        if child is None:
            return os.fstat(current.fileno())
        current = child


def sync_stream(stream):
    stream.flush()
    current = stream
    while getattr(current, "raw", None) is not None:
        current = current.raw
    if isinstance(current, RemoteFile):
        current.sync()
    else:
        os.fsync(current.fileno())


class RemoteFile(io.RawIOBase):
    def __init__(self, files, row, path, flags):
        super().__init__()
        self.files, self.row = files, row
        self.name = str(path)
        self.offset = 0
        self._remote_closed = False
        self.handle = None
        access = flags & os.O_ACCMODE
        self.mode = {os.O_RDONLY: "r", os.O_WRONLY: "w", os.O_RDWR: "rw"}[access]
        operation = "create" if flags & os.O_CREAT else "open"
        self.handle = files.call(row, operation, {
            "path": files.relative(row, path), "mode": self.mode,
            "truncate": bool(flags & os.O_TRUNC),
        })
        try:
            if not stat.S_ISREG(self.stat().st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
        except BaseException:
            self.close()
            raise

    def stat(self):
        return remote_stat(self.files.call(self.row, "fstat", {"handle": self.handle}))

    def readable(self):
        return self.mode in {"r", "rw"}

    def writable(self):
        return self.mode in {"w", "rw"}

    def seekable(self):
        return True

    def tell(self):
        return self.offset

    def seek(self, offset, whence=os.SEEK_SET):
        self._checkClosed()
        if whence == os.SEEK_CUR:
            offset += self.offset
        elif whence == os.SEEK_END:
            offset += self.stat().st_size
        elif whence != os.SEEK_SET:
            raise ValueError("invalid seek mode")
        if offset < 0:
            raise ValueError("negative file offset")
        self.offset = offset
        return offset

    def readinto(self, buffer):
        self._checkClosed()
        if not self.readable():
            raise io.UnsupportedOperation("not readable")
        size = min(len(buffer), CHUNK_SIZE)
        if size == 0:
            return 0
        value = self.files.call(self.row, "read", {"handle": self.handle, "offset": self.offset, "size": size})
        try:
            data = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise OSError(errno.EIO, "invalid mapping read response") from None
        if len(data) > size:
            raise OSError(errno.EIO, "mapping read exceeded requested length")
        buffer[:len(data)] = data
        self.offset += len(data)
        return len(data)

    def write(self, data):
        self._checkClosed()
        if not self.writable():
            raise io.UnsupportedOperation("not writable")
        chunk = bytes(memoryview(data)[:CHUNK_SIZE])
        if not chunk:
            return 0
        written = self.files.call(self.row, "write", {
            "handle": self.handle, "offset": self.offset,
            "data": base64.b64encode(chunk).decode("ascii"),
        })
        if type(written) is not int or not 0 < written <= len(chunk):
            raise OSError(errno.EIO, "invalid mapping write response")
        self.offset += written
        return written

    def truncate(self, size=None):
        self._checkClosed()
        size = self.offset if size is None else size
        self.files.call(self.row, "truncate_handle", {"handle": self.handle, "size": size})
        return size

    def sync(self):
        self._checkClosed()
        self.files.call(self.row, "flush", {"handle": self.handle})

    def close(self):
        if self.closed:
            return
        try:
            if not self._remote_closed and self.handle is not None:
                self.files.call(self.row, "close", {"handle": self.handle})
        finally:
            self._remote_closed = True
            super().close()


class WorkspaceFiles:
    """A small common backend for traversal, streams, and cross-root transfers."""
    def __init__(self, mappings, roots):
        self.mappings = mappings
        self.roots = tuple(Path(root) for root in roots)
        self.paths = SafePathAccess(self.roots)
        self.generations = {}

    def checked(self, path, *, write=False):
        path = Path(os.path.abspath(path))
        if not any(path == root or root in path.parents for root in self.roots):
            raise OSError(errno.EACCES, "path is outside authorized roots")
        row = self.mappings.check_path(path, write=write)
        return path, row

    def call(self, row, operation, args):
        mid = row["id"]
        if mid not in self.generations:
            with self.mappings.lock:
                session = self.mappings.sessions.get(mid)
                if session is None or session.closed:
                    raise OSError(errno.EHOSTDOWN, "mapping client is offline")
                self.generations[mid] = session.generation
        return self.mappings.call(mid, operation, args, generation=self.generations[mid])

    def relative(self, row, path):
        return path.relative_to(self.mappings.mount_path(row)).as_posix()

    @staticmethod
    def root_stat(row):
        stamp = int(row.get("created_at", 0) * 1_000_000_000)
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_size=0, st_ino=0,
                               st_dev=0, st_nlink=2, st_mtime_ns=stamp, st_atime_ns=stamp,
                               st_ctime_ns=stamp, st_mtime=stamp / 1e9,
                               st_atime=stamp / 1e9, st_ctime=stamp / 1e9)

    def stat(self, path):
        path, row = self.checked(path)
        if row:
            return remote_stat(self.call(row, "stat", {"path": self.relative(row, path)}))
        fd = self.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            return os.fstat(fd)
        finally:
            os.close(fd)

    def exists(self, path):
        try:
            self.stat(path)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return False
            raise

    def entries(self, path):
        path, row = self.checked(path)
        if row:
            result, offset = [], 0
            while True:
                page = self.call(row, "list", {"path": self.relative(row, path), "offset": offset, "include_details": True})
                names = page.get("names")
                total = page.get("total")
                if not isinstance(names, list) or type(total) is not int or not 0 <= total <= 100000:
                    raise OSError(errno.EIO, "invalid mapping directory response")
                metadata = page.get("entries", {})
                if not isinstance(metadata, dict):
                    raise OSError(errno.EIO, "invalid mapping directory metadata")
                for name in names:
                    if not isinstance(name, str) or name in {"", ".", "..", ".openkapsel"} or any(c in name for c in "/\\\x00"):
                        raise OSError(errno.EIO, "invalid mapping directory name")
                    details = metadata.get(name)
                    if details is None:
                        details = self.call(row, "stat", {"path": self.relative(row, path / name)})
                    result.append((name, remote_stat(details)))
                offset += len(names)
                if offset > 100000:
                    raise OSError(errno.E2BIG, "mapping directory exceeds listing limit")
                if offset >= total:
                    break
                if not names:
                    raise OSError(errno.EIO, "incomplete mapping directory response")
            return result
        # Do not stat native mountpoints: an offline mount can block, and an
        # unmounted reservation is deliberately unreadable. Merge virtual roots.
        rows = {r["name"]: r for r in self.mappings.store.list(path.name)
                if self.mappings.root / r["workspace"] == path}
        fd = self.paths.open(path, os.O_RDONLY)
        try:
            result = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    if entry.name in rows:
                        continue
                    try:
                        result.append((entry.name, entry.stat(follow_symlinks=False)))
                    except OSError:
                        continue
            result.extend((name, self.root_stat(row)) for name, row in rows.items())
            return result
        finally:
            os.close(fd)

    def open(self, path, flags=os.O_RDONLY):
        path, row = self.checked(path, write=bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)))
        if row:
            raw = RemoteFile(self, row, path, flags)
            if raw.readable() and raw.writable():
                return io.BufferedRandom(raw, CHUNK_SIZE)
            if raw.writable():
                return io.BufferedWriter(raw, CHUNK_SIZE)
            return io.BufferedReader(raw, CHUNK_SIZE)
        fd = self.paths.open(path, flags | getattr(os, "O_NONBLOCK", 0))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise OSError(errno.EINVAL, "not a regular file")
        access = flags & os.O_ACCMODE
        return os.fdopen(fd, {os.O_RDONLY: "rb", os.O_WRONLY: "wb", os.O_RDWR: "r+b"}[access])

    def mkdir(self, path, *, parents=False, exist_ok=False):
        path, row = self.checked(path, write=True)
        if not row:
            return self.paths.mkdir(path, parents=parents, exist_ok=exist_ok)
        root = self.mappings.mount_path(row)
        if path == root:
            if exist_ok:
                return False
            raise FileExistsError(errno.EEXIST, "mapping root already exists")
        if parents:
            self.mkdir(path.parent, parents=True, exist_ok=True)
        try:
            self.call(row, "mkdir", {"path": self.relative(row, path)})
            return True
        except FileExistsError:
            if not exist_ok or not stat.S_ISDIR(self.stat(path).st_mode):
                raise
            return False

    def rename(self, source, destination, *, overwrite=False):
        source, src = self.checked(source, write=True)
        destination, dst = self.checked(destination, write=True)
        if (src or {}).get("id") != (dst or {}).get("id"):
            raise OSError(errno.EXDEV, "cross-root rename requires a transfer")
        if src:
            return self.call(src, "rename", {"path": self.relative(src, source),
                            "destination": self.relative(dst, destination), "overwrite": overwrite})
        if overwrite:
            return self.paths.rename(source, destination, overwrite=True, create_parents=False)
        from .rename_exclusive import rename_exclusive
        with self.paths.parent(source) as src_parent, self.paths.parent(destination) as dst_parent:
            return rename_exclusive(src_parent.name, dst_parent.name, src_parent.fd, dst_parent.fd)

    def unlink(self, path, *, directory=False):
        path, row = self.checked(path, write=True)
        if row:
            return self.call(row, "rmdir" if directory else "unlink", {"path": self.relative(row, path)})
        with self.paths.parent(path) as parent:
            return parent.unlink(directory=directory)

    def remove_tree(self, path, *, max_nodes=10000):
        remaining = [max_nodes]
        def remove(current, depth):
            remaining[0] -= 1
            if remaining[0] < 0 or depth > 64:
                raise OSError(errno.E2BIG, "cleanup exceeds tree limits")
            if stat.S_ISDIR(self.stat(current).st_mode):
                for name, _ in self.entries(current):
                    remove(current / name, depth + 1)
                self.unlink(current, directory=True)
            else:
                self.unlink(current)
        try:
            remove(Path(path), 0)
        except FileNotFoundError:
            pass

"""Local filesystem provider. Remote paths never select the exported root."""

from __future__ import annotations

import base64
import errno
import os
import stat
import threading
from pathlib import Path, PurePosixPath

from .safe_paths import SafePathAccess
from .mapping_transport import CHUNK_SIZE


class ClientFiles:
    def __init__(self, root, *, writable=False):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("export root must be a directory")
        self.writable = writable
        self.paths = SafePathAccess((self.root,))
        self.lock = threading.RLock()
        self.handles = {}
        self.next_handle = 1

    def path(self, value):
        if not isinstance(value, str) or "\x00" in value or "\\" in value or ":" in value:
            raise OSError(errno.EINVAL, "invalid relative path")
        parts = PurePosixPath(value).parts
        if value.startswith("/") or any(p in {"..", ".openkapsel"} for p in parts):
            raise OSError(errno.EACCES, "path is outside exported files")
        return self.root.joinpath(*parts)

    @staticmethod
    def details(st):
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise OSError(errno.EACCES, "only regular files and directories are exported")
        return {key: getattr(st, key) for key in
                ("st_mode", "st_size", "st_atime", "st_mtime", "st_ctime", "st_nlink", "st_ino")}

    def dispatch(self, operation, args):
        if not isinstance(args, dict):
            raise OSError(errno.EINVAL, "arguments must be an object")
        if operation not in {"stat", "list", "read", "open", "close", "flush", "statfs", "recycle_list"} and not self.writable:
            raise OSError(errno.EROFS, "client export is read-only")
        # POSIX directory descriptors prevent path-component substitution.
        # Windows uses a dedicated adapter rather than silently weakening this boundary.
        with self.lock:
            return self._dispatch(operation, args)

    def _dispatch(self, op, args):
        if op == "close":
            fd = self.handles.pop(int(args["handle"]), None)
            if fd is not None:
                os.close(fd)
            return None
        if op in {"read", "write", "flush", "truncate_handle"}:
            fd = self.handles[int(args["handle"])]
            if op == "flush":
                os.fsync(fd)
                return None
            if op == "truncate_handle":
                os.ftruncate(fd, self._number(args["size"]))
                return None
            os.lseek(fd, self._number(args.get("offset", 0)), os.SEEK_SET)
            if op == "read":
                data = os.read(fd, min(CHUNK_SIZE, self._number(args["size"])))
                return base64.b64encode(data).decode()
            data = base64.b64decode(args["data"], validate=True)
            if len(data) > CHUNK_SIZE:
                raise OSError(errno.E2BIG, "write exceeds chunk limit")
            return os.write(fd, data)
        if op == "statfs":
            st = os.statvfs(self.root)
            return {key: getattr(st, key) for key in
                    ("f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_favail", "f_namemax")}
        if op in {"recycle", "recycle_list", "recycle_restore", "recycle_purge"}:
            from .recycle import RecycleBin, RecycleError
            try:
                recycle = RecycleBin(self.root)
                if op == "recycle":
                    return recycle.recycle(self.path(args["path"]))
                if op == "recycle_restore":
                    return recycle.restore(args["recycle_id"])
                if op == "recycle_purge":
                    return recycle.purge(args["recycle_id"])
                entries, total = recycle.list_items(self._number(args.get("offset", 0)),
                                                     min(1000, self._number(args.get("limit", 100))))
                return {"entries": entries, "total": total}
            except RecycleError as exc:
                raise OSError(errno.EIO, exc.code) from None
        path = self.path(args.get("path", "."))
        if op == "stat":
            fd = self.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                return self.details(os.fstat(fd))
            finally:
                os.close(fd)
        if op == "list":
            fd = self.paths.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                offset = self._number(args.get("offset", 0))
                # Explicit cap prevents an enormous directory from exhausting RPC memory.
                names = []
                with os.scandir(fd) as entries:
                    for item in entries:
                        if item.name != ".openkapsel" and (item.is_file(follow_symlinks=False) or item.is_dir(follow_symlinks=False)):
                            names.append(item.name)
                        if len(names) > 100000:
                            raise OSError(errno.E2BIG, "directory exceeds provider listing limit")
                names.sort()
                return {"names": names[offset:offset + 500], "total": len(names)}
            finally:
                os.close(fd)
        if op in {"open", "create"}:
            if len(self.handles) >= 256:
                raise OSError(errno.EMFILE, "provider handle limit reached")
            mode = args.get("mode", "r")
            if mode not in {"r", "w", "rw"}:
                raise OSError(errno.EINVAL, "invalid open mode")
            if (mode != "r" or op == "create") and not self.writable:
                raise OSError(errno.EROFS, "client export is read-only")
            flags = {"r": os.O_RDONLY, "w": os.O_WRONLY, "rw": os.O_RDWR}[mode]
            if op == "create":
                flags |= os.O_CREAT | os.O_EXCL
            if args.get("truncate"):
                if mode == "r":
                    raise OSError(errno.EACCES, "read-only open cannot truncate")
                flags |= os.O_TRUNC
            fd = self.paths.open(path, flags | getattr(os, "O_NONBLOCK", 0), 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise OSError(errno.EACCES, "not a regular file")
            handle = self.next_handle
            self.next_handle += 1
            self.handles[handle] = fd
            return handle
        if path == self.root:
            raise OSError(errno.EBUSY, "export root is protected")
        if op == "mkdir":
            return self.paths.mkdir(path, parents=False, exist_ok=False)
        if op == "rename":
            if not args.get("overwrite", True) and os.name != "nt":
                from .rename_exclusive import rename_exclusive
                with self.paths.parent(path) as src, self.paths.parent(self.path(args["destination"])) as dst:
                    rename_exclusive(src.name, dst.name, src.fd, dst.fd)
                return False
            return self.paths.rename(path, self.path(args["destination"]), overwrite=bool(args.get("overwrite", True)), create_parents=False)
        if op in {"unlink", "rmdir"}:
            with self.paths.parent(path) as parent:
                parent.unlink(directory=op == "rmdir")
            return None
        if op in {"truncate", "chmod", "utimens"}:
            flags = os.O_WRONLY if op == "truncate" else os.O_RDONLY
            fd = self.paths.open(path, flags | getattr(os, "O_NONBLOCK", 0))
            try:
                self.details(os.fstat(fd))
                if op == "truncate":
                    os.ftruncate(fd, self._number(args["size"]))
                elif op == "chmod":
                    os.fchmod(fd, int(args["mode"]) & 0o777)
                else:
                    os.utime(fd, times=args.get("times"))
                return None
            finally:
                os.close(fd)
        raise OSError(errno.ENOSYS, "unsupported filesystem operation")

    @staticmethod
    def _number(value):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
            raise OSError(errno.EINVAL, "invalid nonnegative integer")
        return value

    def close(self):
        with self.lock:
            for fd in self.handles.values():
                os.close(fd)
            self.handles.clear()

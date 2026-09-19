"""Windows provider paths pinned by non-delete-sharing native handles.

Imported only on Windows. Reparse points are rejected, including junctions;
directory handles remain open while pathname-based operations execute.
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import errno
import json
import msvcrt
import os
import secrets
import shutil
import stat
import time
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

from .client_files import ClientFiles

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel.CreateFileW.restype = wintypes.HANDLE
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL


def native_handle(path, *, access=0, create=False):
    handle = kernel.CreateFileW(str(path), access, 3, None, 1 if create else 3,
                                0x02000000 | 0x00200000, None)  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    attrs = (wintypes.DWORD * 2)()
    if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attrs), ctypes.sizeof(attrs)):
        kernel.CloseHandle(handle)
        raise ctypes.WinError(ctypes.get_last_error())
    if attrs[0] & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        kernel.CloseHandle(handle)
        raise OSError(errno.EACCES, "reparse points are not exported")
    return handle


class WindowsPaths:
    def __init__(self, root):
        self.root = root

    @contextlib.contextmanager
    def guard(self, path, *, include_final=False):
        parts = path.relative_to(self.root).parts
        if any(p in {"..", ""} or ":" in p or p.endswith((" ", ".")) for p in parts):
            raise OSError(errno.EACCES, "invalid Windows path component")
        handles = []
        try:
            current = self.root
            handles.append(native_handle(current))
            for part in parts if include_final else parts[:-1]:
                current /= part
                handles.append(native_handle(current))
            yield
        finally:
            for handle in reversed(handles):
                kernel.CloseHandle(handle)

    def open(self, path, flags=os.O_RDONLY, mode=0o600):
        with self.guard(path):
            access = 0x80000000
            if flags & (os.O_WRONLY | os.O_RDWR):
                access = 0x40000000 | (0x80000000 if flags & os.O_RDWR else 0)
            handle = native_handle(path, access=access, create=bool(flags & os.O_CREAT))
            try:
                fd = msvcrt.open_osfhandle(handle, (flags & (os.O_WRONLY | os.O_RDWR)) | os.O_BINARY)
            except Exception:
                kernel.CloseHandle(handle)
                raise
            if flags & os.O_TRUNC:
                os.ftruncate(fd, 0)
            return fd

    def mkdir(self, path, *, parents, exist_ok):
        with self.guard(path):
            path.mkdir(exist_ok=exist_ok)
            return True

    def rename(self, source, destination, *, overwrite, create_parents):
        with self.guard(source), self.guard(destination):
            # Refuse reparse sources; release its non-delete-sharing handle only
            # for rename, which moves the entry itself rather than following it.
            handle = native_handle(source)
            kernel.CloseHandle(handle)
            existed = destination.exists()
            (os.replace if overwrite else os.rename)(source, destination)
            return existed


class WindowsClientFiles(ClientFiles):
    def __init__(self, root, **kwargs):
        super().__init__(root, **kwargs)
        self.paths = WindowsPaths(self.root)

    def path(self, value):
        path = super().path(value)
        for part in path.relative_to(self.root).parts:
            if part.endswith((" ", ".")) or any(c in part for c in '*?"<>|') or part.split(".")[0].upper() in {
                "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
                raise OSError(errno.EACCES, "invalid Windows filename")
        return path

    def _dispatch(self, op, args):
        if op == "statfs":
            disk = shutil.disk_usage(self.root)
            return dict(f_bsize=4096, f_frsize=4096, f_blocks=disk.total // 4096,
                        f_bfree=disk.free // 4096, f_bavail=disk.free // 4096,
                        f_files=0, f_ffree=0, f_favail=0, f_namemax=255)
        if op.startswith("recycle"):
            return self._recycle(op, args)
        if op not in {"stat", "list", "unlink", "rmdir", "chmod", "utimens"}:
            return super()._dispatch(op, args)
        path = self.path(args.get("path", "."))
        if op in {"unlink", "rmdir"}:
            if path == self.root:
                raise OSError(errno.EBUSY, "export root is protected")
            with self.paths.guard(path):
                (os.unlink if op == "unlink" else os.rmdir)(path)
            return None
        with self.paths.guard(path, include_final=True):
            if op == "stat":
                return self.details(path.stat())
            if op == "list":
                names = []
                with os.scandir(path) as items:
                    for item in items:
                        details = item.stat(follow_symlinks=False)
                        if item.name != ".openkapsel" and not getattr(details, "st_file_attributes", 0) & 0x400:
                            names.append(item.name)
                        if len(names) > 100000:
                            raise OSError(errno.E2BIG, "directory exceeds listing limit")
                names.sort()
                offset = self._number(args.get("offset", 0))
                return {"names": names[offset:offset + 500], "total": len(names)}
            if op == "utimens":
                os.utime(path, times=args.get("times"))
            # POSIX permission bits have no equivalent ACL semantics here.
            elif op == "chmod":
                raise OSError(errno.ENOTSUP, "POSIX chmod is not supported on Windows exports")
        return None

    def _recycle(self, op, args):
        store = self.root / ".openkapsel" / "recycle"
        for directory in (store.parent, store):
            with self.paths.guard(directory):
                directory.mkdir(exist_ok=True)
            with self.paths.guard(directory, include_final=True):
                pass
        with self.paths.guard(store, include_final=True):
            if op == "recycle":
                source = self.path(args["path"])
                if source == self.root:
                    raise OSError(errno.EBUSY, "export root is protected")
                rid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ-") + secrets.token_hex(4)
                entry = store / rid
                entry.mkdir()
                metadata = {"recycle_id": rid, "original_path": source.relative_to(self.root).as_posix(),
                            "deleted_at": datetime.now(timezone.utc).isoformat()}
                fd = self.paths.open(entry / "metadata.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w") as handle:
                    json.dump(metadata, handle)
                self.paths.rename(source, entry / "content", overwrite=False, create_parents=False)
                return metadata
            import re
            def load(rid):
                if not re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{8}", rid):
                    raise OSError(errno.EINVAL, "invalid recycle id")
                fd = self.paths.open(store / rid / "metadata.json")
                with os.fdopen(fd) as handle:
                    return json.load(handle)
            if op == "recycle_restore":
                rid = args["recycle_id"]
                metadata = load(rid)
                self.paths.rename(store / rid / "content", self.path(metadata["original_path"]), overwrite=False, create_parents=False)
                return dict(metadata, restored=True)
            if op == "recycle_purge":
                rid = args["recycle_id"]
                load(rid)  # Validate identity and metadata before removal.
                def remove_tree(path):
                    with self.paths.guard(path, include_final=True):
                        for child in path.iterdir():
                            details = child.lstat()
                            reparse = getattr(details, "st_file_attributes", 0) & 0x400
                            if reparse:
                                (os.rmdir if getattr(details, "st_file_attributes", 0) & 0x10 else os.unlink)(child)
                            elif stat.S_ISDIR(details.st_mode):
                                remove_tree(child)
                            else:
                                child.unlink()
                    path.rmdir()
                remove_tree(store / rid)
                return {"recycle_id": rid, "purged": True, "recoverable": False}
            entries = []
            for item in store.iterdir():
                try:
                    record = load(item.name)
                    if (item / "content").exists():
                        entries.append(record)
                except (OSError, ValueError):
                    continue
            entries.sort(key=lambda e: e["recycle_id"], reverse=True)
            offset = self._number(args.get("offset", 0))
            limit = min(1000, self._number(args.get("limit", 100)))
            return {"entries": entries[offset:offset + limit], "total": len(entries)}

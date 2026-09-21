"""Coarse-grained file RPC using the same operations as the REST handlers.

Only explicitly listed operations are callable. Paths always resolve through the
provider's guarded export; display_root is used solely to render public paths.
"""

from __future__ import annotations

import errno
import contextlib
import os
import secrets
import stat
from pathlib import Path
from types import SimpleNamespace

from openkapsel.errors import ApiError
from openkapsel.files.file_handlers import FileHandlersMixin
from openkapsel.mapping.mapping_transport import FILE_API_OPERATIONS, FILE_API_WRITE_OPERATIONS, encode
from openkapsel.files.safe_paths import SafePathError


# The caller's configured limits remain authoritative, within client ceilings.
FILE_API_LIMITS = {
    "default_read_chars": 1024 * 1024,
    "max_read_chars": 16 * 1024 * 1024,
    "max_recursion_depth": 64,
    "max_tree_nodes": 10000,
    "max_search_results": 1000,
    "max_search_file_bytes": 128 * 1024 * 1024,
    "max_text_replace_bytes": 128 * 1024 * 1024,
    "max_batch_file_operations": 1000,
}


class ClientFileAPI(FileHandlersMixin):
    def __init__(self, files, arguments):
        self.files = files
        self.token_scope_root = files.root
        self.token_record = SimpleNamespace(can_read=True, can_write=files.writable)
        limits = arguments.get("limits", {})
        if not isinstance(limits, dict):
            raise OSError(errno.EINVAL, "invalid limits")
        configured = {}
        for name, maximum in FILE_API_LIMITS.items():
            value = limits.get(name, maximum)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise OSError(errno.EINVAL, "invalid operation limit")
            configured[name] = value
        mappings = SimpleNamespace(at_path=lambda path: None, check_path=lambda *a, **kw: None)
        # Batch delete initializes this before using _recycle_path; it must never
        # create a POSIX recycle implementation on a Windows provider.
        self.server = SimpleNamespace(config=SimpleNamespace(**configured), mappings=mappings,
                                      recycle_for=lambda root: None)
        self.body = arguments.get("body", {})
        self.query = arguments.get("query", {})
        if not isinstance(self.body, dict) or not isinstance(self.query, dict):
            raise OSError(errno.EINVAL, "invalid request")
        if any(not isinstance(k, str) or not isinstance(v, list) or
               any(not isinstance(item, str) for item in v) for k, v in self.query.items()):
            raise OSError(errno.EINVAL, "invalid query")
        self.display_root = arguments.get("display_root", ".")
        if not isinstance(self.display_root, str) or len(self.display_root) > 4096:
            raise OSError(errno.EINVAL, "invalid display root")
        self.search_prefix = arguments.get("search_prefix", "")
        if (not isinstance(self.search_prefix, str) or len(self.search_prefix) > 4096
                or "\x00" in self.search_prefix or "\\" in self.search_prefix
                or self.search_prefix.startswith("/") or ".." in self.search_prefix.split("/")):
            raise OSError(errno.EINVAL, "invalid search prefix")
        self.response = None

    @classmethod
    def dispatch(cls, files, operation, arguments):
        if operation not in FILE_API_OPERATIONS:
            raise OSError(errno.ENOSYS, "unsupported file API operation")
        if operation in FILE_API_WRITE_OPERATIONS and not files.writable:
            raise OSError(errno.EROFS, "client export is read-only")
        handler = cls(files, arguments)
        try:
            method = getattr(handler, "_handle_" + operation)
            if operation in {"fs_list", "fs_stat", "fs_read", "fs_tree", "fs_search"}:
                method(handler.query)
            else:
                method()
        except ApiError as exc:
            handler.response = {"status": int(exc.status), "error": {
                "code": exc.code, "message": exc.message, "details": exc.details}}
        except OSError as exc:
            status, code = {errno.ENOENT: (404, "path_not_found"), errno.EACCES: (403, "path_access_denied"),
                            errno.EPERM: (403, "path_access_denied"), errno.EROFS: (403, "permission_denied"),
                            errno.EEXIST: (409, "path_exists"), errno.EINVAL: (400, "invalid_request")}.get(
                                exc.errno, (409, "file_operation_failed"))
            handler.response = {"status": status, "error": {"code": code, "message": "client file operation failed"}}
        result = handler._public(handler.response)
        try:
            encode({"id": "0" * 24, "result": result})
        except OSError:
            # A write may already have completed. Never retry through FUSE.
            return {"status": 413, "error": {"code": "mapping_response_too_large",
                    "message": "mapping response exceeds the RPC limit; reduce the page size, depth, or batch size",
                    "details": {"mutation_may_have_completed": operation in FILE_API_WRITE_OPERATIONS}}}
        return result

    def _public(self, value, key=None):
        if isinstance(value, str):
            if key in {"path", "source", "destination"}:
                try:
                    relative = Path(value).relative_to(self.files.root).as_posix()
                except ValueError:
                    return value
                return self.display_root.rstrip("/") + ("/" + relative if relative != "." else "")
            if key == "message":
                return value.replace(str(self.files.root), self.display_root)
            return value
        if isinstance(value, dict):
            return {key: self._public(item, key) for key, item in value.items()}
        if isinstance(value, list):
            return [self._public(item, key) for item in value]
        return value

    def _try_mapping_file_api(self, *args, **kwargs):
        return False

    def _read_json(self):
        return self.body

    def _send_json(self, status, payload):
        self.response = {"status": int(status), "body": payload}

    @staticmethod
    def _require_permission(granted, message):
        if not granted:
            raise ApiError(403, "permission_denied", message)

    def _resolve_path(self, value, *, write=False):
        path = self.files.path(value)
        if any(self._is_internal_transfer_name(part) for part in path.relative_to(self.files.root).parts):
            raise ApiError(403, "reserved_path", "temporary transfer paths are not available")
        if write and path == self.files.root:
            raise ApiError(403, "root_protected", "mapping root is protected")
        return path

    def _safe_path_access(self):
        return self.files.paths

    def _file_stat(self, path):
        if os.name != "nt":
            return super()._file_stat(path)
        try:
            with self.files.paths.guard(path, include_final=True):
                details = path.stat()
                if not stat.S_ISREG(details.st_mode):
                    return details
                descriptor = self.files.paths.open(path, os.O_RDONLY)
                try:
                    return os.fstat(descriptor)
                finally:
                    os.close(descriptor)
        except OSError as exc:
            self._raise_safe_path_error(SafePathError(exc.errno or errno.EIO, "client path access failed"))

    def _safe_parent(self, path, *, create_parents=False):
        if os.name != "nt":
            return super()._safe_parent(path, create_parents=create_parents)
        @contextlib.contextmanager
        def parent():
            if create_parents:
                self.files.paths.mkdir(path.parent, parents=True, exist_ok=True)
            with self.files.paths.guard(path):
                def lstat():
                    try:
                        return self._file_stat(path)
                    except ApiError as exc:
                        if exc.code == "path_not_found":
                            return None
                        raise
                yield SimpleNamespace(lstat=lstat)
        return parent()

    def _directory_entries(self, path):
        if os.name == "nt":
            with self.files.paths.guard(path, include_final=True):
                entries = self._scan(path)
        else:
            descriptor = self._safe_open_descriptor(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                entries = self._scan(descriptor)
            finally:
                os.close(descriptor)
        # Match the FUSE export's policy: neither symlinks nor special files.
        return [(name, st) for name, st in entries if not getattr(st, "st_file_attributes", 0) & 0x400
                and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode))]

    @staticmethod
    def _scan(path):
        entries = []
        with os.scandir(path) as iterator:
            for item in iterator:
                entries.append((item.name, item.stat(follow_symlinks=False)))
                if len(entries) > 100000:
                    raise OSError(errno.E2BIG, "directory exceeds provider listing limit")
        return entries

    def _recycle_path(self, path):
        return self.files._dispatch("recycle", {"path": path.relative_to(self.files.root).as_posix()})

    def _atomic_write(self, path, content, *, expected_etag=None, create_parents=False, encoding="utf-8"):
        from openkapsel.files.text_encoding import encode_text, text_encoding
        data = encode_text(content, text_encoding(encoding))
        if os.name != "nt":
            return super()._atomic_write(path, content, expected_etag=expected_etag, create_parents=create_parents, encoding=encoding)
        if create_parents:
            self.files.paths.mkdir(path.parent, parents=True, exist_ok=True)
        with self.files.paths.guard(path):
            try:
                previous = self._file_stat(path)
            except ApiError as exc:
                if exc.code != "path_not_found":
                    raise
                previous = None
            if previous and not stat.S_ISREG(previous.st_mode):
                raise ApiError(400, "not_a_file", "path is not a regular file")
            temporary = path.with_name(f".{path.name}.openkapsel-put-{secrets.token_hex(12)}")
            try:
                with os.fdopen(self.files.paths.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    current = self._file_stat(path)
                except ApiError as exc:
                    if exc.code != "path_not_found":
                        raise
                    current = None
                self._check_expected_etag(expected_etag, self._stat_etag(current) if current else None)
                self.files.paths.rename(temporary, path, overwrite=True, create_parents=False)
                final = self._file_stat(path)
                if previous and previous.st_mtime_ns // 1_000_000_000 == final.st_mtime_ns // 1_000_000_000:
                    next_second = (max(previous.st_mtime_ns, final.st_mtime_ns) // 1_000_000_000 + 1) * 1_000_000_000
                    with self.files.paths.guard(path, include_final=True):
                        os.utime(path, ns=(final.st_atime_ns, next_second))
                    final = self._file_stat(path)
                return previous is None, final
            finally:
                temporary.unlink(missing_ok=True)

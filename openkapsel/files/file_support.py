"""Shared filesystem operations used by HTTP handlers and client RPC."""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import hmac
import os
import secrets
import stat
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any

from openkapsel.errors import ApiError
from openkapsel.files.safe_paths import ParentHandle, SafePathError
from openkapsel.workspace.workspace_layout import INTERNAL_DIRECTORY
from openkapsel.mapping.mapping_queries import MappingQueryMixin


class FileOperationSupportMixin(MappingQueryMixin):
    def _workspace_files(self):
        manager = getattr(self.server, "mappings", None)
        if manager is None or not hasattr(manager, "store"):
            return None  # ClientFileAPI and standalone local handlers.
        from openkapsel.mapping.mapping_io import WorkspaceFiles
        roots = (self.token_scope_root, *(Path(p.path) for p in getattr(self.token_record, "allowed_paths", ())))
        return WorkspaceFiles(manager, roots)

    def _open_binary(self, path):
        files = self._workspace_files()
        try:
            if files is not None:
                return files.open(path)
            return os.fdopen(self._safe_open_descriptor(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb")
        except OSError as exc:
            self._raise_file_io_error(exc)

    @staticmethod
    def _stream_stat(handle):
        from openkapsel.mapping.mapping_io import stream_stat
        return stream_stat(handle)

    @staticmethod
    def _raise_file_io_error(exc):
        if isinstance(exc, SafePathError):
            FileOperationSupportMixin._raise_safe_path_error(exc)
        status, code = {
            errno.ENOENT: (404, "path_not_found"), errno.ENOTDIR: (400, "not_a_directory"),
            errno.EINVAL: (400, "not_a_file"),
            errno.EHOSTDOWN: (503, "mapping_offline"), errno.ESTALE: (409, "mapping_session_changed"),
            errno.EACCES: (403, "path_access_denied"), errno.EPERM: (403, "path_access_denied"),
            errno.EROFS: (403, "mapping_read_only"), errno.EEXIST: (409, "path_exists"),
            errno.ENOSYS: (409, "mapping_client_upgrade_required"), errno.E2BIG: (413, "mapping_request_too_large"),
        }.get(exc.errno, (503, "file_operation_failed"))
        raise ApiError(status, code, str(exc)) from None

    def _guard_native_mapping_access(self, path):
        manager = getattr(self.server, "mappings", None)
        if manager is not None and manager.at_path(path) is not None:
            raise ApiError(409, "mapping_native_access_forbidden", "this file operation requires an RPC path, not native mapping access")

    def _path_etag(self, path, details):
        return self._stat_etag(details)

    def _sha256_snapshot(self, path, expected):
        with self._open_binary(path) as handle:
            before = self._stream_stat(handle)
            if self._stat_etag(before) != self._stat_etag(expected):
                raise ApiError(409, "path_changed", "file changed while reading metadata; retry the request")
            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            if self._stat_etag(self._stream_stat(handle)) != self._stat_etag(before):
                raise ApiError(409, "path_changed", "file changed while calculating its hash; retry the request")
            return digest.hexdigest()

    def _file_stat(self, path):
        files = self._workspace_files()
        if files is not None:
            try:
                return files.stat(path)
            except OSError as exc:
                self._raise_file_io_error(exc)
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            return os.fstat(descriptor)
        finally:
            os.close(descriptor)

    def _directory_entries(self, path):
        files = self._workspace_files()
        if files is not None:
            try:
                return files.entries(path)
            except OSError as exc:
                self._raise_file_io_error(exc)
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY)
        try:
            with os.scandir(descriptor) as iterator:
                entries = []
                for entry in iterator:
                    try:
                        entries.append((entry.name, entry.stat(follow_symlinks=False)))
                    except OSError:
                        continue
                return entries
        finally:
            os.close(descriptor)

    def _safe_open_descriptor(
        self,
        path: Path,
        flags: int = os.O_RDONLY,
        mode: int = 0o600,
    ) -> int:
        self._guard_native_mapping_access(path)
        try:
            return self._safe_path_access().open(path, flags, mode)
        except SafePathError as exc:
            self._raise_safe_path_error(exc)

    def _safe_parent(self, path: Path, *, create_parents: bool = False) -> ParentHandle:
        self._guard_native_mapping_access(path)
        try:
            return self._safe_path_access().parent(path, create_parents=create_parents)
        except SafePathError as exc:
            self._raise_safe_path_error(exc)

    @staticmethod
    def _raise_safe_path_error(exc: SafePathError) -> None:
        if exc.errno == errno.ENOENT:
            raise ApiError(HTTPStatus.NOT_FOUND, "path_not_found", "path does not exist") from None
        if exc.errno in {errno.EACCES, errno.EPERM}:
            raise ApiError(HTTPStatus.FORBIDDEN, "path_access_denied", str(exc)) from None
        raise ApiError(
            HTTPStatus.CONFLICT,
            "path_changed",
            "path changed while the operation was being authorized; retry the request",
        ) from None

    @staticmethod
    def _is_internal_transfer_name(name: str) -> bool:
        return (
            name.startswith(".")
            and (
                ".openkapsel-upload-upload_" in name
                or ".openkapsel-put-" in name
                or name.startswith(".openkapsel-share-")
                or name.startswith(".openkapsel-transfer-")
            )
        )

    def _atomic_write(
        self,
        path: Path,
        content: str,
        *,
        expected_etag: str | None = None,
        create_parents: bool = False,
        encoding: str = "utf-8",
    ) -> tuple[bool, os.stat_result]:
        from openkapsel.files.text_encoding import encode_text, text_encoding
        data = encode_text(content, text_encoding(encoding))
        manager = getattr(self.server, "mappings", None)
        row = manager.at_path(path) if manager is not None else None
        if row is not None:
            from types import SimpleNamespace
            from openkapsel.client_runtime.client_file_api import FILE_API_LIMITS
            from openkapsel.mapping.mapping_transport import encode
            capability = manager.rpc_capability(row["id"], "file", operation="fs_write", min_version=3, max_version=4)
            if not capability.available:
                self._raise_mapping_rpc_unavailable(capability)
            arguments = {"body": {"path": path.relative_to(manager.mount_path(row)).as_posix(),
                         "content": content, "encoding": encoding, "expected_etag": expected_etag,
                         "create_parents": create_parents},
                         "limits": {n: getattr(self.server.config, n) for n in FILE_API_LIMITS}}
            try:
                encode({"id": "0" * 24, "op": "api_fs_write", "args": arguments})
            except OSError as exc:
                self._raise_file_io_error(exc)
            result = self._mapping_rpc(row, "api_fs_write", arguments)
            if "error" in result:
                error = result["error"]
                raise ApiError(result["status"], error["code"], error["message"], error.get("details"))
            payload = result["body"]
            return payload["created"], SimpleNamespace(_mapping_etag=payload["etag"])
        try:
            parent = self._safe_parent(path, create_parents=create_parents)
        except ApiError as exc:
            if exc.code == "path_not_found":
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "parent_not_found",
                    "parent directory does not exist",
                ) from None
            raise
        with parent:
            previous_stat = parent.lstat()
            if previous_stat is not None and not stat.S_ISREG(previous_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            mode = previous_stat.st_mode & 0o777 if previous_stat is not None else 0o600
            temp_name = f".{path.name}.openkapsel-put-{secrets.token_hex(12)}"
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temp_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent.fd,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = None
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.fchmod(handle.fileno(), mode)
                current_stat = parent.lstat()
                current_etag = self._path_etag(path, current_stat) if current_stat is not None else None
                self._check_expected_etag(expected_etag, current_etag)
                os.replace(
                    temp_name,
                    parent.name,
                    src_dir_fd=parent.fd,
                    dst_dir_fd=parent.fd,
                )
                temp_name = ""
                final_descriptor = parent.open(os.O_RDONLY)
                try:
                    final_stat = os.fstat(final_descriptor)
                finally:
                    os.close(final_descriptor)
            # Some build caches (notably timestamp-based Python .pyc files)
            # compare mtimes at whole-second precision plus file size. A
            # same-length edit followed immediately by a build could otherwise
            # reuse stale output. Ensure an overwritten file advances at that
            # precision when the atomic replacement happened in the same second.
                if previous_stat is not None:
                    if previous_stat.st_mtime_ns // 1_000_000_000 == final_stat.st_mtime_ns // 1_000_000_000:
                        final_descriptor = parent.open(os.O_RDONLY)
                        try:
                            next_second_ns = (
                                max(previous_stat.st_mtime_ns, final_stat.st_mtime_ns) // 1_000_000_000 + 1
                            ) * 1_000_000_000
                            os.utime(
                                final_descriptor,
                                ns=(final_stat.st_atime_ns, next_second_ns),
                            )
                            final_stat = os.fstat(final_descriptor)
                        finally:
                            os.close(final_descriptor)
                return previous_stat is None, final_stat
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if temp_name:
                    try:
                        os.unlink(temp_name, dir_fd=parent.fd)
                    except FileNotFoundError:
                        pass

    @staticmethod
    def _required_string(body: dict[str, Any], key: str, allow_empty: bool = False) -> str:
        value = body.get(key)
        if not isinstance(value, str) or (not allow_empty and not value):
            qualifier = "a string" if allow_empty else "a non-empty string"
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be {qualifier}")
        return value

    @staticmethod
    def _optional_bool(body: dict[str, Any], key: str, default: bool) -> bool:
        value = body.get(key, default)
        if not isinstance(value, bool):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be boolean")
        return value

    @staticmethod
    def _optional_expected_etag(body: dict[str, Any]) -> str | None:
        value = body.get("expected_etag")
        if value is None:
            return None
        if not isinstance(value, str) or not value or any(
            character in value for character in "\r\n,"
        ):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "expected_etag must be one non-empty ETag string, *, or null",
            )
        return value

    @staticmethod
    def _query_one(query: dict[str, list[str]], key: str, default: str) -> str:
        values = query.get(key)
        return values[0] if values else default

    def _required_query(self, query: dict[str, list[str]], key: str) -> str:
        value = self._query_one(query, key, "")
        if not value:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"query parameter {key} is required")
        return value

    def _query_int(
        self,
        query: dict[str, list[str]],
        key: str,
        default: int,
        minimum: int,
        maximum: int | None = None,
    ) -> int:
        raw = self._query_one(query, key, str(default))
        try:
            value = int(raw)
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be an integer")
        if value < minimum or (maximum is not None and value > maximum):
            bounds = f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be {bounds}")
        return value

    def _query_float(
        self,
        query: dict[str, list[str]],
        key: str,
        default: float,
        minimum: float,
        maximum: float,
    ) -> float:
        raw = self._query_one(query, key, str(default))
        try:
            value = float(raw)
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be a number") from None
        if not minimum <= value <= maximum:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                f"{key} must be between {minimum} and {maximum}",
            )
        return value

    def _query_bool(self, query: dict[str, list[str]], key: str, default: bool) -> bool:
        raw = self._query_one(query, key, "true" if default else "false").strip().lower()
        if raw in {"1", "true", "yes"}:
            return True
        if raw in {"0", "false", "no"}:
            return False
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be boolean")

    @staticmethod
    def _query_fields(
        query: dict[str, list[str]],
        key: str,
        defaults: set[str],
        allowed: set[str],
    ) -> set[str]:
        values = query.get(key)
        if not values:
            return set(defaults)
        requested = {
            field.strip()
            for value in values
            for field in value.split(",")
            if field.strip()
        }
        unknown = sorted(requested - allowed)
        if unknown:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_fields",
                f"unknown field(s): {', '.join(unknown)}",
                {"allowed": sorted(allowed)},
            )
        return requested

    @staticmethod
    def _glob_patterns(values):
        if len(values) > 64 or any(not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value for value in values):
            raise ApiError(400, "invalid_request", "glob filters accept at most 64 non-empty patterns of up to 512 characters")
        return values

    @staticmethod
    def _matches_glob(relative, patterns):
        # Slash-free patterns match basenames; other patterns match root-relative
        # POSIX paths. fnmatch '*' spans slashes; no platform case folding.
        return any(fnmatch.fnmatchcase(relative.rsplit("/", 1)[-1] if "/" not in pattern else relative, pattern)
                   for pattern in patterns)

    def _search_files(self, root: Path, depth: int, *, includes=(), excludes=()):
        root_stat = self._file_stat(root)
        if stat.S_ISREG(root_stat.st_mode):
            if not self._matches_glob(root.name, excludes) and (not includes or self._matches_glob(root.name, includes)):
                yield root
            return
        if not stat.S_ISDIR(root_stat.st_mode):
            return
        stack = [(root, 0)]
        while stack:
            directory, level = stack.pop()
            if self._mapping_root(directory) is not None:
                yield directory  # The caller sends one query for this subtree.
                continue
            try:
                entries = self._directory_entries(directory)
                entries.sort(key=lambda item: item[0].casefold(), reverse=True)
            except (OSError, SafePathError, ApiError):
                continue
            directories = []
            for name, entry_stat in entries:
                entry = directory / name
                if self._is_hidden_internal_path(directory, entry) or stat.S_ISLNK(entry_stat.st_mode):
                    continue
                relative = entry.relative_to(root).as_posix()
                prefix = getattr(self, "search_prefix", "")
                if prefix:
                    relative = prefix + "/" + relative
                if self._matches_glob(relative, excludes):
                    continue
                if stat.S_ISREG(entry_stat.st_mode):
                    if not includes or self._matches_glob(relative, includes):
                        yield entry
                elif stat.S_ISDIR(entry_stat.st_mode) and level < depth:
                    directories.append((entry, level + 1))
            stack.extend(directories)

    def _tree_node(
        self,
        root: Path,
        path: Path,
        max_depth: int,
        level: int,
        state: dict[str, Any],
        known_stat: os.stat_result | None = None,
    ) -> dict[str, Any]:
        if state["count"] >= self.server.config.max_tree_nodes:
            state["truncated"] = True
            return {"name": path.name or str(path), "path": str(path), "truncated": True}
        mapping = self._mapping_root(path)
        if mapping is not None:
            return self._mapping_tree(mapping, path, max_depth - level, state)
        state["count"] += 1
        try:
            file_stat = known_stat if known_stat is not None else self._file_stat(path)
        except ApiError as exc:
            manager = getattr(self.server, "mappings", None)
            row = manager.at_path(path) if manager is not None else None
            if row is not None and path == manager.mount_path(row):
                return {"name": path.name, "path": str(path), "type": "directory",
                        "is_mapping": True, "mapping_id": row["id"], "unavailable": True,
                        "error": {"code": exc.code, "message": exc.message}}
            # The request root itself must still be accessible, but a child
            # which disappeared or became inaccessible must not abort siblings.
            if level == 0:
                raise
            return {"name": path.name, "path": str(path), "type": "unknown",
                    "unavailable": True,
                    "error": {"code": exc.code, "message": exc.message}}
        if stat.S_ISDIR(file_stat.st_mode):
            kind = "directory"
        elif stat.S_ISREG(file_stat.st_mode):
            kind = "file"
        else:
            kind = "other"
        node: dict[str, Any] = {
            "name": path.name or str(path),
            "path": str(path),
            "type": kind,
            "size": file_stat.st_size,
            "modified_at": datetime.fromtimestamp(file_stat.st_mtime, timezone.utc).isoformat(),
        }
        if kind == "directory" and level < max_depth:
            try:
                entries = self._directory_entries(path)
            except ApiError as exc:
                # A root-level filesystem can legitimately contain directories
                # the service account may stat but not enter (ext4 lost+found is
                # the common case). Preserve the node and continue siblings.
                node["unavailable"] = True
                node["error"] = {"code": exc.code, "message": exc.message}
                return node
            children = []
            entries.sort(
                key=lambda item: (
                    not stat.S_ISDIR(item[1].st_mode),
                    item[0].casefold(),
                )
            )
            for name, entry_stat in entries:
                entry = path / name
                if self._is_hidden_internal_path(path, entry):
                    continue
                if state["count"] >= self.server.config.max_tree_nodes:
                    state["truncated"] = True
                    break
                if stat.S_ISLNK(entry_stat.st_mode):
                    state["count"] += 1
                    children.append(
                        {
                            "name": name,
                            "path": str(entry),
                            "type": "symlink",
                            "size": entry_stat.st_size,
                            "modified_at": datetime.fromtimestamp(
                                entry_stat.st_mtime,
                                timezone.utc,
                            ).isoformat(),
                        }
                    )
                    continue
                try:
                    children.append(
                        self._tree_node(
                            root, entry, max_depth, level + 1, state,
                            known_stat=entry_stat,
                        )
                    )
                except ApiError as exc:
                    if exc.code not in {"path_not_found", "path_changed"}:
                        raise
            node["children"] = children
        return node

    def _is_hidden_internal_path(self, parent: Path, entry: Path) -> bool:
        try:
            parent.relative_to(self.token_scope_root)
        except ValueError:
            workspace_internal = False
        else:
            workspace_internal = entry.name == INTERNAL_DIRECTORY
        return (
            workspace_internal
            or self._is_internal_transfer_name(entry.name)
        )

    @staticmethod
    def _stat_etag(stat: os.stat_result) -> str:
        source = f"{stat.st_dev}:{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}".encode("ascii")
        return f'"{hashlib.sha256(source).hexdigest()[:32]}"'

    @staticmethod
    def _valid_sha256(value: str) -> bool:
        return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)

    def _check_expected_etag(
        self,
        supplied: str | None,
        current_etag: str | None,
    ) -> None:
        if supplied is None:
            return
        if not self._expected_etag_matches(supplied, current_etag):
            raise ApiError(
                HTTPStatus.PRECONDITION_FAILED,
                "etag_mismatch",
                "expected_etag does not match the current file",
                {"actual_etag": current_etag},
            )

    @staticmethod
    def _expected_etag_matches(supplied: str, current_etag: str | None) -> bool:
        if supplied == "*":
            return current_etag is not None
        return current_etag is not None and hmac.compare_digest(supplied, current_etag)

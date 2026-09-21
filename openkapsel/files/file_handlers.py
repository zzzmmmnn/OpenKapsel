"""HTTP handlers for files, recycle-bin operations, and resumable uploads."""

from __future__ import annotations

import errno
import hashlib
import io
import mimetypes
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import quote

from openkapsel.errors import ApiError
from openkapsel.files.text_encoding import text_encoding, encode_text, decode_error
from openkapsel.files.file_support import FileOperationSupportMixin
from openkapsel.files.recycle import RecycleError
from openkapsel.files.safe_paths import SafePathError
from openkapsel.files.uploads import UploadError, UploadRecord


class FileHandlersMixin(FileOperationSupportMixin):
    """File-domain methods mixed into the main request handler."""
    def _handle_fs_list(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        if self._try_mapping_file_api("fs_list", query=query):
            return
        path = self._resolve_path(self._query_one(query, "path", ""))
        details = self._file_stat(path)
        if not stat.S_ISDIR(details.st_mode):
            raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_directory", "path is not a directory")
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 1000, minimum=1, maximum=5000)
        entries = []
        for name, item_stat in self._directory_entries(path):
            if self._is_hidden_internal_path(path, path / name):
                continue
            if stat.S_ISLNK(item_stat.st_mode):
                kind = "symlink"
            elif stat.S_ISDIR(item_stat.st_mode):
                kind = "directory"
            elif stat.S_ISREG(item_stat.st_mode):
                kind = "file"
            else:
                kind = "other"
            entries.append((name, kind, item_stat))
        entries.sort(key=lambda item: (item[1] != "directory", item[0].casefold()))
        selected = entries[offset : offset + limit]
        result = []
        for name, kind, item_stat in selected:
            mapping = self.server.mappings.at_path(path / name)
            result.append(
                {
                    "name": name,
                    "path": str(path / name),
                    "type": kind,
                    "size": item_stat.st_size,
                    "modified_at": datetime.fromtimestamp(item_stat.st_mtime, timezone.utc).isoformat(),
                    **({"is_mapping": True, "mapping_id": mapping["id"]} if mapping and self.server.mappings.mount_path(mapping) == path / name else {}),
                }
            )
        self._send_json(
            HTTPStatus.OK,
            {
                "path": str(path),
                "entries": result,
                "offset": offset,
                "limit": limit,
                "total": len(entries),
                "truncated": offset + len(selected) < len(entries),
            },
        )

    def _handle_fs_stat(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        if self._try_mapping_file_api("fs_stat", query=query):
            return
        path = self._resolve_path(self._required_query(query, "path"))
        file_stat = self._file_stat(path)
        if stat.S_ISDIR(file_stat.st_mode):
            kind = "directory"
        elif stat.S_ISREG(file_stat.st_mode):
            kind = "file"
        else:
            kind = "other"
        allowed = {"type", "size", "created_at", "modified_at", "changed_at", "etag", "content_type", "sha256"}
        requested = self._query_fields(
            query,
            "fields",
            {"type", "size", "created_at", "modified_at", "etag", "content_type"},
            allowed,
        )
        result: dict[str, Any] = {"path": str(path), "fields": sorted(requested)}
        if "type" in requested:
            result["type"] = kind
        if "size" in requested:
            result["size"] = file_stat.st_size
        if "created_at" in requested:
            birthtime = getattr(file_stat, "st_birthtime", None)
            result["created_at"] = (
                datetime.fromtimestamp(birthtime, timezone.utc).isoformat()
                if birthtime is not None
                else None
            )
            result["created_at_available"] = birthtime is not None
        if "modified_at" in requested:
            result["modified_at"] = datetime.fromtimestamp(file_stat.st_mtime, timezone.utc).isoformat()
        if "changed_at" in requested:
            result["changed_at"] = datetime.fromtimestamp(file_stat.st_ctime, timezone.utc).isoformat()
        if "etag" in requested:
            result["etag"] = self._path_etag(path, file_stat)
        if "content_type" in requested:
            content_type = mimetypes.guess_type(path.name)[0] if kind == "file" else None
            result["content_type"] = content_type or ("application/octet-stream" if kind == "file" else None)
        if "sha256" in requested:
            if kind == "file":
                result["sha256"] = self._sha256_snapshot(path, file_stat)
            else:
                result["sha256"] = None
        self._send_json(HTTPStatus.OK, result)

    def _handle_fs_manifest(self) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        body = self._read_json()
        if self._try_mapping_file_api("fs_manifest", body=body):
            return
        if self._optional_bool(body, "recursive", False):
            if "items" in body:
                raise ApiError(400, "invalid_request", "recursive mode does not accept items")
            root = self._resolve_path(self._required_string({"path": body.get("path", ".")}, "path"))
            depth = self._body_read_limit(body, "depth", 8, self.server.config.max_recursion_depth, minimum=0)
            include_sha256 = self._optional_bool(body, "include_sha256", False)
            state = {"count": 0, "truncated": False, "manifest": True,
                     "include_sha256": include_sha256}
            tree = self._tree_node(root, root, depth, 0, state)
            results = []
            stack = [tree]
            while stack:
                node = dict(stack.pop())
                stack.extend(reversed(node.pop("children", [])))
                if include_sha256 and "sha256" not in node:
                    path = Path(node["path"])
                    node["sha256"] = None
                    if node.get("type") == "file":
                        details = self._file_stat(path)
                        if details.st_size != node["size"] or datetime.fromtimestamp(details.st_mtime, timezone.utc).isoformat() != node["modified_at"]:
                            raise ApiError(409, "path_changed", "file changed during manifest traversal")
                        node["sha256"] = self._sha256_snapshot(path, details)
                results.append(node)
            self._send_json(200, {"path": str(root), "recursive": True, "depth": depth,
                                  "items": results, "total": len(results),
                                  "truncated": state["truncated"], "include_sha256": include_sha256})
            return
        items = body.get("items")
        if not isinstance(items, list) or not items:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "items must be a non-empty array",
            )
        if len(items) > self.server.config.max_batch_file_operations:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "batch_too_large",
                "items exceeds the configured batch operation limit",
                {
                    "maximum": self.server.config.max_batch_file_operations,
                    "actual": len(items),
                },
            )
        include_sha256 = self._optional_bool(body, "include_sha256", False)
        validated: list[tuple[int, str, Path, int | None, str | None]] = []
        seen: set[Path] = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    f"items[{index}] must be an object",
                )
            requested_path = self._required_string(item, "path")
            expected_size = item.get("size")
            if expected_size is not None and (
                isinstance(expected_size, bool)
                or not isinstance(expected_size, int)
                or expected_size < 0
            ):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    f"items[{index}].size must be a non-negative integer or null",
                )
            expected_sha256 = item.get("sha256")
            if expected_sha256 is not None and (
                not isinstance(expected_sha256, str)
                or not self._valid_sha256(expected_sha256)
            ):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    f"items[{index}].sha256 must be 64 hexadecimal characters or null",
                )
            path = self._resolve_path(requested_path)
            if path in seen:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "duplicate_path",
                    f"items[{index}] resolves to a duplicate path",
                )
            seen.add(path)
            validated.append(
                (
                    index,
                    requested_path,
                    path,
                    expected_size,
                    expected_sha256.lower() if expected_sha256 else None,
                )
            )

        results: list[dict[str, Any]] = []
        counts = {"missing": 0, "same": 0, "conflict": 0, "exists": 0}
        for index, requested_path, path, expected_size, expected_sha256 in validated:
            try:
                file_stat = self._file_stat(path)
            except ApiError as exc:
                if exc.status == HTTPStatus.NOT_FOUND and exc.code == "path_not_found":
                    item_result = {
                        "index": index,
                        "path": requested_path,
                        "status": "missing",
                    }
                    counts["missing"] += 1
                    results.append(item_result)
                    continue
                raise
            if stat.S_ISDIR(file_stat.st_mode):
                kind = "directory"
            elif stat.S_ISREG(file_stat.st_mode):
                kind = "file"
            else:
                kind = "other"
            actual_sha256: str | None = None
            if kind == "file" and (include_sha256 or expected_sha256 is not None):
                actual_sha256 = self._sha256_snapshot(path, file_stat)
            has_expectation = expected_size is not None or expected_sha256 is not None
            matches = kind == "file"
            if expected_size is not None:
                matches = matches and file_stat.st_size == expected_size
            if expected_sha256 is not None:
                matches = matches and actual_sha256 == expected_sha256
            item_status = (
                "same" if has_expectation and matches
                else "conflict" if has_expectation
                else "exists"
            )
            item_result = {
                "index": index,
                "path": requested_path,
                "status": item_status,
                "type": kind,
                "size": file_stat.st_size,
                "modified_at": datetime.fromtimestamp(
                    file_stat.st_mtime, timezone.utc
                ).isoformat(),
                "etag": self._path_etag(path, file_stat),
            }
            if include_sha256 or expected_sha256 is not None:
                item_result["sha256"] = actual_sha256
            counts[item_status] += 1
            results.append(item_result)
        self._send_json(
            HTTPStatus.OK,
            {
                "items": results,
                "counts": counts,
                "total": len(results),
                "include_sha256": include_sha256,
            },
        )

    def _handle_fs_search(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        if self._try_mapping_file_api("fs_search", query=query):
            return
        needle = self._required_query(query, "query")
        root = self._resolve_path(self._query_one(query, "path", "."))
        depth = self._query_int(
            query,
            "depth",
            8,
            minimum=0,
            maximum=self.server.config.max_recursion_depth,
        )
        max_results = self._query_int(
            query,
            "max_results",
            min(100, self.server.config.max_search_results),
            minimum=1,
            maximum=self.server.config.max_search_results,
        )
        regex = self._query_bool(query, "regex", False)
        case_sensitive = self._query_bool(query, "case_sensitive", True)
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(needle if regex else re.escape(needle), flags)
        except re.error as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_regex", f"invalid regular expression: {exc}") from None
        matches: list[dict[str, Any]] = []
        files_searched = 0
        skipped_binary = 0
        skipped_large = 0
        truncated = False
        unavailable_mappings = []
        includes = self._glob_patterns(query.get("include", []))
        excludes = self._glob_patterns(query.get("exclude", []))
        for file_path in self._search_files(root, depth, includes=includes, excludes=excludes):
            mapping = self._mapping_root(file_path)
            if mapping is not None:
                try:
                    result = self._mapping_search(mapping, file_path, root, query,
                        depth - len(file_path.relative_to(root).parts), max_results - len(matches),
                        includes, excludes)
                except ApiError as exc:
                    unavailable_mappings.append(self._unavailable_mapping(mapping, file_path, exc))
                    continue
                matches.extend(result["matches"])
                files_searched += result["files_searched"]
                skipped_binary += result["skipped_binary"]
                skipped_large += result["skipped_large"]
                truncated |= bool(result.get("truncated"))
                if len(matches) >= max_results:
                    truncated = True
                    break
                continue
            try:
                with self._open_binary(file_path) as handle:
                    file_stat = self._stream_stat(handle)
                    if not stat.S_ISREG(file_stat.st_mode):
                        continue
                    if file_stat.st_size > self.server.config.max_search_file_bytes:
                        skipped_large += 1
                        continue
                    raw = handle.read()
                if b"\x00" in raw:
                    skipped_binary += 1
                    continue
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                skipped_binary += 1
                continue
            except (OSError, SafePathError):
                continue
            files_searched += 1
            for line_number, line in enumerate(text.splitlines(), start=1):
                for found in pattern.finditer(line):
                    matches.append(
                        {
                            "path": str(file_path),
                            "line": line_number,
                            "column": found.start() + 1,
                            "match": found.group(0),
                            "text": line[:2000],
                        }
                    )
                    if len(matches) >= max_results:
                        truncated = True
                        break
                if truncated:
                    break
            if truncated:
                break
        self._send_json(
            HTTPStatus.OK,
            {
                "path": str(root),
                "query": needle,
                "regex": regex,
                "case_sensitive": case_sensitive,
                "depth": depth,
                "include": includes,
                "exclude": excludes,
                "matches": matches,
                "match_count": len(matches),
                "files_searched": files_searched,
                "skipped_binary": skipped_binary,
                "skipped_large": skipped_large,
                "truncated": truncated or bool(unavailable_mappings),
                **({"unavailable_mappings": unavailable_mappings} if unavailable_mappings else {}),
            },
        )

    def _handle_fs_tree(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        if self._try_mapping_file_api("fs_tree", query=query):
            return
        root = self._resolve_path(self._query_one(query, "path", "."))
        depth = self._query_int(
            query,
            "depth",
            2,
            minimum=0,
            maximum=self.server.config.max_recursion_depth,
        )
        state = {"count": 0, "truncated": False}
        tree = self._tree_node(root, root, depth, 0, state)
        self._send_json(
            HTTPStatus.OK,
            {
                "path": str(root),
                "depth": depth,
                "node_count": state["count"],
                "truncated": state["truncated"],
                "tree": tree,
            },
        )

    def _handle_fs_content(self, query: dict[str, list[str]], *, head_only: bool) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        path = self._resolve_path(self._required_query(query, "path"))
        handle = self._open_binary(path)
        with handle:
            file_stat = self._stream_stat(handle)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            size = file_stat.st_size
            etag = self._path_etag(path, file_stat)
            if self.headers.get("If-None-Match") == etag:
                self._send_empty(HTTPStatus.NOT_MODIFIED, {"ETag": etag})
                return
            range_header = self.headers.get("Range")
            if range_header:
                start, end = self._parse_byte_range(range_header, size)
                status = HTTPStatus.PARTIAL_CONTENT
            else:
                start, end = 0, size - 1
                status = HTTPStatus.OK
            length = max(0, end - start + 1)
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            context_id = self._finalize_context_operation(
                status,
                {"path": str(path), "bytes_read": length, "etag": etag},
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.send_header(
                "Last-Modified",
                datetime.fromtimestamp(file_stat.st_mtime, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(path.name, safe='')}")
            if context_id is not None:
                self.send_header("OpenKapsel-Context-ID", str(context_id))
            if status == HTTPStatus.PARTIAL_CONTENT:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if head_only or length == 0:
                return
            handle.seek(start)
            remaining = length
            while remaining:
                chunk = handle.read(min(remaining, self.server.config.transfer_buffer_bytes))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _handle_fs_content_put(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        if "overwrite" in query:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "overwrite_not_supported",
                "uploads never overwrite; recycle the existing file before uploading",
            )
        path = self._resolve_path(self._required_query(query, "path"), write=True)
        create_parents = self._query_bool(query, "create_parents", False)
        length = self._content_length(
            min(self.server.config.max_direct_upload_bytes, self.server.config.max_file_bytes)
        )
        expected_sha256 = self.headers.get("X-Content-SHA256")
        if expected_sha256 is not None and not self._valid_sha256(expected_sha256):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_sha256", "X-Content-SHA256 must be 64 hexadecimal characters")
        if self.server.mappings.at_path(path) is not None:
            from openkapsel.mapping.mapping_uploads import put_stream
            put_stream(self, path, length, expected_sha256, create_parents=create_parents)
            return
        try:
            parent = self._safe_parent(path, create_parents=create_parents)
        except ApiError as exc:
            if exc.code == "path_not_found":
                raise ApiError(HTTPStatus.BAD_REQUEST, "parent_not_found", "parent directory does not exist") from None
            raise
        digest = hashlib.sha256()
        with parent:
            previous_stat = parent.lstat()
            if previous_stat is not None and not stat.S_ISREG(previous_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            previous_etag = self._path_etag(path, previous_stat) if previous_stat is not None else None
            if previous_stat is not None:
                raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination already exists")
            self._check_if_match(previous_etag)
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
                    remaining = length
                    while remaining:
                        chunk = self.rfile.read(min(remaining, self.server.config.transfer_buffer_bytes))
                        if not chunk:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "incomplete_body", "request body ended before Content-Length")
                        handle.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.fchmod(handle.fileno(), 0o600)
                actual_sha256 = digest.hexdigest()
                if expected_sha256 is not None and not secrets.compare_digest(expected_sha256.lower(), actual_sha256):
                    raise ApiError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "checksum_mismatch",
                        "uploaded content does not match X-Content-SHA256",
                        {"expected": expected_sha256.lower(), "actual": actual_sha256},
                    )
                current_stat = parent.lstat()
                current_etag = self._path_etag(path, current_stat) if current_stat is not None else None
                if current_stat is not None:
                    raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination already exists")
                self._check_if_match(current_etag)
                self._publish_new_upload(parent, temp_name)
                temp_name = ""
                final_descriptor = parent.open(os.O_RDONLY)
                try:
                    final_stat = os.fstat(final_descriptor)
                finally:
                    os.close(final_descriptor)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if temp_name:
                    try:
                        os.unlink(temp_name, dir_fd=parent.fd)
                    except FileNotFoundError:
                        pass
        self._send_json(
            HTTPStatus.CREATED,
            {
                "path": str(path),
                "created": True,
                "bytes_written": length,
                "sha256": digest.hexdigest(),
                "etag": self._path_etag(path, final_stat),
            },
        )

    @staticmethod
    def _body_read_limit(body, key, default, maximum, *, minimum=1):
        value = body.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ApiError(400, "invalid_request", f"{key} must be an integer between {minimum} and {maximum}")
        return value

    def _handle_fs_read_many(self) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        body = self._read_json()
        encoding = text_encoding(body.get("encoding", "utf-8"))
        if self._try_mapping_file_api("fs_read_many", body=body):
            return
        paths = body.get("paths")
        if not isinstance(paths, list) or not paths or len(paths) > self.server.config.max_batch_file_operations:
            raise ApiError(400, "invalid_request", "paths must be a non-empty array within the batch operation limit")
        if any(not isinstance(path, str) or not path for path in paths):
            raise ApiError(400, "invalid_request", "paths must contain non-empty strings")
        limit = self._body_read_limit(body, "limit", min(65536, self.server.config.max_read_chars), self.server.config.max_read_chars)
        remaining = self._body_read_limit(body, "max_total_chars", min(262144, self.server.config.max_read_chars), self.server.config.max_read_chars)
        items = []
        total = 0
        for index, requested in enumerate(paths):
            item = {"index": index, "path": requested}
            try:
                if remaining == 0:
                    raise ApiError(413, "read_budget_exhausted", "total character budget exhausted; request remaining paths separately")
                path = self._resolve_path(requested)
                with self._open_binary(path) as binary, io.TextIOWrapper(binary, encoding=encoding, newline="") as handle:
                    details = self._stream_stat(handle)
                    if not stat.S_ISREG(details.st_mode):
                        raise ApiError(400, "not_a_file", "path is not a regular file")
                    count = min(limit, remaining)
                    window = handle.read(count + 1)
                    after = self._stream_stat(handle)
                    if self._stat_etag(details) != self._stat_etag(after):
                        raise ApiError(409, "path_changed", "file changed during read")
                content = window[:count]
                truncated = len(window) > count
                item.update(status=200, content=content, length=len(content), encoding=encoding,
                            truncated=truncated, next_offset=len(content) if truncated else None,
                            etag=self._path_etag(path, details))
                remaining -= len(content)
                total += len(content)
            except UnicodeDecodeError:
                error = decode_error(encoding)
                item.update(status=415, error={"code": error.code, "message": error.message})
            except ApiError as exc:
                item.update(status=int(exc.status), error={"code": exc.code, "message": exc.message})
            except OSError as exc:
                status, code = {errno.ENOENT: (404, "path_not_found"), errno.EPERM: (403, "path_access_denied"),
                                errno.EACCES: (403, "path_access_denied"), errno.EINVAL: (400, "invalid_request")}.get(
                                    exc.errno, (409, "file_operation_failed"))
                item.update(status=status, error={"code": code, "message": "file could not be read"})
            items.append(item)
        self._send_json(207 if any(item["status"] != 200 for item in items) else 200,
                        {"items": items, "total": len(items), "total_chars": total})

    def _handle_fs_read(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        if self._try_mapping_file_api("fs_read", query=query):
            return
        requested = self._required_query(query, "path")
        path = self._resolve_path(requested)
        encoding = text_encoding(self._query_one(query, "encoding", "utf-8"))
        if "byte_offset" in query:
            if encoding != "utf-8":
                raise ApiError(400, "invalid_encoding", "byte_offset requires utf-8; use character offsets or binary download")
            self._handle_fs_read_bytes(path, query)
            return
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(
            query,
            "limit",
            self.server.config.default_read_chars,
            minimum=1,
            maximum=self.server.config.max_read_chars,
        )
        try:
            with self._open_binary(path) as binary, io.TextIOWrapper(binary, encoding=encoding, newline="") as handle:
                if not stat.S_ISREG(self._stream_stat(handle).st_mode):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
                remaining = offset
                while remaining:
                    skipped = handle.read(min(remaining, 64 * 1024))
                    if not skipped:
                        break
                    remaining -= len(skipped)
                # Read one extra character to determine truncation without loading
                # the entire file into memory.
                window = handle.read(limit + 1)
        except UnicodeDecodeError:
            raise decode_error(encoding) from None
        content = window[:limit]
        next_offset = offset + len(content)
        truncated = len(window) > limit
        self._send_json(
            HTTPStatus.OK,
            {
                "path": str(path),
                "content": content,
                "offset": offset,
                "length": len(content),
                "truncated": truncated,
                "next_offset": next_offset if truncated else None,
                "encoding": encoding,
            },
        )

    def _handle_fs_read_bytes(self, path: Path, query: dict[str, list[str]]) -> None:
        byte_offset = self._query_int(query, "byte_offset", 0, minimum=0)
        limit = self._query_int(
            query,
            "limit",
            self.server.config.default_read_chars,
            minimum=1,
            maximum=self.server.config.max_read_chars,
        )
        handle = self._open_binary(path)
        with handle:
            file_stat = self._stream_stat(handle)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            size = file_stat.st_size
            if byte_offset > size:
                raise ApiError(
                    HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                    "invalid_offset",
                    "byte_offset is beyond the end of the file",
                    {"size": size},
                )
            handle.seek(byte_offset)
            raw = handle.read(limit + 4)
        if byte_offset < size and raw and raw[0] & 0xC0 == 0x80:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_utf8_boundary",
                "byte_offset points into the middle of a UTF-8 character",
            )
        decoded = None
        complete_raw = b""
        for trim in range(0, min(4, len(raw)) + 1):
            candidate = raw if trim == 0 else raw[:-trim]
            try:
                decoded = candidate.decode("utf-8")
            except UnicodeDecodeError:
                continue
            complete_raw = candidate
            break
        if decoded is None:
            raise ApiError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "not_utf8_text",
                "file is not valid UTF-8 text",
            )
        if raw and not complete_raw:
            raise ApiError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "not_utf8_text",
                "file is not valid UTF-8 text",
            )
        selected: list[str] = []
        consumed = 0
        for character in decoded:
            encoded_length = len(character.encode("utf-8"))
            if selected and consumed + encoded_length > limit:
                break
            selected.append(character)
            consumed += encoded_length
            if consumed >= limit:
                break
        content = "".join(selected)
        next_offset = byte_offset + consumed
        truncated = next_offset < size
        self._send_json(
            HTTPStatus.OK,
            {
                "path": str(path),
                "content": content,
                "byte_offset": byte_offset,
                "bytes_read": consumed,
                "length": len(content),
                "truncated": truncated,
                "next_byte_offset": next_offset if truncated else None,
                "encoding": "utf-8",
            },
        )

    def _handle_fs_write(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        encoding = text_encoding(body.get("encoding", "utf-8"))
        if self._try_mapping_file_api("fs_write", body=body):
            return
        path = self._resolve_path(self._required_string(body, "path"), write=True)
        content = self._required_string(body, "content", allow_empty=True)
        expected_etag = self._optional_expected_etag(body)
        create_parents = body.get("create_parents", False)
        if not isinstance(create_parents, bool):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "create_parents must be boolean")
        created, file_stat = self._atomic_write(
            path,
            content,
            expected_etag=expected_etag,
            create_parents=create_parents,
            encoding=encoding,
        )
        etag = self._path_etag(path, file_stat)
        self._send_json(
            HTTPStatus.CREATED if created else HTTPStatus.OK,
            {
                "path": str(path),
                "created": created,
                "bytes_written": len(encode_text(content, encoding)),
                "etag": etag,
            },
        )

    def _handle_fs_replace(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        encoding = text_encoding(body.get("encoding", "utf-8"))
        if self._try_mapping_file_api("fs_replace", body=body):
            return
        path = self._resolve_path(self._required_string(body, "path"), write=True)
        old = self._required_string(body, "old")
        new = self._required_string(body, "new", allow_empty=True)
        expected_etag = self._optional_expected_etag(body)
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY)
        try:
            with os.fdopen(descriptor, "r", encoding=encoding, newline="") as handle:
                file_stat = self._stream_stat(handle)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
                if file_stat.st_size > self.server.config.max_text_replace_bytes:
                    raise ApiError(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        "file_too_large",
                        "text replacement exceeds the configured file size limit; upload a replacement file instead",
                    )
                text = handle.read()
        except UnicodeDecodeError:
            raise decode_error(encoding) from None
        matches = text.count(old)
        replace_all = body.get("replace_all", False)
        expected = body.get("expected_matches", 1)
        if not isinstance(replace_all, bool):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "replace_all must be boolean")
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "expected_matches must be a positive integer")
        if matches != expected:
            raise ApiError(
                HTTPStatus.CONFLICT,
                "match_count_mismatch",
                f"expected {expected} exact match(es), found {matches}",
                {"expected": expected, "actual": matches},
            )
        count = matches if replace_all else 1
        updated = text.replace(old, new, count)
        _created, updated_stat = self._atomic_write(path, updated, expected_etag=expected_etag, encoding=encoding)
        self._send_json(
            HTTPStatus.OK,
            {
                "path": str(path),
                "replacements": count,
                "etag": self._path_etag(path, updated_stat),
            },
        )

    def _handle_fs_replace_batch(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        if self._try_mapping_file_api("fs_replace_batch", body=body):
            return
        items = body.get("items")
        if not isinstance(items, list) or not items:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "items must be a non-empty array",
            )
        maximum = self.server.config.max_batch_file_operations
        if len(items) > maximum:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "batch_too_large",
                "items exceeds the configured batch operation limit",
                {"maximum": maximum, "actual": len(items)},
            )

        validated: list[dict[str, Any]] = []
        seen: set[Path] = set()
        total_replacement_rules = 0
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    f"items[{index}] must be an object",
                )
            requested_path = self._required_string(item, "path")
            path = self._resolve_path(requested_path, write=True)
            if path in seen:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "duplicate_path",
                    f"items[{index}] resolves to a duplicate path",
                )
            seen.add(path)
            expected_etag = self._optional_expected_etag(item)
            replacements = item.get("replacements")
            if not isinstance(replacements, list) or not replacements:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    f"items[{index}].replacements must be a non-empty array",
                )
            total_replacement_rules += len(replacements)
            if total_replacement_rules > maximum:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "batch_too_large",
                    "replacement rules exceeds the configured batch operation limit",
                    {"maximum": maximum, "actual": total_replacement_rules},
                )
            rules: list[tuple[str, str, int]] = []
            for replacement_index, replacement in enumerate(replacements):
                if not isinstance(replacement, dict):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_request",
                        f"items[{index}].replacements[{replacement_index}] must be an object",
                    )
                old = self._required_string(replacement, "old")
                new = self._required_string(replacement, "new", allow_empty=True)
                expected_matches = replacement.get("expected_matches", 1)
                if (
                    not isinstance(expected_matches, int)
                    or isinstance(expected_matches, bool)
                    or expected_matches < 1
                ):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_request",
                        f"items[{index}].replacements[{replacement_index}].expected_matches "
                        "must be a positive integer",
                    )
                rules.append((old, new, expected_matches))
            validated.append(
                {
                    "index": index,
                    "requested_path": requested_path,
                    "path": path,
                    "expected_etag": expected_etag,
                    "rules": rules,
                    "encoding": text_encoding(item.get("encoding", "utf-8")),
                }
            )

        total_replacements = 0
        for item in validated:
            try:
                with self._open_binary(item["path"]) as binary, io.TextIOWrapper(binary, encoding=item["encoding"], newline="") as handle:
                    file_stat = self._stream_stat(handle)
                    if not stat.S_ISREG(file_stat.st_mode):
                        raise ApiError(
                            HTTPStatus.BAD_REQUEST,
                            "not_a_file",
                            f"items[{item['index']}].path is not a regular file",
                        )
                    if file_stat.st_size > self.server.config.max_text_replace_bytes:
                        raise ApiError(
                            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            "file_too_large",
                            "text replacement exceeds the configured file size limit; "
                            "upload a replacement file instead",
                        )
                    text = handle.read()
            except UnicodeDecodeError:
                raise decode_error(item["encoding"]) from None

            observed_etag = self._path_etag(item["path"], file_stat)
            self._check_expected_etag(item["expected_etag"], observed_etag)
            spans: list[tuple[int, int, str, int]] = []
            for replacement_index, (old, new, expected_matches) in enumerate(item["rules"]):
                actual_matches = text.count(old)
                if actual_matches != expected_matches:
                    raise ApiError(
                        HTTPStatus.CONFLICT,
                        "match_count_mismatch",
                        f"items[{item['index']}].replacements[{replacement_index}] expected "
                        f"{expected_matches} exact match(es), found {actual_matches}",
                        {
                            "item_index": item["index"],
                            "replacement_index": replacement_index,
                            "expected": expected_matches,
                            "actual": actual_matches,
                        },
                    )
                total_replacements += actual_matches
                if total_replacements > maximum:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "batch_too_large",
                        "matched replacements exceeds the configured batch operation limit",
                        {"maximum": maximum, "actual": total_replacements},
                    )
                start = 0
                for _match in range(actual_matches):
                    position = text.find(old, start)
                    spans.append(
                        (position, position + len(old), new, replacement_index)
                    )
                    start = position + len(old)

            spans.sort(key=lambda span: (span[0], span[1], span[3]))
            for previous, current in zip(spans, spans[1:]):
                if current[0] < previous[1]:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "overlapping_replacements",
                        "replacement source ranges must not overlap",
                        {
                            "item_index": item["index"],
                            "first_replacement_index": previous[3],
                            "second_replacement_index": current[3],
                        },
                    )
            chunks: list[str] = []
            cursor = 0
            for start, end, new, _replacement_index in spans:
                chunks.append(text[cursor:start])
                chunks.append(new)
                cursor = end
            chunks.append(text[cursor:])
            item["updated_text"] = "".join(chunks)
            encode_text(item["updated_text"], item["encoding"])
            item["observed_etag"] = observed_etag
            item["replacement_count"] = len(spans)

        results: list[dict[str, Any]] = []
        failures = 0
        for item in validated:
            try:
                _created, updated_stat = self._atomic_write(
                    item["path"],
                    item["updated_text"],
                    expected_etag=item["observed_etag"],
                    encoding=item["encoding"],
                )
            except ApiError as exc:
                failures += 1
                error: dict[str, Any] = {"code": exc.code, "message": exc.message}
                if exc.details is not None:
                    error["details"] = exc.details
                results.append(
                    {
                        "index": item["index"],
                        "path": item["requested_path"],
                        "updated": False,
                        "error": error,
                    }
                )
                continue
            results.append(
                {
                    "index": item["index"],
                    "path": item["requested_path"],
                    "updated": True,
                    "replacements": item["replacement_count"],
                    "etag": self._path_etag(item["path"], updated_stat),
                }
            )
        status = HTTPStatus.OK if failures == 0 else HTTPStatus.MULTI_STATUS
        self._send_json(
            status,
            {
                "items": results,
                "total": len(results),
                "updated": len(results) - failures,
                "failed": failures,
                "replacements": sum(
                    item.get("replacements", 0) for item in results
                ),
                "complete": failures == 0,
            },
        )

    def _handle_fs_mkdir(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        if self._try_mapping_file_api("fs_mkdir", body=body):
            return
        path = self._resolve_path(self._required_string(body, "path"), write=True)
        parents = self._optional_bool(body, "parents", False)
        exist_ok = self._optional_bool(body, "exist_ok", False)
        try:
            created = self._safe_path_access().mkdir(path, parents=parents, exist_ok=exist_ok)
        except (FileNotFoundError, SafePathError) as exc:
            if exc.errno != errno.ENOENT:
                self._raise_safe_path_error(SafePathError(exc.errno or errno.EIO, str(exc), str(path)))
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "parent_not_found",
                "parent directory does not exist; set parents=true to create it",
            ) from None
        except FileExistsError:
            raise ApiError(HTTPStatus.CONFLICT, "path_exists", "path already exists") from None
        except OSError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "mkdir_failed", str(exc)) from None
        self._send_json(
            HTTPStatus.CREATED if created else HTTPStatus.OK,
            {"path": str(path), "created": created},
        )

    def _handle_fs_delete(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        if self._try_mapping_file_api("fs_delete", body=body):
            return
        path = self._resolve_path(self._required_string(body, "path"), write=True)
        if "recursive" in body:
            # Accepted for compatibility with clients using the previous API.
            # Recycle moves do not need recursive traversal.
            self._optional_bool(body, "recursive", False)
        if path == self.token_scope_root:
            raise ApiError(HTTPStatus.FORBIDDEN, "root_protected", "the token workspace root cannot be deleted")
        try:
            path.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "outside_delete_not_supported",
                "recoverable delete is only available inside the token workspace; use Shell for direct external deletion",
            ) from None
        try:
            result = self._recycle_path(path)
        except RecycleError as exc:
            raise ApiError(exc.status, exc.code, exc.message) from None
        result.update({"path": str(path), "deleted": True, "recycled": True})
        self._send_json(HTTPStatus.OK, result)

    def _handle_fs_delete_batch(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        if self._try_mapping_file_api("fs_delete_batch", body=body):
            return
        paths = body.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "paths must be a non-empty array",
            )
        if len(paths) > self.server.config.max_batch_file_operations:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "batch_too_large",
                "paths exceeds the configured batch operation limit",
                {
                    "maximum": self.server.config.max_batch_file_operations,
                    "actual": len(paths),
                },
            )
        try:
            recycle = self.server.recycle_for(self.token_scope_root)
        except RecycleError as exc:
            raise ApiError(exc.status, exc.code, exc.message) from None

        validated: list[tuple[int, str, Path]] = []
        seen: set[Path] = set()
        for index, requested_path in enumerate(paths):
            if not isinstance(requested_path, str) or not requested_path:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    f"paths[{index}] must be a non-empty string",
                )
            path = self._resolve_path(requested_path, write=True)
            if path == self.token_scope_root:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "root_protected",
                    "the token workspace root cannot be deleted",
                )
            try:
                path.relative_to(self.token_scope_root)
            except ValueError:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "outside_delete_not_supported",
                    "recoverable delete is only available inside the token workspace",
                ) from None
            if path in seen:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "duplicate_path",
                    f"paths[{index}] resolves to a duplicate path",
                )
            for _other_index, _other_requested, other_path in validated:
                if path in other_path.parents or other_path in path.parents:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "overlapping_paths",
                        "batch delete paths must not contain one another",
                        {"first": _other_requested, "second": requested_path},
                    )
            seen.add(path)
            validated.append((index, requested_path, path))

        for index, requested_path, path in validated:
            try:
                self._file_stat(path)
            except ApiError as exc:
                if exc.status == HTTPStatus.NOT_FOUND and exc.code == "path_not_found":
                    raise ApiError(
                        HTTPStatus.CONFLICT,
                        "batch_precondition_failed",
                        "no paths were deleted because a requested path does not exist",
                        {
                            "index": index,
                            "path": requested_path,
                            "code": exc.code,
                        },
                    ) from None
                raise
        results: list[dict[str, Any]] = []
        failures = 0
        for index, requested_path, path in validated:
            try:
                result = self._recycle_path(path)
            except (RecycleError, ApiError) as exc:
                failures += 1
                results.append(
                    {
                        "index": index,
                        "path": requested_path,
                        "deleted": False,
                        "error": {"code": exc.code, "message": exc.message},
                    }
                )
                continue
            result.update(
                {
                    "index": index,
                    "path": requested_path,
                    "deleted": True,
                    "recycled": True,
                }
            )
            results.append(result)
        status = HTTPStatus.OK if failures == 0 else HTTPStatus.MULTI_STATUS
        self._send_json(
            status,
            {
                "items": results,
                "total": len(results),
                "deleted": len(results) - failures,
                "failed": failures,
                "complete": failures == 0,
            },
        )

    def _handle_fs_move(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        if self._try_mapping_file_api("fs_move", body=body):
            return
        source = self._resolve_path(self._required_string(body, "source"), write=True)
        destination = self._resolve_path(self._required_string(body, "destination"), write=True)
        overwrite = self._optional_bool(body, "overwrite", False)
        create_parents = self._optional_bool(body, "create_parents", False)
        if source == self.token_scope_root or destination == self.token_scope_root:
            raise ApiError(HTTPStatus.FORBIDDEN, "root_protected", "the token root cannot be moved or replaced")
        try:
            self.server.mappings.check_path(source, write=True, protect_root=True)
            self.server.mappings.check_path(destination, write=True, protect_root=True)
        except OSError:
            raise ApiError(403, "mapping_root_protected", "mapping root cannot be moved or replaced") from None
        if source == destination:
            raise ApiError(HTTPStatus.BAD_REQUEST, "same_path", "source and destination are the same path")
        source_mapping = self.server.mappings.at_path(source)
        destination_mapping = self.server.mappings.at_path(destination)
        if (source_mapping or destination_mapping) and (source_mapping or {}).get("id") != (destination_mapping or {}).get("id"):
            if overwrite:
                raise ApiError(400, "overwrite_not_supported", "cross-root moves never overwrite; recycle the destination first")
            if create_parents:
                try:
                    self._workspace_files().mkdir(destination.parent, parents=True, exist_ok=True)
                except OSError:
                    raise ApiError(409, "parent_unavailable", "could not create destination parents") from None
            self._start_file_transfer(source, destination, move=True)
            return
        try:
            with self._safe_parent(source) as source_parent:
                source_stat = source_parent.lstat()
        except ApiError:
            raise
        if source_stat is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "path_not_found", "source path does not exist")
        if stat.S_ISDIR(source_stat.st_mode):
            try:
                destination.relative_to(source)
            except ValueError:
                pass
            else:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_move",
                    "a directory cannot be moved inside itself",
                )
        try:
            destination_exists = self._safe_path_access().rename(
                source,
                destination,
                overwrite=overwrite,
                create_parents=create_parents,
            )
        except FileNotFoundError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "parent_not_found", "destination parent does not exist") from None
        except FileExistsError:
            raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination path already exists") from None
        except SafePathError as exc:
            self._raise_safe_path_error(exc)
        except OSError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "move_failed", str(exc)) from None
        self._send_json(
            HTTPStatus.OK,
            {
                "source": str(source),
                "destination": str(destination),
                "moved": True,
                "overwritten": destination_exists,
            },
        )

    def _handle_recycle_list(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 1000, minimum=1, maximum=5000)
        row = self._mapped_recycle_root(self._query_one(query, "root", "."))
        if row:
            result = self._mapping_rpc(row, "recycle_list", {"offset": offset, "limit": limit})
            result.update(root=row["name"], offset=offset, limit=limit)
            self._send_json(200, result)
            return
        try:
            entries, total = self.server.recycle_for(self.token_scope_root).list_items(offset, limit)
        except RecycleError as exc:
            raise ApiError(exc.status, exc.code, exc.message) from None
        self._send_json(
            HTTPStatus.OK,
            {
                "entries": entries,
                "offset": offset,
                "limit": limit,
                "total": total,
                "truncated": offset + len(entries) < total,
            },
        )

    def _handle_recycle_restore(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        recycle_id = self._required_string(body, "recycle_id")
        row = self._mapped_recycle_root(body.get("root", "."))
        if row:
            self._send_json(200, self._mapping_rpc(row, "recycle_restore", {"recycle_id": recycle_id}))
            return
        try:
            result = self.server.recycle_for(self.token_scope_root).restore(recycle_id)
        except RecycleError as exc:
            raise ApiError(exc.status, exc.code, exc.message) from None
        self._send_json(HTTPStatus.OK, result)

    def _handle_upload_create(self) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        path = self._resolve_path(self._required_string(body, "path"), write=True)
        size = body.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "size must be a non-negative integer")
        if size > self.server.config.max_file_bytes:
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "file_too_large",
                "file exceeds the configured maximum size",
            )
        sha256 = body.get("sha256")
        if sha256 is not None and (not isinstance(sha256, str) or not self._valid_sha256(sha256)):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_sha256", "sha256 must be 64 hexadecimal characters")
        create_parents = self._optional_bool(body, "create_parents", False)
        if "overwrite" in body:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "overwrite_not_supported",
                "uploads never overwrite; recycle the existing file before uploading",
            )
        if "expected_etag" in body:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "expected_etag_not_supported",
                "uploads only create new files and do not accept expected_etag",
            )
        mapping = self.server.mappings.at_path(path)
        if mapping is not None:
            from openkapsel.mapping.mapping_uploads import prepare_destination
            try:
                prepare_destination(self._workspace_files(), path, create_parents=create_parents)
            except OSError as exc:
                self._raise_file_io_error(exc)
        else:
            try:
                parent = self._safe_parent(path, create_parents=create_parents)
            except ApiError as exc:
                if exc.code == "path_not_found":
                    raise ApiError(HTTPStatus.BAD_REQUEST, "parent_not_found", "parent directory does not exist") from None
                raise
            with parent:
                initial_stat = parent.lstat()
                if initial_stat is not None and not stat.S_ISREG(initial_stat.st_mode):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
                if initial_stat is not None:
                    raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination already exists")
        try:
            record = self.server.uploads.create(
                token=self.token_record.token,
                target=path,
                expected_size=size,
                expected_sha256=sha256,
                create_parents=create_parents,
                mapping_id=mapping["id"] if mapping else None,
            )
        except UploadError as exc:
            self._raise_upload_error(exc)
        self._send_json(HTTPStatus.CREATED, record.public(self._upload_chunk_recommendation()))

    def _handle_upload_status(self, upload_id: str, *, head_only: bool = False) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        record = self._upload_record(upload_id)
        if head_only:
            self._send_empty(
                HTTPStatus.OK,
                {
                    "Upload-Offset": str(record.offset),
                    "Upload-Length": str(record.expected_size),
                    "Upload-Expires": record.expires_at,
                },
            )
            return
        self._send_json(HTTPStatus.OK, record.public(self._upload_chunk_recommendation()))

    def _handle_upload_append(self, upload_id: str) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        if self.headers.get_content_type() != "application/octet-stream":
            raise ApiError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content_type",
                "upload chunks require Content-Type: application/octet-stream",
            )
        offset_header = self.headers.get("Upload-Offset")
        try:
            offset = int(offset_header) if offset_header is not None else -1
        except ValueError:
            offset = -1
        if offset < 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_offset", "Upload-Offset must be a non-negative integer")
        length = self._content_length(self.server.config.upload_chunk_bytes)
        try:
            record = self.server.uploads.append(
                upload_id,
                self.token_record.token,
                offset,
                self.rfile,
                length,
            )
        except UploadError as exc:
            self._raise_upload_error(exc)
        self._send_json(HTTPStatus.OK, record.public(self._upload_chunk_recommendation()))

    def _handle_upload_commit(self, upload_id: str) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        record = self._upload_record(upload_id)
        target = self._resolve_path(record.target_path, write=True)
        mapping = self.server.mappings.at_path(target)
        if (mapping["id"] if mapping else None) != record.mapping_id:
            raise ApiError(409, "upload_mapping_changed", "upload destination mapping identity changed; start a new upload")
        if str(target) != record.target_path:
            raise ApiError(HTTPStatus.CONFLICT, "upload_target_changed", "upload target changed")
        try:
            verified, actual_sha256 = self.server.uploads.verify(upload_id, self.token_record.token)
        except UploadError as exc:
            self._raise_upload_error(exc)
        if mapping is not None:
            from openkapsel.mapping.mapping_uploads import commit_upload
            try:
                commit_upload(self, upload_id, record, verified, actual_sha256, target)
            except UploadError as exc:
                self._raise_upload_error(exc)
            return
        try:
            parent = self._safe_parent(target, create_parents=record.create_parents)
        except ApiError as exc:
            if exc.code == "path_not_found":
                raise ApiError(HTTPStatus.BAD_REQUEST, "parent_not_found", "parent directory does not exist") from None
            raise
        with parent:
            current_stat = parent.lstat()
            if current_stat is not None and not stat.S_ISREG(current_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            if current_stat is not None:
                raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination already exists")
            temp_name = f".{target.name}.openkapsel-put-{secrets.token_hex(12)}"
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temp_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent.fd,
                )
                with os.fdopen(descriptor, "wb") as destination:
                    descriptor = None
                    try:
                        self.server.uploads.copy_to(upload_id, self.token_record.token, destination)
                    except UploadError as exc:
                        self._raise_upload_error(exc)
                    destination.flush()
                    os.fsync(destination.fileno())
                    os.fchmod(destination.fileno(), 0o600)
                latest_stat = parent.lstat()
                if latest_stat is not None:
                    raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination already exists")
                self._publish_new_upload(parent, temp_name)
                temp_name = ""
                final_descriptor = parent.open(os.O_RDONLY)
                try:
                    final_stat = os.fstat(final_descriptor)
                finally:
                    os.close(final_descriptor)
                self.server.uploads.finish(upload_id, self.token_record.token)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if temp_name:
                    try:
                        os.unlink(temp_name, dir_fd=parent.fd)
                    except FileNotFoundError:
                        pass
        self._send_json(
            HTTPStatus.CREATED,
            {
                "path": str(target),
                "created": True,
                "bytes_written": verified.expected_size,
                "sha256": actual_sha256,
                "etag": self._path_etag(target, final_stat),
            },
        )

    def _handle_upload_cancel(self, upload_id: str) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        try:
            self.server.uploads.cancel(upload_id, self.token_record.token)
        except UploadError as exc:
            self._raise_upload_error(exc)
        self._send_empty(HTTPStatus.NO_CONTENT)

    @staticmethod
    def _publish_new_upload(parent: Any, temp_name: str) -> None:
        """Atomically publish a temporary file without replacing a destination."""
        try:
            os.link(
                temp_name,
                parent.name,
                src_dir_fd=parent.fd,
                dst_dir_fd=parent.fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise ApiError(HTTPStatus.CONFLICT, "path_exists", "destination already exists") from None
        except OSError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "upload_publish_failed", str(exc)) from None
        os.unlink(temp_name, dir_fd=parent.fd)

    def _upload_chunk_recommendation(self) -> int:
        if getattr(self, "_capturing_mcp_tool", False):
            return self.server.config.mcp_binary_chunk_bytes
        return self.server.config.upload_chunk_bytes

    def _upload_record(self, upload_id: str) -> UploadRecord:
        if not re.fullmatch(r"upload_[A-Za-z0-9_-]+", upload_id):
            raise ApiError(HTTPStatus.NOT_FOUND, "upload_not_found", "upload does not exist")
        try:
            return self.server.uploads.get(upload_id, self.token_record.token)
        except UploadError as exc:
            self._raise_upload_error(exc)

    @staticmethod
    def _raise_upload_error(exc: UploadError) -> None:
        raise ApiError(exc.status, exc.code, exc.message, exc.details) from None

"""Generic request, path, transfer, and response helpers."""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
from http import HTTPStatus
from pathlib import Path
from typing import Any

from openkapsel.errors import ApiError
from openkapsel.files.safe_paths import SafePathAccess
from openkapsel.workspace.workspace_layout import INTERNAL_DIRECTORY

LOGGER = logging.getLogger("openkapsel")
OAUTH_DISCOVERY_LOGGER = logging.getLogger("openkapsel.oauth.discovery")
OAUTH_DISCOVERY_LOGGER.setLevel(logging.INFO)

class HttpSupportMixin:
    def _resolve_path(self, value: str, *, write: bool = False) -> Path:
        root = self.token_scope_root
        if "\x00" in value:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_path",
                "path must not contain a NUL byte",
            )
        candidate = Path(value).expanduser() if value else root
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = Path(os.path.abspath(candidate))
        try:
            self.server.mappings.check_path(candidate, write=write, protect_root=write)
        except OSError as exc:
            raise ApiError(403 if exc.errno in {errno.EROFS, errno.EBUSY} else 503, "mapping_unavailable", "mapping is protected, read-only, or offline") from None
        try:
            self.server.storage_providers.check_path(candidate, write=write, protect_root=write)
        except OSError as exc:
            raise ApiError(
                403 if exc.errno in {errno.EROFS, errno.EBUSY} else 503,
                "storage_provider_unavailable",
                "Storage Provider mapping is protected, read-only, or offline",
            ) from None
        resolved = candidate if self.server.mappings.at_path(candidate) else candidate.resolve(strict=False)
        self._assert_inside_root(resolved)
        if write:
            self._assert_path_writable(resolved)
        for checked in (candidate.absolute(), resolved):
            try:
                relative_to_workspace = checked.relative_to(self.token_scope_root)
            except ValueError:
                continue
            if INTERNAL_DIRECTORY in relative_to_workspace.parts:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "reserved_path",
                    "workspace internal directories are not available through file endpoints",
                )
        if any(self._is_internal_transfer_name(part) for part in resolved.parts):
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "reserved_path",
                "temporary transfer files are not available through file endpoints",
            )
        return resolved


    def _safe_path_access(self) -> SafePathAccess:
        return SafePathAccess(
            (
                self.token_scope_root,
                *(Path(item.path) for item in self.token_record.allowed_paths),
            )
        )


    def _assert_path_writable(self, path: Path) -> None:
        try:
            path.relative_to(self.token_scope_root)
        except ValueError:
            pass
        else:
            return
        matching = []
        for grant in self.token_record.allowed_paths:
            try:
                path.relative_to(grant.path)
            except ValueError:
                continue
            matching.append(grant)
        if not matching:
            raise ApiError(HTTPStatus.FORBIDDEN, "path_outside_root", "path is not authorized")
        grant = max(matching, key=lambda item: len(Path(item.path).parts))
        if grant.read_only:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "read_only_path",
                f"extra accessible path is read-only: {grant.path}",
            )


    def _assert_inside_root(self, path: Path) -> None:
        for root in (self.token_scope_root, *(Path(item.path) for item in self.token_record.allowed_paths)):
            try:
                path.relative_to(root)
            except ValueError:
                continue
            return
        raise ApiError(
            HTTPStatus.FORBIDDEN,
            "path_outside_root",
            "path is outside the token workspace and extra accessible paths",
        )


    @staticmethod
    def _require_permission(granted: bool, message: str) -> None:
        if not granted:
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", message)


    def _run_transfer(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        if not self.server.transfer_slots.acquire(blocking=False):
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "transfer_limit_reached",
                "too many file transfers are currently running",
            )
        try:
            return operation(*args, **kwargs)
        finally:
            self.server.transfer_slots.release()


    def _read_json(self) -> dict[str, Any]:
        if hasattr(self, "_mcp_tool_arguments"):
            body = self._mcp_tool_arguments
            self._begin_deferred_context_operation(body)
            return body
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "content_type", "Content-Type must be application/json")
        length = self._request_content_length(required=True)
        if length > self.server.config.max_body_bytes:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "request body is too large")
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_json", "request body must be valid UTF-8 JSON")
        if not isinstance(body, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "JSON body must be an object")
        self._begin_deferred_context_operation(body)
        return body


    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()


    def _content_length(self, maximum: int) -> int:
        length = self._request_content_length(required=True)
        if length > maximum:
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"request body exceeds the {maximum}-byte limit",
            )
        return length


    def _request_content_length(self, *, required: bool) -> int:
        if self.headers.get_all("Transfer-Encoding", []):
            self.close_connection = True
            raise ApiError(
                HTTPStatus.NOT_IMPLEMENTED,
                "unsupported_transfer_encoding",
                "Transfer-Encoding request bodies are not supported; send Content-Length",
            )
        raw_values = self.headers.get_all("Content-Length", [])
        values = [item.strip() for raw in raw_values for item in raw.split(",")]
        if not values:
            if required:
                raise ApiError(
                    HTTPStatus.LENGTH_REQUIRED,
                    "length_required",
                    "Content-Length is required",
                )
            return 0
        if len(values) != 1 or not values[0].isdigit():
            self.close_connection = True
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_length",
                "Content-Length must be one non-negative decimal integer",
            )
        return int(values[0])


    def _discard_request_body(self) -> None:
        length = self._request_content_length(required=False)
        if length == 0:
            return
        if length > self.server.config.max_body_bytes:
            self.close_connection = True
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"unexpected request body exceeds the {self.server.config.max_body_bytes}-byte limit",
            )
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(remaining, self.server.config.transfer_buffer_bytes))
            if not chunk:
                self.close_connection = True
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "incomplete_body",
                    "request body ended before Content-Length",
                )
            remaining -= len(chunk)


    def _check_if_match(self, current_etag: str | None) -> None:
        supplied = self.headers.get("If-Match")
        if supplied is None:
            return
        matches = any(
            self._expected_etag_matches(candidate.strip(), current_etag)
            for candidate in supplied.split(",")
        )
        if not matches:
            raise ApiError(
                HTTPStatus.PRECONDITION_FAILED,
                "etag_mismatch",
                "If-Match does not match the current file",
                {"actual_etag": current_etag},
            )


    @staticmethod
    def _parse_byte_range(value: str, size: int) -> tuple[int, int]:
        if not value.startswith("bytes=") or "," in value:
            raise ApiError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "invalid_range",
                "only one byte range is supported",
                {"size": size},
            )
        spec = value.removeprefix("bytes=").strip()
        if "-" not in spec:
            raise ApiError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "invalid_range",
                "invalid byte range",
                {"size": size},
            )
        start_raw, end_raw = spec.split("-", 1)
        try:
            if not start_raw:
                suffix = int(end_raw)
                if suffix <= 0 or size == 0:
                    raise ValueError
                start = max(0, size - suffix)
                end = size - 1
            else:
                start = int(start_raw)
                end = int(end_raw) if end_raw else size - 1
                if start < 0 or start >= size or end < start:
                    raise ValueError
                end = min(end, size - 1)
        except ValueError:
            raise ApiError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "invalid_range",
                "byte range is outside the file",
                {"size": size},
            ) from None
        return start, end


    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        if getattr(self, "_capturing_mcp_tool", False):
            self._mcp_tool_response = (status, payload)
            return
        context_id = self._finalize_context_operation(status, payload)
        if context_id is not None:
            payload = dict(payload)
            payload["context_id"] = context_id
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if status >= 400:
            # Some authorization failures happen before a POST body is read.
            # Closing the connection prevents unread bytes from being mistaken
            # for the next request on an HTTP/1.1 keep-alive connection.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


    def _send_empty(self, status: int, headers: dict[str, str] | None = None) -> None:
        if getattr(self, "_capturing_mcp_tool", False):
            self._mcp_tool_response = (status, {})
            return
        context_id = self._finalize_context_operation(status, {})
        headers = dict(headers or {})
        if context_id is not None:
            headers["OpenKapsel-Context-ID"] = str(context_id)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()


    def log_message(self, fmt: str, *args: Any) -> None:
        message = fmt % args
        if "/oauth/" in self.path:
            message = message.replace(self.path, self.path.split("?", 1)[0])
        request_path = self.path.split("?", 1)[0]
        if request_path.startswith("/.well-known/") or (
            request_path.startswith(self.server.config.url_base_path + "/oauth/")
            and request_path.endswith(("/resource", "/oauth-authorization-server"))
        ):
            OAUTH_DISCOVERY_LOGGER.info("%s - %s", self.address_string(), message.replace(self.path, request_path))
            return
        LOGGER.info("%s - %s", self.address_string(), message)

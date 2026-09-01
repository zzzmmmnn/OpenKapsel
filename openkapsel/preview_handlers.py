"""Static web preview and sandboxed FastAPI reverse-proxy handlers."""

from __future__ import annotations

import hashlib
import http.client
import logging
import mimetypes
import os
import socket
import stat
import time
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from urllib.parse import quote, unquote

from .api_workers import ApiWorkerError
from .errors import ApiError
from .workspace_layout import INTERNAL_DIRECTORY


LOGGER = logging.getLogger("openkapsel")


@dataclass(frozen=True)
class WebApiTarget:
    """Resolved mount information for one workspace FastAPI application."""

    app_root: Path
    target: str
    root_path: str
    worker_key: str


class PreviewHandlersMixin:
    """Preview-domain methods mixed into the main request handler."""
    def _handle_web_preview(
        self,
        route: str,
        request_path: str,
        raw_query: str,
        *,
        head_only: bool,
    ) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        self._require_permission(
            self.token_record.can_preview,
            "web preview permission is not granted",
        )
        encoded_relative = "" if route == "/web" else route.removeprefix("/web/")
        relative = unquote(encoded_relative)
        if "\x00" in relative or Path(relative).is_absolute():
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_preview_path", "preview path is invalid")
        if any(part in {INTERNAL_DIRECTORY, "api"} for part in Path(relative).parts):
            raise ApiError(HTTPStatus.NOT_FOUND, "preview_not_found", "preview file does not exist")
        try:
            target = self._resolve_path(relative)
        except ApiError as exc:
            if exc.code == "reserved_path":
                raise ApiError(
                    HTTPStatus.NOT_FOUND,
                    "preview_not_found",
                    "preview file does not exist",
                ) from None
            raise
        try:
            target.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "preview_outside_workspace",
                "web preview only serves files inside the token workspace",
            ) from None
        try:
            descriptor = self._safe_open_descriptor(target, os.O_RDONLY)
        except ApiError as exc:
            if exc.code == "path_not_found":
                raise ApiError(HTTPStatus.NOT_FOUND, "preview_not_found", "preview file does not exist") from None
            raise
        target_stat = os.fstat(descriptor)
        if stat.S_ISDIR(target_stat.st_mode):
            os.close(descriptor)
            if not request_path.endswith("/"):
                location = request_path + "/"
                if raw_query:
                    location += "?" + raw_query
                self._send_preview_redirect(location)
                return
            target = target / "index.html"
            try:
                descriptor = self._safe_open_descriptor(target, os.O_RDONLY)
            except ApiError as exc:
                if exc.code == "path_not_found":
                    raise ApiError(HTTPStatus.NOT_FOUND, "preview_not_found", "preview file does not exist") from None
                raise
            target_stat = os.fstat(descriptor)
        if not stat.S_ISREG(target_stat.st_mode):
            os.close(descriptor)
            raise ApiError(HTTPStatus.BAD_REQUEST, "preview_not_a_file", "preview path is not a regular file")
        handle = os.fdopen(descriptor, "rb")
        with handle:
            file_stat = os.fstat(handle.fileno())
            size = file_stat.st_size
            etag = self._stat_etag(file_stat)
            if self.headers.get("If-None-Match") == etag:
                self._send_empty(
                    HTTPStatus.NOT_MODIFIED,
                    {
                        "ETag": etag,
                    },
                )
                return
            range_header = self.headers.get("Range")
            if range_header:
                start, end = self._parse_byte_range(range_header, size)
                status = HTTPStatus.PARTIAL_CONTENT
            else:
                start, end = 0, size - 1
                status = HTTPStatus.OK
            length = max(0, end - start + 1)
            content_type, content_encoding = mimetypes.guess_type(target.name)
            content_type = content_type or "application/octet-stream"
            if content_type.startswith("text/") or content_type in {
                "application/javascript",
                "application/json",
                "application/xml",
                "image/svg+xml",
            }:
                content_type += "; charset=utf-8"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            )
            dedicated_preview_origin = self.server.config.preview_base_url is not None
            if dedicated_preview_origin:
                self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            sandbox_flags = "sandbox allow-scripts"
            if dedicated_preview_origin:
                sandbox_flags += " allow-same-origin"
            self.send_header(
                "Content-Security-Policy",
                f"{sandbox_flags} allow-forms allow-modals allow-popups allow-downloads; "
                "default-src 'self' data: blob:; "
                "script-src 'self' data: blob: 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' data: 'unsafe-inline'; "
                "img-src 'self' data: blob: https: http:; "
                "font-src 'self' data: https: http:; "
                "media-src 'self' data: blob: https: http:; "
                "connect-src 'self' https: http: ws: wss:; "
                "frame-ancestors 'none'",
            )
            if content_encoding is not None:
                self.send_header("Content-Encoding", content_encoding)
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

    def _resolve_web_api_target(self, route: str) -> WebApiTarget | None:
        if route == "/api" or route.startswith("/api/"):
            encoded_relative = route.lstrip("/")
        elif route == "/web":
            encoded_relative = ""
        elif route.startswith("/web/"):
            encoded_relative = route.removeprefix("/web/")
        else:
            return None
        relative = unquote(encoded_relative)
        path = Path(relative)
        parts = path.parts
        try:
            api_index = parts.index("api")
        except ValueError:
            return None
        if "\x00" in relative or path.is_absolute():
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_api_path", "API path is invalid")
        if ".." in parts[:api_index] or INTERNAL_DIRECTORY in parts[:api_index]:
            raise ApiError(HTTPStatus.NOT_FOUND, "api_not_found", "Workspace API does not exist")

        app_relative = Path(*parts[:api_index]) if api_index else Path(".")
        lexical_root = self.token_scope_root / app_relative
        app_root = lexical_root.resolve(strict=False)
        try:
            app_root.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "api_outside_workspace",
                "Workspace API must be inside the token workspace",
            ) from None
        if app_root != lexical_root.absolute() or not app_root.is_dir():
            raise ApiError(HTTPStatus.NOT_FOUND, "api_not_found", "Workspace API does not exist")
        api_root = app_root / "api"
        entry = api_root / "app.py"
        if (
            api_root.is_symlink()
            or not api_root.is_dir()
            or entry.is_symlink()
            or not entry.is_file()
        ):
            raise ApiError(HTTPStatus.NOT_FOUND, "api_not_found", "Workspace API does not exist")

        app_label = "" if app_relative == Path(".") else app_relative.as_posix()
        root_path = self._web_root_path().rstrip("/")
        if app_label:
            root_path += "/" + quote(app_label, safe="/")
        root_path += "/api"
        remainder = "/".join(parts[api_index + 1 :])
        target = "/" + quote(remainder, safe="/:@-._~!$&'()*+,;=") if remainder else "/"
        worker_suffix = hashlib.sha256(app_label.encode("utf-8")).hexdigest()[:16]
        return WebApiTarget(
            app_root=app_root,
            target=target,
            root_path=root_path,
            worker_key=f"{self.token_record.app_id}-{worker_suffix}",
        )

    @staticmethod
    def _is_default_fastapi_documentation_path(target: str) -> bool:
        return (
            target == "/openapi.json"
            or target == "/docs"
            or target.startswith("/docs/")
            or target == "/redoc"
            or target.startswith("/redoc/")
        )

    def _handle_web_api(
        self,
        method: str,
        api_target: WebApiTarget,
        raw_query: str,
    ) -> None:
        self._require_permission(self.token_record.can_preview, "web preview permission is not granted")
        if self._is_default_fastapi_documentation_path(api_target.target):
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "api_not_found",
                "Workspace API route does not exist",
            )
        length = self._request_content_length(required=False)
        if length > self.server.config.api_max_body_bytes:
            self.close_connection = True
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"API request body exceeds {self.server.config.api_max_body_bytes} bytes",
            )
        body = self.rfile.read(length) if length else None
        target = api_target.target
        if raw_query:
            target += "?" + raw_query
        forwarded_headers: dict[str, str] = {}
        blocked = {
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "host",
        }
        if getattr(self, "control_authorized", False):
            # The control Bearer authenticates OpenKapsel itself and must never be
            # disclosed to untrusted workspace application code.
            blocked.add("authorization")
        for key, value in self.headers.items():
            if key.lower() not in blocked:
                forwarded_headers[key] = value
        forwarded_headers["Host"] = "localhost"
        forwarded_headers["X-Forwarded-Proto"] = "https" if self._request_is_https() else "http"
        forwarded_headers["X-Forwarded-Host"] = self.headers.get("Host", "")
        try:
            # Ensure the private context directory exists before the worker's
            # mount namespace is assembled, so it can always be hidden.
            self.server.context_for(self.token_scope_root)
            connection = self.server.api_workers.connection(
                self.token_record,
                api_target.app_root,
                api_target.root_path,
                api_target.worker_key,
            )
            connection.request(method, target, body=body, headers=forwarded_headers)
            response = connection.getresponse()
            if self._is_workspace_api_sse(method, response):
                self._stream_workspace_api_sse(response, connection, api_target.worker_key)
                return
            data = response.read(self.server.config.api_max_body_bytes + 1)
            if len(data) > self.server.config.api_max_body_bytes:
                raise ApiWorkerError("FastAPI response exceeds the configured size limit")
        except (ApiWorkerError, OSError, http.client.HTTPException) as exc:
            LOGGER.warning("Workspace API proxy failed for %s: %s", api_target.worker_key, exc)
            raise ApiError(
                HTTPStatus.BAD_GATEWAY,
                "api_worker_failed",
                "Workspace API worker is unavailable",
            ) from None
        finally:
            if "connection" in locals():
                connection.close()
        self.send_response(response.status)
        blocked_response = {"connection", "transfer-encoding", "server", "date", "content-length"}
        for key, value in response.getheaders():
            if key.lower() not in blocked_response:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(data)

    @staticmethod
    def _is_workspace_api_sse(method: str, response: http.client.HTTPResponse) -> bool:
        if method != "GET" or response.status != HTTPStatus.OK:
            return False
        content_type = next(
            (
                value
                for key, value in response.getheaders()
                if key.lower() == "content-type"
            ),
            "",
        )
        media_type = content_type.split(";", 1)[0].strip().lower()
        return media_type == "text/event-stream"

    def _stream_workspace_api_sse(
        self,
        response: http.client.HTTPResponse,
        connection: http.client.HTTPConnection,
        worker_key: str,
    ) -> None:
        limited_by = self.server.acquire_sse_stream(self.token_record.token)
        if limited_by is not None:
            raise ApiError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "too_many_streams",
                "the concurrent SSE stream limit has been reached",
                details={
                    "scope": limited_by,
                    "max_global": self.server.config.max_sse_streams,
                    "max_per_token": self.server.config.max_sse_streams_per_token,
                },
                headers={"Retry-After": "1"},
            )
        try:
            self.send_response(response.status)
            blocked_response = {
                "cache-control",
                "connection",
                "content-length",
                "date",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "server",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "x-accel-buffering",
            }
            for key, value in response.getheaders():
                if key.lower() not in blocked_response:
                    self.send_header(key, value)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True

            started_at = time.monotonic()
            read_chunk = getattr(response, "read1", response.read)
            while True:
                remaining = self.server.config.max_sse_duration_seconds - (
                    time.monotonic() - started_at
                )
                if remaining <= 0:
                    return
                upstream_socket = getattr(connection, "sock", None)
                if upstream_socket is not None:
                    upstream_socket.settimeout(
                        min(self.server.config.http_socket_timeout_seconds, remaining)
                    )
                chunk = read_chunk(self.server.config.transfer_buffer_bytes)
                if not chunk:
                    return
                self.wfile.write(chunk)
                self.wfile.flush()
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            TimeoutError,
            socket.timeout,
            http.client.HTTPException,
            OSError,
        ) as exc:
            LOGGER.info("Workspace API SSE stream ended for %s: %s", worker_key, exc)
        finally:
            self.server.release_sse_stream(self.token_record.token)

    def _web_root_path(self) -> str:
        token = quote(self.token_record.preview_token, safe="")
        if self.server.config.preview_base_url:
            return f"/{token}/"
        return f"{self.server.config.url_base_path}/w/{token}/"

    def _send_preview_redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.PERMANENT_REDIRECT)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

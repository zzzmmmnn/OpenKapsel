"""Administrative authentication, token management, and HTML responses."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

from .admin_ui import render_dashboard, render_login
from .cgroups import SandboxLimits
from .errors import ApiError
from .security import (
    password_hash_needs_upgrade,
    verify_password,
)
from .tokens import DEFAULT_CREDENTIAL_TTL_DAYS, PathGrant, TokenRecord
from .workspace_images import WorkspaceImageError


LOGGER = logging.getLogger("openkapsel")


class AdminHandlersMixin:
    """Admin-domain methods mixed into the main request handler."""
    def _dispatch_admin(self, method: str, path: str, raw_query: str = "") -> None:
        if not self.server.config.admin_enabled:
            self._send_html(HTTPStatus.NOT_FOUND, "<h1>404 Not Found</h1>")
            return
        if method == "GET" and path in {"/admin", "/admin/"}:
            session = self._admin_session()
            if session is None:
                self._send_html(HTTPStatus.OK, render_login(self._admin_path()))
                return
            query = parse_qs(raw_query, keep_blank_values=True)
            if query.get("password_changed") == ["1"]:
                success = "Administrator password updated"
            elif query.get("control_token_rotated") == ["1"]:
                success = "Control token regenerated; the previous control token is now invalid"
            elif query.get("read_token_rotated") == ["1"]:
                success = "Read-only URL token regenerated; the previous Workspace and MCP URLs are now invalid"
            elif query.get("credentials_renewed") == ["1"]:
                success = "Read and control tokens renewed; both previous credentials are now invalid"
            elif query.get("image_created") == ["1"]:
                success = "Workspace image created and mounted"
            elif query.get("image_grown") == ["1"]:
                success = "Workspace image expanded"
            elif query.get("image_deleted") == ["1"]:
                success = "Workspace image permanently deleted"
            else:
                success = None
            image_panel = any(key in query for key in ("image_created", "image_grown", "image_deleted"))
            self._send_admin_dashboard(
                session,
                success=success,
                active_panel=(
                    "password" if query.get("password_changed") == ["1"]
                    else "images" if image_panel else "tokens"
                ),
            )
            return
        if method == "POST" and path == "/admin/login":
            self._handle_admin_login()
            return
        if method == "POST" and path == "/admin/logout":
            self._handle_admin_logout()
            return
        if method == "POST" and path == "/admin/tokens":
            self._handle_admin_tokens()
            return
        if method == "POST" and path == "/admin/images":
            self._handle_admin_images()
            return
        if method == "POST" and path == "/admin/password":
            self._handle_admin_password()
            return
        self._send_html(HTTPStatus.NOT_FOUND, "<h1>404 Not Found</h1>")

    def _handle_admin_login(self) -> None:
        address = self._admin_rate_limit_address()
        retry_after = self.server.admin_login_limiter.retry_after(address)
        if retry_after:
            self._send_html(
                HTTPStatus.TOO_MANY_REQUESTS,
                render_login(
                    self._admin_path(),
                    f"Too many failed login attempts; try again in {retry_after} seconds",
                ),
                headers={"Retry-After": str(retry_after)},
            )
            return
        form = self._read_form()
        username = self._form_one(form, "username")
        password = self._form_one(form, "password")
        if len(password) < 8:
            self._send_html(
                HTTPStatus.BAD_REQUEST,
                render_login(self._admin_path(), "Password must contain at least 8 characters"),
            )
            return
        configured_username = self.server.config.admin_username or ""
        configured_hash = self.server.admin_password_hash
        username_ok = hmac.compare_digest(username, configured_username)
        password_ok = verify_password(password, configured_hash)
        if not (username_ok and password_ok):
            self.server.admin_login_limiter.failed(address)
            self._send_html(
                HTTPStatus.UNAUTHORIZED,
                render_login(self._admin_path(), "Invalid username or password"),
            )
            return
        if password_hash_needs_upgrade(configured_hash):
            try:
                self.server.upgrade_admin_password_hash(password)
            except ValueError as exc:
                LOGGER.warning("could not upgrade legacy admin password hash: %s", exc)
        self.server.admin_login_limiter.succeeded(address)
        session = self.server.admin_sessions.create()
        secure = self._request_is_https()
        cookie = (
            f"ws_admin={session.id}; Path={self._admin_path()}; "
            "HttpOnly; SameSite=Strict; Max-Age=43200"
        )
        if secure:
            cookie += "; Secure"
        self._redirect(self._admin_path(), headers={"Set-Cookie": cookie})

    def _admin_rate_limit_address(self) -> str:
        peer = self.client_address[0]
        try:
            peer_address = ipaddress.ip_address(peer)
        except ValueError:
            return peer
        if not peer_address.is_loopback:
            return peer_address.compressed
        forwarded = self.headers.get("X-Forwarded-For", "")
        if not forwarded:
            return peer_address.compressed
        # Caddy appends the directly connected client to the end of the chain.
        # Taking the last valid address prevents a caller-supplied leading value
        # from selecting somebody else's limiter bucket.
        candidate = forwarded.rsplit(",", 1)[-1].strip()
        try:
            return ipaddress.ip_address(candidate).compressed
        except ValueError:
            return peer_address.compressed

    def _handle_admin_logout(self) -> None:
        session = self._require_admin_session()
        if session is None:
            return
        form = self._read_form()
        if not self._valid_csrf(session, form):
            self._send_html(HTTPStatus.FORBIDDEN, "<h1>403 CSRF validation failed</h1>")
            return
        self.server.admin_sessions.delete(session.id)
        self._redirect(
            self._admin_path(),
            headers={
                "Set-Cookie": (
                    f"ws_admin=; Path={self._admin_path()}; "
                    "HttpOnly; SameSite=Strict; Max-Age=0"
                )
            },
        )

    def _handle_admin_tokens(self) -> None:
        session = self._require_admin_session()
        if session is None:
            return
        form = self._read_form()
        if not self._valid_csrf(session, form):
            self._send_html(HTTPStatus.FORBIDDEN, "<h1>403 CSRF validation failed</h1>")
            return
        action = self._form_one(form, "action")
        try:
            with self.server.workspace_admin_lock:
                self._apply_admin_token_action(action, form)
        except (KeyError, ValueError, WorkspaceImageError) as exc:
            self._send_admin_dashboard(session, error=str(exc), status=HTTPStatus.BAD_REQUEST)
            return
        if action == "rotate_read":
            destination = f"{self._admin_path()}?read_token_rotated=1"
        elif action in {"rotate_control", "rotate_token"}:
            destination = f"{self._admin_path()}?control_token_rotated=1"
        elif action == "renew":
            destination = f"{self._admin_path()}?credentials_renewed=1"
        else:
            destination = self._admin_path()
        self._redirect(destination)

    def _apply_admin_token_action(
        self, action: str, form: dict[str, list[str]]
    ) -> None:
        if action == "create":
            ttl_raw = self._form_one(form, "ttl_hours").strip()
            expires_at = None
            if ttl_raw:
                ttl_hours = float(ttl_raw)
                if not 24 <= ttl_hours <= 17_520:
                    raise ValueError("token lifetime must be between 1 and 730 days")
                expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
            path_prefix, workspace_image = self._workspace_selection(form)
            sandbox_backend, sandbox_image = self._sandbox_selection(form)
            record = self.server.tokens.create(
                name=self._form_one(form, "name"),
                expires_at=expires_at,
                path_prefix=path_prefix,
                workspace_image=workspace_image,
                can_read="can_read" in form,
                can_write="can_write" in form,
                can_preview="can_preview" in form,
                shell_mode=self._form_one(form, "shell_mode"),
                sandbox_backend=sandbox_backend,
                sandbox_image=sandbox_image,
                network_mode=self._form_one(form, "network_mode") or "none",
                allowed_domains=self._network_domains(form, use_defaults=True),
                allowed_paths=self._allowed_paths(form),
                sandbox_max_processes=int(
                    self._form_one(form, "sandbox_max_processes")
                ),
                sandbox_memory_mb=int(self._form_one(form, "sandbox_memory_mb")),
                sandbox_cpu_percent=int(
                    self._form_one(form, "sandbox_cpu_percent")
                ),
            )
            self._refresh_cgroup_limits(record)
        elif action == "update":
            token = self._form_one(form, "token")
            current = self.server.tokens.get(token)
            path_prefix, workspace_image = self._workspace_selection(form, current)
            sandbox_backend, sandbox_image = self._sandbox_selection(form, current)
            expires_raw = self._form_one(form, "expires_at").strip()
            # datetime-local has no timezone; the admin UI labels it UTC and
            # TokenStore normalizes naive values accordingly.
            expires_at = expires_raw or None
            record = self.server.tokens.update(
                token,
                name=self._form_one(form, "name"),
                expires_at=expires_at,
                enabled="enabled" in form,
                path_prefix=path_prefix,
                workspace_image=workspace_image,
                can_read="can_read" in form,
                can_write="can_write" in form,
                can_preview="can_preview" in form,
                shell_mode=self._form_one(form, "shell_mode"),
                sandbox_backend=sandbox_backend,
                sandbox_image=sandbox_image,
                network_mode=self._form_one(form, "network_mode") or current.network_mode,
                allowed_domains=self._network_domains(form),
                allowed_paths=self._allowed_paths(form),
                sandbox_max_processes=int(
                    self._form_one(form, "sandbox_max_processes")
                ),
                sandbox_memory_mb=int(self._form_one(form, "sandbox_memory_mb")),
                sandbox_cpu_percent=int(
                    self._form_one(form, "sandbox_cpu_percent")
                ),
            )
            self.server.api_workers.stop(record.app_id)
            self._refresh_cgroup_limits(record)
        elif action == "delete":
            current = self.server.tokens.get(self._form_one(form, "token"))
            self.server.api_workers.stop(current.app_id)
            self.server.tokens.delete(current.token)
        elif action == "rotate_read":
            record = self.server.tokens.rotate_read_token(self._form_one(form, "token"))
            self._refresh_cgroup_limits(record)
        elif action == "renew":
            days_raw = self._form_one(form, "renew_days").strip()
            days = int(days_raw) if days_raw else DEFAULT_CREDENTIAL_TTL_DAYS
            record = self.server.tokens.renew_credentials(
                self._form_one(form, "token"), days
            )
            self._refresh_cgroup_limits(record)
        elif action in {"rotate_control", "rotate_token"}:
            self.server.tokens.rotate_control_token(self._form_one(form, "token"))
        elif action == "rotate_preview":
            current = self.server.tokens.get(self._form_one(form, "token"))
            self.server.api_workers.stop(current.app_id)
            self.server.tokens.rotate_preview_token(current.token)
        else:
            raise ValueError("unknown administrative action")

    def _workspace_selection(
        self,
        form: dict[str, list[str]],
        current: TokenRecord | None = None,
    ) -> tuple[str, str | None]:
        workspace_type = self._form_one(form, "workspace_type") or "directory"
        if workspace_type == "directory":
            path_prefix = self._form_one(form, "path_prefix")
            if self.server.workspace_images.enabled:
                try:
                    image_names = {item.name for item in self.server.workspace_images.list()}
                except WorkspaceImageError:
                    # Image-helper downtime must not block legacy directory Tokens.
                    image_names = set()
                if path_prefix.strip() in image_names:
                    raise ValueError("this name belongs to a workspace image; select Image workspace")
            return path_prefix, None
        if workspace_type != "image":
            raise ValueError("unknown workspace type")
        image_name = self._form_one(form, "workspace_image").strip()
        if current is not None and current.workspace_image == image_name:
            # Updating unrelated settings remains possible during a short helper outage.
            return current.path_prefix, current.workspace_image
        images = {item.name: item for item in self.server.workspace_images.list()}
        image = images.get(image_name)
        if image is None:
            raise ValueError("the selected workspace image does not exist")
        if not image.mounted:
            raise ValueError("the selected workspace image is not mounted")
        return image.name, image.name

    def _handle_admin_images(self) -> None:
        session = self._require_admin_session()
        if session is None:
            return
        form = self._read_form()
        if not self._valid_csrf(session, form):
            self._send_html(HTTPStatus.FORBIDDEN, "<h1>403 CSRF validation failed</h1>")
            return
        action = self._form_one(form, "action")
        try:
            with self.server.workspace_admin_lock:
                if action == "create":
                    name = self._form_one(form, "name")
                    size_mib = int(self._form_one(form, "size_mib"))
                    self.server.workspace_images.create(name, size_mib * 1024 * 1024)
                    result = "image_created"
                elif action == "grow":
                    name = self._form_one(form, "name")
                    size_mib = int(self._form_one(form, "size_mib"))
                    self.server.workspace_images.grow(name, size_mib * 1024 * 1024)
                    result = "image_grown"
                elif action == "delete":
                    name = self._form_one(form, "name").strip()
                    users = [
                        item for item in self.server.tokens.list()
                        if item.path_prefix == name
                    ]
                    if users:
                        labels = ", ".join(
                            f"{item.name} ({item.token[:8]}…)" for item in users
                        )
                        raise ValueError(f"workspace image is still used by these tokens: {labels}")
                    self.server.workspace_images.delete(name)
                    result = "image_deleted"
                else:
                    raise ValueError("unknown workspace image action")
        except (ValueError, WorkspaceImageError) as exc:
            self._send_admin_dashboard(
                session,
                error=str(exc),
                status=HTTPStatus.BAD_REQUEST,
                active_panel="images",
            )
            return
        self._redirect(f"{self._admin_path()}?{result}=1#images")

    def _handle_admin_password(self) -> None:
        session = self._require_admin_session()
        if session is None:
            return
        form = self._read_form()
        if not self._valid_csrf(session, form):
            self._send_html(HTTPStatus.FORBIDDEN, "<h1>403 CSRF validation failed</h1>")
            return
        old_password = self._form_one(form, "old_password")
        new_password = self._form_one(form, "new_password")
        confirmation = self._form_one(form, "confirm_password")
        if new_password != confirmation:
            self._send_admin_dashboard(
                session,
                error="The new password entries do not match",
                status=HTTPStatus.BAD_REQUEST,
                active_panel="password",
            )
            return
        try:
            self.server.change_admin_password(old_password, new_password)
        except ValueError as exc:
            self._send_admin_dashboard(
                session,
                error=str(exc),
                status=HTTPStatus.BAD_REQUEST,
                active_panel="password",
            )
            return
        self.server.admin_sessions.delete_others(session.id)
        self._redirect(f"{self._admin_path()}?password_changed=1")

    def _send_admin_dashboard(
        self,
        session: AdminSession,
        error: str | None = None,
        status: int = HTTPStatus.OK,
        success: str | None = None,
        active_panel: str = "tokens",
    ) -> None:
        images = []
        images_error = None
        try:
            images = self.server.workspace_images.list()
        except WorkspaceImageError as exc:
            images_error = str(exc)
        self._send_html(
            status,
            render_dashboard(
                self.server.tokens.list(),
                session.csrf,
                self._public_base_url(),
                self._preview_public_base_url(),
                self.server.config.name,
                self._admin_path(),
                self.server.cgroups.available,
                self.server.cgroups.unavailable_reason,
                self.server.config.sandbox_backends,
                self.server.config.sandbox_default_backend,
                self.server.config.podman_image,
                self.server.sandboxes.podman_images(),
                images,
                images_error,
                error=error,
                success=success,
                active_panel=active_panel,
                default_network_domains=self.server.config.default_network_domains,
            ),
        )

    def _network_domains(
        self,
        form: dict[str, list[str]],
        *,
        use_defaults: bool = False,
    ) -> tuple[str, ...]:
        raw = self._form_one(form, "allowed_domains")
        values = tuple(
            item
            for item in raw.replace(",", " ").split()
            if item
        )
        if not values and use_defaults and self._form_one(form, "network_mode") == "domain_allowlist":
            return self.server.config.default_network_domains
        return values

    def _sandbox_selection(
        self,
        form: dict[str, list[str]],
        current: TokenRecord | None = None,
    ) -> tuple[str, str | None]:
        value = self._form_one(form, "sandbox_backend").strip() or "auto"
        if value in {"auto", "bubblewrap"}:
            backend = value
            image = None
        elif value == "podman":
            backend = "podman"
            image = current.sandbox_image if current is not None else None
            image = image or self.server.config.podman_image
        elif value.startswith("podman::"):
            backend = "podman"
            image = value.removeprefix("podman::").strip()
        else:
            raise ValueError("invalid sandbox backend selection")
        resolved_backend = (
            self.server.config.sandbox_default_backend if backend == "auto" else backend
        )
        if resolved_backend not in self.server.config.sandbox_backends:
            raise ValueError(f"sandbox backend is not enabled: {resolved_backend}")
        if backend != "podman":
            return backend, None
        installed = self.server.sandboxes.podman_images()
        retaining_missing = (
            current is not None
            and current.sandbox_backend == "podman"
            and image == (current.sandbox_image or self.server.config.podman_image)
        )
        if not image or (image not in installed and not retaining_missing):
            raise ValueError("selected Podman image is not installed")
        return backend, image

    def _refresh_cgroup_limits(self, record: TokenRecord) -> None:
        if record.shell_mode != "restricted" or not self.server.cgroups.available:
            return
        try:
            self.server.cgroups.configure(
                record.token,
                SandboxLimits(
                    max_processes=record.sandbox_max_processes,
                    memory_bytes=record.sandbox_memory_mb * 1024 * 1024,
                    cpu_percent=record.sandbox_cpu_percent,
                ),
            )
        except (OSError, RuntimeError) as exc:
            LOGGER.error("could not refresh token cgroup limits: %s", exc)

    def _admin_session(self) -> AdminSession | None:
        raw_cookie = self.headers.get("Cookie", "")
        try:
            cookie = SimpleCookie(raw_cookie)
            session_id = cookie["ws_admin"].value if "ws_admin" in cookie else None
        except Exception:
            session_id = None
        return self.server.admin_sessions.get(session_id)

    def _require_admin_session(self) -> AdminSession | None:
        session = self._admin_session()
        if session is None:
            self._send_html(
                HTTPStatus.UNAUTHORIZED,
                render_login(self._admin_path(), "Your session has expired; sign in again"),
            )
        return session

    @staticmethod
    def _valid_csrf(session: AdminSession, form: dict[str, list[str]]) -> bool:
        values = form.get("csrf")
        return bool(values and hmac.compare_digest(values[0], session.csrf))

    @staticmethod
    def _form_one(form: dict[str, list[str]], key: str) -> str:
        values = form.get(key)
        return values[0] if values else ""

    def _allowed_paths(self, form: dict[str, list[str]]) -> tuple[PathGrant, ...]:
        paths = form.get("allowed_path", [])
        modes = form.get("allowed_path_mode", [])
        if len(paths) != len(modes):
            raise ValueError("extra-directory paths and access modes do not match")
        grants = []
        for path, mode in zip(paths, modes):
            cleaned = path.strip()
            if not cleaned:
                continue
            if mode not in {"ro", "rw"}:
                raise ValueError("extra-directory access mode must be read-only or writable")
            grants.append(PathGrant(path=cleaned, read_only=mode == "ro"))
        return tuple(grants)

    def _read_form(self) -> dict[str, list[str]]:
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            raise ApiError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content_type",
                "Content-Type must be application/x-www-form-urlencoded",
            )
        length = self._request_content_length(required=True)
        if length > min(self.server.config.max_body_bytes, 128 * 1024):
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "form body is too large")
        try:
            return parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_form", "form must be UTF-8") from None

    def _public_base_url(self) -> str:
        if self.server.config.public_base_url:
            origin = self.server.config.public_base_url.rstrip("/")
            return origin + self.server.config.url_base_path
        host = self.headers.get("Host", "")
        if not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host):
            address_host, address_port = self.server.server_address[:2]
            host = f"{address_host}:{address_port}"
        scheme = "https" if self._request_is_https() else "http"
        return f"{scheme}://{host}{self.server.config.url_base_path}"

    def _preview_public_base_url(self) -> str:
        if self.server.config.preview_base_url:
            return self.server.config.preview_base_url.rstrip("/")
        return self._public_base_url().rstrip("/") + "/w"

    def _request_is_https(self) -> bool:
        if self.server.config.public_base_url:
            return urlsplit(self.server.config.public_base_url).scheme == "https"
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _send_html(
        self,
        status: int,
        content: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str, headers: dict[str, str] | None = None) -> None:
        data = b""
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()

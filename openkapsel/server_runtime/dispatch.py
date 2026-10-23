"""HTTP routing, authentication, and endpoint dispatch."""

from __future__ import annotations

import base64
import hmac
import hashlib
import secrets
import time
import traceback
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlsplit

from openkapsel.auth.admin_ui import render_discovery, render_http_error
from openkapsel.auth.tokens import CredentialRenewalNotDue
from openkapsel.errors import ApiError
from openkapsel.web_assets import builtin_favicon, builtin_favicon_asset_etag
from openkapsel.routes import EndpointSpec, match_endpoint
from openkapsel.server_runtime.authentication import AuthenticatedRequest, RequestPrincipal

LOGGER = __import__("logging").getLogger("openkapsel")
SIGNED_GET_WINDOW_SECONDS = 300
SIGNED_GET_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
SIGNED_GET_RESERVED_QUERY = frozenset(
    {"req", "timestamp", "nonce", "body", "http_method", "signature"}
)
RESTRICTED_HTTP_HMAC_MAX_KEY_BYTES = 4096
RESTRICTED_HTTP_HMAC_MAX_TARGET_BYTES = 131072


def _hmac_base64url(key: bytes, message: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.digest(key, message, "sha256")).rstrip(b"=").decode("ascii")


class RequestDispatchMixin:
    def version_string(self) -> str:
        """Avoid exposing the Python runtime and stdlib HTTP server versions."""
        return "OpenKapsel"

    def _send_builtin_favicon(self, name: str = "favicon.svg", *, head_only: bool = False) -> None:
        data = builtin_favicon(name)
        etag = builtin_favicon_asset_etag(name)
        if self.headers.get("If-None-Match") == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        content_type = {"favicon.svg": "image/svg+xml; charset=utf-8",
                        "favicon.ico": "image/x-icon", "favicon.png": "image/png"}[name]
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if not head_only:
            self.wfile.write(data)


    def end_headers(self) -> None:
        # Capability URLs must never be disclosed through browser referrers.
        self.send_header("Referrer-Policy", "no-referrer")
        if getattr(self, "_signed_envelope_active", False):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()


    def do_GET(self) -> None:
        self._dispatch("GET")


    def do_HEAD(self) -> None:
        self._dispatch("HEAD")


    def do_POST(self) -> None:
        self._dispatch("POST")


    def do_PUT(self) -> None:
        self._dispatch("PUT")


    def do_PATCH(self) -> None:
        self._dispatch("PATCH")


    def do_DELETE(self) -> None:
        self._dispatch("DELETE")


    def _dispatch(self, method: str) -> None:
        # BaseHTTPRequestHandler reuses this instance for HTTP/1.1 keep-alive.
        # File approval is explicitly opt-in per request, so never retain its
        # temporary path/routing hints across requests on the same connection.
        self._file_approval_operation = None
        self._file_approval_active = False
        self._file_approval_denied_paths = frozenset()
        self._file_approval_external_scope = None
        self._file_approval_external_target = None
        self._file_approval_approved_directory = None
        self._file_function_request = None
        self._file_function_policy = None
        self.__dict__.pop("_file_approval_cached_body", None)
        self.oauth_connection_id = None
        self.static_mcp_connection_id = None
        self.principal = None
        self._signed_envelope_active = False
        self._signed_envelope_body = None
        self._signed_envelope_body_reader = None
        self._response_mode_envelope = False
        self._redact_request_query = False
        self._prepare_context_tracking(None, {})
        try:
            parsed = urlsplit(self.path)
            req_values = parse_qs(parsed.query, keep_blank_values=True).get("req", [])
            self._redact_request_query = any(
                parsed.path.rstrip("/").endswith("/" + route) or route in req_values
                for route in ("restricted_http/hmac", "transport/hmac")
            )
            if self._is_dedicated_preview_request():
                route = self._authenticate_request(method, parsed.path, parsed.query).route
                api_target = self._resolve_web_api_target(route)
                if api_target is not None:
                    self._handle_web_api(method, api_target, parsed.query)
                    return
                self._discard_request_body()
                if method not in {"GET", "HEAD"}:
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                self._handle_web_preview(
                    route,
                    parsed.path,
                    parsed.query,
                    head_only=method == "HEAD",
                )
                return
            if self._dispatch_oauth(method, parsed.path, parsed.query):
                return
            request_path = self._strip_url_base_path(parsed.path)
            # This is a response presentation preference, never an authorization
            # grant. When signed, the literal parameter remains in the raw query
            # covered by the HMAC until authentication has completed.
            if request_path.startswith("/w/"):
                response_modes = parse_qs(parsed.query, keep_blank_values=True).get("response_mode")
                if response_modes is not None and response_modes != ["envelope"]:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_response_mode",
                        "response_mode must appear once with value envelope",
                    )
                self._response_mode_envelope = response_modes == ["envelope"] and method != "HEAD"
            # MCP/OAuth branding must be fetchable without credentials even
            # when the administrator console is disabled. Never claim the
            # shared domain root favicon; only serve our configured prefix.
            if method in {"GET", "HEAD"} and request_path in {
                "/favicon.svg", "/favicon.ico", "/favicon.png"
            }:
                self._discard_request_body()
                self._send_builtin_favicon(request_path[1:], head_only=method == "HEAD")
                return
            if request_path.startswith("/mapping-connect/"):
                self._handle_mapping_provider(method, request_path)
                return
            if request_path == "/skills" or request_path.startswith("/skills/"):
                self._dispatch_skill(method, request_path)
                return
            if (request_path.startswith(("/password-setup/", "/capability/",
                                         "/admin/password-setup/", "/admin/capability/"))):
                if method != "POST":
                    self._discard_request_body()
                self._dispatch_user_page(method, request_path, parsed.query)
                return
            if request_path == "/admin" or request_path.startswith("/admin/"):
                if method != "POST":
                    self._discard_request_body()
                self._dispatch_admin(method, request_path, parsed.query)
                return
            # Layer 1 - authentication: identify the token, verify whichever
            # credential was supplied and record one RequestPrincipal.
            authenticated = self._authenticate_request(method, request_path, parsed.query)
            route = authenticated.route
            query = authenticated.query
            effective_method = authenticated.method
            query_routed = authenticated.query_routed
            # Layer 2 - routing: workspace web APIs, then the endpoint table.
            api_target = self._resolve_web_api_target(authenticated.entry_route)
            if api_target is not None:
                self._handle_web_api(method, api_target, parsed.query)
                return
            # Remove the presentation-only field *after* signed verification,
            # so the endpoint sees its normal query schema.
            query.pop("response_mode", None)
            if query_routed and (route == "/web" or route.startswith("/web/")):
                self._discard_request_body()
                raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
            if query_routed and route.rstrip("/") == "/mcp":
                self._discard_request_body()
                raise ApiError(404, "not_found", "Create an MCP connection in administration")
            if effective_method == "GET" and route in ("", "/"):
                self._prepare_context_tracking(None, query)
                self._discard_request_body()
                discovery = self._discovery()
                if self._wants_html():
                    self._send_html(
                        HTTPStatus.OK,
                        render_discovery(discovery),
                        headers={"Vary": "Authorization"},
                    )
                else:
                    self._send_json(
                        HTTPStatus.OK,
                        discovery,
                        headers={"Vary": "Authorization"},
                    )
            elif effective_method in {"GET", "HEAD"} and (route == "/web" or route.startswith("/web/")):
                self._prepare_context_tracking(None, query)
                self._discard_request_body()
                self._handle_web_preview(
                    route,
                    parsed.path,
                    parsed.query,
                    head_only=effective_method == "HEAD",
                )
            else:
                matched_endpoint = match_endpoint(effective_method, route)
                if matched_endpoint is None:
                    self._prepare_context_tracking(None, query)
                    self._discard_request_body()
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                endpoint, route_match = matched_endpoint
                if self._signed_envelope_body and not endpoint.request_body:
                    self._discard_request_body()
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "signed_envelope_body_not_allowed",
                        "body is not accepted by the requested endpoint",
                    )
                if endpoint.control_required:
                    self._require_control_token()
                self._prepare_context_tracking(endpoint, query)
                if not endpoint.request_body:
                    self._discard_request_body()
                self._dispatch_endpoint(endpoint, route_match, query, effective_method)
        except ApiError as exc:
            if (getattr(self, "_file_approval_active", False)
                    and exc.code in {"path_not_found", "path_outside_root",
                                     "path_access_denied", "read_only_path",
                                     "not_a_directory", "file_approval_path_mismatch",
                                     "file_approval_target_mismatch"}):
                exc = ApiError(404, "path_unavailable",
                               "path does not exist or access is denied")
            error_payload: dict[str, Any] = {
                "error": {"code": exc.code, "message": exc.message}
            }
            details = exc.details
            # Denied File/Shell operations never generate approval tickets.
            # A permission-like failure may be recoverable using an explicit
            # request_approval, but never imply that an explicit policy deny,
            # missing path, or OS permission can be overridden.
            file_access = getattr(self, "_file_approval_operation", None)
            shell_access = locals().get("route") == "/shell/exec"
            if exc.status in {403, 404} and (file_access or shell_access):
                if file_access and exc.code in {"permission_denied", "path_outside_root",
                                                "read_only_path", "path_unavailable",
                                                "capability_approval_required"}:
                    hint = ("If this may be a temporary File API permission issue, call "
                            "files.request_approval with the explicit target, access mode, "
                            "writer_nonce, in-progress Plan and a reason. Approval cannot "
                            "override protected paths or OS permissions.")
                elif shell_access and exc.code in {"permission_denied", "client_execution_disabled",
                                                   "capability_approval_required"}:
                    hint = ("If temporary unsandboxed Shell approval is appropriate, call "
                            "shell.request_approval with an explicit target, writer_nonce, "
                            "in-progress Plan and reason. Approval cannot override Shell "
                            "permission or a read-only Mapping.")
                else:
                    hint = None
                if hint:
                    details = {**(details if isinstance(details, dict) else {}),
                               "approval_hint": hint}
            if details is not None:
                error_payload["error"]["details"] = details
            if self._wants_html() and not self._response_mode_envelope:
                self._finalize_context_operation(exc.status, error_payload)
                self._send_html(
                    exc.status,
                    render_http_error(exc.status, exc.code, exc.message),
                    headers=exc.headers,
                )
                return
            self._send_json(exc.status, error_payload, headers=exc.headers)
        except (BrokenPipeError, ConnectionResetError):
            self._finalize_context_operation(
                499,
                {"error": {"code": "client_disconnected", "message": "client disconnected"}},
            )
            return
        except Exception:
            request_id = secrets.token_hex(6)
            LOGGER.error("unhandled request error %s\n%s", request_id, traceback.format_exc())
            error_payload = {
                "error": {
                    "code": "internal_error",
                    "message": "internal server error",
                    "request_id": request_id,
                }
            }
            if self._wants_html() and not self._response_mode_envelope:
                self._finalize_context_operation(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    error_payload,
                )
                self._send_html(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    render_http_error(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "internal server error",
                        request_id,
                    ),
                )
                return
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                error_payload,
            )


    @staticmethod
    def _query_ends_with_signature(raw_query: str) -> bool:
        if not raw_query:
            return False
        key, separator, _ = raw_query.rsplit("&", 1)[-1].partition("=")
        return bool(separator and key == "signature")


    @staticmethod
    def _route_from_req(value: str) -> str:
        if (
            not value
            or len(value) > 512
            or value.startswith("/")
            or value != value.strip()
            or any(char in value for char in ("\x00", "?", "#", "\\"))
        ):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_req_route",
                "req must be a non-empty relative route without a leading slash",
            )
        return "/" + value


    def _decode_query_route(
        self,
        query: dict[str, list[str]],
    ) -> tuple[str, dict[str, list[str]]]:
        req_values = query.pop("req", [])
        if len(req_values) != 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_req_route",
                "req must appear exactly once",
            )
        reserved = (SIGNED_GET_RESERVED_QUERY - {"req"}).intersection(query)
        if reserved:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "signed_envelope_required",
                "signed-envelope parameters require a final signature parameter",
            )
        return self._route_from_req(req_values[0]), query


    def _decode_signed_get_envelope(
        self,
        raw_query: str,
        *,
        outer_method: str = "GET",
        record: Any,
    ) -> tuple[str, str, dict[str, list[str]]]:
        self._signed_envelope_active = True
        if not raw_query.isascii():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_signed_envelope",
                "signed envelope query parameters must use ASCII URL encoding",
            )
        if outer_method not in SIGNED_GET_METHODS:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_signed_method", "unsupported HTTP method")
        native_method = outer_method != "GET"
        if not native_method and self._request_content_length(required=False):
            self._discard_request_body()
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "signed_envelope_transport_body",
                "signed GET envelopes carry JSON through the body query parameter",
            )
        raw_fields = raw_query.split("&")
        if len(raw_fields) < 2:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_signed_envelope", "signature must be final")
        last_key, last_separator, _ = raw_fields[-1].partition("=")
        method_key, method_separator, _ = raw_fields[-2].partition("=")
        if not last_separator or last_key != "signature":
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_signed_envelope", "signature must be final")
        if not native_method and (not method_separator or method_key != "http_method"):
            raise ApiError(
                HTTPStatus.BAD_REQUEST, "invalid_signed_envelope",
                "http_method must be penultimate and signature must be final",
            )
        try:
            pairs = parse_qsl(
                raw_query,
                keep_blank_values=True,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=256,
            )
        except (UnicodeError, ValueError):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_signed_envelope",
                "signed envelope query parameters are malformed",
            ) from None

        reserved_values = {name: [] for name in SIGNED_GET_RESERVED_QUERY}
        for key, value in pairs:
            if key in reserved_values:
                reserved_values[key].append(value)
        for name in (("req", "timestamp", "nonce", "signature") if native_method
                     else ("req", "timestamp", "nonce", "http_method", "signature")):
            if len(reserved_values[name]) != 1:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_signed_envelope",
                    f"{name} must appear exactly once",
                )
        if len(reserved_values["body"]) > 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_signed_envelope",
                "body must appear at most once",
            )
        if native_method:
            if reserved_values["http_method"]:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST, "signed_envelope_get_required",
                    "http_method is only valid with a signed GET envelope; native requests use the actual HTTP method",
                )
            if reserved_values["body"]:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST, "signed_envelope_transport_body",
                    "native signed requests must send the body as HTTP request bytes",
                )
            effective_method = outer_method
        else:
            if pairs[-1][0] != "signature" or pairs[-2][0] != "http_method":
                raise ApiError(
                    HTTPStatus.BAD_REQUEST, "invalid_signed_envelope",
                    "http_method must be penultimate and signature must be final",
                )
            effective_method = reserved_values["http_method"][0]
            if effective_method not in SIGNED_GET_METHODS:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST, "invalid_signed_method",
                    "http_method must be GET, HEAD, POST, PUT, PATCH, or DELETE",
                )

        timestamp_text = reserved_values["timestamp"][0]
        if (
            not timestamp_text
            or len(timestamp_text) > 12
            or not timestamp_text.isascii()
            or not timestamp_text.isdigit()
        ):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_signed_timestamp",
                "timestamp must be Unix time in whole seconds",
            )
        timestamp = int(timestamp_text)
        now = int(time.time())
        if abs(now - timestamp) > SIGNED_GET_WINDOW_SECONDS:
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "signed_envelope_expired",
                "timestamp is outside the signed-envelope acceptance window",
            )

        nonce = reserved_values["nonce"][0]
        if len(nonce) != 8 or not nonce.isascii() or not nonce.isalnum():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_signed_nonce",
                "nonce must be exactly 8 ASCII letters or digits",
            )

        supplied_signature = reserved_values["signature"][0]
        if (
            len(supplied_signature) != 43
            or not supplied_signature.isascii()
            or any(not (char.isalnum() or char in "_-") for char in supplied_signature)
        ):
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "invalid_signed_signature",
                "signature is invalid",
            )
        signed_query = raw_query.rsplit("&", 1)[0]
        key = record.control_token.encode("utf-8")
        if native_method:
            # METHOD/ binds the physical method; the body is left on the socket
            # and read by the endpoint exactly as with Authorization headers.
            signed_bytes = outer_method.encode("ascii") + b"/" + signed_query.encode("ascii")
            if not hmac.compare_digest(supplied_signature, _hmac_base64url(key, signed_bytes)):
                # Legacy native format also appends LF + lowercase SHA256 hex of the body.
                length = self._request_content_length(required=False)
                if length > self.server.config.max_body_bytes:
                    self.close_connection = True
                    raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "request body is too large")
                raw_body = self.rfile.read(length)
                if len(raw_body) != length:
                    self.close_connection = True
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_length", "request body is incomplete")
                self._signed_envelope_body = raw_body
                legacy_bytes = signed_bytes + b"\n" + hashlib.sha256(raw_body).hexdigest().encode("ascii")
                if not hmac.compare_digest(supplied_signature, _hmac_base64url(key, legacy_bytes)):
                    raise ApiError(
                        HTTPStatus.UNAUTHORIZED,
                        "invalid_signed_signature",
                        "signature is invalid",
                    )
        elif not hmac.compare_digest(supplied_signature, _hmac_base64url(key, signed_query.encode("ascii"))):
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "invalid_signed_signature",
                "signature is invalid",
            )

        identity = record.app_id or record.token
        if not self.server.tokens.consume_signed_nonce(
            identity,
            nonce,
            now=now,
            ttl_seconds=max(1, timestamp + SIGNED_GET_WINDOW_SECONDS - now),
        ):
            raise ApiError(
                HTTPStatus.CONFLICT,
                "signed_envelope_replay",
                "nonce has already been used within the acceptance window",
            )

        route = self._route_from_req(reserved_values["req"][0])
        if reserved_values["body"]:
            encoded_body = reserved_values["body"][0].encode("utf-8")
            if len(encoded_body) > self.server.config.max_body_bytes:
                raise ApiError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "body_too_large",
                    "signed-envelope body is too large",
                )
            self._signed_envelope_body = encoded_body

        query: dict[str, list[str]] = {}
        for key, value in pairs:
            if key in SIGNED_GET_RESERVED_QUERY:
                continue
            query.setdefault(key, []).append(value)
        return effective_method, route, query


    @property
    def control_authorized(self) -> bool:
        """Control authority derived only from the authenticated principal."""
        principal = getattr(self, "principal", None)
        return bool(principal is not None and principal.control)

    def _set_principal(
        self,
        record: Any,
        scope_root: Any,
        *,
        control: bool,
        method: str,
        connection_id: str | None = None,
    ) -> None:
        self.principal = RequestPrincipal(record, scope_root, control, method, connection_id)
        self.token_record = record
        self.token_scope_root = scope_root

    def _rebind_principal_record(self, record: Any) -> None:
        """Keep the principal coherent after a credential rotation."""
        scope_root = self.server.tokens.scope_root(record)
        principal = getattr(self, "principal", None)
        if principal is None:
            self.token_record = record
            self.token_scope_root = scope_root
            return
        self._set_principal(
            record, scope_root, control=principal.control,
            method=principal.method, connection_id=principal.connection_id,
        )

    def _authenticate_request(
        self, method: str, request_path: str, raw_query: str,
    ) -> AuthenticatedRequest:
        """Authentication layer for every API entrance.

        Connection entrances authenticate their MCP credential; workspace
        entrances authenticate the URL token, an optional Bearer control token
        and, at the workspace root, a signed query. Every path ends with exactly
        one ``_set_principal`` call before routing begins; credential checks
        never publish an intermediate principal.
        """
        query = parse_qs(raw_query, keep_blank_values=True)
        if self._is_dedicated_preview_request():
            route = self._preview_authenticated_route(request_path)
            return AuthenticatedRequest(route, route, method, query, False)
        if request_path.startswith("/connect/"):
            route = self._oauth_authenticated_route(request_path)
            return AuthenticatedRequest(route, route, method, query, False)
        if request_path.startswith("/mcp-connect/"):
            route = self._static_mcp_authenticated_route(request_path)
            return AuthenticatedRequest(route, route, method, query, False)
        record, scope_root, entry_route, via_preview_token = self._identify_workspace_token(request_path)
        control = self._verify_bearer_control(record)
        principal_method = "bearer_control" if control else ("preview" if via_preview_token else "url_token")
        if entry_route.rstrip("/") == "/mcp":
            raise ApiError(404, "not_found", "Create an MCP connection in administration")
        route, effective_method, query_routed = entry_route, method, False
        if entry_route in ("", "/"):
            if self._query_ends_with_signature(raw_query):
                effective_method, route, query = self._decode_signed_get_envelope(
                    raw_query, outer_method=method, record=record,
                )
                self.command = effective_method
                control = True
                principal_method = "signed_get" if method == "GET" else "signed_native"
                query_routed = True
            elif "req" in query:
                route, query = self._decode_query_route(query)
                query_routed = True
        self._set_principal(record, scope_root, control=control, method=principal_method)
        return AuthenticatedRequest(entry_route, route, effective_method, query, query_routed)

    def _identify_workspace_token(self, path: str) -> tuple[Any, Any, str, bool]:
        """Resolve the URL token of a workspace entrance without granting anything."""
        parts = path.split("/")
        if len(parts) < 3 or parts[1] != "w":
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        supplied = unquote(parts[2])
        route = "/" + "/".join(parts[3:]) if len(parts) > 3 else ""
        record = None
        via_preview_token = False
        if self.server.config.preview_base_url is None:
            record = self.server.tokens.authenticate_preview(supplied)
            if record is not None:
                route = "/web" + route
                via_preview_token = True
        if record is None:
            record = self.server.tokens.authenticate(supplied)
            if route == "/web" or route.startswith("/web/"):
                record = None
        if record is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        try:
            scope_root = self.server.tokens.scope_root(record)
        except ValueError:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist") from None
        return record, scope_root, route, via_preview_token

    def _verify_bearer_control(self, record: Any) -> bool:
        """Return True only for a valid Bearer control token bound to ``record``."""
        authorization_values = self.headers.get_all("Authorization") or []
        if not authorization_values:
            return False
        if len(authorization_values) != 1:
            self._raise_invalid_control_token()
        scheme, separator, credential = authorization_values[0].partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not credential
            or credential != credential.strip()
            or any(char.isspace() for char in credential)
        ):
            self._raise_invalid_control_token()
        control_record = self.server.tokens.authenticate_control(credential)
        if control_record is None:
            self._raise_invalid_control_token()
        if not secrets.compare_digest(control_record.token, record.token):
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "token_binding_mismatch",
                "the Bearer token does not belong to this read-only workspace URL",
            )
        return True


    def _preview_authenticated_route(self, path: str) -> str:
        parts = path.split("/")
        if len(parts) < 2 or parts[0] != "" or not parts[1]:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        supplied = unquote(parts[1])
        record = self.server.tokens.authenticate_preview(supplied)
        if record is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        try:
            scope_root = self.server.tokens.scope_root(record)
        except ValueError:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist") from None
        self._set_principal(record, scope_root, control=False, method="preview")
        tail = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
        return "/web" + tail


    def _is_dedicated_preview_request(self) -> bool:
        configured = self.server.config.preview_base_url
        if configured is None:
            return False
        expected_host = urlsplit(configured).hostname
        try:
            request_host = urlsplit("//" + self.headers.get("Host", "")).hostname
        except ValueError:
            return False
        return bool(
            expected_host
            and request_host
            and hmac.compare_digest(request_host.lower(), expected_host.lower())
        )


    def _wants_html(self) -> bool:
        return (
            not getattr(self, "_signed_envelope_active", False)
            and self.command == "GET"
            and "text/html" in self.headers.get("Accept", "").lower()
        )


    def _base_path(self) -> str:
        return f"{self.server.config.url_base_path}/w/{quote(self.token_record.token, safe='')}"


    def _strip_url_base_path(self, path: str) -> str:
        prefix = self.server.config.url_base_path
        if not prefix:
            return path
        if path == prefix:
            return "/"
        if not path.startswith(prefix + "/"):
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        return path[len(prefix) :]


    def _dispatch_endpoint(
        self,
        endpoint: EndpointSpec,
        route_match: Any,
        query: dict[str, list[str]],
        method: str,
    ) -> None:
        # File approval is authorized before the existing File handler runs.
        # The handler and Mapping client still enforce all path boundaries.
        from openkapsel.files.file_handlers import FILE_APPROVAL_READ, FILE_APPROVAL_WRITE
        if endpoint.name in FILE_APPROVAL_READ | FILE_APPROVAL_WRITE:
            if endpoint.invocation in {"query", "query_head"}:
                if self._authorize_file_approval(endpoint.name, query, query=True):
                    return
            elif endpoint.name in {
                "fs_manifest", "fs_read_files", "fs_read_large", "fs_mutate",
                "fs_replace_large", "fs_mkdir", "fs_move",
            }:
                body = self._read_json()
                self._file_approval_cached_body = body
                if self._authorize_file_approval(endpoint.name, body):
                    return
        handler = getattr(self, endpoint.handler)
        args: tuple[Any, ...] = ()
        kwargs: dict[str, Any] = {}
        if endpoint.invocation in {"query", "query_head"}:
            args = (query,)
        elif endpoint.invocation in {"param", "param_query", "param_head"}:
            if endpoint.parameter is None:
                raise RuntimeError(f"endpoint {endpoint.name} has no path parameter")
            parameter = route_match.group(endpoint.parameter)
            args = (parameter, query) if endpoint.invocation == "param_query" else (parameter,)
        if endpoint.invocation in {"query_head", "param_head"}:
            kwargs["head_only"] = method == "HEAD"
        if endpoint.transfer_slot:
            self._run_transfer(handler, *args, **kwargs)
        else:
            handler(*args, **kwargs)


    def _handle_restricted_http_hmac(self, query: dict[str, list[str]]) -> None:
        unexpected = sorted(set(query) - {"key", "target"})
        if unexpected:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_restricted_http_hmac",
                "restricted HTTP HMAC accepts only key and target query parameters",
            )

        values: dict[str, str] = {}
        for name in ("key", "target"):
            items = query.get(name, [])
            if len(items) != 1:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_restricted_http_hmac",
                    f"{name} must appear exactly once",
                )
            values[name] = items[0]

        key_bytes = values["key"].encode("utf-8")
        target_bytes = values["target"].encode("utf-8")
        if len(key_bytes) > RESTRICTED_HTTP_HMAC_MAX_KEY_BYTES:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "restricted_http_hmac_key_too_large",
                f"key must not exceed {RESTRICTED_HTTP_HMAC_MAX_KEY_BYTES} UTF-8 bytes",
            )
        if len(target_bytes) > RESTRICTED_HTTP_HMAC_MAX_TARGET_BYTES:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "restricted_http_hmac_target_too_large",
                f"target must not exceed {RESTRICTED_HTTP_HMAC_MAX_TARGET_BYTES} UTF-8 bytes",
            )

        result = _hmac_base64url(key_bytes, target_bytes)
        self._send_json(
            HTTPStatus.OK,
            {
                "algorithm": "HMAC-SHA256",
                "encoding": "base64url-nopad",
                "result": result,
            },
        )


    def _require_control_token(self) -> None:
        if getattr(self, "control_authorized", False):
            return
        raise ApiError(
            HTTPStatus.UNAUTHORIZED,
            "control_token_required",
            "this endpoint requires Authorization: Bearer <CONTROL_TOKEN>",
            headers={"WWW-Authenticate": 'Bearer realm="OpenKapsel"'},
        )


    def _handle_credential_renew(self) -> None:
        previous_token = self.token_record.token
        try:
            record = self.server.tokens.renew_credentials_if_due(previous_token)
        except CredentialRenewalNotDue as exc:
            raise ApiError(
                HTTPStatus.CONFLICT,
                "credentials_renewal_not_due",
                str(exc),
                details={
                    "credentials_expires_at": exc.expires_at,
                    "remaining_seconds": exc.remaining_seconds,
                    "renewal_window_seconds": 2 * 24 * 60 * 60,
                },
            ) from None
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.CONFLICT,
                "credentials_cannot_be_renewed",
                str(exc),
            ) from None
        workspace_url = (
            f"{self._public_base_url().rstrip('/')}/w/"
            f"{quote(record.token, safe='')}/"
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "read_token": record.token,
                "control_token": record.control_token,
                "workspace_url": workspace_url,
                "credentials_expires_at": record.credentials_expires_at,
            },
            headers={"Cache-Control": "no-store"},
        )


    @staticmethod
    def _raise_invalid_control_token() -> None:
        raise ApiError(
            HTTPStatus.UNAUTHORIZED,
            "invalid_control_token",
            "the Bearer control token is invalid or expired",
            headers={
                "WWW-Authenticate": 'Bearer realm="OpenKapsel", error="invalid_token"'
            },
        )


    def _admin_path(self) -> str:
        return f"{self.server.config.url_base_path}/admin"

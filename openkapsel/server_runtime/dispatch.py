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
from openkapsel.web_assets import builtin_favicon_etag, builtin_favicon_svg
from openkapsel.routes import EndpointSpec, match_endpoint

LOGGER = __import__("logging").getLogger("openkapsel")
SIGNED_GET_WINDOW_SECONDS = 300
SIGNED_GET_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
SIGNED_GET_RESERVED_QUERY = frozenset(
    {"req", "timestamp", "nonce", "body", "http_method", "signature"}
)
TRANSPORT_HMAC_MAX_KEY_BYTES = 4096
TRANSPORT_HMAC_MAX_TARGET_BYTES = 131072

class RequestDispatchMixin:
    def version_string(self) -> str:
        """Avoid exposing the Python runtime and stdlib HTTP server versions."""
        return "OpenKapsel"

    def _send_builtin_favicon(self, *, head_only: bool = False) -> None:
        data = builtin_favicon_svg()
        etag = builtin_favicon_etag()
        if self.headers.get("If-None-Match") == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
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
        self.oauth_connection_id = None
        self.static_mcp_connection_id = None
        self.control_authorized = False
        self._signed_envelope_active = False
        self._signed_envelope_body = None
        self._signed_envelope_body_reader = None
        self._redact_request_query = False
        self._prepare_context_tracking(None, {})
        try:
            parsed = urlsplit(self.path)
            req_values = parse_qs(parsed.query, keep_blank_values=True).get("req", [])
            self._redact_request_query = (
                parsed.path.rstrip("/").endswith("/transport/hmac")
                or "transport/hmac" in req_values
            )
            if self._is_dedicated_preview_request():
                route = self._preview_authenticated_route(parsed.path)
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
            if (
                self.server.config.admin_enabled
                and method in {"GET", "HEAD"}
                and request_path == "/favicon.svg"
            ):
                self._discard_request_body()
                self._send_builtin_favicon(head_only=method == "HEAD")
                return
            if request_path.startswith("/mapping-connect/"):
                self._handle_mapping_provider(method, request_path)
                return
            if request_path == "/skills" or request_path.startswith("/skills/"):
                self._dispatch_skill(method, request_path)
                return
            if request_path == "/admin" or request_path.startswith("/admin/"):
                if method != "POST":
                    self._discard_request_body()
                self._dispatch_admin(method, request_path, parsed.query)
                return
            if request_path.startswith("/share/query/") and method == "GET":
                parts = request_path.split("/")
                if len(parts) != 4 or not parts[3]:
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                self._discard_request_body()
                self._handle_share_query(parts[3], parse_qs(parsed.query, keep_blank_values=True))
                return
            if request_path.startswith("/connect/"):
                route = self._oauth_authenticated_route(request_path)
            elif request_path.startswith("/mcp-connect/"):
                route = self._static_mcp_authenticated_route(request_path)
            elif request_path == "/transfer" or request_path.startswith("/transfer/"):
                route = self._control_authenticated_transfer_route(request_path)
            else:
                route = self._authenticated_route(request_path)
                if route.rstrip("/") == "/mcp":
                    raise ApiError(404, "not_found", "Create an MCP connection in administration")
            api_target = self._resolve_web_api_target(route)
            if api_target is not None:
                self._handle_web_api(method, api_target, parsed.query)
                return
            query = parse_qs(parsed.query, keep_blank_values=True)
            effective_method = method
            query_routed = False
            if route in ("", "/"):
                if self._query_ends_with_signature(parsed.query):
                    effective_method, route, query = self._decode_signed_get_envelope(
                        parsed.query, outer_method=method,
                    )
                    self.command = effective_method
                    query_routed = True
                elif "req" in query:
                    route, query = self._decode_query_route(query)
                    query_routed = True
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
            error_payload: dict[str, Any] = {
                "error": {"code": exc.code, "message": exc.message}
            }
            if exc.details is not None:
                error_payload["error"]["details"] = exc.details
            if self._wants_html():
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
            if self._wants_html():
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
        signed_bytes = signed_query.encode("ascii")
        if native_method:
            length = self._request_content_length(required=False)
            if length > self.server.config.max_body_bytes:
                self.close_connection = True
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "request body is too large")
            raw_body = self.rfile.read(length)
            if len(raw_body) != length:
                self.close_connection = True
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_length", "request body is incomplete")
            # METHOD/ and the SHA256 of the *exact* body bytes bind both to the HMAC.
            signed_bytes = (outer_method.encode("ascii") + b"/" + signed_bytes
                            + b"\n" + hashlib.sha256(raw_body).hexdigest().encode("ascii"))
            self._signed_envelope_body = raw_body
        expected_signature = base64.urlsafe_b64encode(
            hmac.digest(
                self.token_record.control_token.encode("utf-8"),
                signed_bytes,
                "sha256",
            )
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ApiError(
                HTTPStatus.UNAUTHORIZED,
                "invalid_signed_signature",
                "signature is invalid",
            )

        identity = self.token_record.app_id or self.token_record.token
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
        self.control_authorized = True
        return effective_method, route, query


    def _authenticated_route(self, path: str) -> str:
        parts = path.split("/")
        if len(parts) < 3 or parts[1] != "w":
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        supplied = unquote(parts[2])
        route = "/" + "/".join(parts[3:]) if len(parts) > 3 else ""
        record = None
        if self.server.config.preview_base_url is None:
            record = self.server.tokens.authenticate_preview(supplied)
            if record is not None:
                route = "/web" + route
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
        self.token_record = record
        self.token_scope_root = scope_root
        self.control_authorized = False
        authorization_values = self.headers.get_all("Authorization") or []
        if authorization_values:
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
            self.control_authorized = True
        return route


    def _control_authenticated_transfer_route(self, path: str) -> str:
        route = path.removeprefix("/transfer")
        if route != "/fs/content" and not route.startswith("/upload/"):
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        authorization_values = self.headers.get_all("Authorization") or []
        if len(authorization_values) != 1:
            if not authorization_values:
                self._require_control_token()
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
        record = self.server.tokens.authenticate_control(credential)
        if record is None:
            self._raise_invalid_control_token()
        try:
            scope_root = self.server.tokens.scope_root(record)
        except ValueError:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist") from None
        self.token_record = record
        self.token_scope_root = scope_root
        self.control_authorized = True
        return route


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
        self.token_record = record
        self.token_scope_root = scope_root
        self.control_authorized = False
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


    def _handle_transport_hmac(self, query: dict[str, list[str]]) -> None:
        unexpected = sorted(set(query) - {"key", "target"})
        if unexpected:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_transport_hmac",
                "transport HMAC accepts only key and target query parameters",
            )

        values: dict[str, str] = {}
        for name in ("key", "target"):
            items = query.get(name, [])
            if len(items) != 1:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_transport_hmac",
                    f"{name} must appear exactly once",
                )
            values[name] = items[0]

        key_bytes = values["key"].encode("utf-8")
        target_bytes = values["target"].encode("utf-8")
        if len(key_bytes) > TRANSPORT_HMAC_MAX_KEY_BYTES:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "transport_hmac_key_too_large",
                f"key must not exceed {TRANSPORT_HMAC_MAX_KEY_BYTES} UTF-8 bytes",
            )
        if len(target_bytes) > TRANSPORT_HMAC_MAX_TARGET_BYTES:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "transport_hmac_target_too_large",
                f"target must not exceed {TRANSPORT_HMAC_MAX_TARGET_BYTES} UTF-8 bytes",
            )

        result = base64.urlsafe_b64encode(
            hmac.digest(key_bytes, target_bytes, "sha256")
        ).rstrip(b"=").decode("ascii")
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

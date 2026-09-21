"""HTTP routing, authentication, and endpoint dispatch."""

from __future__ import annotations

import hmac
import secrets
import traceback
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from openkapsel.auth.admin_ui import render_discovery, render_http_error
from openkapsel.auth.tokens import CredentialRenewalNotDue
from openkapsel.errors import ApiError
from openkapsel.routes import EndpointSpec, match_endpoint

LOGGER = __import__("logging").getLogger("openkapsel")

class RequestDispatchMixin:
    def version_string(self) -> str:
        """Avoid exposing the Python runtime and stdlib HTTP server versions."""
        return "OpenKapsel"


    def end_headers(self) -> None:
        # Capability URLs must never be disclosed through browser referrers.
        self.send_header("Referrer-Policy", "no-referrer")
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
        self._prepare_context_tracking(None, {})
        try:
            parsed = urlsplit(self.path)
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
            if request_path.startswith("/shares/") and method == "GET":
                parts = request_path.split("/")
                if len(parts) != 3 or not parts[2]:
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                self._discard_request_body()
                self._handle_share_query(parts[2], parse_qs(parsed.query, keep_blank_values=True))
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
            if method == "GET" and route in ("", "/"):
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
            elif method in {"GET", "HEAD"} and (route == "/web" or route.startswith("/web/")):
                self._prepare_context_tracking(None, query)
                self._discard_request_body()
                self._handle_web_preview(
                    route,
                    parsed.path,
                    parsed.query,
                    head_only=method == "HEAD",
                )
            else:
                matched_endpoint = match_endpoint(method, route)
                if matched_endpoint is None:
                    self._prepare_context_tracking(None, query)
                    self._discard_request_body()
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                endpoint, route_match = matched_endpoint
                if endpoint.control_required:
                    self._require_control_token()
                self._prepare_context_tracking(endpoint, query)
                if not endpoint.request_body:
                    self._discard_request_body()
                self._dispatch_endpoint(endpoint, route_match, query, method)
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
        if route != "/fs/content" and not route.startswith("/uploads/"):
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
        return self.command == "GET" and "text/html" in self.headers.get("Accept", "").lower()


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


    def _require_control_token(self) -> None:
        if getattr(self, "control_authorized", False):
            return
        raise ApiError(
            HTTPStatus.UNAUTHORIZED,
            "control_token_required",
            "this endpoint requires Authorization: Bearer <CONTROL_TOKEN>",
            headers={"WWW-Authenticate": 'Bearer realm="OpenKapsel"'},
        )


    def _handle_credentials_renew(self) -> None:
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

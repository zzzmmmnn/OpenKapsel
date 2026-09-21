"""OAuth discovery, dynamic registration, consent and MCP authentication."""

from __future__ import annotations

import base64
import binascii
import html
import re
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from openkapsel.auth.admin_ui import _page
from openkapsel.auth.oauth_consent import consent_page, consent_metadata
from openkapsel.auth.oauth_consent_handlers import OAuthConsentMixin
from openkapsel.errors import ApiError
from openkapsel.auth.oauth_store import OAuthError, SCOPE


CONNECTION_ID = r"[A-Za-z0-9_-]{32}"


class OAuthHandlersMixin(OAuthConsentMixin):
    def _oauth_base(self, cid: str) -> str:
        # Never derive an OAuth issuer or redirect from caller-controlled Host.
        if not self.server.config.public_base_url:
            raise OAuthError("temporarily_unavailable", "OAuth requires a configured public_base_url", 503)
        public = urlsplit(self.server.config.public_base_url)
        if public.scheme != "https" and not (public.scheme == "http" and public.hostname in {"127.0.0.1", "::1", "localhost"}):
            raise OAuthError("temporarily_unavailable", "OAuth requires HTTPS (HTTP loopback is allowed for local development)", 503)
        return self._public_base_url() + "/oauth/" + cid

    def _oauth_resource(self, cid: str) -> str:
        self._oauth_base(cid)
        return self._public_base_url() + "/connect/" + cid + "/mcp"

    def _oauth_resource_metadata_url(self, cid: str) -> str:
        resource = urlsplit(self._oauth_resource(cid))
        return f"{resource.scheme}://{resource.netloc}/.well-known/oauth-protected-resource{resource.path}"

    def _oauth_record(self, cid: str):
        connection = self.server.oauth.get(cid)
        record = self.server.tokens.get_by_app_id(connection["app_id"])
        if record is None or not record.valid or record.path_prefix != connection["workspace"]:
            raise OAuthError("access_denied", "Linked workspace is unavailable or its directory has changed", 403)
        return record

    @staticmethod
    def _oauth_fields(values: dict[str, list[str]]) -> dict[str, str]:
        if any(len(items) != 1 for items in values.values()):
            raise OAuthError("invalid_request", "Duplicate parameters are not allowed")
        return {key: items[0] for key, items in values.items()}

    def _dispatch_oauth(self, method: str, path: str, raw_query: str) -> bool:
        base_path = self.server.config.url_base_path
        # RFC 8414 / RFC 9728 insert .well-known before the issuer/resource path.
        as_match = re.fullmatch(r"/\.well-known/oauth-authorization-server" + re.escape(base_path) + r"/oauth/(" + CONNECTION_ID + r")", path)
        resource_match = re.fullmatch(r"/\.well-known/oauth-protected-resource" + re.escape(base_path) + r"/connect/(" + CONNECTION_ID + r")/mcp", path)
        local = path[len(base_path):] if path.startswith(base_path + "/") else path if not base_path else ""
        # Legacy GET links land on the new page, never on administrator login.
        # Reject old POSTs instead of forwarding any credential-bearing body.
        if local == "/admin/oauth/approve":
            try:
                if method != "GET":
                    raise OAuthError("invalid_request", "Reload authorization in the client; the old approval form is no longer accepted")
                self._discard_request_body()
                query = self._oauth_fields(parse_qs(raw_query, keep_blank_values=True, max_num_fields=4))
                if set(query) != {"request"}:
                    raise OAuthError("invalid_request", "Invalid authorization request")
                pending = self.server.oauth.request(query["request"])
                self._redirect(self._oauth_base(pending["connection_id"]) + "/consent?request=" + pending["id"])
            except (OAuthError, ValueError) as exc:
                self._send_html(getattr(exc, "status", 400), consent_page(error="Restart authorization from the client"), script_src="'none'")
            return True
        endpoint = re.fullmatch(r"/oauth/(" + CONNECTION_ID + r")/(resource|register|authorize|consent|token|\.well-known/oauth-authorization-server)", local)
        if endpoint and endpoint.group(2) == "consent":
            self._handle_oauth_consent(method, endpoint.group(1), raw_query)
            return True
        if not as_match and not resource_match and not endpoint:
            return False
        try:
            cid = (as_match or resource_match or endpoint).group(1)
            base = self._oauth_base(cid)
            resource = self._oauth_resource(cid)
            self._oauth_record(cid)
            action = "metadata" if as_match else "resource" if resource_match else endpoint.group(2)
            if method in {"GET", "HEAD"} and action in {"metadata", ".well-known/oauth-authorization-server"}:
                self._discard_request_body()
                self._send_json(200, {
                    "issuer": base, "authorization_endpoint": base + "/authorize",
                    "token_endpoint": base + "/token", "registration_endpoint": base + "/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
                    "code_challenge_methods_supported": ["S256"], "scopes_supported": [SCOPE],
                    "client_id_metadata_document_supported": False,
                    "openkapsel_consent": consent_metadata(),
                })
            elif method in {"GET", "HEAD"} and action == "resource":
                self._discard_request_body()
                self._send_json(200, {"resource": resource, "authorization_servers": [base],
                                      "scopes_supported": [SCOPE], "bearer_methods_supported": ["header"]})
            elif method == "POST" and action == "register":
                self._send_json(201, self.server.oauth.register(cid, self._read_json()))
            elif method == "GET" and action == "authorize":
                self._discard_request_body()
                params = self._oauth_fields(parse_qs(raw_query, keep_blank_values=True, max_num_fields=32))
                if "control_token" in params:
                    raise OAuthError("invalid_request", "Control credentials must not be sent in authorization URLs")
                rid = self.server.oauth.start(cid, params, resource)
                self._redirect(base + "/consent?request=" + rid)
            elif method == "POST" and action == "token":
                form = self._oauth_fields(self._read_form())
                auth_method = "client_secret_post" if "client_secret" in form else "none"
                headers = self.headers.get_all("Authorization") or []
                if headers:
                    if len(headers) != 1 or "client_secret" in form:
                        raise OAuthError("invalid_client", "Ambiguous client authentication", 401)
                    scheme, _, encoded = headers[0].partition(" ")
                    try:
                        if scheme.lower() != "basic":
                            raise ValueError()
                        client_id, secret = base64.b64decode(encoded, validate=True).decode("utf-8").split(":", 1)
                    except (ValueError, UnicodeError, binascii.Error):
                        raise OAuthError("invalid_client", "Invalid client authentication", 401) from None
                    client_id, secret = unquote(client_id), unquote(secret)
                    if "client_id" in form and form["client_id"] != client_id:
                        raise OAuthError("invalid_client", "Client ID mismatch", 401)
                    form.update(client_id=client_id, client_secret=secret)
                    auth_method = "client_secret_basic"
                self._send_json(200, self.server.oauth.exchange(cid, form, resource, auth_method))
            else:
                self._send_json(405, {"error": "invalid_request", "error_description": "Method not allowed"}, headers={"Allow": "POST" if action in {"register", "token"} else "GET"})
        except OAuthError as exc:
            self._send_json(exc.status, {"error": exc.code, "error_description": str(exc)})
        except ValueError:
            self._send_json(400, {"error": "invalid_request", "error_description": "Invalid OAuth parameters"})
        return True

    def _oauth_authenticated_route(self, path: str) -> str:
        match = re.fullmatch(r"/connect/(" + CONNECTION_ID + r")/(mcp|transfer/(?:fs/content|uploads/[^/]+(?:/commit)?))", path)
        if not match:
            raise ApiError(404, "not_found", "endpoint does not exist")
        cid, route = match.groups()
        try:
            record = self._oauth_record(cid)
            self._oauth_base(cid)
            headers = self.headers.get_all("Authorization") or []
            scheme, _, access = headers[0].partition(" ") if len(headers) == 1 else ("", "", "")
            if scheme.lower() != "bearer" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", access):
                raise OAuthError("invalid_token", "OAuth access token required", 401)
            self.server.oauth.authenticate(cid, access)
            self.token_record = record
            self.token_scope_root = self.server.tokens.scope_root(record)
            self.control_authorized = True
            self.oauth_connection_id = cid
            self.server.oauth.touch(cid)
        except OAuthError as exc:
            headers = {"WWW-Authenticate": f'Bearer resource_metadata="{self._oauth_resource_metadata_url(cid)}", scope="{SCOPE}"'} if exc.status == 401 else None
            raise ApiError(exc.status, exc.code, str(exc), headers=headers) from None
        except ValueError:
            raise ApiError(403, "access_denied", "Workspace directory is unavailable") from None
        return "/mcp" if route == "mcp" else "/" + route.removeprefix("transfer/")

    def _handle_admin_oauth(self, method: str, path: str, raw_query: str) -> None:
        try:
            if path in {"/admin/oauth", "/admin/static-mcp"} and method == "POST":
                session = self._require_admin_session()
                if session is None:
                    return
                form = self._read_form()
                if not self._valid_csrf(session, form):
                    raise OAuthError("access_denied", "CSRF validation failed", 403)
                static = path == "/admin/static-mcp"
                store = self.server.static_mcp if static else self.server.oauth
                if self._form_one(form, "action") == "create":
                    if not static:
                        self._oauth_base("")
                    record = self.server.tokens.get_by_app_id(self._form_one(form, "app_id"))
                    if record is None or not record.valid or record.path_prefix == ".":
                        raise OAuthError("invalid_request", "Select an active child workspace")
                    args = (self._form_one(form, "days") or "365",) if static else ()
                    store.create(record.app_id, record.path_prefix, self._form_one(form, "comment"), *args)
                elif self._form_one(form, "action") == "update":
                    record = self.server.tokens.get_by_app_id(self._form_one(form, "app_id"))
                    if record is None or not record.valid or record.path_prefix == ".":
                        raise OAuthError("invalid_request", "Select an active child workspace")
                    args = (self._form_one(form, "days") or None,) if static else ()
                    store.update(
                        self._form_one(form, "connection_id"),
                        self._form_one(form, "comment"),
                        *args,
                        app_id=record.app_id,
                        workspace=record.path_prefix,
                    )
                elif self._form_one(form, "action") == "delete":
                    store.delete(self._form_one(form, "connection_id"))
                else:
                    raise OAuthError("invalid_request", "Unknown connection action")
                self._redirect(self._admin_path() + ("#static-mcp" if static else "#connections"))
                return
            raise OAuthError("invalid_request", "Endpoint does not exist", 404)
        except OAuthError as exc:
            self._send_html(exc.status, _page("MCP connection", f'<main><h1>MCP connection</h1><p>{html.escape(str(exc))}</p><a href="{html.escape(self._admin_path())}">Administration</a></main>'))

"""Dedicated control-token consent endpoints, never administrator login."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlsplit

from .errors import ApiError
from .oauth_consent import consent_cookie, consent_page
from .oauth_store import OAuthError, REQUEST_SECONDS


class OAuthConsentMixin:
    def _consent_cookie_name(self):
        # __Host prevents sibling subdomains from injecting a shadow cookie.
        return "__Host-openkapsel_oauth" if self._request_is_https() else "openkapsel_oauth"

    def _consent_send_page(self, request, record, *, status=200, error=None, retry_after=None):
        name = self._consent_cookie_name()
        cookie, csrf = self.server.oauth_consent.issue(consent_cookie(self.headers, name), request, record)
        header = f"{name}={cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age={REQUEST_SECONDS}"
        if self._request_is_https():
            header += "; Secure"
        headers = {"Set-Cookie": header}
        if retry_after:
            headers["Retry-After"] = str(retry_after)
        callback = urlsplit(request["params"]["redirect_uri"])
        self._send_html(status, consent_page(request, record,
                        action=self._oauth_base(request["connection_id"]) + "/consent", csrf=csrf, error=error),
                        headers=headers, script_src="'none'",
                        form_action=f"'self' {callback.scheme}://{callback.netloc}")

    def _consent_check_origin(self):
        expected = urlsplit(self.server.config.public_base_url)
        def origin(value):
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError()
            return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            origins = self.headers.get_all("Origin") or []
            if len(origins) > 1 or (origins and (origins[0] == "null" or origin(origins[0]) != origin(expected.geturl())
                                              or urlsplit(origins[0]).path or urlsplit(origins[0]).query or urlsplit(origins[0]).fragment)):
                raise ValueError()
            if not origins:
                refs = self.headers.get_all("Referer") or []
                if len(refs) > 1 or (refs and origin(refs[0]) != origin(expected.geturl())):
                    raise ValueError()
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                raise ValueError()
        except ValueError:
            raise OAuthError("access_denied", "Consent must be submitted from this OpenKapsel authorization page", 403) from None

    def _handle_oauth_consent(self, method, cid, raw_query):
        request = record = None
        try:
            self._oauth_base(cid)
            if method == "GET":
                self._discard_request_body()
                query = self._oauth_fields(parse_qs(raw_query, keep_blank_values=True, max_num_fields=4))
                if set(query) != {"request"}:
                    raise OAuthError("invalid_request", "The authorization page requires only a request ID")
                rid = query["request"]
                form = None
            elif method == "POST":
                if raw_query or self._request_content_length(required=True) > 8192:
                    raise OAuthError("invalid_request", "Consent accepts a bounded form body, not query parameters")
                form = self._oauth_fields(self._read_form())
                if set(form) - {"request", "csrf", "decision", "control_token"}:
                    raise OAuthError("invalid_request", "Unknown consent form fields")
                rid = form.get("request", "")
                if form.get("decision") not in {"approve", "deny"}:
                    raise OAuthError("invalid_request", "Choose authorize or cancel explicitly")
                self._consent_check_origin()
            else:
                self._send_html(405, consent_page(error="Use GET or POST for authorization"),
                                headers={"Allow": "GET, POST"}, script_src="'none'")
                return
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", rid):
                raise OAuthError("invalid_request", "Invalid authorization request")
            request = self.server.oauth.request(rid)
            if request["connection_id"] != cid:
                request = None
                raise OAuthError("access_denied", "Authorization request does not belong to this connection", 403)
            record = self._oauth_record(cid)
            if (record.app_id, record.path_prefix) != (request["app_id"], request["workspace"]):
                request = record = None
                raise OAuthError("access_denied", "Connection ownership changed; restart authorization", 403)
            if form is None:
                self._consent_send_page(request, record)
                return
            retry = self.server.oauth_consent_limiter.take(self._admin_rate_limit_address(), rid)
            if retry:
                self._consent_send_page(request, record, status=429,
                    error="Too many authorization attempts; try again after the indicated delay", retry_after=retry)
                return
            cookie = consent_cookie(self.headers, self._consent_cookie_name())
            self.server.oauth_consent.verify(cookie, form.get("csrf"), request, record)
            if form["decision"] == "deny":
                params = self.server.oauth.deny(rid)
                query = {"error": "access_denied"}
            else:
                supplied = form.get("control_token", "").strip()
                if not supplied or len(supplied) > 1024 or not supplied.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in supplied):
                    raise OAuthError("access_denied", "A current control token for this exact configuration is required", 403)
                # Token lock precedes the OAuth transaction. Rotation or permission
                # changes cannot slip between this check and code publication.
                with self.server.tokens.control_authorization(supplied) as verified:
                    if verified is None or (verified.app_id, verified.path_prefix) != (request["app_id"], request["workspace"]):
                        raise OAuthError("access_denied", "A current control token for this exact configuration is required", 403)
                    self.server.oauth_consent.verify(cookie, form.get("csrf"), request, verified)
                    params, code = self.server.oauth.approve(rid, expected_binding=(verified.app_id, verified.path_prefix))
                query = {"code": code}
            if "state" in params:
                query["state"] = params["state"]
            uri = params["redirect_uri"]
            # 303 changes POST to GET. Never forward the control-token form to
            # the client with 307/308, and never put its values in the redirect.
            self._redirect(uri + ("&" if "?" in uri else "?") + urlencode(query))
        except (OAuthError, ApiError) as exc:
            if request is not None and record is not None:
                self._consent_send_page(request, record, status=int(exc.status), error=str(exc) if isinstance(exc, OAuthError) else exc.message)
            else:
                self._send_html(int(exc.status), consent_page(error=str(exc) if isinstance(exc, OAuthError) else exc.message), script_src="'none'")
        except ValueError:
            self._send_html(400, consent_page(error="Invalid authorization form"), script_src="'none'")

"""Browser-only OAuth consent protection, separate from administrator sessions.

No control credential is placed in cookies, signed forms, URLs or this module's
state. The browser proof binds the exact request and displayed permissions.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import threading
import time

from .oauth_store import OAuthError, REQUEST_SECONDS

COOKIE_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
CONSENT_WINDOW_SECONDS = 60
CONSENT_ADDRESS_ATTEMPTS = 10
CONSENT_REQUEST_ATTEMPTS = 5
MAX_CONSENT_BUCKETS = 4096


def consent_metadata():
    """Public flow description, shared by OAuth metadata and MCP Discovery."""
    return {"authentication": "matching_control_token", "administrator_login_required": False,
            "exact_configuration_required": True, "browser_csrf_required": True,
            "browser_proof_seconds": REQUEST_SECONDS,
            "attempt_window_seconds": CONSENT_WINDOW_SECONDS,
            "attempts_per_address": CONSENT_ADDRESS_ATTEMPTS,
            "attempts_per_request": CONSENT_REQUEST_ATTEMPTS,
            "credential_delivery": "same-origin consent form POST only; never client redirects or token endpoint",
            "oauth_lifetime": "independent of normal control-token renewal",
            "rest_credentials_exportable": True,
            "rest_credentials_tools": ["get_workspace_credentials", "renew_workspace_credentials"]}


def consent_cookie(headers, name: str) -> str | None:
    """Reject ambiguous cookie names rather than choosing a shadowing cookie."""
    values = []
    for header in headers.get_all("Cookie") or []:
        for part in header.split(";"):
            key, sep, value = part.strip().partition("=")
            if key == name and sep:
                values.append(value)
    if len(values) != 1 or not COOKIE_PATTERN.fullmatch(values[0]):
        return None
    return values[0]


def permission_fingerprint(record) -> str:
    # Daily credential rotation is not a permission change. Hash everything else
    # so a stale page cannot silently approve newly expanded permissions.
    public = {key: value for key, value in record.to_dict().items()
              if key not in {"token", "preview_token", "control_token", "created_at", "credentials_expires_at"}}
    return hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ConsentProtector:
    """Stateless, expiring HMAC proof bound to an unpredictable browser cookie."""
    def __init__(self):
        self._key = secrets.token_bytes(32)

    def _signature(self, cookie, expiry, request, record):
        material = [cookie, expiry, request["id"], request["connection_id"],
                    request["client_id"], request["params"], permission_fingerprint(record)]
        data = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def issue(self, cookie, request, record):
        if not isinstance(cookie, str) or not COOKIE_PATTERN.fullmatch(cookie):
            cookie = secrets.token_urlsafe(32)
        expires = int(min(request["expires_at"], time.time() + REQUEST_SECONDS))
        return cookie, f"{expires}.{self._signature(cookie, expires, request, record)}"

    def verify(self, cookie, proof, request, record):
        valid = isinstance(cookie, str) and COOKIE_PATTERN.fullmatch(cookie)
        valid = valid and isinstance(proof, str) and re.fullmatch(r"[0-9]{1,12}\.[0-9a-f]{64}", proof)
        if valid:
            raw_expiry, signature = proof.split(".")
            expiry = int(raw_expiry)
            now = time.time()
            valid = now < expiry <= request["expires_at"] and expiry <= now + REQUEST_SECONDS
            valid = valid and hmac.compare_digest(signature, self._signature(cookie, expiry, request, record))
        if not valid:
            raise OAuthError("access_denied", "Consent verification failed or permissions changed; reload this authorization page", 403)


class ConsentLimiter:
    """Atomic bounded window budgets; independent of admin password attempts."""
    def __init__(self):
        self._lock = threading.Lock()
        self._buckets = {}

    def take(self, address: str, request_id: str) -> int:
        """Reserve one POST attempt, returning retry seconds if disallowed."""
        with self._lock:
            now = time.monotonic()
            self._buckets = {k: v for k, v in self._buckets.items() if v[0] > now}
            keys = [("address", address, CONSENT_ADDRESS_ATTEMPTS),
                    ("request", request_id, CONSENT_REQUEST_ATTEMPTS)]
            missing = sum((kind, value) not in self._buckets for kind, value, _ in keys)
            if len(self._buckets) + missing > MAX_CONSENT_BUCKETS:
                return CONSENT_WINDOW_SECONDS
            retry = 0
            for kind, value, limit in keys:
                until, count = self._buckets.get((kind, value), (now + CONSENT_WINDOW_SECONDS, 0))
                if count >= limit:
                    retry = max(retry, max(1, int(until - now + .999)))
            if retry:
                return retry
            for kind, value, _ in keys:
                until, count = self._buckets.get((kind, value), (now + CONSENT_WINDOW_SECONDS, 0))
                self._buckets[(kind, value)] = (until, count + 1)
            return 0


STYLE = """
:root{color-scheme:light dark}*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,sans-serif;background:light-dark(#f5f5f7,#18181b);color:light-dark(#1d1d1f,#f5f5f7)}main{max-width:680px;margin:5vh auto;padding:22px}.card{padding:28px;border:1px solid #8886;border-radius:16px;background:light-dark(#fff,#27272a)}h1{font-size:25px;margin:0 0 16px}h2{font-size:17px}p{overflow-wrap:anywhere}label{display:block;font-weight:600;margin:20px 0 6px}input{width:100%;padding:12px;border:1px solid #888;border-radius:8px;font:inherit}button{padding:11px 16px;border:1px solid #8886;border-radius:8px;font:inherit;cursor:pointer;background:#0769cf;color:white}button.secondary{background:transparent;color:inherit}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}.notice,.error{padding:12px;border:1px solid #8886;border-radius:8px}.error{border-color:#cf4848}dl{display:grid;grid-template-columns:130px 1fr;gap:8px}dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}code{overflow-wrap:anywhere}small{opacity:.8}
"""


def consent_page(request=None, record=None, *, action="", csrf="", error=None) -> str:
    """No scripts, remote assets, credential echo, or administrator navigation."""
    esc = html.escape
    body = f'<p class="error" role="alert">{esc(error)}</p>' if error else ""
    if request is not None:
        conn, client = request["connection"], request["client"]
        allowed = lambda value: "Allowed" if value else "Not allowed"
        # The public consent page must not reveal service-host directory names.
        extras = f"{len(record.allowed_paths)} administrator-configured extra path(s)" if record.allowed_paths else "None"
        shell_notice = ('<p class="notice"><strong>Full Shell:</strong> commands run with the service OS account privileges, '
                        'without workspace-path or network-policy confinement.</p>' if record.shell_mode == "full" else "")
        body += f'''<p>Authorize this client using the current <strong>control token</strong> for the configuration below. Administrator sign-in is not required.</p>
<dl><dt>Connection</dt><dd>{esc(conn['comment'])}</dd><dt>Workspace</dt><dd>{esc(conn['workspace'])}</dd><dt>Configuration</dt><dd>{esc(record.name)}</dd><dt>Client</dt><dd>{esc(client['client_name'])} <small>(self-reported, not verified)</small></dd><dt>Client ID</dt><dd>{esc(request['client_id'])}</dd><dt>Return address</dt><dd>{esc(request['params']['redirect_uri'])}</dd></dl>
<h2>Permissions granted to this client</h2>
<dl><dt>Files</dt><dd>Read: {allowed(record.can_read)}; Write: {allowed(record.can_write)}</dd><dt>Shell</dt><dd>{esc(record.shell_mode)}</dd><dt>Schedules</dt><dd>{allowed(record.can_schedule)}</dd><dt>Preview</dt><dd>{allowed(record.can_preview)}</dd><dt>Network</dt><dd>{esc(record.network_mode)}</dd><dt>Extra paths</dt><dd>{esc(extras)}</dd></dl>
{shell_notice}<p class="notice">Authorize only a client you intended to connect. It receives this configuration's current permissions, including enabled Shell operations, and may export or rotate this configuration's portable REST workspace URL and control token through MCP tools. Later permission changes also apply. OAuth access continues independently of normal control-token renewal. Revoke the OAuth connection as well if a token was compromised.</p>
<form method="post" action="{esc(action, quote=True)}" autocomplete="off">
<input type="hidden" name="request" value="{esc(request['id'], quote=True)}">
<input type="hidden" name="csrf" value="{esc(csrf, quote=True)}">
<label for="control-token">Control token</label><input id="control-token" type="password" name="control_token" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="1024" required>
<p><small>The token is verified only by OpenKapsel. It is not sent to the client, saved in this form, or used to sign in to administration.</small></p>
<div class="actions"><button name="decision" value="approve">Verify and authorize</button><button name="decision" value="deny" class="secondary" formnovalidate>Cancel</button></div></form>'''
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize MCP connection - OpenKapsel</title><style>{STYLE}</style></head><body><main><section class="card"><h1>Authorize MCP connection</h1>{body}</section></main></body></html>'

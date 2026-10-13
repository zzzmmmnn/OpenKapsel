"""Browser approvals and administrator management for temporary capabilities."""
from __future__ import annotations

import html
import ipaddress
import logging
import re
import secrets
from urllib.parse import urlsplit

from openkapsel.auth.capability_grants import PENDING_SECONDS
from openkapsel.auth.oauth_consent import STYLE, consent_cookie
from openkapsel.auth.oauth_store import OAuthError
from openkapsel.errors import ApiError

LOGGER = logging.getLogger("openkapsel.capability")


def page(body):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Temporary capabilities - OpenKapsel</title><style>{STYLE}</style>'
            f'</head><body><main><section class="card">{body}</section></main></body></html>')


class CapabilityHandlersMixin:
    def _require_password_transport(self):
        if self._request_is_https():
            return
        host = urlsplit(self._public_base_url()).hostname
        try:
            local = ipaddress.ip_address(host).is_loopback and ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            local = host == "localhost" and ipaddress.ip_address(self.client_address[0]).is_loopback
        if not local:
            raise ApiError(403, "https_required", "Workspace passwords require HTTPS (or local loopback development)")

    def _require_capability(self, body, target, capability):
        self._require_password_transport()
        if not self.server.config.admin_enabled:
            raise ApiError(409, "capability_unavailable", "Capability approval requires administration to be enabled")
        plan = self._parse_operation_plan_id(body.get("plan_id", self._context_header_plan_id()), required=True)
        try:
            conversation = self.server.context_for(self.token_scope_root).capability_conversation(plan, body.get("writer_nonce"))
        except PermissionError:
            raise ApiError(403, "conversation_writer_nonce_mismatch", "Conversation writer_nonce does not match") from None
        except (ValueError, KeyError) as exc:
            raise ApiError(400, "invalid_capability_conversation", str(exc)) from None
        # Workspace password/grants belong to the Token record, not the
        # filesystem directory shared by potentially many Tokens.
        workspace = self.token_record.app_id
        grants = self.server.capability_grants
        if grants.granted(workspace, conversation, target, capability):
            return
        try:
            ticket = grants.request(workspace, conversation, target, capability)
        except RuntimeError:
            raise ApiError(429, "capability_approval_capacity", "Too many pending capability approvals; retry later") from None
        LOGGER.info("approval requested workspace=%r conversation=%s target=%r capability=%s", workspace, conversation, target, capability)
        raise ApiError(403, "capability_approval_required", "Pause operation and request user approval.", {
            "approval_url": self._public_base_url() + "/admin/capability/" + ticket,
            "approval_expires_in": PENDING_SECONDS, "capability": capability, "target": target,
        })

    def _capability_binding(self, item):
        record = self.server.tokens.get_by_app_id(item.workspace)
        if record is None or not record.valid:
            raise ValueError("Token Workspace is unavailable")
        if item.target == "server":
            return "Workspace Server"
        row = self.server.mappings.store.get(item.target)
        if row["workspace"] != record.path_prefix or not row["enabled"]:
            raise ValueError("Mapping is unavailable or ownership changed")
        return row["name"] + " (" + item.target + ")"

    def _handle_capability_approval(self, method, ticket, raw_query):
        grants = self.server.capability_grants
        status, error = 200, ""
        try:
            self._require_password_transport()
            if raw_query or not re.fullmatch(r"[A-Za-z0-9_-]{32}", ticket):
                raise ValueError("Invalid approval URL")
            item = grants.pending(ticket)
            if item is None:
                raise ValueError("Approval expired or already used; ask the AI to retry")
            target = self._capability_binding(item)
            name = "__Host-openkapsel_capability" if self._request_is_https() else "openkapsel_capability"
            cookie = consent_cookie(self.headers, name)
            if method == "POST":
                if self._request_content_length(required=True) > 8192:
                    raise ValueError("Approval form is too large")
                form = self._read_form()
                if any(len(values) != 1 for values in form.values()) or set(form) - {"csrf", "password", "minutes"}:
                    raise ValueError("Invalid approval form")
                # Reuse the OAuth browser origin checks, independent of OAuth credentials.
                try:
                    self._consent_check_origin()
                except OAuthError as exc:
                    raise ApiError(exc.status, "csrf_failed", str(exc)) from None
                if not grants.verify_browser(ticket, cookie, self._form_one(form, "csrf")):
                    raise ApiError(403, "csrf_failed", "Approval verification failed; reload this page")
                retry = self.server.capability_limiter.take(self._admin_rate_limit_address(), "workspace:" + item.workspace)
                if retry:
                    self._send_html(429, page("<h1>Too many approval attempts</h1><p>Retry after the indicated delay.</p>"),
                                    headers={"Retry-After": str(retry)}, script_src="'none'")
                    return
                minutes = int(self._form_one(form, "minutes") or "10")
                with self.server.workspace_admin_lock:
                    self._capability_binding(item)
                    grants.approve(ticket, self._form_one(form, "password"), minutes * 60)
                LOGGER.info("approved workspace=%r conversation=%s target=%r capability=%s seconds=%s", item.workspace, item.conversation_id, item.target, item.capability, minutes * 60)
                self._send_html(200, page("<h1>Capability approved</h1><p>The AI may retry its operation now. This page has not executed any command.</p>"), script_src="'none'")
                return
            if method != "GET":
                self._send_html(405, page("<h1>Use GET or POST</h1>"), headers={"Allow": "GET, POST"}, script_src="'none'")
                return
        except PermissionError:
            LOGGER.info("approval password rejected workspace=%r", item.workspace)
            status, error = 403, "Workspace password incorrect or approval attempts exhausted"
        except (ValueError, KeyError):
            self._send_html(400, page("<h1>Approval unavailable</h1><p>Invalid, expired, used, or unavailable approval. Ask the AI to retry.</p>"), script_src="'none'")
            return
        # GET and recoverable wrong-password responses never echo credentials.
        cookie = cookie or secrets.token_urlsafe(32)
        proof = grants.browser_proof(ticket, cookie)
        esc = html.escape
        body = f'<h1>Approve temporary capability</h1><p class="error">{esc(error)}</p>' if error else '<h1>Approve temporary capability</h1>'
        warning = ("Shell elevation runs as the target's current OS user without sandbox restrictions. "
                   if item.capability == "shell.elevated" else "")
        workspace_record = self.server.tokens.get_by_app_id(item.workspace)
        workspace_label = (f"{workspace_record.name} ({workspace_record.path_prefix})"
                           if workspace_record else "Unavailable Token")
        body += f'''<dl><dt>Workspace Token</dt><dd>{esc(workspace_label)}</dd><dt>Token ID</dt><dd>{esc(item.workspace)}</dd><dt>Conversation ID</dt><dd>{item.conversation_id}</dd><dt>Target</dt><dd>{esc(target)}</dd><dt>Capability</dt><dd>{esc(item.capability)}</dd></dl>
<p class="notice">{esc(warning)}Approve only the conversation and target you intend.</p>
<form method="post" action="{esc(self._admin_path() + '/capability/' + ticket, quote=True)}" autocomplete="off">
<input type="hidden" name="csrf" value="{proof}"><label>Workspace password</label><input type="password" name="password" required maxlength="1024" autocomplete="off">
<label>Duration (minutes)</label><input type="number" name="minutes" min="1" max="1440" value="10" required><div class="actions"><button>Approve</button></div></form>
<p>The URL expires after five minutes and can be approved once. Approval does not rerun the operation. Restarting the server clears all temporary grants.</p>'''
        header = f"{name}={cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300" + ("; Secure" if self._request_is_https() else "")
        self._send_html(status, page(body), headers={"Set-Cookie": header}, script_src="'none'")

    def _handle_admin_capabilities(self, method):
        session = self._require_admin_session()
        if session is None:
            return
        self._require_password_transport()
        grants = self.server.capability_grants
        workspaces = sorted(self.server.tokens.list(), key=lambda record: record.name)
        message, status = "", 200
        if method == "POST":
            form = self._read_form()
            if any(len(values) != 1 for values in form.values()) or not self._form_one(form, "csrf").isascii() or not self._valid_csrf(session, form):
                raise ApiError(403, "csrf_failed", "CSRF validation failed")
            workspace = self._form_one(form, "workspace")
            try:
                with self.server.workspace_admin_lock:
                    record = self.server.tokens.get_by_app_id(workspace)
                    if record is None:
                        raise ValueError("Unknown Token Workspace")
                    action = self._form_one(form, "action")
                    if action == "password":
                        return_to = self._form_one(form, "return_to")
                        token_app_id = self._form_one(form, "token_app_id")
                        if return_to:
                            if return_to != "token" or not re.fullmatch(
                                r"[A-Za-z0-9_-]{1,128}", token_app_id
                            ) or not any(
                                item.app_id == token_app_id == workspace
                                for item in self.server.tokens.list()
                            ):
                                raise ValueError("Invalid token password settings return target")
                        grants.set_password(workspace, self._form_one(form, "password"))
                        message = "Workspace password updated; all pending approvals and active grants revoked."
                        if return_to == "token":
                            self._redirect(
                                f"{self._admin_path()}?workspace_password_changed=1"
                                f"#token-{token_app_id}-credentials"
                            )
                            return
                    elif action == "revoke":
                        grants.revoke(workspace, int(self._form_one(form, "conversation_id")),
                                      self._form_one(form, "target"), self._form_one(form, "capability"))
                        message = "Grant revoked."
                    else:
                        raise ValueError("Unknown action")
                LOGGER.info("admin capability action=%s workspace=%r", action, workspace)
            except ValueError as exc:
                message, status = str(exc), 400
        elif method != "GET":
            self._send_html(405, page("<h1>Use GET or POST</h1>"), headers={"Allow": "GET, POST"}, script_src="'none'")
            return
        esc = html.escape
        action_url = esc(self._admin_path() + "/capabilities", quote=True)
        body = (f'<h1>Workspace passwords and grants</h1>'
                '<p>Set a separate password for each Workspace. This is used for temporary '
                'Shell elevation approvals and is not the administrator login password.</p>'
                f'<p>{esc(message)}</p><p><a href="{esc(self._admin_path(), quote=True)}">'
                'Back to administration</a></p>')
        for record in workspaces:
            workspace = record.app_id
            hidden = f'<input type="hidden" name="csrf" value="{esc(session.csrf, quote=True)}"><input type="hidden" name="workspace" value="{esc(workspace, quote=True)}">'
            body += f'<h2>{esc(record.name)} · {esc(record.path_prefix)}</h2><p>Password: {"Configured" if grants.configured(workspace) else "Not configured"}</p><form method="post" action="{action_url}">{hidden}<input type="hidden" name="action" value="password"><label>Set or reset workspace password</label><input type="password" name="password" minlength="6" maxlength="1024" required autocomplete="new-password"><div class="actions"><button>Save password and revoke grants</button></div></form>'
            for grant in grants.list_grants(workspace):
                fields = "".join(f'<input type="hidden" name="{key}" value="{esc(str(grant[key]), quote=True)}">' for key in ("conversation_id", "target", "capability"))
                body += f'<p>Conversation {grant["conversation_id"]} · {esc(grant["target"])} · {esc(grant["capability"])} · {grant["remaining_seconds"]} seconds remaining</p><form method="post" action="{action_url}">{hidden}{fields}<button name="action" value="revoke">Revoke</button></form>'
        self._send_html(status, page(body), script_src="'none'")

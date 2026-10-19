"""Generic, function-owned Approval transport.

Only the function controls the meaning of request and auth JSON.  The server
handles conversation/target binding, display URL and browser confirmation.
"""
from __future__ import annotations

import html
import json
import re

from openkapsel.auth.capability_grants import PENDING_SECONDS
from openkapsel.auth.capability_handlers import page
from openkapsel.auth.oauth_consent import consent_cookie
from openkapsel.auth.oauth_store import OAuthError
from openkapsel.errors import ApiError


class FunctionApprovalHandlersMixin:
    def _function_target(self, target):
        if target == "server":
            return None
        row = self._mapping_for_caller(target)
        if not row["enabled"]:
            raise ApiError(409, "mapping_unavailable", "Mapping is disabled")
        return row

    def _function_methods(self, function, target, row=None):
        if row is None and target == "server":
            registry = self.server.local_client.functions
            try:
                return registry.approval_methods(function)
            except KeyError:
                return ()
        if row is None:
            return ()
        with self.server.mappings.lock:
            session = self.server.mappings.sessions.get(row["id"])
            if session is None or session.closed or not session.ready:
                raise ApiError(503, "mapping_unavailable", "Mapping Client is offline")
            funcs = session.capabilities.get("functions", {})
            metadata = funcs.get(function) if isinstance(funcs, dict) else None
        if not isinstance(metadata, dict) or metadata.get("approval") is not True:
            return ()
        return ("approval.prepare", "approval.grant") if metadata.get(
            "approval_prepare") is True else ("approval.grant",)

    def _function_internal(self, target, envelope):
        if target == "server":
            return self.server.local_client.functions.dispatch_internal(envelope)
        # Browser approval has no caller Token. Target ownership was checked
        # against the pending ticket's Workspace before reaching this method.
        row = self.server.mappings.store.get(target)
        if row is None or not row["enabled"]:
            raise ApiError(409, "mapping_unavailable", "Mapping is unavailable")
        return self._mapping_rpc(row, "function", envelope, retry=False)

    def _handle_function_approval_request(self, body=None, *, response_fields=None):
        if body is None:
            body = self._read_json()
        if set(body) - {"function", "target", "args", "reason",
                        "writer_nonce", "plan_id", "taskname", "message"}:
            raise ApiError(400, "invalid_request", "unexpected approval request fields")
        function, target = body.get("function"), body.get("target")
        args = body.get("args", {})
        if (not isinstance(function, str) or not re.fullmatch(
                r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", function)
                or not isinstance(target, str) or not target
                or not isinstance(args, dict)):
            raise ApiError(400, "invalid_request", "function, target and args are required")
        if function == "shell.exec":
            self._require_permission(self.token_record.shell_mode != "none",
                                     "Shell permission is required for approval")
        elif function not in {"files.read", "files.write"}:
            self._require_permission(self.token_record.can_write,
                                     "write permission is required for approval")
        row = self._function_target(target)
        if row is not None:
            if function in {"shell.exec", "files.write"} and not row["writable"]:
                raise ApiError(403, "mapping_read_only", "Mapping Shell is read-only")
            target = row["id"]
        methods = self._function_methods(function, target, row)
        if "approval.grant" not in methods:
            raise ApiError(409, "function_approval_unavailable",
                           "this function does not support Approval")
        self._require_control_token()
        # Identical Conversation/Plan validation to the legacy approvals.
        conversation = self._file_approval_conversation(body)
        if (row is not None and function in {"shell.exec", "files.read", "files.write"}
                and self.server.mappings.full_approval_status(target)["active"]):
            permission = (self.token_record.can_read if function == "files.read"
                          else self.token_record.can_write)
            self._require_permission(permission, "permission is not granted")
            if function == "shell.exec" and not row["allow_exec"]:
                raise ApiError(403, "client_execution_disabled", "Mapping execution is disabled")
            self._send_json(200, {**(response_fields or {}), "status": "granted",
                "function": function, "target": target,
                **({"capability": "shell.unsandboxed"} if function == "shell.exec" else {})})
            return
        if (row is not None and function in {"files.read", "files.write"}
                and self.server.mappings.supports_configured_file_paths(target)):
            permitted = self.token_record.can_write if function == "files.write" else self.token_record.can_read
            if permitted:
                checked = self._function_internal(target, {"function": function, "method": "execute",
                    "args": {"operation": "approval_status", "arguments": args},
                    "internal": {"auth": {"configured_client_paths": True}}})
                if isinstance(checked, dict) and checked.get("granted") is True:
                    self._send_json(200, {**(response_fields or {}), "status": "granted",
                                          "function": function, "target": target})
                    return
        self._require_password_transport()
        if not self.server.config.admin_enabled:
            raise ApiError(409, "capability_unavailable", "Capability approval requires administration to be enabled")
        reason = body.get("reason", body.get("message", ""))
        if (not isinstance(reason, str) or len(reason) > 500
                or any(ord(c) < 32 and c not in "\n\r\t" for c in reason)
                or "reason" in body and not reason.strip()):
            raise ApiError(400, "invalid_approval_reason", "reason must be non-empty text of at most 500 characters")
        display = None
        if "approval.prepare" in methods:
            # The client is the only component allowed to inspect and
            # interpret the requested scope.
            display = self._function_internal(target, {
                "function": function, "method": "approval.prepare", "args": args,
            })
            if isinstance(display, dict) and display.get("allowed") is False:
                raise ApiError(403, "function_approval_rejected",
                               "the function does not permit this approval")
            if isinstance(display, dict) and "request" in display:
                args = display["request"]
        try:
            ticket = self.server.function_grants.request(
                self.token_record.app_id, conversation, target, function,
                args, display=display if display is not None else {"request": args}, reason=reason,
            )
        except (TypeError, ValueError) as exc:
            raise ApiError(400, "invalid_approval_request", str(exc)) from None
        self._send_json(200, {
            **(response_fields or {}),
            "status": "approval_required",
            "approval_url": self._public_base_url() + "/capability/" + ticket,
            "approval_expires_in": PENDING_SECONDS,
            "function": function, "target": target,
            **({"capability": "shell.unsandboxed"} if function == "shell.exec" else {}),
        })

    def _function_binding(self, entry):
        record = self.server.tokens.get_by_app_id(entry.workspace)
        if record is None or not record.valid:
            raise ApiError(409, "approval_target_unavailable", "Token is unavailable")
        if entry.target != "server":
            row = self.server.mappings.store.get(entry.target)
            if (row is None or row["workspace"] != record.path_prefix or not row["enabled"]
                    or entry.function in {"shell.exec", "files.write"} and not row["writable"]):
                raise ApiError(409, "approval_target_unavailable", "Mapping is unavailable")
        return record

    def _function_confirmation_page(self, entry, ticket, proof, proposed):
        # Display the Client's entire proposal as JSON. The Server does not
        # extract or interpret paths, access modes, or any other auth fields.
        title = ("Confirm actual File access directory" if entry.function.startswith("files.")
                 else "Confirm function authorization")
        detail = "Actual authorized directory / Client proposal" if entry.function.startswith("files.") else "Client proposal"
        summary = html.escape(json.dumps(proposed, ensure_ascii=False, indent=2))
        action = html.escape(self._admin_path().removesuffix("/admin") + "/capability/" + ticket, quote=True)
        return page(f"<h1>{title}</h1><p>{detail}</p><pre>{summary}</pre>"
            f"<p><strong>AI request reason:</strong> {html.escape(entry.reason or 'Not provided by the AI')}</p>"
            f'<form method="post" action="{action}"><input type="hidden" name="csrf" value="{proof}">'
            '<button name="confirm" value="actual_path">Confirm and approve</button></form>')

    def _handle_function_approval(self, method, ticket):
        grants, store = self.server.capability_grants, self.server.function_grants
        entry = store.pending(ticket)
        if entry is None:
            raise ApiError(400, "approval_unavailable", "approval expired or already used")
        self._require_password_transport()
        record = self._function_binding(entry)
        name = "__Host-openkapsel_capability" if self._request_is_https() else "openkapsel_capability"
        cookie = consent_cookie(self.headers, name)
        proof = grants.browser_proof(ticket, cookie) if cookie else ""
        callback = lambda old, request, seconds: self._function_internal(entry.target, {
            "function": entry.function, "method": "approval.grant",
            "old_auth": old, "request": request, "seconds": seconds})
        if method == "POST":
            if self._request_content_length(required=True) > 8192:
                raise ApiError(413, "approval_too_large", "form is too large")
            form = self._read_form()
            if (any(len(v) != 1 for v in form.values())
                    or set(form) - {"csrf", "password", "minutes", "confirm"}):
                raise ApiError(400, "invalid_request", "invalid approval form")
            try:
                self._consent_check_origin()
            except OAuthError as exc:
                raise ApiError(exc.status, "csrf_failed", str(exc)) from None
            if not grants.verify_browser(ticket, cookie, self._form_one(form, "csrf")):
                raise ApiError(403, "csrf_failed", "approval verification failed")
            confirm = self._form_one(form, "confirm")
            with self.server.workspace_admin_lock:
                self._function_binding(entry)
                try:
                    if confirm:
                        staged = store.confirmation(ticket, proof)
                        if confirm != "actual_path" or staged is None:
                            raise ApiError(403, "csrf_failed", "confirmation requires password-verified browser")
                        store.approve(ticket, seconds=staged[1], grant=callback, browser=proof)
                    else:
                        retry = self.server.capability_limiter.take(
                            self._admin_rate_limit_address(), "workspace:" + entry.workspace)
                        if retry:
                            raise ApiError(429, "too_many_attempts", "approval rate limit exceeded")
                        password = self._form_one(form, "password")
                        if not store.password_attempt(ticket, lambda owner: grants.verify_workspace_password(owner, password)):
                            raise ApiError(403, "password_incorrect", "Workspace password incorrect")
                        minutes = int(self._form_one(form, "minutes") or "10")
                        if minutes not in {10, 30, 120, 360, 1440}:
                            raise ValueError("unsupported approval duration")
                        if isinstance(entry.display, dict) and entry.display.get("confirmation_required") is True:
                            proposed = store.prepare_confirmation(ticket, browser=proof, seconds=minutes * 60, grant=callback)
                            self._send_html(200, self._function_confirmation_page(entry, ticket, proof, proposed), script_src="'none'")
                            return
                        store.approve(ticket, seconds=minutes * 60, grant=callback)
                except (ValueError, TypeError):
                    raise ApiError(400, "approval_unavailable", "approval expired, changed or unavailable") from None
            self._send_html(200, page("<h1>Capability approved</h1><p>The operation may now be retried.</p>"), script_src="'none'")
            return
        if method != "GET":
            raise ApiError(405, "method_not_allowed", "use GET or POST")
        cookie = cookie or __import__("secrets").token_urlsafe(32)
        proof = grants.browser_proof(ticket, cookie)
        header = (f"{name}={cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age={PENDING_SECONDS}"
                  + ("; Secure" if self._request_is_https() else ""))
        staged = store.confirmation(ticket, proof)
        if staged is not None:
            self._send_html(200, self._function_confirmation_page(entry, ticket, proof, staged[0]),
                            headers={"Set-Cookie": header}, script_src="'none'")
            return
        info = entry.display if entry.display is not None else entry.request
        summary = html.escape(json.dumps(info, ensure_ascii=False, indent=2))
        action = html.escape(self._admin_path().removesuffix("/admin") + "/capability/" + ticket, quote=True)
        body = (
            "<h1>Approve temporary capability</h1>"
            f"<p>Workspace Token: {html.escape(record.name)} ({html.escape(record.path_prefix)})</p>"
            f"<p>Token ID: {html.escape(entry.workspace)} · Conversation ID: {entry.conversation_id}</p>"
            f"<p>Function: <strong>{html.escape(entry.function)}</strong></p>"
            f"<p>Target: <strong>{html.escape(entry.target)}</strong></p>"
            + ("<p>Capability: shell.unsandboxed</p><p>An approved Shell command runs as the target's current OS user without sandbox restrictions.</p>" if entry.function == "shell.exec" else "")
            + f"<p><strong>AI request reason:</strong> {html.escape(entry.reason or 'Not provided by the AI')}</p>"
            f"<pre>{summary}</pre>"
            f'<form method="post" action="{action}" autocomplete="off">'
            f'<input type="hidden" name="csrf" value="{proof}">'
            '<label>Workspace password</label><input type="password" name="password" required maxlength="1024">'
            '<label>Duration</label><select name="minutes" required>'
            '<option value="10">10 minutes</option><option value="30">30 minutes</option>'
            '<option value="120">2 hours</option><option value="360">6 hours</option>'
            '<option value="1440">24 hours</option></select><button>Approve</button></form>')
        self._send_html(200, page(body), headers={"Set-Cookie": header}, script_src="'none'")

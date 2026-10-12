"""Temporary capability workflow across REST, MCP, browser and Mapping jobs."""
import json
import os
import re
import threading
import unittest
from contextlib import closing
from dataclasses import replace
from unittest.mock import patch
from urllib.parse import urlsplit

from tests import test_shell_routing, test_oauth_control_consent


@unittest.skipIf(os.name == "nt", "HTTP server runs on POSIX")
class CapabilityHTTPTests(unittest.TestCase):
    setUp = test_shell_routing.UnifiedShellHTTPTests.setUp
    tearDown = test_shell_routing.UnifiedShellHTTPTests.tearDown
    request = test_shell_routing.UnifiedShellHTTPTests.request
    api = test_shell_routing.UnifiedShellHTTPTests.api
    form = test_shell_routing.UnifiedShellHTTPTests.form
    finished = test_shell_routing.UnifiedShellHTTPTests.finished
    authorize = test_shell_routing.UnifiedShellHTTPTests.authorize
    rpc = test_shell_routing.UnifiedShellHTTPTests.rpc

    PASSWORD = "workspace-test-password-123"

    def ownership(self):
        store = self.server.context_for(self.server.tokens.scope_root(self.record))
        with closing(store._connect()) as db:
            row = db.execute("SELECT c.id,c.writer_nonce FROM conversations c JOIN context_entries p ON p.conversation_id=c.id WHERE p.id=?", (self.plan,)).fetchone()
        return row["id"], row["writer_nonce"]

    def elevated(self, **values):
        body = {"command": "printf elevated", "elevated": True, "writer_nonce": self.ownership()[1]}
        body.update(values)
        return self.api("/shell/exec", body)

    def approval(self, result):
        location = urlsplit(result["error"]["details"]["approval_url"]).path
        status, headers, raw = self.request("GET", location)
        self.assertEqual(200, status, raw)
        proof = re.search(rb'name="csrf" value="([^"]+)"', raw).group(1).decode()
        return location, {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "Origin": "https://example.test"}, {"csrf": proof, "password": self.PASSWORD, "minutes": "10"}, raw

    def approve(self, result):
        location, headers, form, _ = self.approval(result)
        status, _, raw = self.form(location, form, headers)
        self.assertEqual(200, status, raw)
        self.assertIn(b"Capability approved", raw)
        return location

    def configure(self):
        self.server.capability_grants.set_password(self.record.path_prefix, self.PASSWORD)

    def request_elevation(self, target="server", **values):
        body = {"target": target, "writer_nonce": self.ownership()[1]}
        body.update(values)
        return self.api("/shell/elevation/request", body)

    def test_proactive_elevation_request_is_command_free_and_reuses_grant(self):
        self.configure()
        self.server.tokens.update(self.record.token, shell_mode="restricted")
        marker = self.server.tokens.scope_root(self.record) / "proactive-marker"
        with patch.object(self.server.tasks, "start", wraps=self.server.tasks.start) as launch:
            status, pending = self.request_elevation()
            self.assertEqual(200, status, pending)
            self.assertEqual("approval_required", pending["status"])
            self.assertEqual("server", pending["target"])
            self.assertEqual("shell.elevated", pending["capability"])
            self.assertEqual(300, pending["approval_expires_in"])
            launch.assert_not_called()
            self.assertFalse(marker.exists())
            self.approve({"error": {"details": pending}})
            launch.assert_not_called()
            status, granted = self.request_elevation()
            self.assertEqual(200, status, granted)
            self.assertEqual("granted", granted["status"])
            self.assertEqual("server", granted["target"])
            self.assertEqual("shell.elevated", granted["capability"])
            launch.assert_not_called()
            status, task = self.elevated(command="printf approved > proactive-marker")
            self.assertEqual(202, status, task)
        self.finished(task["task_id"])
        self.assertEqual("approved", marker.read_text())

    def test_proactive_request_mapping_is_target_scoped_and_requires_write(self):
        self.configure()
        mapping = self.row["id"]
        # Approval may be requested while normal Client Shell is disabled;
        # only an approved elevated invocation may override those flags.
        self.server.mappings.store.update(mapping, allow_exec=False)
        self.legacy_tasks.enabled = False
        self.session.capabilities["execution"] = self.tasks.capabilities()
        self.assertEqual(400, self.request_elevation("auto")[0])
        self.assertEqual(404, self.request_elevation("invalid-mapping")[0])
        status, pending = self.request_elevation(mapping)
        self.assertEqual(200, status, pending)
        self.assertEqual(mapping, pending["target"])
        self.approve({"error": {"details": pending}})
        self.assertEqual("granted", self.request_elevation(mapping)[1]["status"])
        self.assertEqual("approval_required", self.request_elevation("server")[1]["status"])
        self.server.mappings.store.update(mapping, writable=False)
        self.assertEqual(403, self.request_elevation(mapping)[0])
        self.server.mappings.store.update(mapping, writable=True)
        self.session.closed = True
        self.assertEqual(503, self.request_elevation(mapping)[0])
        self.session.closed = False
        self.session.capabilities["execution"].pop("unsandboxed", None)
        self.assertEqual(409, self.request_elevation(mapping)[0])

    def test_proactive_request_writer_nonce_and_payload_validation(self):
        self.configure()
        for override in ({"writer_nonce": None}, {"writer_nonce": "@xxxx@"},
                         {"writer_nonce": 17}, {"command": "echo do not run"}):
            with self.subTest(override=override):
                status, result = self.request_elevation(**override)
                self.assertIn(status, (400, 403), result)
                self.assertNotIn("approval_url", str(result))
        status, _ = self.request_elevation()
        self.assertEqual(200, status)
        store = self.server.context_for(self.server.tokens.scope_root(self.record))
        with closing(store._connect()) as db, db:
            db.execute("UPDATE context_entries SET plan_status='cancelled' WHERE id=?", (self.plan,))
        self.assertEqual(400, self.request_elevation()[0])

    def test_mcp_proactive_elevation_returns_link_without_error_or_execution(self):
        self.configure()
        token, _, _ = self.authorize()
        arguments = {
            "family": "shell", "operation": "request_elevation",
            "args": {"target": "server", "writer_nonce": self.ownership()[1]},
            "plan_id": self.plan, "taskname": "approve shell",
            "message": "Request proactive Shell elevation",
        }
        with patch.object(self.server.tasks, "start", wraps=self.server.tasks.start) as launch:
            status, result = self.rpc(token["access_token"], "tools/call",
                                      {"name": "capability_call", "arguments": arguments})
            self.assertEqual(200, status, result)
            data = result["result"]
            self.assertFalse(data["isError"], data)
            pending = data["structuredContent"]
            self.assertEqual("approval_required", pending["status"])
            self.assertIn("approval_url", pending)
            launch.assert_not_called()
            self.approve({"error": {"details": pending}})
            status, result = self.rpc(token["access_token"], "tools/call",
                                      {"name": "capability_call", "arguments": arguments})
            self.assertEqual(200, status, result)
            self.assertEqual("granted", result["result"]["structuredContent"]["status"])
            launch.assert_not_called()

    def test_server_approval_is_single_use_no_execution_then_restricted_retry(self):
        self.configure()
        self.server.tokens.update(self.record.token, shell_mode="restricted")
        marker = self.server.tokens.scope_root(self.record) / "elevated-marker"
        with patch.object(self.server.tasks, "start", wraps=self.server.tasks.start) as launch:
            status, result = self.elevated(command="printf approved > elevated-marker")
            self.assertEqual(403, status, result)
            self.assertEqual("capability_approval_required", result["error"]["code"])
            self.assertEqual("server", result["error"]["details"]["target"])
            launch.assert_not_called()
            location = self.approve(result)
            launch.assert_not_called()
            self.assertFalse(marker.exists())
            self.assertEqual(400, self.request("GET", location)[0])
            status, task = self.elevated(command="printf approved > elevated-marker")
            self.assertEqual(202, status, task)
            self.assertFalse(launch.call_args.kwargs["sandboxed"])
        self.finished(task["task_id"])
        self.assertEqual("approved", marker.read_text())
        status, result = self.api("/shell/exec", {"command": "printf ordinary", "unsandboxed": True})
        self.assertNotEqual(202, status, result)  # restricted backend unavailable here
        with closing(self.server.context_for(marker.parent)._connect()) as db:
            stored = str(db.execute("SELECT request_json,result_json FROM context_entries WHERE operation='shell.exec'").fetchall())
        self.assertNotIn(location.rsplit("/", 1)[1], stored)
        self.assertNotIn(self.ownership()[1], stored)

    def test_writer_plan_scope_and_reserved_capability(self):
        self.configure()
        for value in (None, "@xxxx@", 123):
            status, result = self.elevated(writer_nonce=value)
            self.assertIn(status, (400, 403), result)
            self.assertNotEqual("capability_approval_required", result["error"]["code"])
        status, result = self.elevated()
        self.assertEqual(403, status)
        self.approve(result)
        store = self.server.context_for(self.server.tokens.scope_root(self.record))
        with closing(store._connect()) as db, db:
            db.execute("UPDATE context_entries SET plan_status='cancelled' WHERE id=?", (self.plan,))
        self.assertEqual(400, self.elevated()[0])
        with closing(store._connect()) as db, db:
            db.execute("UPDATE context_entries SET plan_status='in_progress' WHERE id=?", (self.plan,))
        other = store.create_conversation(store.conversation_query()[2], [{"role": "user", "content": "another conversation"}, {"role": "ai", "content": "new owner"}])
        # Plan identity determines the scope even when a valid foreign nonce/ID is sent.
        self.assertEqual(403, self.elevated(writer_nonce=other["writer_nonce"], conversation_id=other["conversation_id"])[0])
        status, _, raw = self.request("POST", self.base + "/context", json.dumps({
            "type": "plan", "subplans": [], "taskname": "new owner", "content": "New conversation plan",
            "conversation_id": other["conversation_id"], "writer_nonce": other["writer_nonce"],
            "conversation_entries": [{"role": "ai", "content": "Create another conversation's plan"}],
        }), self.headers)
        self.assertEqual(201, status, raw)
        original = self.plan
        try:
            self.plan = json.loads(raw)["id"]
            self.assertEqual("capability_approval_required", self.elevated()[1]["error"]["code"])
        finally:
            self.plan = original
        self.server.capability_grants.revoke_workspace(self.record.path_prefix)
        ticket = self.server.capability_grants.request(self.record.path_prefix, self.ownership()[0], "server", "files.write")
        self.server.capability_grants.approve(ticket, self.PASSWORD)
        self.assertEqual("capability_approval_required", self.elevated()[1]["error"]["code"])

    def test_mapping_disabled_short_long_and_target_isolation(self):
        self.configure()
        self.server.mappings.store.update(self.row["id"], allow_exec=False)
        self.legacy_tasks.enabled = False
        self.session.capabilities["execution"] = self.tasks.capabilities()
        self.assertEqual(403, self.api("/shell/exec", {"command": "printf denied", "cwd": "laptop"})[0])
        _, server_request = self.elevated()
        self.approve(server_request)
        status, result = self.elevated(cwd="laptop")
        self.assertEqual(403, status, result)
        self.assertEqual(self.row["id"], result["error"]["details"]["target"])
        self.approve(result)
        # Both configured isolation paths must be bypassed for this one invocation.
        self.legacy_tasks.sandbox = True
        self.tasks.job_sandbox = {"type": "current_user"}
        for timeout in (120, 121):
            with self.subTest(timeout=timeout):
                status, task = self.elevated(cwd="laptop", timeout_seconds=timeout)
                self.assertEqual(202, status, task)
                self.assertEqual("client", task["location"])
                self.assertEqual("elevated", self.finished(task["task_id"])["stdout"])
        self.assertTrue(self.legacy_tasks.sandbox)
        with patch("openkapsel.client_runtime.shared_job_tasks.request") as manager:
            prepared = self.tasks._prepare({"command": "echo trusted", "cwd": ".", "task_id": "&Ab12&", "unsandboxed": True})
            self.assertNotIn("sandbox", prepared)
            self.assertIsNone(prepared["container"])
            self.assertNotEqual("podman", prepared["argv"][0])
            manager.assert_not_called()
        other, _ = self.server.mappings.store.create(self.record.path_prefix, "second", writable=True, allow_exec=False)
        try:
            mount = self.server.mappings.mount_path(other)
            mount.mkdir()
            self.server.mappings.sessions[other["id"]] = self.session
            status, result = self.elevated(cwd="second")
            self.assertEqual(403, status, result)
            self.assertEqual(other["id"], result["error"]["details"]["target"])
        finally:
            self.server.mappings.sessions.pop(other["id"], None)
            self.server.mappings.store.delete(other["id"])

    def test_csrf_password_attempts_headers_and_no_secret_echo(self):
        self.configure()
        _, result = self.elevated()
        location, headers, form, raw = self.approval(result)
        self.assertNotIn(self.PASSWORD.encode(), raw)
        self.assertIn(self.record.path_prefix.encode(), raw)
        self.assertIn(b"shell.elevated", raw)
        status, response_headers, _ = self.request("GET", location)
        self.assertEqual("no-store", response_headers["Cache-Control"])
        self.assertEqual("no-referrer", response_headers["Referrer-Policy"])
        self.assertIn("script-src 'none'", response_headers["Content-Security-Policy"])
        self.assertIn("Secure", response_headers["Set-Cookie"])
        self.assertEqual(403, self.form(location, form, {})[0])
        self.assertEqual(403, self.form(location, dict(form, csrf="無效"), headers)[0])
        self.assertEqual(403, self.form(location, form, dict(headers, Origin="https://evil.test"))[0])
        for _ in range(5):
            status, _, raw = self.form(location, dict(form, password="incorrect-secret"), headers)
            self.assertEqual(403, status, raw)
            self.assertNotIn(b"incorrect-secret", raw)
        self.assertEqual(400, self.form(location, form, headers)[0])
        self.assertFalse(self.server.capability_grants.granted(self.record.path_prefix, self.ownership()[0], "server", "shell.elevated"))
        # New URL cannot reset the shared workspace password budget.
        _, new = self.elevated()
        location, headers, form, _ = self.approval(new)
        self.assertEqual(429, self.form(location, form, headers)[0])

    def test_admin_password_reset_revoke_and_lifecycle(self):
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        path = "/kapsel/admin/capabilities"
        form = {"workspace": self.record.path_prefix, "action": "password", "password": self.PASSWORD, "csrf": session.csrf}
        self.assertEqual(403, self.form(path, dict(form, csrf="invalid"), headers)[0])
        self.assertEqual(200, self.form(path, form, headers)[0])
        _, result = self.elevated()
        self.approve(result)
        self.assertIn(b"shell.elevated", self.request("GET", path, headers=headers)[2])
        grant = {"workspace": self.record.path_prefix, "action": "revoke", "conversation_id": str(self.ownership()[0]), "target": "server", "capability": "shell.elevated", "csrf": session.csrf}
        self.assertEqual(200, self.form(path, grant, headers)[0])
        self.assertEqual(403, self.elevated()[0])
        self.assertEqual(200, self.form(path, dict(form, password="new-workspace-password-123"), headers)[0])
        self.assertEqual({}, self.server.capability_grants.pending_requests)
        delete = {"action": "delete", "token": self.record.token, "csrf": session.csrf}
        self.assertEqual(303, self.form("/kapsel/admin/tokens", delete, headers)[0])
        self.assertFalse(self.server.capability_grants.configured(self.record.path_prefix))

    def test_expiry_blocks_new_jobs_and_preserves_running_job(self):
        self.configure()
        _, first = self.elevated()
        _, second = self.elevated()
        self.assertNotEqual(first["error"]["details"]["approval_url"], second["error"]["details"]["approval_url"])
        location = urlsplit(second["error"]["details"]["approval_url"]).path
        self.server.capability_grants.pending_requests[location.rsplit("/", 1)[1]].deadline = 0
        self.assertEqual(400, self.request("GET", location)[0])
        self.approve(first)
        status, task = self.elevated(command="cat", interactive=True)
        self.assertEqual(202, status, task)
        self.server.capability_grants.active[(self.record.path_prefix, self.ownership()[0], "server", "shell.elevated")] = 0
        self.assertEqual(403, self.elevated()[0])
        self.assertEqual(200, self.api("/task/stdin/" + task["task_id"], {"data": "still-running\n", "close": True})[0])
        self.assertEqual("still-running\n", self.finished(task["task_id"])["stdout"])

    def test_mcp_approval_error_and_retry_share_rest_grant(self):
        self.configure()
        token, _, _ = self.authorize()
        arguments = {"family": "shell", "operation": "exec", "args": {"command": "printf mcp", "elevated": True, "writer_nonce": self.ownership()[1]}, "plan_id": self.plan, "taskname": "elevation", "message": "Test MCP elevation"}
        status, result = self.rpc(token["access_token"], "tools/call", {"name": "capability_call", "arguments": arguments})
        self.assertEqual(200, status, result)
        self.assertTrue(result["result"]["isError"])
        error = result["result"]["structuredContent"]
        self.assertIn(error["error"]["details"]["approval_url"], result["result"]["content"][0]["text"])
        self.approve(error)
        status, result = self.rpc(token["access_token"], "tools/call", {"name": "capability_call", "arguments": arguments})
        self.assertFalse(result["result"]["isError"], result)
        task = result["result"]["structuredContent"]
        self.assertEqual("mcp", self.finished(task["task_id"])["stdout"])

    def test_remote_http_passwords_are_rejected(self):
        self.server.config = replace(self.server.config, public_base_url="http://example.test")
        self.assertEqual(403, self.elevated()[0])

    def test_real_mapping_websocket_elevated_shell(self):
        try:
            import websocket
            import wsproto
        except ImportError:
            self.skipTest("install client transport dependencies")
        from openkapsel.client import ClientRuntime, run_once
        self.configure()
        self.server.config = replace(self.server.config, mappings_enabled=True)
        row, token = self.server.mappings.store.create(self.record.path_prefix, "real", writable=True, allow_exec=False)
        self.server.mappings.mount_path(row).mkdir()
        config = {"url": f"ws://127.0.0.1:{self.server.server_port}/kapsel/mapping-connect/{row['id']}",
                  "token": token, "root": str(self.export), "writable": True, "allow_exec": False}
        with patch.dict(os.environ, {"OPENKAPSEL_JOB_MANAGER_HOME": str(self.manager_home)}):
            runtime = ClientRuntime(config)
        ready, stop = threading.Event(), threading.Event()
        client = threading.Thread(target=run_once, args=(config, stop), kwargs={"runtime": runtime, "on_ready": ready.set}, daemon=True)
        client.start()
        try:
            self.assertTrue(ready.wait(5), "Mapping client did not connect")
            status, result = self.elevated(cwd="real")
            self.assertEqual(403, status, result)
            self.approve(result)
            for timeout in (120, 121):
                status, task = self.elevated(cwd="real", timeout_seconds=timeout)
                self.assertEqual(202, status, task)
                self.assertEqual("elevated", self.finished(task["task_id"])["stdout"])
            self.assertFalse(runtime.tasks.enabled)
            self.assertTrue(runtime.tasks.sandbox)
        finally:
            stop.set()
            with self.server.mappings.lock:
                session = self.server.mappings.sessions.get(row["id"])
            if session is not None:
                session.close()
            client.join(5)
            runtime.close()
            self.server.mappings.store.delete(row["id"])

    def test_expiry_during_launch_preparation_does_not_start_shell(self):
        self.configure()
        _, result = self.elevated()
        self.approve(result)
        key = (self.record.path_prefix, self.ownership()[0], "server", "shell.elevated")
        # Environment configuration is loaded before the final authorization.
        from openkapsel.execution.environment_store import EnvironmentStore
        original = EnvironmentStore.shell_file
        def expired_file(store, *args):
            self.server.capability_grants.active[key] = 0
            return original(store, *args)
        with patch.object(EnvironmentStore, "shell_file", expired_file), patch.object(self.server.tasks, "start") as launch:
            self.assertEqual(403, self.elevated()[0])
            launch.assert_not_called()


class WorkspacePasswordOAuthTests(unittest.TestCase):
    setUp = test_oauth_control_consent.ControlConsentHTTPTests.setUp
    tearDown = test_oauth_control_consent.ControlConsentHTTPTests.tearDown
    request = test_oauth_control_consent.ControlConsentHTTPTests.request
    form = test_oauth_control_consent.ControlConsentHTTPTests.form
    pending = test_oauth_control_consent.ControlConsentHTTPTests.pending
    submit = test_oauth_control_consent.ControlConsentHTTPTests.submit

    def test_workspace_password_oauth_is_independent_of_capability_grants(self):
        self.server.capability_grants.set_password(self.record.path_prefix, "workspace-test-password-123")
        pending = self.pending()
        self.assertIn(b'name="workspace_password"', pending["page"])
        status, _, raw = self.submit(pending, values={"control_token": "", "workspace_password": "incorrect-password"})
        self.assertEqual(403, status, raw)
        status, headers, raw = self.submit(pending, values={"control_token": "", "workspace_password": "workspace-test-password-123"})
        self.assertEqual(303, status, raw)
        self.assertNotIn("workspace-test-password-123", headers["Location"])
        self.assertEqual({}, self.server.capability_grants.active)
        self.assertEqual({}, self.server.admin_sessions._sessions)

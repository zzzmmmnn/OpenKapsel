"""Real HTTP/admin and WebSocket acceptance test for full Client grants."""
import os
import threading
import unittest
from unittest.mock import patch
from openkapsel.client import ClientRuntime


@unittest.skipIf(os.name == "nt", "real HTTP server runs on POSIX")
class FullApprovalHTTPTests(unittest.TestCase):
    from tests.test_mapping_file_api import MappingFileHTTPTests as _fixture
    from tests.test_oauth import OAuthHTTPTests as _oauth
    setUp = _fixture.setUp
    tearDown = _fixture.tearDown
    request = _fixture.request
    api = _fixture.api
    form = _oauth.form
    from tests.test_capability_http import CapabilityHTTPTests as _capability
    ownership = _capability.ownership

    def test_admin_csrf_real_websocket_host_files_revoke_expire_reconnect(self):
        from dataclasses import replace
        from openkapsel.client import run_once
        self.server.config = replace(self.server.config, mappings_enabled=True)
        row, secret = self.server.mappings.store.create(
            self.record.path_prefix, "full-test", writable=True, allow_exec=True)
        self.server.mappings.mount_path(row).mkdir()
        external = self.export.parent / "external-full-test"
        external.mkdir()
        secret_file = external / "sample.txt"
        secret_file.write_text("host sample")
        config = {"url": f'ws://127.0.0.1:{self.server.server_port}/kapsel/mapping-connect/{row["id"]}',
            "token": secret, "root": str(self.export), "writable": True,
            "allow_exec": True}
        runtime = ClientRuntime(config)
        runtime.files.sandbox_denied_paths = frozenset({secret_file})
        ready, stop = threading.Event(), threading.Event()
        client = threading.Thread(target=run_once, args=(config, stop),
            kwargs={"runtime": runtime, "on_ready": ready.set}, daemon=True)
        client.start()
        try:
            self.assertTrue(ready.wait(5), "real Client did not become ready")
            status, headers, raw = self.form("/kapsel/admin/login",
                {"username": "admin", "password": "test-password-123"})
            self.assertEqual(303, status, raw)
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            admin = self.server.admin_sessions.get(cookie.split("=", 1)[1])
            form = {"action": "full_approval", "id": row["id"],
                    "duration_seconds": "1800", "csrf": admin.csrf}
            auth = {"Cookie": cookie}
            self.form("/kapsel/admin/mappings", form)
            self.assertFalse(runtime.full_approval_active())
            self.assertEqual(403, self.form("/kapsel/admin/mappings", dict(form, csrf="bad"), auth)[0])
            self.assertFalse(runtime.full_approval_active())
            status, raw = self.api("/fs/read/files", {"paths": [str(secret_file)], "target": row["id"]})
            self.assertNotIn("host sample", str(raw))
            self.assertEqual(200, self.form("/kapsel/admin/mappings", form, auth)[0])
            self.assertTrue(runtime.full_approval_active())
            # Simulate the Windows preflight contract over the real wire,
            # while actually executing a harmless native POSIX command.
            runtime.tasks.legacy.approval_only = True
            peer = self.server.mappings.sessions[row["id"]]
            peer.capabilities["execution"].update(platform="win32", safe_powershell=True)
            self.assertEqual(403, self.api("/shell/exec",
                {"cwd": row["name"], "command": "printf blocked-by-token"})[0])
            self.server.tokens.update(self.record.token, shell_mode="full")
            for endpoint, extra in (
                    ("/shell/approval/request", {}),
                    ("/files/approval/request", {"access": "read", "path": str(external)}),
                    ("/function/approval/request", {"function": "files.write", "args": {}})):
                status, existing = self.api(endpoint, {
                    "target": row["id"], "writer_nonce": self.ownership()[1], **extra})
                self.assertEqual(200, status, existing)
                self.assertEqual("granted", existing["status"], existing)
                self.assertNotIn("approval_url", existing)
            status, shell = self.api("/shell/exec", {"cwd": row["name"], "command": "printf full-shell"})
            self.assertEqual(202, status, shell)
            job = runtime.tasks.legacy.tasks[shell["task_id"].rsplit(".", 1)[-1]]
            self.assertTrue(job["done"].wait(5))
            self.server.mappings.store.update(row["id"], allow_exec=False)
            self.assertEqual(403, self.api("/shell/exec",
                {"cwd": row["name"], "command": "printf blocked"})[0])
            self.server.mappings.store.update(row["id"], allow_exec=True)
            self.server.tokens.update(self.record.token, can_write=False)
            blocked = external / "token-blocked.txt"
            self.assertEqual(403, self.api("/fs/write/mutate", {"target": row["id"], "items": [
                {"op": "file.create", "path": str(blocked), "content": "blocked"}]})[0])
            self.assertFalse(blocked.exists())
            self.server.tokens.update(self.record.token, can_write=True)
            status, data = self.api("/fs/read/files", {"paths": [str(secret_file)], "target": row["id"]})
            self.assertEqual(200, status, data)
            self.assertEqual("host sample", data["items"][0]["content"])
            status, _, data = self.request("GET",
                self.base + "/fs/content?target=" + row["id"] + "&path=" + str(secret_file), headers=self.headers)
            self.assertEqual((200, b"host sample"), (status, data))
            created = external / "created.txt"
            status, data = self.api("/fs/write/mutate", {"target": row["id"], "items": [
                {"op": "file.create", "path": str(created), "content": "E2E write"}]})
            self.assertEqual(200, status, data)
            self.assertEqual("E2E write", created.read_text())
            status, _, page = self.request("GET", "/kapsel/admin", headers=auth)
            self.assertEqual(200, status)
            self.assertIn(b"Temporary full Client approval", page)
            self.assertIn(b"Active", page)
            self.assertEqual(200, self.form("/kapsel/admin/mappings",
                dict(form, action="full_revoke"), auth)[0])
            self.assertFalse(runtime.full_approval_active())
            self.assertEqual(403, self.api("/shell/exec",
                {"cwd": row["name"], "command": "printf blocked"})[0])
            self.assertNotIn("host sample", str(self.api("/fs/read/files",
                {"paths": [str(secret_file)], "target": row["id"]})[1]))
            self.server.mappings.set_full_approval(row["id"], 1800)
            with patch("openkapsel.client.time.monotonic", return_value=runtime._full_approval_deadline):
                self.assertFalse(runtime.full_approval_active())
                self.assertNotIn("host sample", str(self.api("/fs/read/files",
                    {"paths": [str(secret_file)], "target": row["id"]})[1]))
            self.server.mappings.set_full_approval(row["id"], 1800)
            stop.set()
            self.server.mappings.disconnect(row["id"])
            client.join(5)
            self.assertFalse(client.is_alive())
            self.assertFalse(runtime.full_approval_active())
            self.assertFalse(self.server.mappings.full_approval_status(row["id"])["active"])
            ready.clear()
            stop.clear()
            client = threading.Thread(target=run_once, args=(config, stop),
                kwargs={"runtime": runtime, "on_ready": ready.set}, daemon=True)
            client.start()
            self.assertTrue(ready.wait(5))
            self.assertFalse(runtime.full_approval_active())
            self.assertFalse(self.server.mappings.full_approval_status(row["id"])["active"])
        finally:
            stop.set()
            self.server.mappings.disconnect(row["id"])
            client.join(5)
            runtime.close()
            self.server.mappings.store.delete(row["id"])

"""Temporary capability workflow across REST, MCP, browser and Mapping jobs."""
import http.client
import json
import os
import re
import threading
import tempfile
import unittest
from pathlib import Path
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
        location, headers, form, first_page = self.approval(result)
        status, _, raw = self.form(location, form, headers)
        self.assertEqual(200, status, raw)
        if b"Confirm actual File access directory" in raw:
            self.assertNotIn(b"Actual authorized directory", first_page)
            self.assertFalse(self.server.capability_grants.granted(
                self.record.app_id, self.ownership()[0],
                result["error"]["details"]["target"],
                result["error"]["details"]["capability"],
                result["error"]["details"].get("path", "")))
            status, _, raw = self.form(location, {
                "csrf": form["csrf"], "confirm": "actual_path",
            }, headers)
            self.assertEqual(200, status, raw)
        self.assertIn(b"Capability approved", raw)
        return location

    def configure(self):
        self.server.capability_grants.set_password(self.record.app_id, self.PASSWORD)

    def request_elevation(self, target="server", **values):
        body = {"target": target, "writer_nonce": self.ownership()[1]}
        body.update(values)
        return self.api("/shell/elevation/request", body)

    def test_shared_directory_tokens_have_independent_passwords_and_grants(self):
        self.configure()
        original = self.server.tokens.get(self.record.token)
        second = self.server.tokens.create(
            name="Second Token", path_prefix=original.path_prefix,
            shell_mode="full", expires_at=None, can_read=True, can_write=True,
        )
        grants = self.server.capability_grants
        self.assertEqual(original.path_prefix, second.path_prefix)
        self.assertNotEqual(original.app_id, second.app_id)
        self.assertTrue(grants.configured(original.app_id))
        self.assertFalse(grants.configured(second.app_id))
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        _, _, page = self.request("GET", "/kapsel/admin", headers=headers)
        second_card = page.decode().split(f'data-token-app="{second.app_id}"', 1)[1]
        self.assertIn(f'name="workspace" value="{second.app_id}"', second_card)
        self.assertIn("Not configured", second_card)
        second_password = "second-token-password-456"
        grants.set_password(second.app_id, second_password)
        first_ticket = grants.request(original.app_id, self.ownership()[0],
                                      "server", "shell.elevated")
        second_ticket = grants.request(second.app_id, self.ownership()[0],
                                       "server", "shell.elevated")
        with self.assertRaises(PermissionError):
            grants.approve(second_ticket, self.PASSWORD)
        grants.approve(first_ticket, self.PASSWORD)
        grants.approve(second_ticket, second_password)
        self.assertTrue(grants.granted(original.app_id, self.ownership()[0],
                                       "server", "shell.elevated"))
        self.assertTrue(grants.granted(second.app_id, self.ownership()[0],
                                       "server", "shell.elevated"))
        grants.set_password(second.app_id, "rotated-second-token-password-789")
        self.assertFalse(grants.granted(second.app_id, self.ownership()[0],
                                        "server", "shell.elevated"))
        self.assertTrue(grants.granted(original.app_id, self.ownership()[0],
                                       "server", "shell.elevated"))
        # Rotating the first Token's credentials preserves its password/grants.
        rotated = self.server.tokens.rotate_control_token(original.token)
        self.assertEqual(original.app_id, rotated.app_id)
        self.assertTrue(grants.verify_workspace_password(rotated.app_id, self.PASSWORD))
        self.assertTrue(grants.granted(rotated.app_id, self.ownership()[0],
                                       "server", "shell.elevated"))
        delete = {"action": "delete", "token": second.token, "csrf": session.csrf}
        self.assertEqual(303, self.form("/kapsel/admin/tokens", delete, headers)[0])
        self.assertFalse(grants.configured(second.app_id))
        self.assertTrue(grants.configured(original.app_id))
        self.assertTrue(grants.granted(original.app_id, self.ownership()[0],
                                       "server", "shell.elevated"))

    def test_same_directory_http_elevation_requires_own_token_password(self):
        self.configure()
        second = self.server.tokens.create(
            name="Separate Workspace Token", path_prefix=self.record.path_prefix,
            shell_mode="full", expires_at=None, can_read=True, can_write=True,
        )
        second_password = "second-workspace-pass-123"
        self.server.capability_grants.set_password(second.app_id, second_password)
        first_status, first = self.request_elevation()
        self.assertEqual(200, first_status, first)
        self.approve({"error": {"details": first}})
        self.assertEqual("granted", self.request_elevation()[1]["status"])
        body = {
            "target": "server", "writer_nonce": self.ownership()[1],
            "plan_id": self.plan, "taskname": "token-isolation",
            "message": "Verify exact Token password scope",
        }
        url = f"/kapsel/w/{second.token}/shell/elevation/request"
        auth = {
            "Authorization": "Bearer " + second.control_token,
            "Content-Type": "application/json",
        }
        status, _, raw = self.request("POST", url, json.dumps(body), auth)
        self.assertEqual(200, status, raw)
        result = json.loads(raw)
        self.assertEqual("approval_required", result["status"])
        location, headers, approval, page = self.approval(
            {"error": {"details": result}}
        )
        self.assertIn(second.name.encode(), page)
        self.assertIn(second.app_id.encode(), page)
        self.assertEqual(403, self.form(location, approval, headers)[0])
        self.assertEqual(200, self.form(
            location, dict(approval, password=second_password), headers
        )[0])
        status, _, raw = self.request("POST", url, json.dumps(body), auth)
        self.assertEqual(200, status, raw)
        self.assertEqual("granted", json.loads(raw)["status"])
        self.assertEqual("granted", self.request_elevation()[1]["status"])

    def test_old_directory_password_does_not_apply_to_token(self):
        self.server.capability_grants.set_password(self.record.path_prefix, self.PASSWORD)
        self.assertFalse(self.server.capability_grants.configured(self.record.app_id))
        status, body = self.elevated()
        self.assertEqual(403, status)
        self.assertEqual("capability_approval_required", body["error"]["code"])
        location, headers, form, _ = self.approval(body)
        self.assertEqual(403, self.form(location, form, headers)[0])
        self.assertFalse(self.server.capability_grants.granted(
            self.record.app_id, self.ownership()[0], "server", "shell.elevated"
        ))

    def request_file_elevation(self, access, target="server", **values):
        return self.api("/files/elevation/request", {
            "access": access, "target": target,
            "writer_nonce": self.ownership()[1], **values,
        })

    def test_explicit_server_request_does_not_reveal_directory_existence(self):
        self.configure()
        with tempfile.TemporaryDirectory(prefix="kapsel-existence-oracle-") as raw:
            base = Path(raw).resolve()
            real = base / "private-real"
            real.mkdir()
            alias = base / "public-alias"
            alias.symlink_to(real, target_is_directory=True)
            missing = base / "missing"
            for requested in (alias, missing):
                status, pending = self.request_file_elevation("read", path=str(requested))
                self.assertEqual(200, status, pending)
                self.assertEqual("approval_required", pending["status"])
                self.assertEqual(str(requested), pending["path"])
                self.assertNotIn("original_path", pending)
                self.assertNotIn(str(real), str(pending))
                location, headers, form, page = self.approval(
                    {"error": {"details": pending}})
                self.assertNotIn(b"Actual authorized directory", page)
                self.assertNotIn(str(real).encode(), page)
                if requested == alias:
                    status, _, wrong = self.form(location, dict(form, password="bad-secret"), headers)
                    self.assertEqual(403, status, wrong)
                    self.assertNotIn(str(real).encode(), wrong)
                    status, _, confirmation = self.form(location, form, headers)
                    self.assertEqual(200, status, confirmation)
                    self.assertIn(str(real).encode(), confirmation)
                    self.assertFalse(self.server.capability_grants.granted_path(
                        self.record.app_id, self.ownership()[0],
                        "server", "files.read", str(real)))
                    # Possession of an approval URL is NOT enough to finish
                    # confirmation from a different unauthenticated browser.
                    _, attacker_headers, attacker_form, leaked_get = self.approval(
                        {"error": {"details": pending}})
                    self.assertNotIn(str(real).encode(), leaked_get)
                    status, _, failed = self.form(location, {
                        "csrf": attacker_form["csrf"], "confirm": "actual_path",
                    }, attacker_headers)
                    self.assertEqual(403, status, failed)
                    self.assertNotIn(str(real).encode(), failed)
                    status, _, completed = self.form(location, {
                        "csrf": form["csrf"], "confirm": "actual_path",
                    }, headers)
                    self.assertEqual(200, status, completed)
                    self.assertIn(b"Capability approved", completed)
                else:
                    self.assertEqual(400, self.form(location, form, headers)[0])

    def test_mapping_file_approval_never_resolves_without_correct_password(self):
        self.configure()
        mapping = self.row["id"]
        self.session.capabilities.setdefault("file_stream", {}).update(
            external_root_file_api=True, external_realpath=True)
        observed = []
        def client_call(operation, args):
            if operation == "resolve_path":
                observed.append(args["path"])
            if operation.startswith("api_") or operation == "resolve_path":
                return self.files.dispatch(operation, args)
            return self.tasks.dispatch(operation, args)
        self.session.call = client_call
        with tempfile.TemporaryDirectory(prefix="kapsel-mapping-oracle-") as raw:
            base = Path(raw).resolve()
            real = base / "sensitive-real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            missing = base / "missing"
            for requested in (alias, missing):
                status, pending = self.request_file_elevation(
                    "read", mapping, path=str(requested))
                self.assertEqual(200, status, pending)
                self.assertEqual("approval_required", pending["status"])
                self.assertEqual(str(requested), pending["path"])
                location, headers, form, page = self.approval(
                    {"error": {"details": pending}})
                self.assertNotIn(str(real).encode(), page)
                self.assertEqual([], observed)
                self.assertEqual(403, self.form(
                    location, dict(form, password="incorrect"), headers)[0])
                self.assertEqual([], observed)
            # The implicit elevated File API is also a prompt, not an oracle.
            for requested in (alias / "unused.txt", missing / "unused.txt"):
                status, error = self.api("/fs/read/files", {
                    "paths": [str(requested)], "elevated": True,
                    "target": mapping, "writer_nonce": self.ownership()[1]})
                self.assertEqual(403, status, error)
                self.assertEqual("capability_approval_required", error["error"]["code"])
                self.assertNotIn(str(real), str(error))
                self.assertEqual([], observed)
            # Correct password may now resolve and reveal the target to
            # this authenticated browser only.
            status, _, confirmation = self.form(location, form, headers)
            self.assertEqual(400, status)  # Last requested directory is absent.
            self.assertIn(str(missing), observed)

    def test_server_external_approval_is_bound_to_actual_symlink_target(self):
        self.configure()
        nonce = self.ownership()[1]
        with tempfile.TemporaryDirectory(prefix="kapsel-symlink-grant-") as raw:
            base = Path(raw).resolve()
            allowed = base / "approved"
            other = base / "private"
            allowed.mkdir()
            other.mkdir()
            (allowed / "public.txt").write_text("permitted", encoding="utf-8")
            (other / "private.txt").write_text("MUST_NOT_DISCLOSE", encoding="utf-8")
            alias = base / "alias"
            alias.symlink_to(allowed, target_is_directory=True)

            status, pending = self.request_file_elevation(
                "read", path=str(alias)
            )
            self.assertEqual(200, status, pending)
            # The human must approve the real, immutable target, not a
            # symbolic link whose destination could be changed afterward.
            self.assertEqual(str(alias), pending["path"])
            self.assertNotIn("original_path", pending)
            location, headers, form, page = self.approval({"error": {"details": pending}})
            self.assertNotIn(b"Actual authorized directory", page)
            self.assertIn(str(alias).encode(), page)
            self.assertNotIn(str(allowed).encode(), page)
            status, _, confirmed_page = self.form(location, form, headers)
            self.assertEqual(200, status)
            self.assertIn(b"Actual authorized directory", confirmed_page)
            self.assertIn(str(allowed).encode(), confirmed_page)
            status, _, done_page = self.form(location, {"csrf": form["csrf"],
                                                        "confirm": "actual_path"}, headers)
            self.assertEqual(200, status, done_page)
            self.assertIn(b"Capability approved", done_page)
            args = {
                "paths": [str(alias / "public.txt")],
                "elevated": True, "target": "server", "writer_nonce": nonce,
            }
            status, readable = self.api("/fs/read/files", args)
            self.assertEqual(200, status, readable)
            self.assertEqual("permitted", readable["items"][0]["content"])

            alias.unlink()
            alias.symlink_to(other, target_is_directory=True)
            status, denied = self.api(
                "/fs/read/files",
                dict(args, paths=[str(alias / "private.txt")]),
            )
            self.assertNotEqual(200, status, denied)
            self.assertNotIn("MUST_NOT_DISCLOSE", str(denied))
            self.assertFalse(self.server.capability_grants.granted_path(
                self.record.app_id, self.ownership()[0],
                "server", "files.read", str(other / "private.txt")
            ))

    def test_external_approval_rejects_dot_dot_and_cannot_escape(self):
        self.configure()
        nonce = self.ownership()[1]
        with tempfile.TemporaryDirectory(prefix="kapsel-dotdot-grant-") as raw:
            base = Path(raw).resolve()
            allowed = base / "approved"
            allowed.mkdir()
            (base / "private.txt").write_text("SECRET", encoding="utf-8")
            self.assertEqual(400, self.request_file_elevation(
                "read", path=str(allowed) + "/../"
            )[0])
            status, pending = self.request_file_elevation("read", path=str(allowed))
            self.assertEqual(200, status, pending)
            self.approve({"error": {"details": pending}})
            status, denied = self.api("/fs/read/files", {
                "paths": [str(allowed) + "/../private.txt"],
                "elevated": True, "target": "server", "writer_nonce": nonce,
            })
            self.assertEqual(400, status, denied)
            self.assertEqual("invalid_path", denied["error"]["code"])
            self.assertNotIn("SECRET", str(denied))
            self.assertIsNone(self.server.capability_grants.granted_path(
                self.record.app_id, self.ownership()[0],
                "server", "files.read", str(allowed) + "/../private.txt"
            ))

    def test_mapping_external_approval_cannot_follow_symlink_parent(self):
        self.configure()
        nonce = self.ownership()[1]
        mapping = self.row["id"]
        self.session.call = lambda operation, args: (
            self.files.dispatch(operation, args) if (operation.startswith("api_") or operation == "resolve_path")
            else self.tasks.dispatch(operation, args)
        )
        self.session.capabilities.setdefault("file_stream", {}).update(
            external_root_file_api=True, external_realpath=True)
        with tempfile.TemporaryDirectory(prefix="kapsel-remote-symlink-") as raw:
            base = Path(raw).resolve()
            first = base / "first"
            second = base / "second"
            for directory in (first, second):
                (directory / "sub").mkdir(parents=True)
            (first / "sub" / "visible.txt").write_text("public", encoding="utf-8")
            (second / "sub" / "private.txt").write_text("MUST_NOT_DISCLOSE", encoding="utf-8")
            alias = base / "alias"
            alias.symlink_to(first, target_is_directory=True)
            scope = str(alias / "sub")
            status, approval = self.request_file_elevation("read", mapping, path=scope)
            self.assertEqual(200, status, approval)
            self.assertEqual(scope, approval["path"])
            self.assertNotIn("original_path", approval)
            location, headers, form, page = self.approval({"error": {"details": approval}})
            self.assertIn(scope.encode(), page)
            self.assertNotIn(str(first / "sub").encode(), page)
            self.assertNotIn(b"Actual authorized directory", page)
            # Only the authenticated response reveals the real path.
            status, _, confirmation = self.form(location, form, headers)
            self.assertEqual(200, status, confirmation)
            self.assertIn(str(first / "sub").encode(), confirmation)
            self.assertIn(b"Actual authorized directory", confirmation)
            # An alias that moves after password but before final confirmation
            # must not receive a grant to either destination.
            alias.unlink()
            alias.symlink_to(second, target_is_directory=True)
            self.assertEqual(400, self.form(location, {
                "csrf": form["csrf"], "confirm": "actual_path",
            }, headers)[0])
            alias.unlink()
            alias.symlink_to(first, target_is_directory=True)
            self.approve({"error": {"details": self.request_file_elevation(
                "read", mapping, path=scope)[1]}})
            args = {
                "paths": [scope + "/visible.txt"], "elevated": True,
                "target": mapping, "writer_nonce": nonce,
            }
            status, allowed = self.api("/fs/read/files", args)
            self.assertEqual(200, status, allowed)
            self.assertEqual("public", allowed["items"][0]["content"])
            alias.unlink()
            alias.symlink_to(second, target_is_directory=True)
            status, denied = self.api("/fs/read/files", dict(
                args, paths=[scope + "/private.txt"],
            ))
            self.assertNotEqual(200, status, denied)
            self.assertNotIn("MUST_NOT_DISCLOSE", str(denied))

    def test_mapping_file_symlink_approval_binds_leaf_destination(self):
        self.configure()
        mapping = self.row["id"]
        self.session.call = lambda operation, args: (
            self.files.dispatch(operation, args)
            if (operation.startswith("api_") or operation == "resolve_path")
            else self.tasks.dispatch(operation, args)
        )
        self.session.capabilities.setdefault("file_stream", {}).update(
            external_root_file_api=True, external_realpath=True)
        with tempfile.TemporaryDirectory(prefix="kapsel-remote-leaf-link-") as raw:
            base = Path(raw).resolve()
            allowed, other = base / "allowed", base / "other"
            allowed.mkdir()
            other.mkdir()
            (allowed / "ok.txt").write_text("SAFE")
            (other / "secret.txt").write_text("PRIVATE")
            alias = base / "alias.txt"
            alias.symlink_to(allowed / "ok.txt")
            args = {"paths": [str(alias)], "elevated": True,
                    "target": mapping, "writer_nonce": self.ownership()[1]}
            status, prompted = self.api("/fs/read/files", args)
            self.assertEqual(403, status, prompted)
            self.assertEqual(str(alias.parent), prompted["error"]["details"]["path"])
            self.assertNotIn("original_path", prompted["error"]["details"])
            self.approve(prompted)
            status, readable = self.api("/fs/read/files", args)
            self.assertEqual(200, status, readable)
            self.assertEqual("SAFE", readable["items"][0]["content"])
            alias.unlink()
            alias.symlink_to(other / "secret.txt")
            status, blocked = self.api("/fs/read/files", args)
            self.assertNotEqual(200, status, blocked)
            self.assertNotIn("PRIVATE", str(blocked))

    def test_external_directory_requires_separate_path_scoped_approval(self):
        from urllib.parse import urlencode
        from openkapsel.auth.tokens import PathGrant
        self.configure()
        nonce = self.ownership()[1]
        with tempfile.TemporaryDirectory(prefix="kapsel-outside-") as raw:
            outer = Path(raw).resolve()
            (outer / "public.txt").write_text("external content")
            (outer / "denied.txt").write_text("private")
            status, blocked = self.api("/fs/read/files", {
                "paths": [str(outer / "public.txt")],
            })
            self.assertNotEqual(200, status, blocked)
            self.assertNotIn("external content", str(blocked))
            # An already granted unscoped files.read grant cannot read outside.
            self.approve({"error": {"details": self.request_file_elevation("read")[1]}})
            status, denied = self.api("/fs/read/files", {
                "paths": [str(outer / "public.txt")], "elevated": True,
                "target": "server", "writer_nonce": nonce,
            })
            self.assertEqual(403, status)
            self.assertEqual("capability_approval_required", denied["error"]["code"])
            self.assertEqual(str(outer), denied["error"]["details"]["path"])

            status, approval = self.request_file_elevation("read", path=str(outer))
            self.assertEqual(200, status, approval)
            location, _, _, page = self.approval({"error": {"details": approval}})
            self.assertIn(str(outer).encode(), page)
            self.approve({"error": {"details": approval}})
            query = urlencode({"path": str(outer), "elevated": "true",
                               "target": "server", "writer_nonce": nonce,
                               "plan_id": self.plan})
            status, _, raw_reply = self.request(
                "GET", self.base + "/fs/query/list?" + query, headers=self.headers)
            self.assertEqual(200, status, raw_reply)
            self.assertIn(b"public.txt", raw_reply)

            status, response = self.api("/fs/read/files", {
                "paths": [str(outer / "public.txt")], "elevated": True,
                "target": "server", "writer_nonce": nonce,
            })
            self.assertEqual(200, status, response)
            self.assertEqual("external content", response["items"][0]["content"])
            # The grant is a path-component subtree, not a string prefix.
            sibling = str(outer) + "-sibling"
            status, blocked = self.api("/fs/read/files", {
                "paths": [sibling], "elevated": True,
                "target": "server", "writer_nonce": nonce,
            })
            self.assertEqual(403, status)
            self.assertEqual("capability_approval_required", blocked["error"]["code"])
            self.server.tokens.update(self.record.token, shell_mode="restricted", allowed_paths=(
                PathGrant(str(outer), access="ro"),
                PathGrant(str(outer / "denied.txt"), access="deny"),
            ))
            self.assertEqual(403, self.api("/fs/read/files", {
                "paths": [str(outer / "denied.txt")], "elevated": True,
                "target": "server", "writer_nonce": nonce,
            })[0])
            self.assertEqual(400, self.request_file_elevation("read", path="/")[0])
            self.assertEqual(400, self.request_file_elevation(
                "read", path="/Users/../etc")[0])

    def test_file_json_body_cache_does_not_leak_across_keepalive(self):
        self.configure()
        nonce = self.ownership()[1]
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=5
        )
        try:
            first_body = json.dumps({"paths": ["hello.txt"]})
            conn.request(
                "POST",
                self.base + "/fs/read/files",
                first_body,
                self.headers,
            )
            response = conn.getresponse()
            first = json.loads(response.read())
            self.assertEqual(200, response.status, first)
            self.assertEqual("hello", first["items"][0]["content"])

            # The next request on the same HTTP/1.1 handler must parse its own
            # body, not the body cached while authorizing the previous File API.
            second_body = json.dumps({
                "access": "read",
                "target": "server",
                "writer_nonce": nonce,
                "plan_id": self.plan,
                "taskname": "body-cache",
                "message": "Verify request body isolation",
            })
            conn.request(
                "POST",
                self.base + "/files/elevation/request",
                second_body,
                self.headers,
            )
            response = conn.getresponse()
            second = json.loads(response.read())
            self.assertEqual(200, response.status, second)
            self.assertEqual("approval_required", second["status"])
            self.assertEqual("files.read", second["capability"])
            self.assertEqual("server", second["target"])

            # The second body must also have been consumed completely, leaving
            # framing intact for another request on this same connection.
            conn.request(
                "GET",
                self.base + "/fs/query/list?path=.",
                headers=self.headers,
            )
            response = conn.getresponse()
            third = json.loads(response.read())
            self.assertEqual(200, response.status, third)
            self.assertIn("hello.txt", [entry["name"] for entry in third["entries"]])
        finally:
            conn.close()

    def test_mapping_external_elevation_state_does_not_leak_across_keepalive(self):
        from urllib.parse import urlencode

        self.configure()
        nonce = self.ownership()[1]
        mapping = self.row["id"]
        self.session.call = lambda operation, args: (
            self.files.dispatch(operation, args) if (operation.startswith("api_") or operation == "resolve_path")
            else self.tasks.dispatch(operation, args)
        )
        self.session.capabilities.setdefault("file_stream", {}).update(
            external_root_file_api=True, external_realpath=True)

        with tempfile.TemporaryDirectory(prefix="kapsel-client-keepalive-") as raw:
            raw = str(Path(raw).resolve())
            outside = Path(raw)
            (outside / "visible.txt").write_text("keepalive external content")
            status, pending = self.request_file_elevation("read", mapping, path=raw)
            self.assertEqual(200, status, pending)
            self.approve({"error": {"details": pending}})

            elevated = urlencode({
                "path": raw,
                "elevated": "true",
                "target": mapping,
                "writer_nonce": nonce,
                "plan_id": self.plan,
            })
            plain = urlencode({"path": raw})
            unrelated = urlencode({"path": str(outside.parent)})

            conn = http.client.HTTPConnection(
                "127.0.0.1", self.server.server_address[1], timeout=5
            )
            try:
                def get(query):
                    conn.request(
                        "GET",
                        self.base + "/fs/query/list?" + query,
                        headers=self.headers,
                    )
                    response = conn.getresponse()
                    return response.status, json.loads(response.read())

                status, first = get(elevated)
                self.assertEqual(200, status, first)
                self.assertIn(
                    "visible.txt", [entry["name"] for entry in first["entries"]]
                )

                # Same TCP connection and therefore the same HTTP handler:
                # request-local elevation must not survive without elevated=true.
                status, second = get(plain)
                self.assertEqual(403, status, second)
                self.assertEqual("path_outside_root", second["error"]["code"])

                status, third = get(unrelated)
                self.assertEqual(403, status, third)
                self.assertEqual("path_outside_root", third["error"]["code"])
                self.assertNotEqual(
                    "file_elevation_path_mismatch", third["error"]["code"]
                )

                # The approved grant still works when explicitly opted into again.
                status, fourth = get(elevated)
                self.assertEqual(200, status, fourth)
                self.assertIn(
                    "visible.txt", [entry["name"] for entry in fourth["entries"]]
                )
            finally:
                conn.close()

    def test_external_mapping_file_rpc_directory_read_and_write(self):
        from urllib.parse import urlencode
        self.configure()
        nonce = self.ownership()[1]
        mapping = self.row["id"]
        self.session.call = lambda operation, args: (
            self.files.dispatch(operation, args) if (operation.startswith("api_") or operation == "resolve_path")
            else self.tasks.dispatch(operation, args)
        )
        self.session.capabilities.setdefault("file_stream", {}).update(
            external_root_file_api=True, external_realpath=True)
        with tempfile.TemporaryDirectory(prefix="kapsel-client-external-") as raw:
            raw = str(Path(raw).resolve())
            outside = Path(raw)
            (outside / "visible.txt").write_text("client external content")
            (outside / "protected.txt").write_text("client secret")
            self.files.global_protected_paths = (
                *self.files.global_protected_paths, outside / "protected.txt",
            )
            plain_query = urlencode({"path": raw})
            status, _, plain = self.request(
                "GET", self.base + "/fs/query/list?" + plain_query, headers=self.headers)
            self.assertEqual(403, status, plain)
            plain_error = json.loads(plain)["error"]
            self.assertEqual("path_outside_root", plain_error["code"])
            self.assertEqual("read", plain_error["details"]["access"])
            self.assertIn("request_elevation", plain_error["details"]["elevation"])
            elevated_query = urlencode({
                "path": raw, "elevated": "true", "target": mapping,
                "writer_nonce": nonce, "plan_id": self.plan,
            })
            status, _, first_prompt = self.request(
                "GET", self.base + "/fs/query/list?" + elevated_query,
                headers=self.headers)
            self.assertEqual(403, status, first_prompt)
            first_error = json.loads(first_prompt)["error"]
            self.assertEqual("capability_approval_required", first_error["code"])
            self.assertEqual(raw, first_error["details"]["path"])
            self.assertIn("approval_url", first_error["details"])
            status, pending = self.request_file_elevation("read", mapping, path=raw)
            self.assertEqual(200, status, pending)
            self.approve({"error": {"details": pending}})
            # The MCP dynamic tool must expose/forward the optional directory.
            access, _, _ = self.authorize()
            status, mcp_reply = self.rpc(access["access_token"], "tools/call", {
                "name": "capability_call",
                "arguments": {
                    "family": "files", "operation": "request_elevation",
                    "args": {"access": "read", "target": mapping,
                             "writer_nonce": nonce, "path": raw},
                    "plan_id": self.plan, "taskname": "file-elevation",
                    "message": "Verify MCP scoped directory approval",
                },
            })
            self.assertEqual(200, status, mcp_reply)
            self.assertFalse(mcp_reply["result"]["isError"], mcp_reply)
            self.assertEqual("granted", mcp_reply["result"]["structuredContent"]["status"])
            query = urlencode({
                "path": raw, "elevated": "true", "target": mapping,
                "writer_nonce": nonce, "plan_id": self.plan,
            })
            status, _, raw_reply = self.request(
                "GET", self.base + "/fs/query/list?" + query, headers=self.headers)
            self.assertEqual(200, status, raw_reply)
            listing = json.loads(raw_reply)
            self.assertIn("visible.txt", [x["name"] for x in listing["entries"]])
            self.session.capabilities["file_stream"].pop("external_root_file_api")
            status, _, old_client = self.request(
                "GET", self.base + "/fs/query/list?" + query, headers=self.headers)
            self.assertEqual(409, status, old_client)
            self.assertIn(b"mapping_client_upgrade_required", old_client)
            self.session.capabilities["file_stream"]["external_root_file_api"] = True
            self.session.capabilities["file_stream"].pop("external_realpath")
            status, unsupported = self.request_file_elevation("read", mapping, path=raw)
            self.assertEqual(409, status, unsupported)
            self.assertEqual("mapping_client_upgrade_required", unsupported["error"]["code"])
            self.session.capabilities["file_stream"]["external_realpath"] = True
            self.assertNotIn("protected.txt", [x["name"] for x in listing["entries"]])
            status, result = self.api("/fs/read/files", {
                "paths": [str(outside / "visible.txt")], "elevated": True,
                "target": mapping, "writer_nonce": nonce,
            })
            self.assertEqual(200, status, result)
            self.assertEqual("client external content", result["items"][0]["content"])
            status, protected = self.api("/fs/read/files", {
                "paths": [str(outside / "protected.txt")], "elevated": True,
                "target": mapping, "writer_nonce": nonce,
            })
            self.assertNotIn("client secret", str(protected))
            self.assertNotEqual(200, status)
            status, pending = self.request_file_elevation("write", mapping, path=raw)
            self.assertEqual(200, status, pending)
            self.approve({"error": {"details": pending}})
            status, created = self.api("/fs/write/mkdir", {
                "path": str(outside / "created"), "elevated": True,
                "target": mapping, "writer_nonce": nonce,
            })
            self.assertIn(status, (200, 201), created)
            self.assertTrue((outside / "created").is_dir())
            self.assertEqual(403, self.api("/fs/write/mkdir", {
                "path": str(outside.parent / "escape"), "elevated": True,
                "target": mapping, "writer_nonce": nonce,
            })[0])

    def test_file_read_write_temporary_elevation_needs_individual_grants(self):
        self.configure()
        root = self.server.tokens.scope_root(self.record)
        (root / "elevated-file.txt").write_text("protected-content")
        self.server.tokens.update(self.record.token, can_read=False, can_write=False)
        self.assertEqual(403, self.api("/fs/read/files", {
            "paths": ["elevated-file.txt"],
        })[0])
        status, read = self.request_file_elevation("read")
        self.assertEqual(200, status, read)
        self.assertEqual("approval_required", read["status"])
        self.assertEqual("files.read", read["capability"])
        self.approve({"error": {"details": read}})
        self.assertEqual("granted", self.request_file_elevation("read")[1]["status"])
        # Approval is opt-in on EACH file request, not a blanket token policy.
        self.assertEqual(403, self.api("/fs/read/files", {
            "paths": ["elevated-file.txt"],
        })[0])
        status, response = self.api("/fs/read/files", {
            "paths": ["elevated-file.txt"], "elevated": True,
            "target": "server", "writer_nonce": self.ownership()[1],
        })
        self.assertEqual(200, status, response)
        self.assertEqual("protected-content", response["items"][0]["content"])
        self.assertEqual(403, self.api("/fs/write/mkdir", {
            "path": "elevated-dir", "elevated": True, "target": "server",
            "writer_nonce": self.ownership()[1],
        })[0])
        status, write = self.request_file_elevation("write")
        self.assertEqual(200, status, write)
        self.assertEqual("files.write", write["capability"])
        self.approve({"error": {"details": write}})
        self.assertEqual(403, self.api("/fs/write/mkdir", {
            "path": "elevated-dir",
        })[0])
        status, created = self.api("/fs/write/mkdir", {
            "path": "elevated-dir", "elevated": True, "target": "server",
            "writer_nonce": self.ownership()[1],
        })
        self.assertIn(status, (200, 201), created)
        self.assertTrue((root / "elevated-dir").is_dir())
        status, mutation = self.api("/fs/write/mutate", {
            "items": [{"op": "file.create", "path": "elevated-dir/written.txt",
                       "content": "authorized"}],
            "elevated": True, "target": "server",
            "writer_nonce": self.ownership()[1],
        })
        self.assertEqual(200, status, mutation)
        self.assertEqual("authorized", (root / "elevated-dir/written.txt").read_text())
        self.assertEqual(404, self.api("/fs/read/files", {
            "paths": ["elevated-file.txt"], "elevated": True,
            "target": "other-mapping", "writer_nonce": self.ownership()[1],
        })[0])

    def test_file_elevation_get_and_mapping_target_binding(self):
        from urllib.parse import urlencode
        self.configure()
        self.server.tokens.update(self.record.token, can_read=False)
        status, pending = self.request_file_elevation("read", "server")
        self.assertEqual(200, status)
        self.approve({"error": {"details": pending}})
        query = urlencode({
            "path": ".", "elevated": "true", "target": "server",
            "writer_nonce": self.ownership()[1], "plan_id": self.plan,
        })
        status, _, raw = self.request("GET", self.base + "/fs/query/list?" + query,
                                      headers=self.headers)
        self.assertEqual(200, status, raw)
        query = urlencode({
            "path": "laptop", "elevated": "true", "target": "server",
            "writer_nonce": self.ownership()[1], "plan_id": self.plan,
        })
        status, _, raw = self.request("GET", self.base + "/fs/query/list?" + query,
                                      headers=self.headers)
        self.assertEqual(403, status, raw)
        self.assertIn(b"file_elevation_target_mismatch", raw)
        status, pending = self.request_file_elevation("read", self.row["id"])
        self.assertEqual(200, status, pending)
        self.approve({"error": {"details": pending}})
        # The Shell test fixture routes tasks to SharedClientTasks, which
        # does not implement the independent File API RPC protocol. Delegate
        # only file RPC operations to the separate ClientFiles fixture.
        self.session.call = lambda operation, args: (
            self.files.dispatch(operation, args) if (operation.startswith("api_") or operation == "resolve_path")
            else self.tasks.dispatch(operation, args)
        )
        query = urlencode({
            "path": "laptop", "elevated": "true", "target": self.row["id"],
            "writer_nonce": self.ownership()[1], "plan_id": self.plan,
        })
        status, _, raw = self.request("GET", self.base + "/fs/query/list?" + query,
                                      headers=self.headers)
        self.assertEqual(200, status, raw)

    def test_file_elevation_proactive_mcp_and_permission_flags(self):
        self.configure()
        self.server.tokens.update(self.record.token, can_read=False, can_write=False)
        access, _, _ = self.authorize()
        arguments = {
            "family": "files", "operation": "request_elevation",
            "args": {"access": "read", "target": "server",
                     "writer_nonce": self.ownership()[1]},
            "plan_id": self.plan, "taskname": "file elevation",
            "message": "Request read permission",
        }
        status, result = self.rpc(access["access_token"], "tools/call", {
            "name": "capability_call", "arguments": arguments,
        })
        self.assertEqual(200, status)
        self.assertFalse(result["result"]["isError"], result)
        pending = result["result"]["structuredContent"]
        self.assertEqual("files.read", pending["capability"])
        self.approve({"error": {"details": pending}})
        tool_args = {
            "name": "fs_read_files", "arguments": {
                "paths": ["file.txt"], "elevated": True,
                "writer_nonce": self.ownership()[1], "target": "server",
                "plan_id": self.plan, "taskname": "file elevation",
                "message": "Read with approval",
            },
        }
        self.server.tokens.scope_root(self.record).joinpath("file.txt").write_text("readable")
        status, reply = self.rpc(access["access_token"], "tools/call", tool_args)
        self.assertEqual(200, status)
        self.assertFalse(reply["result"]["isError"], reply)
        self.assertEqual("readable", reply["result"]["structuredContent"]["items"][0]["content"])

        # A read grant must not authorize a write MCP tool.
        write_args = {
            "name": "fs_write",
            "arguments": {
                "path": "elevated-mcp.txt", "content": "new",
                "elevated": True, "writer_nonce": self.ownership()[1],
                "target": "server", "plan_id": self.plan,
                "taskname": "file elevation", "message": "Write with approval",
            },
        }
        status, denied = self.rpc(access["access_token"], "tools/call", write_args)
        self.assertEqual(200, status)
        self.assertTrue(denied["result"]["isError"], denied)
        self.assertIn("capability_approval_required",
                      str(denied["result"]["structuredContent"]))
        arguments["args"]["access"] = "write"
        status, asked = self.rpc(access["access_token"], "tools/call", {
            "name": "capability_call", "arguments": arguments,
        })
        self.assertEqual(200, status)
        self.approve({"error": {"details": asked["result"]["structuredContent"]}})
        status, written = self.rpc(access["access_token"], "tools/call", write_args)
        self.assertEqual(200, status)
        self.assertFalse(written["result"]["isError"], written)
        self.assertEqual(
            "new", self.server.tokens.scope_root(self.record)
            .joinpath("elevated-mcp.txt").read_text(),
        )

    def test_file_elevation_respects_denied_and_readonly_paths(self):
        from openkapsel.auth.tokens import PathGrant
        self.configure()
        root = self.server.tokens.scope_root(self.record)
        (root / "secret.txt").write_text("not available")
        (root / "readonly").mkdir()
        self.server.tokens.update(
            self.record.token, can_read=False, can_write=False, shell_mode="restricted",
            allowed_paths=(
                PathGrant(str(root / "secret.txt"), access="deny"),
                PathGrant(str(root / "readonly"), access="ro"),
            ),
        )
        for access in ("read", "write"):
            status, pending = self.request_file_elevation(access)
            self.assertEqual(200, status, pending)
            self.approve({"error": {"details": pending}})
        nonce = self.ownership()[1]
        self.assertEqual(403, self.api("/fs/read/files", {
            "paths": ["secret.txt"], "elevated": True,
            "target": "server", "writer_nonce": nonce,
        })[0])
        self.assertEqual(403, self.api("/fs/write/mkdir", {
            "path": "readonly/newdir", "elevated": True,
            "target": "server", "writer_nonce": nonce,
        })[0])
        self.assertFalse((root / "readonly/newdir").exists())
        # The same read/write approvals do not authorize Shell tasks.
        status, body = self.elevated()
        self.assertEqual(403, status)
        self.assertEqual("capability_approval_required", body["error"]["code"])

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
        self.server.capability_grants.revoke_workspace(self.record.app_id)
        ticket = self.server.capability_grants.request(self.record.app_id, self.ownership()[0], "server", "files.write")
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
        self.assertFalse(self.server.capability_grants.granted(self.record.app_id, self.ownership()[0], "server", "shell.elevated"))
        # New URL cannot reset the shared workspace password budget.
        _, new = self.elevated()
        location, headers, form, _ = self.approval(new)
        self.assertEqual(429, self.form(location, form, headers)[0])

    def test_six_character_workspace_password_admin_and_approval(self):
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        status, _, dashboard = self.request("GET", "/kapsel/admin", headers=headers)
        self.assertEqual(200, status)
        self.assertIn(b'name="password" type="password" minlength="6"', dashboard)
        self.assertIn(b'name="new_password" type="password"', dashboard)
        self.assertIn(b'name="new_password" type="password" autocomplete="new-password" minlength="12"', dashboard)
        status, _, legacy = self.request("GET", "/kapsel/admin/capabilities", headers=headers)
        self.assertEqual(200, status)
        self.assertIn(b'name="password" minlength="6"', legacy)

        values = {
            "csrf": session.csrf, "workspace": self.record.app_id,
            "action": "password", "password": "abc123",
            "return_to": "token", "token_app_id": self.record.app_id,
        }
        status, response_headers, _ = self.form(
            "/kapsel/admin/capabilities", values, headers
        )
        self.assertEqual(303, status)
        self.assertIn(f"#token-{self.record.app_id}-credentials",
                      response_headers["Location"])
        grants = self.server.capability_grants
        self.assertTrue(grants.verify_workspace_password(self.record.app_id, "abc123"))

        self.assertEqual(400, self.form(
            "/kapsel/admin/capabilities",
            dict(values, password="abc12"), headers,
        )[0])
        self.assertTrue(grants.verify_workspace_password(self.record.app_id, "abc123"))

        status, pending = self.request_elevation()
        self.assertEqual(200, status, pending)
        location, approval_headers, form, _ = self.approval({
            "error": {"details": pending},
        })
        form["password"] = "abc123"
        status, _, response = self.form(location, form, approval_headers)
        self.assertEqual(200, status, response)
        self.assertTrue(grants.granted(
            self.record.app_id, self.ownership()[0], "server", "shell.elevated"
        ))

    def test_admin_token_tabs_option_a_underline_and_mobile_scrolling(self):
        session = self.server.admin_sessions.create()
        status, _, dashboard = self.request(
            "GET", "/kapsel/admin",
            headers={"Cookie": "ws_admin=" + session.id},
        )
        self.assertEqual(200, status)
        page = dashboard.decode()
        css = page.split("<style>", 1)[1].split("</style>", 1)[0]
        self.assertIn(".token-tablist{display:flex", css)
        self.assertIn("border-bottom:1px solid var(--line)", css)
        self.assertIn("overflow-x:auto", css)
        self.assertIn('border-bottom-color:var(--brand)', css)
        self.assertIn('.token-tab[aria-selected="true"]', css)
        self.assertIn("@media(max-width:520px){.token-tablist", css)
        # The first pane starts selected; other panes remain proper tabs,
        # not independent action buttons or permanently visible forms.
        card = page.split(f'data-token-app="{self.record.app_id}"', 1)[1].split(
            "</details>", 1
        )[0]
        self.assertIn('role="tablist"', card)
        buttons = re.findall(r'<button type="button" role="tab"[^>]*>', card)
        self.assertEqual(3, len(buttons))
        self.assertEqual(
            ["true", "false", "false"],
            [re.search(r'aria-selected="([^"]+)"', button).group(1)
             for button in buttons],
        )

    def test_admin_token_tabs_include_workspace_password_settings(self):
        import re
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        status, _, dashboard = self.request("GET", "/kapsel/admin", headers=headers)
        self.assertEqual(200, status, dashboard)
        self.assertNotIn(b"Workspace password</span>", dashboard)
        page = dashboard.decode()
        scripts = re.findall(r'<script>(.*?)</script>', page, re.S)
        admin_script = next(script for script in scripts
                            if 'function setAdminPanel(' in script)
        self.assertLess(admin_script.index('function setAdminPanel('),
                        admin_script.index('function setTokenPane('))
        import shutil
        import subprocess
        if shutil.which("node"):
            result = subprocess.run(["node", "--check"], input=admin_script,
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
        card = page.split(f'data-token-app="{self.record.app_id}"', 1)[1].split(
            '</details>', 1)[0]
        self.assertEqual(
            ["basic", "permissions", "credentials"],
            re.findall(r'<button[^>]*data-token-tab="([^"]+)"', card),
        )
        panes = re.findall(r'<section class="token-pane"[^>]*>', card)
        self.assertEqual(3, len(panes))
        self.assertNotIn(" hidden", panes[0])
        self.assertIn(" hidden", panes[1])
        self.assertIn(" hidden", panes[2])
        update = card.split('<form data-token-update ', 1)[1].split('</form>', 1)[0]
        self.assertNotIn("<form ", update)  # no nested forms
        names = re.findall(r'<(?:input|select|textarea)[^>]*name="([^"]+)"', update)
        for name in ("name", "expires_at", "workspace_type", "path_prefix",
                     "workspace_image", "can_read", "can_write", "can_preview",
                     "can_schedule", "enabled", "shell_mode", "network_mode",
                     "sandbox_max_processes", "allowed_domains"):
            self.assertIn(name, names)
        credentials = card.split('data-token-pane="credentials"', 1)[1]
        self.assertIn('action="/kapsel/admin/capabilities"', credentials)
        self.assertIn(f'name="workspace" value="{self.record.app_id}"',
                      credentials)
        self.assertIn(f'name="token_app_id" value="{self.record.app_id}"',
                      credentials)
        self.assertFalse(self.server.capability_grants.configured(self.record.app_id))
        values = {"workspace": self.record.app_id, "action": "password",
                  "password": self.PASSWORD, "csrf": session.csrf,
                  "return_to": "token", "token_app_id": self.record.app_id}
        self.assertEqual(403, self.form("/kapsel/admin/capabilities",
                                         dict(values, csrf="invalid"), headers)[0])
        self.assertEqual(400, self.form("/kapsel/admin/capabilities",
                                         dict(values, token_app_id="unknown"), headers)[0])
        status, post_headers, _ = self.form("/kapsel/admin/capabilities", values, headers)
        self.assertEqual(303, status)
        self.assertIn(f"#token-{self.record.app_id}-credentials",
                      post_headers["Location"])
        self.assertTrue(self.server.capability_grants.configured(self.record.app_id))
        self.assertIn(b"Configured", self.request("GET", "/kapsel/admin",
                                                 headers=headers)[2])

    def test_admin_token_update_restores_permissions_tab(self):
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        record = self.server.tokens.get(self.record.token)
        values = {
            "csrf": session.csrf, "action": "update", "token": record.token,
            "name": record.name, "workspace_type": "directory",
            "path_prefix": record.path_prefix, "expires_at": "",
            "shell_mode": record.shell_mode, "network_mode": record.network_mode,
            "sandbox_backend": "auto",
            "allowed_domains": "\n".join(record.allowed_domains),
            "sandbox_max_processes": str(record.sandbox_max_processes),
            "sandbox_memory_mb": str(record.sandbox_memory_mb),
            "sandbox_cpu_percent": str(record.sandbox_cpu_percent),
            "enabled": "on", "token_pane": "permissions",
        }
        for name in ("can_read", "can_write", "can_preview", "can_schedule"):
            if getattr(record, name):
                values[name] = "on"
        status, response_headers, _ = self.form("/kapsel/admin/tokens", values, headers)
        self.assertEqual(303, status)
        self.assertEqual(
            f"/kapsel/admin?token_updated=1#token-{record.app_id}-permissions",
            response_headers["Location"],
        )

    def test_admin_password_reset_revoke_and_lifecycle(self):
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        path = "/kapsel/admin/capabilities"
        form = {"workspace": self.record.app_id, "action": "password", "password": self.PASSWORD, "csrf": session.csrf}
        self.assertEqual(403, self.form(path, dict(form, csrf="invalid"), headers)[0])
        self.assertEqual(200, self.form(path, form, headers)[0])
        _, result = self.elevated()
        self.approve(result)
        self.assertIn(b"shell.elevated", self.request("GET", path, headers=headers)[2])
        grant = {"workspace": self.record.app_id, "action": "revoke", "conversation_id": str(self.ownership()[0]), "target": "server", "capability": "shell.elevated", "csrf": session.csrf}
        self.assertEqual(200, self.form(path, grant, headers)[0])
        self.assertEqual(403, self.elevated()[0])
        self.assertEqual(200, self.form(path, dict(form, password="new-workspace-password-123"), headers)[0])
        self.assertEqual({}, self.server.capability_grants.pending_requests)
        delete = {"action": "delete", "token": self.record.token, "csrf": session.csrf}
        self.assertEqual(303, self.form("/kapsel/admin/tokens", delete, headers)[0])
        self.assertFalse(self.server.capability_grants.configured(self.record.app_id))

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
        self.server.capability_grants.active[(self.record.app_id, self.ownership()[0], "server", "shell.elevated", "")] = 0
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
        key = (self.record.app_id, self.ownership()[0], "server", "shell.elevated", "")
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

    def test_shared_directory_oauth_cannot_use_another_tokens_password(self):
        first = self.record
        second = self.server.tokens.create(
            name="Same Directory Other Token", path_prefix=first.path_prefix,
            shell_mode="none", expires_at=None, can_read=True, can_write=False,
        )
        second_password = "other-token-oauth-pass-123"
        self.server.capability_grants.set_password(second.app_id, second_password)
        pending = self.pending()
        # OAuth consent for the first Token must not authenticate with a
        # separate Token's password, even though both share path_prefix.
        self.assertEqual(403, self.submit(
            pending, values={"control_token": "", "workspace_password": second_password}
        )[0])
        self.server.capability_grants.set_password(first.app_id, "first-token-oauth-pass-456")
        self.assertEqual(303, self.submit(
            pending, values={"control_token": "", "workspace_password": "first-token-oauth-pass-456"}
        )[0])

    def test_workspace_password_oauth_is_independent_of_capability_grants(self):
        self.server.capability_grants.set_password(self.record.app_id, "workspace-test-password-123")
        pending = self.pending()
        self.assertIn(b'name="workspace_password"', pending["page"])
        status, _, raw = self.submit(pending, values={"control_token": "", "workspace_password": "incorrect-password"})
        self.assertEqual(403, status, raw)
        status, headers, raw = self.submit(pending, values={"control_token": "", "workspace_password": "workspace-test-password-123"})
        self.assertEqual(303, status, raw)
        self.assertNotIn("workspace-test-password-123", headers["Location"])
        self.assertEqual({}, self.server.capability_grants.active)
        self.assertEqual({}, self.server.admin_sessions._sessions)

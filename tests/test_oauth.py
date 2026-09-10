from __future__ import annotations

import base64
import http.client
import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from openkapsel.oauth_store import OAuthError, OAuthStore, challenge
from openkapsel.security import hash_password
from openkapsel.server import ServerConfig, create_server


class OAuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "oauth.sqlite3"
        self.store = OAuthStore(self.path)
        self.cid = self.store.create("app", "project", "Claude")["id"]
        self.resource = "https://example.test/kapsel/connect/" + self.cid + "/mcp"
        self.client = self.store.register(self.cid, {"redirect_uris": ["https://client.test/callback"], "token_endpoint_auth_method": "none"})
        self.verifier = "v" * 64

    def tearDown(self):
        self.temp.cleanup()

    def params(self, **changes):
        params = {"client_id": self.client["client_id"], "response_type": "code", "redirect_uri": "https://client.test/callback", "code_challenge": challenge(self.verifier), "code_challenge_method": "S256", "resource": self.resource, "state": "opaque-state"}
        params.update(changes)
        return params

    def form(self, code, **changes):
        result = {"grant_type": "authorization_code", "client_id": self.client["client_id"], "redirect_uri": "https://client.test/callback", "code": code, "code_verifier": self.verifier, "resource": self.resource}
        result.update(changes)
        return result

    def issue(self):
        rid = self.store.start(self.cid, self.params(), self.resource)
        _, code = self.store.approve(rid)
        return self.store.exchange(self.cid, self.form(code), self.resource, "none")

    def test_registration_does_not_bind_and_requires_owner_approval(self):
        other = self.store.register(self.cid, {"redirect_uris": ["https://other.test/cb"], "token_endpoint_auth_method": "none"})
        self.assertIsNone(self.store.get(self.cid)["client_id"])
        rid = self.store.start(self.cid, self.params(), self.resource)
        with self.assertRaises(OAuthError):
            self.store.exchange(self.cid, self.form(rid), self.resource, "none")
        self.store.approve(rid)
        with self.assertRaises(OAuthError):
            self.store.start(self.cid, self.params(client_id=other["client_id"], redirect_uri="https://other.test/cb"), self.resource)
        with self.assertRaises(OAuthError):
            self.store.register(self.cid, {"redirect_uris": ["https://new.test/cb"]})

    def test_pkce_redirect_resource_and_client_binding(self):
        for changes in ({"redirect_uri": "https://evil.test/cb"}, {"code_challenge_method": "plain"}, {"resource": "https://evil.test/mcp"}):
            with self.subTest(changes=changes), self.assertRaises(OAuthError):
                self.store.start(self.cid, self.params(**changes), self.resource)
        rid = self.store.start(self.cid, self.params(), self.resource)
        _, code = self.store.approve(rid)
        for changes in ({"code_verifier": "x" * 64}, {"redirect_uri": "https://evil.test/cb"}, {"resource": "https://evil.test/mcp"}, {"client_id": "wrong"}):
            with self.subTest(changes=changes), self.assertRaises(OAuthError):
                self.store.exchange(self.cid, self.form(code, **changes), self.resource, "none")
        token = self.store.exchange(self.cid, self.form(code), self.resource, "none")
        self.assertEqual(self.cid, self.store.authenticate(self.cid, token["access_token"])["id"])
        with self.assertRaises(OAuthError):
            self.store.exchange(self.cid, self.form(code), self.resource, "none")

    def test_refresh_rotation_replay_revokes_family_and_persists(self):
        token = self.issue()
        self.store = OAuthStore(self.path)
        form = {"grant_type": "refresh_token", "client_id": self.client["client_id"], "resource": self.resource, "refresh_token": token["refresh_token"]}
        renewed = self.store.exchange(self.cid, form, self.resource, "none")
        self.store.authenticate(self.cid, renewed["access_token"])
        with self.assertRaises(OAuthError):
            self.store.exchange(self.cid, form, self.resource, "none")
        for access in (token["access_token"], renewed["access_token"]):
            with self.assertRaises(OAuthError):
                self.store.authenticate(self.cid, access)
        data = self.path.read_bytes()
        for raw in (token["access_token"], token["refresh_token"], renewed["access_token"]):
            self.assertNotIn(raw.encode(), data)

    def test_cross_connection_and_delete_revoke(self):
        token = self.issue()
        other = self.store.create("other", "another", "ChatGPT")["id"]
        with self.assertRaises(OAuthError):
            self.store.authenticate(other, token["access_token"])
        self.store.delete(self.cid)
        with self.assertRaises(OAuthError):
            self.store.authenticate(self.cid, token["access_token"])
        with self.store._db() as db:
            for table in ("clients", "grants", "credentials", "requests"):
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0])

    def test_concurrent_code_redemption_only_one_succeeds(self):
        rid = self.store.start(self.cid, self.params(), self.resource)
        _, code = self.store.approve(rid)
        def redeem(_):
            try:
                self.store.exchange(self.cid, self.form(code), self.resource, "none")
                return True
            except OAuthError:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(1, sum(pool.map(redeem, range(4))))

    def test_expiration_deny_and_registration_bounds(self):
        rid = self.store.start(self.cid, self.params(), self.resource)
        self.store.deny(rid)
        with self.assertRaises(OAuthError):
            self.store.approve(rid)
        token = self.issue()
        with self.store._db() as db:
            db.execute("UPDATE credentials SET expires_at=?", (time.time() - 1,))
        with self.assertRaises(OAuthError):
            self.store.authenticate(self.cid, token["access_token"])
        for metadata in ({"redirect_uris": ["http://evil.test/cb"]}, {"redirect_uris": ["https://a.test/cb#fragment"]}, {"redirect_uris": ["https://a.test/cb"], "grant_types": [{}]}):
            with self.subTest(metadata=metadata), self.assertRaises(OAuthError):
                self.store.register(self.cid, metadata)


class OAuthHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "workspace"
        root.mkdir()
        self.server = create_server("127.0.0.1", 0, ServerConfig(
            root=root, token="legacy", token_data_file=Path(self.temp.name) / "tokens.json",
            public_base_url="https://example.test", url_base_path="/kapsel",
            admin_username="admin", admin_password_hash=hash_password("test-password-123"),
        ))
        self.record = self.server.tokens.create(name="Project", path_prefix="project", shell_mode="none", expires_at=None, can_read=True, can_write=True)
        (root / "project" / "hello.txt").write_text("hello", encoding="utf-8")
        self.cid = self.server.oauth.create(self.record.app_id, "project", "Claude test")["id"]
        self.prefix = "/kapsel/oauth/" + self.cid
        self.mcp = "/kapsel/connect/" + self.cid + "/mcp"
        self.resource = "https://example.test" + self.mcp
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def form(self, path, form, headers=None):
        return self.request("POST", path, urlencode(form), {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})

    def authorize(self, auth="none"):
        metadata = {"redirect_uris": ["https://client.test/callback"], "token_endpoint_auth_method": auth, "client_name": "Test client"}
        status, _, raw = self.request("POST", self.prefix + "/register", json.dumps(metadata), {"Content-Type": "application/json"})
        self.assertEqual(201, status, raw)
        client = json.loads(raw)
        verifier = "x" * 64
        params = {"client_id": client["client_id"], "response_type": "code", "redirect_uri": metadata["redirect_uris"][0], "code_challenge": challenge(verifier), "code_challenge_method": "S256", "resource": self.resource, "state": "state-123"}
        status, headers, _ = self.request("GET", self.prefix + "/authorize?" + urlencode(params))
        self.assertEqual(303, status)
        location = headers["Location"]
        rid = parse_qs(urlsplit(location).query)["request"][0]
        status, _, raw = self.request("GET", location)
        self.assertIn(b'name="oauth_request"', raw)
        status, _, raw = self.form("/kapsel/admin/login", {"username": "admin", "password": "incorrect-password", "oauth_request": rid})
        self.assertEqual(401, status)
        self.assertIn(rid.encode(), raw)
        status, headers, raw = self.form("/kapsel/admin/login", {"username": "admin", "password": "test-password-123", "oauth_request": rid})
        self.assertEqual(303, status, raw)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertEqual(location, headers["Location"])
        status, consent_headers, raw = self.request("GET", location, headers={"Cookie": cookie})
        self.assertIn(b"Authorize MCP connection", raw)
        self.assertIn("form-action 'self' https://client.test", consent_headers["Content-Security-Policy"])
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        status, _, _ = self.form("/kapsel/admin/oauth/approve", {"request": rid, "decision": "approve", "csrf": "wrong"}, {"Cookie": cookie})
        self.assertEqual(403, status)
        status, headers, raw = self.form("/kapsel/admin/oauth/approve", {"request": rid, "decision": "approve", "csrf": session.csrf}, {"Cookie": cookie})
        self.assertEqual(303, status, raw)
        callback = parse_qs(urlsplit(headers["Location"]).query)
        self.assertEqual(["state-123"], callback["state"])
        form = {"grant_type": "authorization_code", "client_id": client["client_id"], "code": callback["code"][0], "redirect_uri": metadata["redirect_uris"][0], "code_verifier": verifier, "resource": self.resource}
        headers = {}
        if auth == "client_secret_post":
            form["client_secret"] = client["client_secret"]
        if auth == "client_secret_basic":
            headers["Authorization"] = "Basic " + base64.b64encode((client["client_id"] + ":" + client["client_secret"]).encode()).decode()
        status, _, raw = self.form(self.prefix + "/token", form, headers)
        self.assertEqual(200, status, raw)
        return json.loads(raw), cookie, session

    def rpc(self, token, name, arguments=None):
        message = {"jsonrpc": "2.0", "id": 1, "method": name}
        if arguments is not None:
            message["params"] = arguments
        status, _, raw = self.request("POST", self.mcp, json.dumps(message), {"Content-Type": "application/json", "Authorization": "Bearer " + token})
        return status, json.loads(raw)

    def test_discovery_and_full_flow_survive_credential_renewal(self):
        status, headers, _ = self.request("POST", self.mcp, "{}", {"Content-Type": "application/json"})
        self.assertEqual(401, status)
        self.assertIn("/.well-known/oauth-protected-resource" + self.mcp, headers["WWW-Authenticate"])
        for path in (self.prefix + "/resource", "/.well-known/oauth-protected-resource" + self.mcp, "/.well-known/oauth-authorization-server" + self.prefix):
            status, _, raw = self.request("GET", path)
            self.assertEqual(200, status, raw)
            status, head_headers, raw = self.request("HEAD", path)
            self.assertEqual(200, status)
            self.assertEqual(b"", raw)
            self.assertGreater(int(head_headers["Content-Length"]), 0)
        token, cookie, session = self.authorize()
        status, payload = self.rpc(token["access_token"], "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
        self.assertEqual(200, status, payload)
        self.assertIn("serverInfo", payload["result"])
        self.server.tokens.renew_credentials(self.record.token)
        renewed = self.server.tokens.get_by_app_id(self.record.app_id)
        self.server.tokens.update(renewed.token, credentials_expires_at="2000-01-01T00:00:00+00:00")
        status, payload = self.rpc(token["access_token"], "tools/list")
        self.assertEqual(200, status, payload)
        self.assertIn("tools", payload["result"])
        status, payload = self.rpc(token["access_token"], "tools/call", {"name": "workspace_info", "arguments": {}})
        self.assertEqual(200, status)
        text = json.dumps(payload)
        self.assertIn("oauth2", text)
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        for secret in (current.token, current.control_token, current.preview_token):
            self.assertNotIn(secret, text)
        status, payload = self.rpc(token["access_token"], "tools/call", {"name": "prepare_download", "arguments": {"path": "hello.txt"}})
        transfer = payload["result"]["structuredContent"]["transfer"]["url"]
        self.assertIn("/connect/" + self.cid + "/transfer/", transfer)
        parsed = urlsplit(transfer)
        status, _, raw = self.request("GET", parsed.path + "?" + parsed.query, headers={"Authorization": "Bearer " + token["access_token"]})
        self.assertEqual((200, b"hello"), (status, raw))
        self.assertIsNotNone(self.server.oauth.get(self.cid)["last_used_at"])
        reassigned = self.server.tokens.create(
            name="OAuth reassigned", path_prefix="oauth-reassigned", shell_mode="none",
            expires_at=None, can_read=True, can_write=False,
        )
        (self.server.config.root / "oauth-reassigned" / "new.txt").write_text("new", encoding="utf-8")
        self.server.oauth.update(
            self.cid, "Claude reassigned", app_id=reassigned.app_id, workspace="oauth-reassigned"
        )
        status, payload = self.rpc(token["access_token"], "tools/call", {"name": "list_files", "arguments": {"path": "."}})
        self.assertEqual(200, status)
        self.assertEqual(["new.txt"], [item["name"] for item in payload["result"]["structuredContent"]["entries"]])
        self.assertEqual("Claude reassigned", self.server.oauth.get(self.cid)["comment"])
        status, _, raw = self.request("GET", "/kapsel/admin", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertIn(b"OAuth connections", raw)
        status, _, _ = self.form("/kapsel/admin/oauth", {"action": "delete", "connection_id": self.cid, "csrf": session.csrf}, {"Cookie": cookie})
        self.assertEqual(303, status)
        status, _ = self.rpc(token["access_token"], "tools/list")
        self.assertEqual(404, status)

    def test_confidential_client_and_workspace_disable(self):
        token, _, _ = self.authorize("client_secret_basic")
        self.server.tokens.update(self.record.token, enabled=False)
        self.assertEqual(403, self.rpc(token["access_token"], "tools/list")[0])

    def test_post_secret_client_and_path_change(self):
        token, _, _ = self.authorize("client_secret_post")
        self.server.tokens.update(self.record.token, path_prefix="other")
        self.assertEqual(403, self.rpc(token["access_token"], "tools/list")[0])

    def test_admin_creation_requires_csrf_and_escapes_comment(self):
        form = {"action": "create", "app_id": self.record.app_id, "comment": "<script>alert(1)</script>"}
        self.assertEqual(401, self.form("/kapsel/admin/oauth", form)[0])
        session = self.server.admin_sessions.create()
        headers = {"Cookie": "ws_admin=" + session.id}
        self.assertEqual(403, self.form("/kapsel/admin/oauth", form, headers)[0])
        form["csrf"] = session.csrf
        self.assertEqual(303, self.form("/kapsel/admin/oauth", form, headers)[0])
        status, _, raw = self.request("GET", "/kapsel/admin", headers=headers)
        self.assertEqual(200, status)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", raw)
        self.assertNotIn(b"<script>alert(1)</script>", raw)

    def test_keepalive_does_not_reuse_authorization_and_rest_stays_separate(self):
        token, _, _ = self.authorize()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
            conn.request("POST", self.mcp, body, {"Content-Type": "application/json", "Authorization": "Bearer " + token["access_token"]})
            response = conn.getresponse()
            self.assertEqual(200, response.status)
            response.read()
            conn.request("POST", self.mcp, body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            self.assertEqual(401, response.status)
            response.read()
        finally:
            conn.close()
        status, _, _ = self.request("GET", "/kapsel/w/" + self.record.token + "/", headers={"Authorization": "Bearer " + token["access_token"]})
        self.assertEqual(401, status)
        self.assertEqual(401, self.rpc(self.record.control_token, "tools/list")[0])


if __name__ == "__main__":
    unittest.main()

"""Static MCP lifecycle, REST isolation, and administration integration."""

import json
import html
import re
import time
import unittest
from urllib.parse import urlsplit

from openkapsel.oauth_store import OAuthError
from openkapsel.static_mcp import StaticMcpStore
from tests import test_oauth


class StaticMcpTests(unittest.TestCase):
    setUp = test_oauth.OAuthHTTPTests.setUp
    tearDown = test_oauth.OAuthHTTPTests.tearDown
    request = test_oauth.OAuthHTTPTests.request
    form = test_oauth.OAuthHTTPTests.form
    rpc = test_oauth.OAuthHTTPTests.rpc

    def connection(self):
        conn = self.server.static_mcp.create(self.record.app_id, "project", "Static client")
        self.mcp = "/kapsel/mcp-connect/" + conn["id"] + "/mcp"
        return conn

    def test_independent_credentials_transfer_expiry_and_revocation(self):
        conn = self.connection()
        self.assertAlmostEqual(time.time() + 365 * 86400, conn["expires_at"], delta=5)
        self.server.tokens.renew_credentials(self.record.token)
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.server.tokens.update(current.token, credentials_expires_at="2000-01-01T00:00:00+00:00")
        self.assertEqual(200, self.rpc(conn["secret"], "tools/list")[0])
        self.assertEqual(401, self.rpc(current.control_token, "tools/list")[0])
        status, result = self.rpc(conn["secret"], "tools/call", {"name": "workspace_info", "arguments": {}})
        self.assertEqual(200, status)
        text = json.dumps(result)
        self.assertIn("static_mcp", text)
        for credential in (current.token, current.control_token, current.preview_token, conn["secret"]):
            self.assertNotIn(credential, text)
        status, result = self.rpc(conn["secret"], "tools/call", {"name": "prepare_download", "arguments": {"path": "hello.txt"}})
        self.assertEqual(200, status)
        url = urlsplit(result["result"]["structuredContent"]["transfer"]["url"])
        auth = {"Authorization": "Bearer " + conn["secret"]}
        self.assertEqual((200, b"hello"), self.request("GET", url.path + "?" + url.query, headers=auth)[::2])
        self.assertEqual(404, self.request("GET", self.mcp.removesuffix("/mcp") + "/context", headers=auth)[0])
        root = self.server.tokens.scope_root(current)
        plan = self.server.context_for(root).add("plan", "Transfer test", taskname="transfer", actor_id=current.actor_id)
        context = {"plan_id": plan, "taskname": "transfer", "message": "Upload file"}
        status, result = self.rpc(conn["secret"], "tools/call", {"name": "start_upload", "arguments": {"path": "uploaded.txt", "size": 3, **context}})
        self.assertEqual(200, status)
        self.assertFalse(result['result']['isError'], result)
        transfer = result['result']['structuredContent']['raw_transfer']
        headers = {**auth, "OpenKapsel-Plan-Id": str(plan), "OpenKapsel-Taskname": "transfer", "OpenKapsel-Message": "Upload file"}
        self.assertEqual(200, self.request('PATCH', urlsplit(transfer['url']).path, b'abc', {**headers, 'Upload-Offset': '0', 'Content-Type': 'application/octet-stream'})[0])
        self.assertEqual(201, self.request('POST', urlsplit(transfer['commit_url']).path, headers=headers)[0])
        self.assertEqual(b'abc', (root / 'uploaded.txt').read_bytes())
        self.assertIsNotNone(self.server.static_mcp.get(conn["id"])["last_used_at"])
        self.server.static_mcp.update(conn["id"], "Renamed", 730)
        updated = self.server.static_mcp.get(conn["id"])
        self.assertEqual(conn["secret"], updated["secret"])
        self.assertEqual("Renamed", updated["comment"])
        self.assertAlmostEqual(time.time() + 730 * 86400, updated["expires_at"], delta=5)
        with self.server.static_mcp._db() as db:
            db.execute("UPDATE connections SET expires_at=?", (time.time() - 1,))
        self.assertEqual(401, self.rpc(conn["secret"], "tools/list")[0])
        self.server.static_mcp.update(conn["id"], "Extended", 30)
        self.assertEqual(200, self.rpc(conn["secret"], "tools/list")[0])
        self.server.static_mcp.delete(conn["id"])
        self.assertEqual(404, self.rpc(conn["secret"], "tools/list")[0])

    def test_scope_rest_separation_and_persistence(self):
        conn = self.connection()
        restored = StaticMcpStore(self.server.static_mcp.path)
        self.assertEqual(conn["id"], restored.authenticate(conn["id"], conn["secret"])["id"])
        other = restored.create(self.record.app_id, "project", "Other")
        with self.assertRaises(OAuthError):
            restored.authenticate(other["id"], conn["secret"])
        with self.assertRaises(OAuthError):
            restored.update(conn["id"], "Invalid", 1)
        self.assertEqual("Static client", restored.get(conn["id"])["comment"])
        base = "/kapsel/w/" + self.record.token
        self.assertEqual(404, self.request("POST", base + "/mcp", "{}", {"Content-Type": "application/json", "Authorization": "Bearer " + self.record.control_token})[0])
        self.assertEqual(401, self.request("GET", base + "/context", headers={"Authorization": "Bearer " + conn["secret"]})[0])
        for path in (base + "/", base + "/discovery/full", base + "/discovery/files"):
            status, _, raw = self.request("GET", path)
            self.assertEqual(200, status)
            self.assertNotIn('"mcp"', raw.decode())
            self.assertNotIn(base + "/mcp", raw.decode())
        self.server.tokens.update(self.record.token, enabled=False)
        self.assertEqual(403, self.rpc(conn["secret"], "tools/list")[0])
        self.server.tokens.update(self.record.token, enabled=True, path_prefix="elsewhere")
        self.assertEqual(403, self.rpc(conn["secret"], "tools/list")[0])

    def test_admin_groups_edit_copy_and_csrf(self):
        status, headers, _ = self.form("/kapsel/admin/login", {"username": "admin", "password": "test-password-123"})
        self.assertEqual(303, status)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        form = {"action": "create", "app_id": self.record.app_id, "comment": "Static", "days": "91"}
        self.assertEqual(403, self.form("/kapsel/admin/static-mcp", form, auth)[0])
        form["csrf"] = session.csrf
        self.assertEqual(303, self.form("/kapsel/admin/static-mcp", form, auth)[0])
        conn = self.server.static_mcp.list()[0]
        self.assertAlmostEqual(time.time() + 91 * 86400, conn["expires_at"], delta=5)
        form.update(action="update", connection_id=conn["id"], comment="<New>", days="182")
        self.assertEqual(303, self.form("/kapsel/admin/static-mcp", form, auth)[0])
        form.update(connection_id=self.cid, comment="OAuth renamed")
        self.assertEqual(303, self.form("/kapsel/admin/oauth", form, auth)[0])
        status, _, raw = self.request("GET", "/kapsel/admin", headers=auth)
        self.assertEqual(200, status)
        page = raw.decode()
        self.assertEqual(2, page.count("Project: project"))
        self.assertIn("&lt;New&gt;", page)
        self.assertIn("OAuth renamed", page)
        self.assertIn("Copy MCP JSON", page)
        self.assertIn('<span class="badge">Active</span><span class="muted">Expires:', page)
        self.assertNotIn("Configuration:", page)
        static_card = page.index(f'id="json-{conn["id"]}"')
        copy_json = page.index("Copy MCP JSON", static_card)
        self.assertLess(page.rfind("Copy MCP URL", 0, copy_json), copy_json)
        self.assertLess(copy_json, page.index("Save changes", copy_json))
        self.assertIn(conn["secret"], page)
        copied = json.loads(html.unescape(re.search(r'<pre id="json-' + conn['id'] + r'" hidden>(.*?)</pre>', page, re.S).group(1)))
        client = copied['mcpServers']['openkapsel']
        self.assertEqual('http', client['type'])
        self.assertEqual('Bearer ' + conn['secret'], client['headers']['Authorization'])
        self.assertEqual('https://example.test/kapsel/mcp-connect/' + conn['id'] + '/mcp', client['url'])
        self.assertNotIn("/w/" + self.record.token + "/mcp", page)
        form.update(action="delete", connection_id=conn["id"])
        self.assertEqual(303, self.form("/kapsel/admin/static-mcp", form, auth)[0])
        self.assertEqual([], self.server.static_mcp.list())

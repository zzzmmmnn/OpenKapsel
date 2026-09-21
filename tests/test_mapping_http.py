"""Administration and HTTP credential boundaries without mounting FUSE."""

import html
import json
import re
import unittest
from unittest.mock import patch

from tests import test_oauth


class MappingHTTPTests(unittest.TestCase):
    setUp = test_oauth.OAuthHTTPTests.setUp
    tearDown = test_oauth.OAuthHTTPTests.tearDown
    request = test_oauth.OAuthHTTPTests.request
    form = test_oauth.OAuthHTTPTests.form

    def test_admin_csrf_and_one_time_provider_configuration(self):
        path = "/kapsel/admin/mappings"
        self.assertNotEqual(200, self.request("GET", path)[0])
        status, headers, _ = self.form("/kapsel/admin/login", {"username": "admin", "password": "test-password-123"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        form = {"action": "create", "app_id": self.record.app_id, "name": "laptop", "writable": "on"}
        self.assertEqual(403, self.form(path, form, auth)[0])
        self.assertEqual([], self.server.mappings.store.list())
        form["csrf"] = session.csrf
        with patch.object(self.server.mappings, "mount"):
            status, _, raw = self.form(path, form, auth)
        self.assertEqual(status, 200)
        page = raw.decode()
        config = json.loads(html.unescape(re.search(r'<pre[^>]*id="mapping-client-config"[^>]*>(.*?)</pre>', page, re.S)[1]))
        self.assertIn('class="admin-shell" data-initial-panel="mappings"', page)
        self.assertIn('data-admin-tab="mappings"', page)
        self.assertIn("'static-mcp','mappings']", page)
        self.assertIn('action="/kapsel/admin/mappings"', page)
        for icon in ("🔑", "💾", "🔒", "🔗", "🔌", "🗂️", "🚪"):
            self.assertIn(icon, page)
        row = self.server.mappings.store.list()[0]
        self.assertEqual(config["url"], "wss://example.test/kapsel/mapping-connect/" + row["id"])
        self.server.mappings.store.authenticate(row["id"], config["token"])
        self.assertTrue(config["sandbox"])
        self.assertFalse(config["allow_exec"])
        self.assertEqual(60, config["transport_timeout_seconds"])
        self.assertNotIn("source_root", config)
        self.assertFalse(config["auto_reload"])
        self.assertEqual({"git": True, "archive": True}, config["rpc"])
        self.assertEqual([], config["rpc_plugins"])
        self.assertNotIn(config["token"].encode(), self.request("GET", path, headers=auth)[2])
        base = "/kapsel/w/" + self.record.token
        self.assertNotIn(config["token"].encode(), self.request("GET", base + "/mappings")[2])
        # Provider credentials cannot grant REST control or task access.
        for credential in (None, config["token"]):
            headers = {} if credential is None else {"Authorization": "Bearer " + credential}
            self.assertEqual(401, self.request("GET", base + "/mappings/" + row["id"] + "/tasks", headers=headers)[0])

    def test_generic_readonly_rpc_plugin_rest_and_mcp(self):
        from types import SimpleNamespace

        row, _ = self.server.mappings.store.create(self.record.path_prefix, "plugin-client", writable=False)
        root = self.server.tokens.scope_root(self.record)
        (root / row["name"]).mkdir()
        calls = []

        def call(operation, args):
            calls.append((operation, args))
            if operation == "vendor_update":
                return {"status": 200, "body": {"updated": args.get("value")}}
            return {"status": 200, "body": {"echo": args.get("value")}}

        session = SimpleNamespace(
            closed=False, ready=True,
            capabilities={"rpc": {"vendor": {
                "state": "available",
                "version": 1,
                "description": "Inspect or update vendor metadata.",
                "operations": ["inspect", "update"],
                "operation_specs": {
                    "inspect": {
                        "description": "Inspect one integer.",
                        "input_schema": {
                            "type": "object",
                            "properties": {"value": {"type": "integer"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                        "write": False,
                    },
                    "update": {
                        "description": "Update one integer.",
                        "input_schema": {
                            "type": "object",
                            "properties": {"value": {"type": "integer"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                        "write": True,
                    },
                },
                "read_only": False,
            }}},
            call=call,
            close=lambda: None,
        )
        self.server.mappings.sessions[row["id"]] = session
        try:
            base = "/kapsel/w/" + self.record.token
            status, _, raw = self.request("GET", base + "/mappings")
            self.assertEqual(200, status, raw)
            advertised = json.loads(raw)["mappings"][0]["capabilities"]["rpc"]["vendor"]
            self.assertEqual("Inspect or update vendor metadata.", advertised["description"])
            self.assertEqual(
                "integer",
                advertised["operation_specs"]["inspect"]["input_schema"]["properties"]["value"]["type"],
            )

            endpoint = base + f"/mappings/{row['id']}/rpc/vendor/inspect"
            status, _, raw = self.request(
                "POST", endpoint, json.dumps({"args": {"value": 7}}),
                {"Content-Type": "application/json"},
            )
            self.assertEqual(200, status, raw)
            payload = json.loads(raw)
            self.assertEqual(7, payload["result"]["echo"])
            self.assertEqual([("vendor_inspect", {"value": 7})], calls)

            write_endpoint = base + f"/mappings/{row['id']}/rpc/vendor/update"
            status, _, raw = self.request(
                "POST", write_endpoint, json.dumps({"args": {"value": 9}}),
                {"Authorization": "Bearer " + self.record.control_token, "Content-Type": "application/json"},
            )
            self.assertEqual(403, status, raw)
            self.assertEqual("mapping_read_only", json.loads(raw)["error"]["code"])
            self.assertEqual([("vendor_inspect", {"value": 7})], calls)

            self.server.mappings.store.update(row["id"], writable=True)
            status, _, raw = self.request(
                "POST", write_endpoint, json.dumps({"args": {"value": 9}}),
                {"Content-Type": "application/json"},
            )
            self.assertEqual(401, status, raw)
            self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

            control = {"Authorization": "Bearer " + self.record.control_token, "Content-Type": "application/json"}
            status, _, raw = self.request(
                "POST", base + "/context",
                json.dumps({"type": "plan", "taskname": "rpc", "content": "RPC write test"}),
                control,
            )
            self.assertEqual(201, status, raw)
            plan_id = json.loads(raw)["id"]
            status, _, raw = self.request(
                "POST",
                write_endpoint,
                json.dumps({
                    "args": {"value": 9},
                    "plan_id": plan_id,
                    "taskname": "rpc",
                    "message": "Update vendor metadata",
                }),
                control,
            )
            self.assertEqual(200, status, raw)
            self.assertEqual(9, json.loads(raw)["result"]["updated"])
            self.assertEqual(("vendor_update", {"value": 9}), calls[-1])

            conn = self.server.static_mcp.create(self.record.app_id, self.record.path_prefix, "Plugin reads")
            tool = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "rpc",
                "arguments": {
                    "mapping_id": row["id"],
                    "family": "vendor",
                    "operation": "inspect",
                    "args": {"value": 8},
                },
            }}
            _, _, raw = self.request(
                "POST", "/kapsel/mcp-connect/" + conn["id"] + "/mcp", json.dumps(tool),
                {"Authorization": "Bearer " + conn["secret"], "Content-Type": "application/json"},
            )
            result = json.loads(raw)["result"]
            self.assertFalse(result["isError"], result)
            self.assertEqual(8, json.loads(result["content"][0]["text"])["result"]["echo"])

            write_tool = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "rpc",
                "arguments": {
                    "mapping_id": row["id"],
                    "family": "vendor",
                    "operation": "update",
                    "args": {"value": 11},
                    "plan_id": plan_id,
                    "taskname": "rpc",
                    "message": "Update vendor metadata through MCP",
                },
            }}
            _, _, raw = self.request(
                "POST", "/kapsel/mcp-connect/" + conn["id"] + "/mcp", json.dumps(write_tool),
                {"Authorization": "Bearer " + conn["secret"], "Content-Type": "application/json"},
            )
            write_result = json.loads(raw)["result"]
            self.assertFalse(write_result["isError"], write_result)
            self.assertEqual(11, json.loads(write_result["content"][0]["text"])["result"]["updated"])
            self.assertEqual(("vendor_update", {"value": 11}), calls[-1])

            # Family read_only is compatibility metadata only; operation write is authoritative.
            session.capabilities["rpc"]["vendor"]["read_only"] = True
            session.capabilities["rpc"]["vendor"]["operation_specs"]["inspect"]["write"] = True
            status, _, raw = self.request(
                "POST", endpoint, json.dumps({"args": {}}),
                {"Content-Type": "application/json"},
            )
            self.assertEqual(401, status, raw)
            self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])
        finally:
            self.server.mappings.sessions.pop(row["id"], None)
            self.server.mappings.store.delete(row["id"])

    def test_offline_mapping_is_not_an_empty_local_directory(self):
        row, _ = self.server.mappings.store.create(self.record.path_prefix, "offline")
        root = self.server.tokens.scope_root(self.record)
        (root / row["name"]).mkdir()
        base = "/kapsel/w/" + self.record.token
        self.assertEqual(503, self.request("GET", base + "/fs/list?path=offline")[0])
        self.assertEqual(200, self.request("GET", base + "/fs/list?path=.")[0])

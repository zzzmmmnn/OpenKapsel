"""Git REST/MCP authorization and client-local RPC integration."""

import json
import os
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from openkapsel.client_files import ClientFiles
from openkapsel.client_tasks import ClientTasks
from tests import test_oauth
from tests.test_git_operations import make_repo


@unittest.skipIf(os.name == "nt" or not shutil.which("git"), "POSIX server and Git required")
class GitHTTPTests(unittest.TestCase):
    request = test_oauth.OAuthHTTPTests.request

    def setUp(self):
        test_oauth.OAuthHTTPTests.setUp(self)
        self.record = self.server.tokens.update(self.record.token, shell_mode="full")
        self.base = "/kapsel/w/" + self.record.token
        self.headers = {"Authorization": "Bearer " + self.record.control_token}
        self.root = self.server.config.root / self.record.path_prefix
        make_repo(self.root)

    def tearDown(self):
        test_oauth.OAuthHTTPTests.tearDown(self)

    def test_local_git_auth_errors_discovery_and_mcp(self):
        for op in ("status", "diff", "log", "show", "ls_files", "diff_stat"):
            status, _, raw = self.request("GET", self.base + "/git/" + op, headers=self.headers)
            result = json.loads(raw)
            self.assertEqual(200, status, result)
            self.assertEqual(0, result["exit_code"])
        status, _, _ = self.request("GET", self.base + "/git/status")
        self.assertIn(status, (401, 403))
        status, _, raw = self.request("GET", self.base + "/git/show?revision=does-not-exist", headers=self.headers)
        self.assertEqual(422, status, raw)
        status, _, raw = self.request("GET", self.base + "/git/show?" + urlencode({"revision": "HEAD; touch injected"}), headers=self.headers)
        self.assertEqual(422, status, raw)
        self.assertFalse((self.root / "injected").exists())
        status, _, raw = self.request("GET", self.base + "/discovery/shell", headers=self.headers)
        self.assertIn("git_status", json.loads(raw)["endpoints"])
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "git_log", "arguments": {"limit": 1}}}
        conn = self.server.static_mcp.create(self.record.app_id, "project", "Git test")
        mcp = "/kapsel/mcp-connect/" + conn["id"] + "/mcp"
        status, _, raw = self.request("POST", mcp, json.dumps(body),
                                      {"Authorization": "Bearer " + conn["secret"], "Content-Type": "application/json"})
        self.assertEqual(200, status, raw)
        result = json.loads(raw)["result"]
        self.assertFalse(result["isError"], result)
        self.assertIn("Initial fixture", result["structuredContent"]["output"])
        self.assertNotIn("status_url", result["structuredContent"])
        self.assertEqual("get_git_task", result["structuredContent"]["poll_tool"])
        body["params"] = {"name": "get_git_task", "arguments": result["structuredContent"]["poll_arguments"]}
        status, _, raw = self.request("POST", mcp, json.dumps(body),
                                      {"Authorization": "Bearer " + conn["secret"], "Content-Type": "application/json"})
        self.assertFalse(json.loads(raw)["result"]["isError"], raw)
        self.server.tokens.update(self.record.token, shell_mode="none")
        self.assertEqual(403, self.request("GET", self.base + "/git/status", headers=self.headers)[0])

    def test_mapping_git_is_one_rpc_and_never_falls_back(self):
        export = Path(self.temp.name) / "export"
        export.mkdir()
        make_repo(export)
        files = ClientFiles(export, writable=True)
        tasks = ClientTasks(files, enabled=True, sandbox=False)
        row, _ = self.server.mappings.store.create(self.record.path_prefix, "laptop", writable=True, allow_exec=True)
        calls = []
        def call(op, args):
            calls.append(op)
            return tasks.dispatch(op, args) if op.startswith("task_") else tasks.git(op[4:], args)
        session = SimpleNamespace(closed=False, capabilities={"git_api": {"version": 1, "enabled": True}}, call=call)
        self.server.mappings.sessions[row["id"]] = session
        try:
            status, _, raw = self.request("GET", self.base + "/git/log?path=laptop", headers=self.headers)
            self.assertEqual(200, status, raw)
            self.assertEqual(["git_log"], calls)
            self.assertIn("Initial fixture", json.loads(raw)["output"])
            conn = self.server.static_mcp.create(self.record.app_id, "project", "Mapped Git")
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "get_git_task", "arguments": {"task_id": json.loads(raw)["task_id"], "mapping_id": row["id"]}}}
            _, _, polled = self.request("POST", "/kapsel/mcp-connect/" + conn["id"] + "/mcp", json.dumps(body),
                                        {"Authorization": "Bearer " + conn["secret"], "Content-Type": "application/json"})
            self.assertFalse(json.loads(polled)["result"]["isError"], polled)
            self.assertEqual(["git_log", "task_get"], calls)
            self.server.mappings.store.update(row["id"], allow_exec=False)
            self.assertEqual(403, self.request("GET", self.base + "/git/status?path=laptop", headers=self.headers)[0])
            self.assertEqual(["git_log", "task_get"], calls)
            session.capabilities = {}
            self.assertEqual(409, self.request("GET", self.base + "/git/status?path=laptop", headers=self.headers)[0])
        finally:
            self.server.mappings.sessions.clear()
            self.server.mappings.store.delete(row["id"])
            tasks.close()
            files.close()

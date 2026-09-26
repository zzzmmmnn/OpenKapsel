"""Read-only Git REST/MCP and mapping RPC authorization."""
import json
import os
import shutil
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from openkapsel.client_runtime.client_files import ClientFiles
from tests import test_oauth
from tests.test_git_operations import make_repo


@unittest.skipIf(os.name == "nt" or not shutil.which("git"), "POSIX server and Git required")
class GitHTTPTests(unittest.TestCase):
    request = test_oauth.OAuthHTTPTests.request
    rpc = test_oauth.OAuthHTTPTests.rpc

    def setUp(self):
        test_oauth.OAuthHTTPTests.setUp(self)
        self.record = self.server.tokens.update(self.record.token, can_write=False, shell_mode="none")
        self.base = "/kapsel/w/" + self.record.token
        self.root = self.server.config.root / self.record.path_prefix
        make_repo(self.root)

    def tearDown(self):
        test_oauth.OAuthHTTPTests.tearDown(self)

    def connection(self, comment="Git RPC tests"):
        conn = self.server.static_mcp.create(self.record.app_id, self.record.path_prefix, comment)
        self.mcp = "/kapsel/mcp-connect/" + conn["id"] + "/mcp"
        return conn

    def wait_task(self, secret, task_id):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, payload = self.rpc(secret, "tools/call", {
                "name": "get_task", "arguments": {"task_id": task_id},
            })
            self.assertEqual(200, status, payload)
            result = payload["result"]["structuredContent"]
            if result["status"] == "finished":
                return result
            time.sleep(.02)
        self.fail("Git RPC task did not finish")

    def test_read_url_git_and_readonly_mcp_tools(self):
        operations = ("status", "diff", "log", "show", "ls_files", "diff_stat")
        for op in operations:
            status, _, raw = self.request("GET", self.base + "/git/" + op)
            self.assertEqual(200, status, raw)

        conn = self.connection("Reads")
        status, listed = self.rpc(conn["secret"], "tools/list")
        self.assertEqual(200, status, listed)
        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertNotIn("git", tools)
        self.assertIn("rpc", tools)
        self.assertNotIn("mapping_id", tools["rpc"]["inputSchema"].get("required", []))
        for op in operations:
            self.assertIn("git_" + op, tools)

        for name, args in (("git_log", {}), ("read_files", {"paths": ["source.txt"]}),
                           ("file_manifest", {"recursive": True, "depth": 1}),
                           ("search_files", {"query": "original", "include": ["*.txt"], "exclude": [".git"]})):
            status, payload = self.rpc(conn["secret"], "tools/call", {"name": name, "arguments": args})
            self.assertEqual(200, status, payload)
            self.assertFalse(payload["result"]["isError"], payload)

        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {"family": "git", "operation": "status", "args": {"cwd": "."}},
        })
        self.assertEqual(200, status, payload)
        self.assertFalse(payload["result"]["isError"], payload)
        result = payload["result"]["structuredContent"]
        self.assertEqual("server", result["location"])
        self.assertEqual("git", result["family"])
        self.assertEqual("status", result["operation"])

        self.server.tokens.update(self.record.token, can_read=False)
        self.assertEqual(403, self.request("GET", self.base + "/git/status")[0])

    def test_server_git_write_rpc_uses_normal_tasks_without_shell(self):
        self.record = self.server.tokens.update(
            self.record.token, can_write=True, shell_mode="none", network_mode="none"
        )
        conn = self.connection("Server Git writes")
        plan_id = self.server.context_for(self.root).add(
            "plan", "Server Git RPC mutation", taskname="git", actor_id=self.record.actor_id
        )
        context = {"plan_id": plan_id, "taskname": "git", "message": "Test server Git RPC mutation"}
        (self.root / "source.txt").write_text("changed through rpc\n", encoding="utf-8")

        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {
                "family": "git", "operation": "add",
                "args": {"cwd": ".", "paths": ["source.txt"]}, **context,
            },
        })
        self.assertEqual(200, status, payload)
        self.assertFalse(payload["result"]["isError"], payload)
        task_id = payload["result"]["structuredContent"]["task_id"]
        self.assertTrue(task_id.startswith("task_"), task_id)
        staged = self.wait_task(conn["secret"], task_id)
        self.assertEqual(0, staged["exit_code"], staged)
        self.assertEqual("rpc", staged["kind"])
        self.assertEqual("git", staged["rpc_family"])
        self.assertEqual("add", staged["rpc_operation"])

        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {
                "family": "git", "operation": "commit",
                "args": {"cwd": ".", "message": "Server RPC commit"}, **context,
            },
        })
        self.assertEqual(200, status, payload)
        self.assertFalse(payload["result"]["isError"], payload)
        committed = self.wait_task(
            conn["secret"], payload["result"]["structuredContent"]["task_id"]
        )
        self.assertEqual(0, committed["exit_code"], committed)
        self.assertEqual("commit", committed["result"]["operation"])
        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {"family": "git", "operation": "log", "args": {"cwd": ".", "limit": 1}},
        })
        self.assertEqual(200, status, payload)
        self.assertIn("Server RPC commit", payload["result"]["structuredContent"]["result"]["output"])

        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {
                "family": "git", "operation": "fetch", "args": {"cwd": "."}, **context,
            },
        })
        self.assertEqual(200, status, payload)
        self.assertTrue(payload["result"]["isError"], payload)
        self.assertEqual(
            "git_network_denied",
            payload["result"]["structuredContent"]["error"]["code"],
        )

    def test_mapping_git_generic_rpc_is_exposed(self):
        export = Path(self.temp.name) / "rpc-export"
        export.mkdir()
        make_repo(export)
        files = ClientFiles(export, writable=False)
        row, _ = self.server.mappings.store.create(
            self.record.path_prefix, "rpc-laptop", writable=False, allow_exec=False
        )
        calls = []

        def call(op, args):
            calls.append(op)
            return files.dispatch(op, args)

        self.server.mappings.sessions[row["id"]] = SimpleNamespace(
            closed=False, ready=True,
            capabilities={"rpc": files.rpc_capabilities}, call=call,
        )
        try:
            conn = self.connection("Mapped Git RPC")
            status, payload = self.rpc(conn["secret"], "tools/call", {
                "name": "rpc",
                "arguments": {
                    "mapping_id": row["id"], "family": "git", "operation": "status",
                    "args": {"cwd": "."},
                },
            })
            self.assertEqual(200, status, payload)
            self.assertFalse(payload["result"]["isError"], payload)
            result = payload["result"]["structuredContent"]
            self.assertEqual(row["id"], result["mapping_id"])
            self.assertEqual("git", result["family"])
            self.assertEqual("status", result["operation"])
            self.assertEqual(["git_status"], calls)
        finally:
            self.server.mappings.sessions.pop(row["id"], None)
            self.server.mappings.store.delete(row["id"])
            files.close()

    def test_mapping_git_one_rpc_without_exec_or_write(self):
        export = Path(self.temp.name) / "export"
        export.mkdir()
        make_repo(export)
        files = ClientFiles(export, writable=False)
        row, _ = self.server.mappings.store.create(self.record.path_prefix, "laptop", writable=False, allow_exec=False)
        calls = []
        def call(op, args):
            calls.append(op)
            return files.dispatch(op, args)
        session = SimpleNamespace(closed=False, ready=True, capabilities={"git_api": {"version": 2, "read_only": True}}, call=call)
        self.server.mappings.sessions[row["id"]] = session
        try:
            status, _, raw = self.request("GET", self.base + "/git/log?path=laptop")
            self.assertEqual(200, status, raw)
            self.assertEqual(["git_log"], calls)
            self.assertIn("Initial fixture", json.loads(raw)["output"])

            session.capabilities = {"rpc": {"git": {
                "state": "available", "version": 2,
                "operations": ["status", "commit"], "read_only": False,
                "operation_specs": {
                    "status": {"write": False, "execution": "sync"},
                    "commit": {"write": True, "execution": "task"},
                },
            }}}
            status, _, raw = self.request("GET", self.base + "/git/status?path=laptop")
            self.assertEqual(200, status, raw)
            self.assertEqual(["git_log", "git_status"], calls)

            session.capabilities = {"git_api": {"version": 1, "enabled": True}}
            status, _, raw = self.request("GET", self.base + "/git/status?path=laptop")
            self.assertEqual(409, status)
            self.assertEqual("mapping_rpc_unsupported", json.loads(raw)["error"]["code"])
            self.assertEqual(["git_log", "git_status"], calls)

            session.capabilities = {"rpc": {"git": {
                "state": "disabled", "reason": "client_config", "version": 2,
                "operations": ["status"], "read_only": True,
            }}}
            status, _, raw = self.request("GET", self.base + "/git/status?path=laptop")
            self.assertEqual(403, status)
            self.assertEqual("mapping_rpc_disabled", json.loads(raw)["error"]["code"])
            self.assertEqual(["git_log", "git_status"], calls)

            session.capabilities = {"rpc": {"git": {
                "state": "unsupported", "reason": "dependency_missing", "version": 2,
                "operations": ["status"], "read_only": True,
            }}}
            status, _, raw = self.request("GET", self.base + "/git/status?path=laptop")
            self.assertEqual(409, status)
            self.assertEqual("mapping_rpc_unsupported", json.loads(raw)["error"]["code"])
            self.assertEqual("dependency_missing", json.loads(raw)["error"]["details"]["reason"])
            self.assertEqual(["git_log", "git_status"], calls)

            self.server.mappings.sessions.pop(row["id"])
            status, _, raw = self.request("GET", self.base + "/git/status?path=laptop")
            self.assertEqual(503, status)
            self.assertEqual("mapping_offline", json.loads(raw)["error"]["code"])
            self.assertEqual(["git_log", "git_status"], calls)
        finally:
            self.server.mappings.sessions.clear()
            self.server.mappings.store.delete(row["id"])
            files.close()

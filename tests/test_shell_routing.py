"""Unified Shell placement, RPC lifetime and permission regression tests."""

import base64
import json
import os
import time
import unittest
from unittest.mock import patch
from openkapsel.client_runtime.client_tasks import ClientTasks
from tests import test_mapping_file_api as fixture
from tests import test_oauth


@unittest.skipIf(os.name == "nt", "HTTP server runs on POSIX")
class UnifiedShellHTTPTests(unittest.TestCase):
    request = fixture.MappingFileHTTPTests.request
    api = fixture.MappingFileHTTPTests.api
    form = test_oauth.OAuthHTTPTests.form
    authorize = test_oauth.OAuthHTTPTests.authorize
    rpc = test_oauth.OAuthHTTPTests.rpc

    def setUp(self):
        fixture.MappingFileHTTPTests.setUp(self)
        self.record = self.server.tokens.update(self.record.token, shell_mode="full")
        self.row, _ = self.server.mappings.store.update(self.row["id"], allow_exec=True)
        self.tasks = ClientTasks(self.files, enabled=True, sandbox=False)
        self.session.capabilities["execution"] = self.tasks.capabilities()
        self.session.call = self.tasks.dispatch

    def tearDown(self):
        self.tasks.close()
        for task in self.tasks.tasks.values():
            task["done"].wait(5)
        fixture.MappingFileHTTPTests.tearDown(self)

    def finished(self, tid):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, result = self.api("/tasks/" + tid)
            self.assertEqual(200, status, result)
            if result["status"] == "finished":
                return result
            time.sleep(.02)
        self.fail("task did not finish")

    def test_auto_and_explicit_placement_and_listing(self):
        (self.export / "nested").mkdir()
        status, remote = self.api("/shell/exec", {"command": "printf client > result", "cwd": "laptop/nested"})
        self.assertEqual(202, status, remote)
        self.assertEqual("client", remote["location"])
        self.finished(remote["task_id"])
        self.assertEqual("client", (self.export / "nested/result").read_text())
        self.assertFalse((self.mount / "nested/result").exists())
        with patch.object(self.server.mappings, "mount") as mounted:
            status, local = self.api("/shell/exec", {"command": "printf server", "cwd": "laptop", "target": "server"})
        mounted.assert_called_once()
        self.assertEqual(202, status, local)
        self.assertEqual("server", local["location"])
        self.assertEqual("server", self.finished(local["task_id"])["stdout"])
        status, root = self.api("/shell/exec", {"command": "printf root"})
        self.assertEqual("server", root["location"])
        self.finished(root["task_id"])
        status, listing = self.api("/tasks")
        self.assertEqual(200, status, listing)
        self.assertEqual({remote["task_id"], local["task_id"], root["task_id"]}, {t["task_id"] for t in listing["tasks"]})
        self.assertEqual(1, self.api("/tasks?target=client")[1]["total"])

    def test_no_fallback_and_workspace_authorization(self):
        body = {"command": "touch forbidden", "cwd": "laptop"}
        self.session.closed = True
        self.assertEqual(503, self.api("/shell/exec", body)[0])
        self.assertTrue(self.api("/tasks")[1]["unavailable_mappings"])
        self.session.closed = False
        self.session.capabilities["execution"].pop("shell_command")
        self.assertEqual(409, self.api("/shell/exec", body)[0])
        self.session.capabilities["execution"] = self.tasks.capabilities()
        self.server.mappings.store.update(self.row["id"], allow_exec=False)
        self.assertEqual(403, self.api("/shell/exec", body)[0])
        self.assertFalse((self.mount / "forbidden").exists())
        self.assertEqual(400, self.api("/shell/exec", dict(body, target="client", cwd="."))[0])
        self.assertEqual(400, self.api("/shell/exec", dict(body, target=[]))[0])
        self.assertEqual(400, self.api("/shell/exec", dict(body, cwd="laptop\x00"))[0])
        self.server.mappings.store.update(self.row["id"], allow_exec=True)
        self.assertEqual(400, self.api("/shell/exec", dict(body, timeout_seconds=601))[0])
        self.server.mappings.store.update(self.row["id"], writable=False)
        self.assertEqual(403, self.api("/shell/exec", body)[0])
        self.server.mappings.store.update(self.row["id"], writable=True)
        self.server.tokens.update(self.record.token, can_write=False)
        self.assertEqual(403, self.api("/shell/exec", body)[0])
        self.server.tokens.update(self.record.token, can_write=True, shell_mode="none")
        self.assertEqual(403, self.api("/shell/exec", body)[0])
        self.server.tokens.update(self.record.token, shell_mode="full")
        other, _ = self.server.mappings.store.create("other", "foreign", writable=True)
        try:
            self.assertEqual(404, self.api("/tasks/client." + other["id"] + ".abcdefgh")[0])
        finally:
            self.server.mappings.store.delete(other["id"])

    def test_remote_output_input_reconnect_and_termination(self):
        status, result = self.api("/shell/exec", {"command": "cat", "cwd": "laptop", "target": "client", "interactive": True})
        self.assertEqual(202, status, result)
        tid = result["task_id"]
        self.session.closed = True
        self.assertEqual(503, self.api("/tasks/" + tid)[0])
        self.session.closed = False
        self.assertEqual(413, self.api("/tasks/" + tid + "/stdin", {"data": "x" * 16385})[0])
        status, result = self.api("/tasks/" + tid + "/stdin", {"data": "hello\n", "close": True})
        self.assertEqual(200, status, result)
        self.assertEqual(6, result["bytes_written"])
        self.assertEqual("hello\n", self.finished(tid)["stdout"])
        status, result = self.api("/tasks/" + tid + "/output?limit=3")
        self.assertEqual("hel", result["stdout"]["data"])
        self.assertTrue(result["output_combined"])
        self.assertEqual("lo\n", self.api("/tasks/" + tid + "/output?stdout_offset=3")[1]["stdout"]["data"])
        for action in ("interrupt", "kill"):
            status, task = self.api("/shell/exec", {"command": "sleep 30", "cwd": "laptop"})
            self.assertEqual(202, status, task)
            headers = dict(self.headers, **{"OpenKapsel-Plan-Id": str(self.plan), "OpenKapsel-Taskname": "rpc", "OpenKapsel-Message": "Stop task"})
            status, _, raw = self.request("POST", self.base + "/tasks/" + task["task_id"] + "/" + action, None, headers)
            self.assertEqual(200, status, raw)
            self.finished(task["task_id"])

    def test_sse_drains_finished_output_larger_than_one_rpc(self):
        status, task = self.api("/shell/exec", {"command": "head -c 150000 /dev/zero", "cwd": "laptop"})
        self.assertEqual(202, status, task)
        self.finished(task["task_id"])
        status, _, raw = self.request("GET", self.base + "/tasks/" + task["task_id"] + "/stream", None, self.headers)
        self.assertEqual(200, status, raw[:500])
        chunks = [json.loads(line[6:]) for line in raw.decode().splitlines() if line.startswith("data: ")]
        self.assertEqual(150000, sum(len(base64.b64decode(c["stdout"]["data_base64"])) for c in chunks if "stdout" in c))
        self.assertEqual("finished", chunks[-1]["status"])

    def test_mcp_uses_same_target_and_task_tools(self):
        credentials, _, _ = self.authorize()
        status, listing = self.rpc(credentials["access_token"], "tools/list")
        self.assertEqual(200, status, listing)
        run = next(tool for tool in listing["result"]["tools"] if tool["name"] == "run_shell")
        self.assertEqual(["auto", "server", "client"], run["inputSchema"]["properties"]["target"]["enum"])
        status, response = self.rpc(credentials["access_token"], "tools/call", {
            "name": "run_shell", "arguments": {"command": "printf mcp-client", "cwd": "laptop", "target": "auto",
                                               "plan_id": self.plan, "taskname": "rpc", "message": "Test MCP routing"}})
        self.assertEqual(200, status, response)
        result = response["result"]["structuredContent"]
        self.assertEqual("client", result["location"])
        self.finished(result["task_id"])
        status, response = self.rpc(credentials["access_token"], "tools/call", {"name": "get_task", "arguments": {"task_id": result["task_id"]}})
        self.assertEqual("mcp-client", response["result"]["structuredContent"]["stdout"])


if __name__ == "__main__":
    unittest.main()

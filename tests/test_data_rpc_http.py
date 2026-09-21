"""New data families through the real REST/task adapters without Shell or FUSE."""
import json
import os
import time
import unittest
from unittest.mock import patch

from tests import test_rpc_task_http as fixture


@unittest.skipIf(os.name == "nt", "HTTP server fixture is POSIX-only")
class DataRpcHTTPTests(unittest.TestCase):
    request = fixture.RpcTaskHTTPTests.request
    control = fixture.RpcTaskHTTPTests.control
    create_plan = fixture.RpcTaskHTTPTests.create_plan

    def setUp(self):
        fixture.RpcTaskHTTPTests.setUp(self)
        self.mount_guard = patch.object(self.server.mappings, "mount", side_effect=AssertionError("data RPC must never mount"))
        self.mount_guard.start()
        self.addCleanup(self.mount_guard.stop)
        (self.export / "config.json").write_text('{"limit":2}\n', encoding="utf-8")
        (self.export / "data.csv").write_text('group,value\na,1\na,2\nb,5\n', encoding="utf-8")

    def tearDown(self):
        self.tasks.close()
        for task in list(self.tasks.tasks.values()):
            task["done"].wait(5)
        fixture.RpcTaskHTTPTests.tearDown(self)

    def rpc_call(self, family, operation, args, *, context=None, headers=None):
        body = {"args": args}
        if context:
            body.update(context)
        status, _, raw = self.request("POST", self.base + f"/mappings/{self.row['id']}/rpc/{family}/{operation}",
                                      json.dumps(body), self.control() if headers is None else headers)
        return status, json.loads(raw)

    def finished(self, task_id):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, _, raw = self.request("GET", self.base + "/tasks/" + task_id, headers=self.control())
            self.assertEqual(200, status, raw)
            body = json.loads(raw)
            if body["status"] == "finished":
                return body
            time.sleep(.01)
        self.fail("data RPC task did not finish")

    def test_readonly_scan_runs_without_write_shell_or_native_mount(self):
        self.server.tokens.update(self.record.token, can_write=False, shell_mode="none")
        self.server.mappings.store.update(self.row["id"], writable=False, allow_exec=False)
        self.files.writable = False
        before = (self.export / "data.csv").read_bytes()
        status, doc = self.rpc_call("structured", "read", {"path": "config.json"}, headers={"Content-Type": "application/json"})
        self.assertEqual(200, status, doc)
        self.assertEqual(2, doc["result"]["value"]["limit"])
        status, start = self.rpc_call("tabular", "scan", {"path": "data.csv"}, headers={"Content-Type": "application/json"})
        self.assertEqual(202, status, start)
        self.assertFalse(start["write"])
        task = self.finished(start["task_id"])
        self.assertEqual(0, task["exit_code"], task)
        self.assertEqual(3, task["result"]["matched_rows"])
        self.assertTrue(task["result"]["complete"])
        summaries = self.tasks.dispatch("task_list", {})
        summary = next(item for item in summaries if item["task_id"] == start["task_id"].split(".")[-1])
        self.assertTrue(summary["result_available"])
        self.assertNotIn("result", summary)
        self.assertEqual(before, (self.export / "data.csv").read_bytes())
        self.assertFalse((self.export / ".openkapsel").exists())
        status, denied = self.rpc_call("structured", "write", {"path": "new.json", "content": '{}'})
        self.assertEqual(403, status, denied)
        self.assertFalse((self.export / "new.json").exists())

    def test_structured_task_requires_context_and_writable_mapping(self):
        status, denied = self.rpc_call("structured", "write", {"path": "new.json", "content": '{}'})
        self.assertEqual(400, status, denied)
        plan_id = self.create_plan()
        context = {"plan_id": plan_id, "taskname": "data-rpc", "message": "Edit configuration through a typed parser"}
        status, read = self.rpc_call("structured", "read", {"path": "config.json"})
        self.assertEqual(200, status, read)
        args = {"path": "config.json", "expected_etag": read["result"]["etag"],
                "operations": [{"op": "test", "path": "/limit", "value": 2}, {"op": "replace", "path": "/limit", "value": 8}]}
        status, started = self.rpc_call("structured", "patch", args, context=context)
        self.assertEqual(202, status, started)
        self.assertTrue(started["write"])
        task = self.finished(started["task_id"])
        self.assertEqual(0, task["exit_code"], task)
        self.assertEqual({"limit": 8}, json.loads((self.export / "config.json").read_text()))
        self.server.mappings.store.update(self.row["id"], writable=False)
        status, denied = self.rpc_call("structured", "patch", args, context=context)
        self.assertEqual(403, status, denied)

    def test_discovery_exposes_strict_schemas_and_readonly_task_metadata(self):
        status, _, raw = self.request("GET", self.base + "/mappings", headers=self.control())
        self.assertEqual(200, status, raw)
        caps = json.loads(raw)["mappings"][0]["capabilities"]["rpc"]
        self.assertEqual("task", caps["structured"]["operation_specs"]["patch"]["execution"])
        self.assertFalse(caps["structured"]["operation_specs"]["preview"]["write"])
        self.assertTrue(caps["tabular"]["read_only"])
        self.assertFalse(caps["tabular"]["operation_specs"]["scan"]["write"])
        self.assertEqual("task", caps["tabular"]["operation_specs"]["scan"]["execution"])
        status, _, raw = self.request("GET", self.base + "/discovery/full", headers=self.control())
        self.assertEqual(200, status, raw)
        families = json.loads(raw)["capabilities"]["mappings"]["rpc"]["families"]
        self.assertEqual(["write", "patch"], families["structured"]["task_writes"])
        self.assertEqual(["scan"], families["tabular"]["task_reads"])
        self.assertTrue(families["tabular"]["read_only"])
        status, bad = self.rpc_call("tabular", "read", {"path": "data.csv", "offset": 1000000})
        self.assertEqual(400, status, bad)
        self.assertNotIn(str(self.export), json.dumps(bad))


if __name__ == "__main__":
    unittest.main()

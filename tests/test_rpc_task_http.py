import errno
import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

from openkapsel.client_files import ClientFiles
from openkapsel.client_tasks import ClientTasks
from tests import test_oauth


@unittest.skipIf(os.name == "nt", "server fixture runs on POSIX")
class RpcTaskHTTPTests(unittest.TestCase):
    request = test_oauth.OAuthHTTPTests.request

    def setUp(self):
        test_oauth.OAuthHTTPTests.setUp(self)
        self.record = self.server.tokens.update(
            self.record.token,
            shell_mode="none",
            can_read=True,
            can_write=True,
        )
        self.base = "/kapsel/w/" + self.record.token
        self.export = Path(self.temp.name) / "rpc-task-export"
        self.export.mkdir()
        (self.export / "source").mkdir()
        (self.export / "source" / "hello.txt").write_text("rpc task http", encoding="utf-8")
        self.files = ClientFiles(self.export, writable=True)
        self.tasks = ClientTasks(self.files, enabled=False, max_tasks=2, max_seconds=30)
        self.row, _ = self.server.mappings.store.create(
            self.record.path_prefix,
            "rpc-client",
            writable=True,
            allow_exec=False,
        )
        mount = self.server.mappings.mount_path(self.row)
        mount.mkdir()

        def call(operation, args):
            if operation.startswith("task_"):
                return self.tasks.dispatch(operation, args)
            return self.files.dispatch(operation, args)

        self.session = SimpleNamespace(
            closed=False, ready=True,
            generation="g" * 24,
            capabilities={
                "rpc": self.files.rpc_capabilities,
                "execution": self.tasks.capabilities(),
            },
            call=call,
            close=lambda: None,
        )
        self.server.mappings.sessions[self.row["id"]] = self.session

    def tearDown(self):
        self.server.mappings.sessions.clear()
        try:
            self.server.mappings.store.delete(self.row["id"])
        except Exception:
            pass
        self.tasks.close()
        self.files.close()
        test_oauth.OAuthHTTPTests.tearDown(self)

    def control(self):
        return {
            "Authorization": "Bearer " + self.record.control_token,
            "Content-Type": "application/json",
        }

    def create_plan(self):
        status, _, raw = self.request(
            "POST",
            self.base + "/context",
            json.dumps({
                "type": "plan",
                "taskname": "rpc-task",
                "content": "Exercise RPC task execution",
            }),
            self.control(),
        )
        self.assertEqual(201, status, raw)
        return json.loads(raw)["id"]

    def test_task_rpc_starts_immediately_and_is_queryable_without_shell_permission(self):
        plan_id = self.create_plan()
        endpoint = (
            self.base
            + f"/mappings/{self.row['id']}/rpc/archive/create"
        )
        status, _, raw = self.request(
            "POST",
            endpoint,
            json.dumps({
                "args": {
                    "destination": "bundle.zip",
                    "sources": ["source"],
                    "format": "zip",
                },
                "timeout_seconds": 20,
                "plan_id": plan_id,
                "taskname": "rpc-task",
                "message": "Create archive as a client task",
            }),
            self.control(),
        )
        self.assertEqual(202, status, raw)
        started = json.loads(raw)
        self.assertEqual("rpc", started["kind"])
        self.assertEqual("archive", started["rpc_family"])
        self.assertEqual("create", started["rpc_operation"])
        self.assertEqual("task", started["execution"])
        self.assertTrue(started["write"])
        self.assertTrue(started["task_id"].startswith("client." + self.row["id"] + "."))

        status, _, raw = self.request(
            "GET",
            self.base + "/tasks?target=client",
            headers={"Authorization": "Bearer " + self.record.control_token},
        )
        self.assertEqual(200, status, raw)
        listed = json.loads(raw)["tasks"]
        self.assertIn(started["task_id"], {item["task_id"] for item in listed})

        deadline = time.monotonic() + 10
        result = None
        while time.monotonic() < deadline:
            status, _, raw = self.request(
                "GET",
                self.base + "/tasks/" + started["task_id"],
                headers={"Authorization": "Bearer " + self.record.control_token},
            )
            self.assertEqual(200, status, raw)
            result = json.loads(raw)
            if result["status"] == "finished":
                break
            time.sleep(0.02)
        self.assertIsNotNone(result)
        self.assertEqual("finished", result["status"])
        self.assertEqual(0, result["exit_code"], result)
        self.assertEqual("bundle.zip", result["result"]["destination"])

        status, _, raw = self.request(
            "GET",
            self.base + "/tasks/" + started["task_id"] + "/output",
            headers={"Authorization": "Bearer " + self.record.control_token},
        )
        self.assertEqual(200, status, raw)
        output = json.loads(raw)
        self.assertEqual("rpc", output["kind"])
        self.assertEqual("archive", output["rpc_family"])
        self.assertEqual("bundle.zip", output["result"]["destination"])
        self.assertTrue(output["finished"])

        with zipfile.ZipFile(self.export / "bundle.zip") as archive:
            self.assertEqual(
                "rpc task http",
                archive.read("source/hello.txt").decode("utf-8"),
            )

    def test_ambiguous_task_start_returns_candidate_id_for_reconnect_recovery(self):
        plan_id = self.create_plan()
        original_call = self.session.call

        def ambiguous_call(operation, args):
            if operation == "task_start":
                raise OSError(errno.ETIMEDOUT, "reply was lost after dispatch")
            return original_call(operation, args)

        self.session.call = ambiguous_call
        status, _, raw = self.request(
            "POST",
            self.base + f"/mappings/{self.row['id']}/rpc/archive/create",
            json.dumps({
                "args": {
                    "destination": "ambiguous.zip",
                    "sources": ["source"],
                    "format": "zip",
                },
                "plan_id": plan_id,
                "taskname": "rpc-task",
                "message": "Start archive task with lost reply",
            }),
            self.control(),
        )
        self.assertEqual(503, status, raw)
        error = json.loads(raw)["error"]
        self.assertEqual("mapping_operation_failed", error["code"])
        details = error["details"]
        self.assertEqual(errno.ETIMEDOUT, details["errno"])
        self.assertFalse(details["task_start_confirmed"])
        self.assertTrue(details["task_may_have_started"])
        self.assertTrue(
            details["candidate_task_id"].startswith("client." + self.row["id"] + ".")
        )
        self.assertIn("query/list", details["recovery"])
        self.assertFalse((self.export / "ambiguous.zip").exists())

    def test_shell_task_start_remains_disabled_for_same_mapping(self):
        plan_id = self.create_plan()
        status, _, raw = self.request(
            "POST",
            self.base + f"/mappings/{self.row['id']}/tasks",
            json.dumps({
                "argv": ["python", "-V"],
                "plan_id": plan_id,
                "taskname": "rpc-task",
                "message": "Shell should remain disabled",
            }),
            self.control(),
        )
        self.assertEqual(403, status, raw)


if __name__ == "__main__":
    unittest.main()

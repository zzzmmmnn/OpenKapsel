import json
import os
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import ClientRuntime, run_once
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.mapping.mapping_transport import MAPPING_HANDSHAKE_VERSION, MINIMUM_MAPPING_CLIENT_VERSION, SERVER_SOURCE_FINGERPRINT


class RpcPluginTaskTests(unittest.TestCase):
    def wait_task(self, tasks, task_id, timeout=10):
        deadline = time.monotonic() + timeout
        result = None
        while time.monotonic() < deadline:
            result = tasks.dispatch("task_get", {"task_id": task_id, "offset": 0})
            if not result["running"]:
                return result
            time.sleep(0.02)
        self.fail(f"task did not finish: {result}")

    def test_archive_create_and_extract_are_tasks_without_shell_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source" / "hello.txt").write_text("hello task archive", encoding="utf-8")
            files = ClientFiles(root, writable=True)
            tasks = ClientTasks(files, enabled=False, max_tasks=2, max_seconds=30)
            try:
                create = tasks.dispatch("task_start", {
                    "task_id": "archive-create-1",
                    "rpc": {
                        "family": "archive",
                        "operation": "create",
                        "args": {
                            "destination": "bundle.zip",
                            "sources": ["source"],
                            "format": "zip",
                        },
                    },
                })
                self.assertEqual("rpc", create["kind"])
                self.assertTrue(create["write"])
                self.assertEqual("archive", create["rpc_family"])
                created = self.wait_task(tasks, "archive-create-1")
                self.assertEqual(0, created["exit_code"], created)
                self.assertEqual("bundle.zip", created["result"]["destination"])
                self.assertTrue((root / "bundle.zip").is_file())
                with zipfile.ZipFile(root / "bundle.zip") as archive:
                    self.assertEqual(
                        "hello task archive",
                        archive.read("source/hello.txt").decode("utf-8"),
                    )

                extracted = tasks.dispatch("task_start", {
                    "task_id": "archive-extract-1",
                    "rpc": {
                        "family": "archive",
                        "operation": "extract",
                        "args": {
                            "path": "bundle.zip",
                            "destination": "unpacked",
                        },
                    },
                })
                self.assertEqual("rpc", extracted["kind"])
                extracted = self.wait_task(tasks, "archive-extract-1")
                self.assertEqual(0, extracted["exit_code"], extracted)
                self.assertEqual(
                    "hello task archive",
                    (root / "unpacked" / "source" / "hello.txt").read_text(encoding="utf-8"),
                )
            finally:
                tasks.close()
                files.close()

    def test_rpc_task_survives_provider_disconnect_and_keeps_filesystem_access(self):
        class SlowPlugin:
            family = "slow"
            version = 1
            description = "Test reconnect-persistent RPC tasks."
            operations = {
                "write_after_disconnect": {
                    "description": "Wait, then create one file.",
                    "write": True,
                    "execution": "task",
                    "input_schema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                }
            }

            def __init__(self, started, release):
                self.started = started
                self.release = release

            def probe(self, _config):
                return "available", None, None

            def dispatch(self, _files, _operation, _args):
                raise AssertionError("task operation must not use sync dispatch")

            def dispatch_task(self, files, _operation, _args, task):
                self.started.set()
                while not self.release.wait(0.02):
                    task.check_cancelled()
                path = files.path("after-disconnect.txt")
                fd = files.paths.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(b"survived")
                return {"status": 200, "body": {"path": "after-disconnect.txt"}}

        with tempfile.TemporaryDirectory() as directory:
            started = threading.Event()
            release = threading.Event()
            config = {
                "url": "ws://127.0.0.1/provider",
                "token": "test",
                "root": directory,
                "writable": True,
                "allow_exec": False,
            }
            runtime = ClientRuntime(config)
            plugin = SlowPlugin(started, release)
            runtime.files.rpc_registry.register(plugin, source="test:slow")
            runtime.files.rpc_capabilities = runtime.files.rpc_registry.capability_map(config)
            try:
                started_task = runtime.tasks.dispatch("task_start", {
                    "task_id": "rpc-survive-1",
                    "rpc": {
                        "family": "slow",
                        "operation": "write_after_disconnect",
                        "args": {},
                    },
                })
                self.assertTrue(started.wait(2))
                self.assertTrue(started_task["running"])

                messages = iter([
                    json.dumps({
                        "type": "server_hello",
                        "handshake_version": MAPPING_HANDSHAKE_VERSION,
                        "server_version": MINIMUM_MAPPING_CLIENT_VERSION,
                        "server_fingerprint": SERVER_SOURCE_FINGERPRINT,
                        "minimum_client_version": MINIMUM_MAPPING_CLIENT_VERSION,
                        "hello_timeout_seconds": 30,
                    }),
                    json.dumps({
                        "type": "ready",
                        "handshake_version": MAPPING_HANDSHAKE_VERSION,
                    }),
                    "",
                ])

                class Socket:
                    def send(self, _data):
                        pass

                    def recv(self):
                        return next(messages)

                    def ping(self, *_args):
                        pass

                    def close(self):
                        pass

                with patch("websocket.create_connection", return_value=Socket()):
                    run_once(config, runtime=runtime)

                still_running = runtime.tasks.dispatch(
                    "task_get",
                    {"task_id": "rpc-survive-1", "offset": 0},
                )
                self.assertTrue(still_running["running"])
                release.set()
                result = self.wait_task(runtime.tasks, "rpc-survive-1")
                self.assertEqual(0, result["exit_code"], result)
                self.assertEqual(
                    "survived",
                    (Path(directory) / "after-disconnect.txt").read_text(),
                )
            finally:
                release.set()
                runtime.close()

    def test_archive_create_interrupt_removes_temporary_and_final_outputs(self):
        import openkapsel.rpc_plugins.archive as archive_plugin

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source" / "large.bin").write_bytes(b"x" * (1024 * 1024))
            files = ClientFiles(root, writable=True)
            tasks = ClientTasks(files, enabled=False, max_tasks=1, max_seconds=30)
            started = threading.Event()

            def blocked_copy(_files, _source, _target, task):
                started.set()
                while not task.cancelled:
                    time.sleep(0.01)
                task.check_cancelled()

            try:
                with patch.object(archive_plugin, "_copy_safe_file", blocked_copy):
                    task = tasks.dispatch("task_start", {
                        "task_id": "archive-cancel-1",
                        "rpc": {
                            "family": "archive",
                            "operation": "create",
                            "args": {
                                "destination": "cancelled.zip",
                                "sources": ["source"],
                                "format": "zip",
                            },
                        },
                    })
                    self.assertTrue(task["running"])
                    self.assertTrue(started.wait(2))
                    tasks.dispatch("task_interrupt", {"task_id": "archive-cancel-1"})
                    result = self.wait_task(tasks, "archive-cancel-1")
                self.assertEqual(130, result["exit_code"], result)
                self.assertEqual("rpc_task_cancelled", result["error"]["code"])
                self.assertFalse((root / "cancelled.zip").exists())
                internal = root / ".openkapsel" / "rpc-tasks"
                self.assertTrue(internal.is_dir())
                self.assertEqual([], list(internal.iterdir()))
            finally:
                tasks.close()
                files.close()

    def test_interrupt_cancels_cooperative_rpc_task(self):
        class WaitPlugin:
            family = "waiter"
            version = 1
            description = "Test cancellation."
            operations = {
                "wait": {
                    "description": "Wait until cancelled.",
                    "execution": "task",
                    "input_schema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                }
            }

            def __init__(self, started):
                self.started = started

            def probe(self, _config):
                return "available", None, None

            def dispatch(self, _files, _operation, _args):
                raise AssertionError

            def dispatch_task(self, _files, _operation, _args, task):
                self.started.set()
                while True:
                    task.check_cancelled()
                    time.sleep(0.01)

        with tempfile.TemporaryDirectory() as directory:
            files = ClientFiles(directory, writable=False)
            started = threading.Event()
            plugin = WaitPlugin(started)
            files.rpc_registry.register(plugin, source="test:waiter")
            files.rpc_capabilities = files.rpc_registry.capability_map({})
            tasks = ClientTasks(files, enabled=False, max_tasks=1, max_seconds=30)
            try:
                tasks.dispatch("task_start", {
                    "task_id": "rpc-waiter-1",
                    "rpc": {"family": "waiter", "operation": "wait", "args": {}},
                })
                self.assertTrue(started.wait(2))
                tasks.dispatch("task_interrupt", {"task_id": "rpc-waiter-1"})
                result = self.wait_task(tasks, "rpc-waiter-1")
                self.assertTrue(result["interrupted"])
                self.assertEqual(130, result["exit_code"])
                self.assertEqual("rpc_task_cancelled", result["error"]["code"])
            finally:
                tasks.close()
                files.close()


if __name__ == "__main__":
    unittest.main()

"""The Server's Local Client invokes the same RPC registry without WebSocket."""
import tempfile
import os
import unittest
from pathlib import Path

from openkapsel.client_runtime.local_client import LocalClient


class FakeRpcRegistry:
    def __init__(self):
        self.calls = []

    def capability_map(self, config):
        return {}

    def dispatch_sync(self, files, family, operation, args):
        self.calls.append(("sync", files.root, files.writable,
                           family, operation, args))
        return {"status": 200, "body": {"ok": True}}

    def dispatch_task(self, files, family, operation, args, task):
        self.calls.append(("task", files.root, files.writable,
                           family, operation, args, task))
        return {"status": 200, "body": {"task": True}}


class LocalClientTests(unittest.TestCase):
    def test_local_rpc_uses_workspace_root_and_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = FakeRpcRegistry()
            index = object()
            local = LocalClient(registry, {"git": {"state": "available"}},
                                filename_index=lambda: index)
            session = local.rpc_session(Path(temporary), writable=True)
            self.assertIs(session.files.rpc_registry, registry)
            self.assertIs(session.files.filename_index, index)
            self.assertFalse(session.files._index_owned)
            self.assertEqual({"status": 200, "body": {"ok": True}},
                             session.dispatch_sync("git", "status", {"paths": []}))
            context = object()
            self.assertEqual({"status": 200, "body": {"task": True}},
                             session.dispatch_task("git", "commit", {"message": "x"}, context))
            self.assertEqual(["sync", "task"], [item[0] for item in registry.calls])
            self.assertEqual(Path(temporary).resolve(), registry.calls[0][1])
            self.assertTrue(registry.calls[0][2])
            self.assertIs(registry.calls[1][-1], context)

    def test_local_client_registers_functions_without_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = LocalClient(FakeRpcRegistry(), {})
            self.assertEqual(Path(temporary).resolve(),
                             local.rpc_session(temporary, writable=False).files.root)
            local.functions.register("ping", execute=lambda args, auth: args["value"])
            self.assertEqual(3, local.functions.execute("ping", {"value": 3}))

    @unittest.skipIf(os.name == "nt", "Server Shell executor is POSIX-only")
    def test_local_shell_calls_shared_function_dispatch(self):
        from unittest.mock import patch
        local = LocalClient(FakeRpcRegistry(), {})
        self.assertEqual(("approval.grant",),
                         local.functions.approval_methods("shell.exec"))
        auth = local.functions.grant(
            "shell.exec", old_auth={"other": 1}, request={"reason": "tests"},
        )
        self.assertEqual({"other": 1, "unsandboxed": True}, auth)
        server, record, scope_root = object(), object(), object()
        with patch("openkapsel.execution.shell_execution.start_shell_task",
                   return_value="task") as start:
            result = local.start_shell(
                server, record, scope_root, command="echo ok",
                cwd_value=".", timeout_seconds=30, auth=auth,
            )
        self.assertEqual("task", result)
        args, kwargs = start.call_args
        self.assertEqual((server, record, scope_root), args)
        self.assertTrue(kwargs["unsandboxed"])
        self.assertEqual("echo ok", kwargs["command"])

    def test_local_file_dispatch_uses_client_file_api(self):
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "example.txt").write_text("content")
            local = LocalClient(FakeRpcRegistry(), {})
            session = local.file_session(temporary, writable=True)
            response = session.dispatch_file("fs_list", {
                "query": {"path": ["."]}, "body": {}, "display_root": ".",
            })
            self.assertEqual(200, response["status"])
            self.assertIn("example.txt", str(response["body"]))
            with self.assertRaises(ValueError):
                session.dispatch_file("unknown_operation", {})

if __name__ == "__main__":
    unittest.main()

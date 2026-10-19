"""Temporary administrator grants: protocol, host I/O and lifecycle."""
import errno
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from openkapsel.client import ClientRuntime, _capabilities
from openkapsel.client_runtime.client_rpc import ClientRpcSession
from openkapsel.mapping.mapping_manager import MappingManager
from openkapsel.mapping.mapping_ui import render_mappings

MARKER = {"full_client_approval": True}


class FullApprovalClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.export = self.root / "export"
        self.export.mkdir()
        self.runtime = ClientRuntime({"url": "ws://127.0.0.1/provider", "token": "test",
            "root": str(self.export), "writable": True, "allow_exec": True})
        self.session = ClientRpcSession(self.runtime, SimpleNamespace(), threading.Event())

    def tearDown(self):
        self.session.close()
        self.runtime.close()
        for job in self.runtime.tasks.tasks.values():
            job["done"].wait(5)
        self.temp.cleanup()

    def control(self, seconds, **extra):
        return self.session._dispatch({"id": "control", "op": "approval_mode",
            "args": dict(duration_seconds=seconds, **extra)})

    def file(self, op, *, body=None, query=None):
        return self.session.file_functions.execute(
            "files.write" if op == "fs_mutate" else "files.read",
            {"operation": op, "arguments": {"body": body or {}, "query": query or {},
                "display_root": "/workspace/laptop", "rules": []}}, auth=MARKER)

    def test_private_control_exact_types_expiry_and_capability(self):
        self.assertTrue(_capabilities(self.runtime.files, self.runtime.tasks)["temporary_full_approval"])
        self.assertFalse(self.runtime.full_approval_active())
        for value in (True, False, "1800", 1800.0, -1, 1, 600, None):
            self.assertIn("error", self.control(value), value)
        self.assertIn("error", self.control(1800, extra=True))
        for duration in (1800, 7200, 28800, 86400, 0):
            with patch("openkapsel.client.time.monotonic", return_value=100):
                self.assertEqual({"active": bool(duration), "duration_seconds": duration},
                                 self.control(duration)["result"])
            with patch("openkapsel.client.time.monotonic", return_value=100 + duration):
                self.assertFalse(self.runtime.full_approval_active())
        self.assertNotIn("approval_mode", self.runtime.files.rpc_capabilities)
        self.control(1800)
        self.session.close()
        self.assertFalse(self.runtime.full_approval_active())
        self.assertIsNone(self.control(1800))
        self.assertFalse(self.runtime.full_approval_active())

    def test_external_read_create_update_and_revoke(self):
        outside = self.root / "outside"
        outside.mkdir()
        path = outside / "sample.txt"
        path.write_text("outside data")
        with self.assertRaises(OSError):
            self.file("fs_read_files", body={"paths": [str(path)]})
        self.control(1800)
        result = self.file("fs_read_files", body={"paths": [str(path)]})
        self.assertEqual("outside data", result["body"]["items"][0]["content"], result)
        created = outside / "new.txt"
        result = self.file("fs_mutate", body={"items": [
            {"op": "file.create", "path": str(created), "content": "created"}]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("created", created.read_text())
        etag = self.file("fs_stat", query={"path": [str(created)], "fields": ["etag"]})["body"]["etag"]
        result = self.file("fs_mutate", body={"items": [{"op": "text.replace",
            "path": str(created), "expected_etag": etag,
            "replacements": [{"old": "created", "new": "updated", "expected_count": 1}]}]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("updated", created.read_text())
        self.control(0)
        with self.assertRaises(OSError):
            self.file("fs_read_files", body={"paths": [str(path)]})

    def test_external_mkdir_move_find_and_recycle(self):
        parent = self.root / "external-operations"
        parent.mkdir()
        self.control(1800)
        def write(op, body):
            return self.session.file_functions.execute("files.write",
                {"operation": op, "arguments": {"body": body, "rules": []}}, auth=MARKER)
        directory = parent / "created"
        result = write("fs_mkdir", {"path": str(directory)})
        self.assertEqual(201, result["status"], result)
        original = directory / "a.txt"
        original.write_text("recoverable")
        moved = directory / "b.txt"
        result = write("fs_move", {"source": str(original), "destination": str(moved)})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("recoverable", moved.read_text())
        result = self.file("fs_find", query={"path": [str(parent)], "query": ["b.txt"]})
        self.assertEqual(200, result["status"], result)
        self.assertIn("b.txt", str(result))
        etag = self.file("fs_stat", query={"path": [str(moved)], "fields": ["etag"]})["body"]["etag"]
        result = write("fs_mutate", {"items": [
            {"op": "path.delete", "path": str(moved), "expected_etag": etag}]})
        self.assertEqual(200, result["status"], result)
        self.assertFalse(moved.exists())
        self.assertTrue(result["body"]["items"][0]["recycled"])

    def test_external_delete_failure_restores_all_originals(self):
        from openkapsel.client_runtime.approved_file_api import FullApprovedFiles
        outside = self.root / "rollback"
        outside.mkdir()
        self.control(1800)
        items = []
        for name in ("one", "two"):
            path = outside / name
            path.write_text(name)
            etag = self.file("fs_stat", query={"path": [str(path)], "fields": ["etag"]})["body"]["etag"]
            items.append({"op": "path.delete", "path": str(path), "expected_etag": etag})
        original = FullApprovedFiles.recycle
        calls = []
        def recycle(files, path, original_path=None):
            calls.append(path)
            if len(calls) == 2:
                raise OSError(errno.EIO, "injected second recycle failure")
            return original(files, path, original_path)
        with patch.object(FullApprovedFiles, "recycle", new=recycle):
            result = self.file("fs_mutate", body={"items": items})
        self.assertNotEqual(200, result["status"], result)
        self.assertEqual(2, len(calls))
        self.assertEqual("one", (outside / "one").read_text())
        self.assertEqual("two", (outside / "two").read_text())

    def test_client_readonly_setting_is_temporary_during_full_grant(self):
        self.runtime.files.writable = False
        self.session.files.writable = False
        self.assertFalse(self.runtime.files.writable)
        self.control(1800)
        self.assertTrue(self.runtime.files.writable)
        self.assertFalse(self.runtime.files.configured_writable)
        created = self.root / "readonly-override.txt"
        result = self.file("fs_mutate", body={"items": [
            {"op": "file.create", "path": str(created), "content": "admin grant"}]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("admin grant", created.read_text())
        self.control(0)
        self.assertFalse(self.runtime.files.writable)
        self.assertFalse(self.session.files.writable)

    def test_client_deny_bypass_then_expiry_and_stream_recheck(self):
        denied = self.export / "denied.txt"
        denied.write_text("private sample")
        self.session.files.sandbox_denied_paths = frozenset({denied})
        self.assertTrue(self.session.files.is_protected_path(denied))
        self.control(1800)
        self.assertFalse(self.session.files.is_protected_path(denied))
        function = self.session.file_functions
        arguments = {"operation": "file_stream", "arguments": {
            "operation": "open", "args": {"path": str(denied), "mode": "r"}, "rules": []}}
        handle = function.execute("files.read", arguments, auth=MARKER)
        deadline = self.runtime._full_approval_deadline
        with patch("openkapsel.client.time.monotonic", return_value=deadline):
            self.assertTrue(self.session.files.is_protected_path(denied))
            arguments["arguments"].update(operation="read", args={"handle": handle, "size": 100})
            with self.assertRaises(OSError):
                function.execute("files.read", arguments, auth=MARKER)

    def test_windows_approval_only_shell_grant_and_existing_job_survives_revoke(self):
        self.runtime.tasks.approval_only = True
        args = {"task_id": "&Te01&", "argv": [sys.executable, "-c", "print('full grant')"]}
        with self.assertRaises(OSError):
            self.runtime.tasks.dispatch("task_start", args)
        self.control(1800)
        started = self.runtime.tasks.dispatch("task_start", args)
        self.control(0)
        job = self.runtime.tasks.tasks["&Te01&"]
        self.assertTrue(job["done"].wait(5))
        self.assertEqual(0, self.runtime.tasks.dispatch("task_get", {"task_id": "&Te01&"})["exit_code"], started)
        with self.assertRaises(OSError):
            self.runtime.tasks.dispatch("task_start", dict(args, task_id="&Te02&"))


    def test_git_network_policy_restored_after_revoke(self):
        tasks = self.runtime.tasks
        tasks.git_network_mode = "none"
        registry = self.runtime.files.rpc_registry
        captures = []
        def dispatch(files, family, operation, args, context):
            captures.append(dict(args))
            return {"status": 200, "body": {"operation": operation}}
        with patch.object(registry, "operation_spec", return_value={"write": True, "execution": "task"}), \
                patch.object(registry, "dispatch_task", side_effect=dispatch):
            for index, seconds in enumerate((0, 1800, 0)):
                self.control(seconds)
                tid = "network-" + str(index)
                tasks.dispatch("task_start", {"task_id": tid, "rpc": {
                    "family": "git", "operation": "fetch",
                    "args": {"_network_mode": "full", "_allowed_domains": ["forged"]}}})
                self.assertTrue(tasks.tasks[tid]["done"].wait(5))
        self.assertEqual(["none", "full", "none"], [args["_network_mode"] for args in captures])
        self.assertTrue(all(not args["_allowed_domains"] for args in captures))

    def test_shared_manager_removes_native_sandbox_only_during_grant(self):
        from openkapsel.client_runtime.shared_job_tasks import SharedClientTasks
        wrapper = SharedClientTasks(self.runtime.tasks,
            url="ws://127.0.0.1/mapping-connect/" + "M" * 24,
            home=self.root / "manager", job_sandbox={"type": "test-native"})
        wrapper.full_approval_active = self.runtime.full_approval_active
        with patch("openkapsel.client_runtime.shared_job_tasks.request",
                   return_value={"started": True}) as manager:
            for duration in (0, 1800, 0):
                self.control(duration)
                wrapper.dispatch("task_start", {"task_id": "&Lo01&", "command": "echo test",
                                               "timeout_seconds": 121})
        prepared = [call.args[3] for call in manager.call_args_list]
        self.assertEqual([True, False, True], ["sandbox" in args for args in prepared])
        self.assertTrue(all(args["container"] is None for args in prepared))

    def test_full_file_grant_retains_token_deny_and_path_validation(self):
        from openkapsel.client_runtime.approved_file_api import FullApprovedFiles
        from openkapsel.errors import ApiError
        parent = self.root / "outside"
        parent.mkdir()
        child = parent / "child"
        child.mkdir()
        self.control(1800)
        files = FullApprovedFiles(self.runtime.files, MARKER, True, (
            SimpleNamespace(path=str(parent) + "/", access="deny"),
            SimpleNamespace(path=str(child) + "/", access="rw")))
        with self.assertRaises(OSError):
            files.path(str(child / "blocked"))
        plain = FullApprovedFiles(self.runtime.files, MARKER, True, ())
        with self.assertRaises(ApiError):
            plain.path("../escape")
        with self.assertRaises(ApiError):
            plain.path("bad\x00path")


class FullApprovalManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.manager = MappingManager(base / "root", base / "state", enabled=False)
        self.row, _ = self.manager.store.create("workspace", "laptop", writable=True)
        self.mid = self.row["id"]
        self.session = SimpleNamespace(ready=True, closed=False,
            capabilities={"temporary_full_approval": True}, close=Mock())
        self.session.call = Mock(side_effect=lambda op, args: {
            "active": bool(args["duration_seconds"]), "duration_seconds": args["duration_seconds"]})
        self.manager.sessions[self.mid] = self.session

    def tearDown(self):
        self.manager.sessions.clear()
        for row in self.manager.store.list():
            self.manager.store.delete(row["id"])
        self.manager.close()
        self.temp.cleanup()

    def test_validation_old_client_isolation_expiry_revoke(self):
        for value in (True, "1800", 1800.0, 600, -1):
            with self.assertRaises(ValueError):
                self.manager.set_full_approval(self.mid, value)
        self.session.capabilities.clear()
        with self.assertRaisesRegex(ValueError, "upgrade"):
            self.manager.set_full_approval(self.mid, 1800)
        self.session.call.assert_not_called()
        self.session.close.assert_not_called()
        self.session.capabilities["temporary_full_approval"] = True
        with patch("openkapsel.mapping.mapping_manager.time.monotonic", return_value=100):
            result = self.manager.set_full_approval(self.mid, 1800)
            self.assertTrue(result["active"])
            self.assertEqual(1800, result["remaining_seconds"])
        other, _ = self.manager.store.create("workspace", "desktop")
        self.assertFalse(self.manager.full_approval_status(other["id"])["active"])
        with patch("openkapsel.mapping.mapping_manager.time.monotonic", return_value=1900):
            self.assertFalse(self.manager.full_approval_status(self.mid)["active"])
        self.manager.set_full_approval(self.mid, 7200)
        self.assertFalse(self.manager.set_full_approval(self.mid, 0)["active"])
        self.manager.set_full_approval(self.mid, 1800)
        self.manager.sessions[self.mid] = SimpleNamespace(ready=True, closed=False,
            capabilities={"temporary_full_approval": True})
        self.assertFalse(self.manager.full_approval_status(self.mid)["active"])

    def test_bad_ack_fences_transport(self):
        for ack in (None, {}, {"active": True, "duration_seconds": True}):
            self.manager.sessions[self.mid] = self.session
            self.session.call = Mock(return_value=ack)
            with self.assertRaises(ValueError):
                self.manager.set_full_approval(self.mid, 1800)
            self.assertNotIn(self.mid, self.manager.sessions)
            self.assertFalse(self.manager.full_approval_status(self.mid)["active"])
        self.session.close.assert_called()

    def test_concurrent_admin_calls_preserve_peer_order(self):
        entered, release = threading.Event(), threading.Event()
        calls, failures = [], []
        def call(op, args):
            seconds = args["duration_seconds"]
            calls.append(seconds)
            if seconds:
                entered.set()
                if not release.wait(3):
                    raise AssertionError("test synchronization timeout")
            return {"active": bool(seconds), "duration_seconds": seconds}
        self.session.call = call
        def update(seconds):
            try:
                self.manager.set_full_approval(self.mid, seconds)
            except Exception as exc:
                failures.append(exc)
        enable = threading.Thread(target=update, args=(1800,))
        revoke = threading.Thread(target=update, args=(0,))
        enable.start()
        self.assertTrue(entered.wait(3))
        revoke.start()
        release.set()
        enable.join(3)
        revoke.join(3)
        self.assertFalse(enable.is_alive() or revoke.is_alive())
        self.assertEqual([], failures)
        self.assertEqual([1800, 0], calls)
        self.assertFalse(self.manager.full_approval_status(self.mid)["active"])

    def test_failed_old_generation_never_disconnects_replacement(self):
        replacement = SimpleNamespace(ready=True, closed=False,
            capabilities={"temporary_full_approval": True}, close=Mock())
        def fail(op, args):
            self.manager.sessions[self.mid] = replacement
            raise OSError(errno.ECONNRESET, "lost acknowledgement")
        self.session.call = fail
        with self.assertRaises(OSError):
            self.manager.set_full_approval(self.mid, 1800)
        self.assertIs(replacement, self.manager.sessions[self.mid])
        replacement.close.assert_not_called()
        self.manager.sessions.clear()
        self.assertFalse(self.manager.set_full_approval(self.mid, 0)["active"])

    def test_ui_supported_active_and_offline(self):
        row = dict(self.row, online=True)
        for supported in (False, True):
            page = render_mappings([row], [], "csrf-value", "/admin", enabled=True,
                approvals={self.mid: {"supported": supported, "active": supported,
                                     "remaining_seconds": 7200 if supported else 0}})
            self.assertIn('name="csrf" value="csrf-value"', page)
            self.assertIn('value="full_revoke"', page)
            self.assertIn('value="86400"', page)
            self.assertIn("Active · 2h 0m left" if supported else "Client upgrade required", page)
            self.assertEqual(not supported, 'value="full_approval" disabled' in page)

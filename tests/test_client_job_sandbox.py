"""Client job_sandbox configuration and automatic OS backend selection."""
from __future__ import annotations

import base64
import json
import os
import platform
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import ClientRuntime
from openkapsel.job_manager import shutdown


class ClientJobSandboxTests(unittest.TestCase):
    MAPPING = "C" * 24

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-client-job-sandbox-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.readonly = self.base / "references"
        self.readonly.mkdir()
        (self.readonly / "example.txt").write_text("REFERENCE")
        self.writable = self.base / "writable"
        self.writable.mkdir()
        self.state = self.base / "manager"
        self.env = patch.dict(os.environ, {"OPENKAPSEL_JOB_MANAGER_HOME": str(self.state)})
        self.env.start()
        self.addCleanup(self.env.stop)
        def stop():
            try:
                shutdown(self.state, force=True)
            except (ConnectionError, OSError, EOFError):
                return
            if os.name != "nt":
                from openkapsel.job_manager import endpoint
                socket_path, _ = endpoint(self.state)
                until = time.monotonic() + 8
                while Path(socket_path).exists() and time.monotonic() < until:
                    time.sleep(.04)
        self.addCleanup(stop)

    def _config(self, **overrides):
        base = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING,
            "token": "t" * 32,
            "root": str(self.root),
            "allow_exec": True,
            "writable": False,
            "job_sandbox": {
                "paths": [
                    {"path": str(self.readonly), "access": "ro"},
                    {"path": str(self.writable), "access": "rw"},
                ],
                "network": {"mode": "domain_allowlist", "domains": ["EXAMPLE.COM", ".GitHub.com", "example.com"]},
            },
        }
        base.update(overrides)
        return base

    def test_client_selects_native_backend_and_domain_matching_table(self):
        from openkapsel.execution.network_proxy import domain_allowed
        if platform.system() not in {"Linux", "Darwin", "Windows"}:
            self.skipTest("Native sandbox requires Linux, macOS or Windows")
        runtime = ClientRuntime(self._config())
        try:
            spec = runtime.tasks.job_sandbox
            self.assertEqual(
                {"Linux": "bubblewrap", "Darwin": "seatbelt",
                 "Windows": "approval_only"}[platform.system()],
                spec["type"],
            )
            self.assertEqual(str(self.root), spec["root"])
            self.assertFalse(spec["writable"])
            self.assertEqual(["example.com", ".github.com"], spec["allowed_domains"])
            self.assertEqual("domain_allowlist", runtime.tasks.legacy.git_network_mode)
            self.assertEqual(("example.com", ".github.com"),
                             runtime.tasks.legacy.git_allowed_domains)
            self.assertTrue(domain_allowed("sub.github.com", tuple(spec["allowed_domains"])))
            self.assertFalse(domain_allowed("otherexample.com", tuple(spec["allowed_domains"])))
            self.assertEqual([True, False], [p["access"] == "ro" for p in spec["allowed_paths"]])
            if platform.system() == "Windows":
                # Windows interprets literal file operations and requires approval for other Shell commands.
                capabilities = runtime.tasks.capabilities()
                self.assertFalse(capabilities["sandbox"])
                self.assertTrue(capabilities["safe_powershell"])
                self.assertTrue(capabilities["approval_required"])
                self.assertEqual("native-unsandboxed", capabilities["backend"])
                self.assertEqual(120, capabilities["restart_persistence_timeout_gt"])
            else:
                self.assertTrue(runtime.tasks.capabilities()["sandbox"])
                self.assertEqual(0, runtime.tasks.capabilities()["restart_persistence_timeout_gt"])
        finally:
            runtime.close()

    def test_approved_unsandboxed_shell_ignores_unrelated_deny_rule(self):
        denied = self.root / "absolute-deny"
        denied.mkdir()
        secret = denied / "secret.txt"
        secret.write_text("PRIVATE")
        runtime = ClientRuntime(self._config(
            writable=True,
            job_sandbox={
                "paths": [{"path": str(denied), "access": "deny"}],
                "network": {"mode": "none"},
            },
        ))
        try:
            job = {"task_id": "&De01&", "command": "echo APPROVED",
                   "unsandboxed": True, "timeout_seconds": 5}
            # Test dispatch without launching real unsandboxed commands.
            with patch.object(runtime.tasks.legacy, "_start",
                              return_value={"approved": True}) as launch:
                self.assertEqual({"approved": True},
                                 runtime.tasks.dispatch("task_start", job))
                self.assertEqual({"approved": True},
                                 runtime.tasks.legacy.dispatch("task_start", job))
                self.assertEqual(2, launch.call_count)
                self.assertTrue(all(call.args[1]["unsandboxed"]
                                    for call in launch.call_args_list))
            # Long approved Shell must reach the shared Job Manager too;
            # unrelated deny must not abort before manager dispatch.
            long_job = dict(job, task_id="&De02&", timeout_seconds=121)
            with patch.object(runtime.tasks, "_prepare", side_effect=lambda args: args), \
                    patch("openkapsel.client_runtime.shared_job_tasks.request",
                          return_value={"approved": "manager"}) as manager:
                self.assertEqual({"approved": "manager"},
                                 runtime.tasks.dispatch("task_start", long_job))
                self.assertTrue(manager.call_args.args[3]["unsandboxed"])
            # The same deny is still enforced on Client File operations.
            with self.assertRaises(OSError):
                runtime.files.ensure_accessible_path(secret)
            self.assertEqual("PRIVATE", secret.read_text())
        finally:
            runtime.close()

    def test_job_sandbox_presence_is_the_only_activation_switch(self):
        if platform.system() not in {"Linux", "Darwin", "Windows"}:
            self.skipTest("unsupported native platform")
        unsandboxed = self._config(writable=True)
        unsandboxed.pop("job_sandbox")
        # A Client without job_sandbox must never require legacy Podman.
        with patch("openkapsel.client_runtime.client_tasks.shutil.which", return_value=None):
            runtime = ClientRuntime(unsandboxed)
        try:
            self.assertIsNone(runtime.tasks.job_sandbox)
            self.assertFalse(runtime.tasks.legacy.sandbox)
            self.assertFalse(runtime.tasks.capabilities()["sandbox"])
        finally:
            runtime.close()

        with patch("openkapsel.client_runtime.client_tasks.shutil.which", return_value=None):
            runtime = ClientRuntime(self._config(writable=True, job_sandbox={}))
        try:
            self.assertIsNotNone(runtime.tasks.job_sandbox)
            self.assertEqual(
                {"Linux": "bubblewrap", "Darwin": "seatbelt",
                 "Windows": "approval_only"}[platform.system()],
                runtime.tasks.job_sandbox["type"],
            )
            self.assertEqual(platform.system() != "Windows",
                             runtime.tasks.capabilities()["sandbox"])
        finally:
            runtime.close()

    def test_invalid_configs_fail_closed(self):
        cases = [
            {"job_sandbox": {"type": "seatbelt"}},
            {"job_sandbox": None},
            {"job_sandbox": {"paths": [{"path": str(self.readonly), "access": "invalid"}]}},
            {"job_sandbox": {"paths": [{"path": "/"}]}},
            {"job_sandbox": {"network": {"mode": "bogus"}}},
            {"job_sandbox": {"network": {"mode": "none", "domains": ["example.com"]}}},
            {"job_sandbox": {"network": {"mode": "domain_allowlist", "domains": []}}},
            {"job_sandbox": {"network": {"mode": "domain_allowlist", "domains": ["foo/bar"]}}},
        ]
        for variant in cases:
            with self.subTest(variant=variant):
                with self.assertRaises(ValueError):
                    runtime = ClientRuntime(self._config(**variant))
                    runtime.close()
        with patch("openkapsel.client_runtime.job_sandbox_config.platform.system", return_value="Windows"):
            runtime = ClientRuntime(self._config())
            try:
                self.assertEqual("approval_only", runtime.tasks.job_sandbox["type"])
            finally:
                runtime.close()
        with patch("openkapsel.client_runtime.job_sandbox_config.platform.system", return_value="Windows"):
            runtime = ClientRuntime(self._config(job_sandbox={
                "network": {"mode": "full"},
            }))
            try:
                self.assertEqual("approval_only", runtime.tasks.job_sandbox["type"])
                self.assertEqual("full", runtime.tasks.job_sandbox["network_mode"])
                self.assertEqual("full", runtime.tasks.legacy.git_network_mode)
                # platform.system is mocked above, but os.name is the host OS;
                # an actual Windows Client enables approval-only Shell.
                self.assertEqual(os.name == "nt", runtime.tasks.capabilities()["approval_required"])
            finally:
                runtime.close()
        # Explicit extra mounts may never expose a protected config file.
        protected_dir = self.base / "secrets"
        protected_dir.mkdir()
        protected = protected_dir / "secret-client-config.json"
        protected.write_text("{}")
        runtime = ClientRuntime(self._config(job_sandbox={
            "paths": [{"path": str(protected_dir), "access": "ro"}],
        }), protected_paths=[protected])
        try:
            self.assertIn(str(protected), runtime.tasks.job_sandbox["hidden_paths"])
        finally:
            runtime.close()
        # A Shell grant may enclose the Mapping root and Client config.
        # It must neither override the root's read-only policy nor expand
        # file/RPC access beyond that root.
        enclosing = self.base / "shared"
        enclosing.mkdir()
        exported = enclosing / "project"
        exported.mkdir()
        config_file = enclosing / "client.json"
        config_file.write_text('{"token":"private"}')
        runtime = ClientRuntime(self._config(root=str(exported), job_sandbox={
            "paths": [
                {"path": str(enclosing), "access": "rw"},
                {"path": str(config_file), "access": "deny"},
            ],
        }), protected_paths=[config_file])
        try:
            spec = runtime.tasks.job_sandbox
            self.assertIn({"path": str(enclosing), "access": "rw"}, spec["allowed_paths"])
            self.assertIn(str(config_file), spec["hidden_paths"])
            self.assertFalse(spec["writable"])
            with self.assertRaises(OSError):
                runtime.files.path("../client.json")
        finally:
            runtime.close()
        internal = self.root / ".openkapsel"
        internal.mkdir()
        runtime = ClientRuntime(self._config(job_sandbox={
            "paths": [],  # Default .openkapsel deny applies automatically.
        }))
        try:
            self.assertIn(str(internal), runtime.tasks.job_sandbox["hidden_paths"])
        finally:
            runtime.close()
        runtime = ClientRuntime(self._config(job_sandbox={
            "paths": [{"path": str(internal) + "/", "access": "rw"}],
        }))
        try:
            # A deliberate administrator rule now overrides a default deny,
            # unlike a protected Client config file, which stays hard-denied.
            self.assertNotIn(str(internal), runtime.tasks.job_sandbox["hidden_paths"])
        finally:
            runtime.close()
        # Overlapping rules are valid; read-only takes precedence over writable.
        child = self.writable / "nested"
        child.mkdir()
        runtime = ClientRuntime(self._config(job_sandbox={
            "paths": [
                {"path": str(self.writable), "access": "rw"},
                {"path": str(child), "access": "r"},
            ],
        }))
        try:
            self.assertIn({"path": str(child), "access": "ro"},
                          runtime.tasks.job_sandbox["allowed_paths"])
        finally:
            runtime.close()


    @unittest.skipUnless(
        platform.system() == "Linux"
        and os.environ.get("OPENKAPSEL_REAL_SANDBOX_TESTS") == "1",
        "real Client-to-Manager Bubblewrap runs in dedicated Linux CI",
    )
    def test_linux_short_shell_really_uses_manager_and_write_grants(self):
        self.assertIsNotNone(__import__("shutil").which("bwrap"))
        runtime = ClientRuntime(self._config(job_sandbox={
            "paths": [
                {"path": str(self.readonly), "access": "ro"},
                {"path": str(self.writable), "access": "rw"},
            ],
            "network": {"mode": "none"},
        }))
        try:
            code = (
                "import pathlib,socket;"
                "p=pathlib.Path;"
                "print('granted_read',p(" + repr(str(self.readonly / "example.txt")) + ").read_text());"
                "\ntry:p(" + repr(str(self.root / "blocked")) + ").write_text('unsafe')"
                "\nexcept OSError:print('root_write_denied')"
                "\np(" + repr(str(self.writable / "created.txt")) + ").write_text('allowed');"
                "print('granted_write')"
                "\ns=socket.socket();print('network_denied',s.connect_ex(('1.1.1.1',443)))"
            )
            runtime.tasks.dispatch("task_start", {
                "task_id": "&Lnx1&", "argv": ["/usr/bin/python3", "-c", code],
                "timeout_seconds": 15, "interactive": False,
            })
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                task = runtime.tasks.dispatch("task_get", {"task_id": "&Lnx1&"})
                if not task["running"]:
                    break
                time.sleep(.05)
            self.assertFalse(task["running"])
            self.assertEqual(0, task["exit_code"],
                             base64.b64decode(task.get("output", "")).decode(errors="replace"))
            result = base64.b64decode(task["output"]).decode()
            for expected in ("granted_read REFERENCE", "root_write_denied",
                             "granted_write", "network_denied"):
                self.assertIn(expected, result)
            self.assertEqual("allowed", (self.writable / "created.txt").read_text())
            self.assertFalse((self.root / "blocked").exists())
        finally:
            runtime.close()

    @unittest.skipUnless(platform.system() == "Darwin", "Real Seatbelt integration requires macOS")
    def test_read_only_subdirectory_overrides_writable_workspace(self):
        nested = self.root / "read-only-subtree"
        nested.mkdir()
        (nested / "visible.txt").write_text("VISIBLE")
        runtime = ClientRuntime(self._config(writable=True, job_sandbox={
            "paths": [{"path": str(nested), "access": "ro"}],
            "network": {"mode": "none"},
        }))
        try:
            code = (
                "import pathlib; p=pathlib.Path;"
                "print('read', p('read-only-subtree/visible.txt').read_text());"
                "\ntry:p('read-only-subtree/nope').write_text('bad')"
                "\nexcept OSError:print('nested_write_denied')"
                "\np('root_can_write').write_text('good');print('root_write_ok')"
            )
            runtime.tasks.dispatch("task_start", {
                "task_id": "&RoSb&",
                "argv": [sys.executable, "-c", code],
                "timeout_seconds": 12, "interactive": False,
            })
            end = time.monotonic() + 12
            while time.monotonic() < end:
                task = runtime.tasks.dispatch("task_get", {"task_id": "&RoSb&"})
                if not task["running"]:
                    break
                time.sleep(.05)
            self.assertFalse(task["running"])
            self.assertEqual(
                0, task["exit_code"],
                base64.b64decode(task.get("output", "")).decode(errors="replace")
                + "\nManager log: "
                + ((self.state / "manager.log").read_text(errors="replace")
                   if (self.state / "manager.log").exists() else "(missing)"),
            )
            output = base64.b64decode(task["output"]).decode()
            self.assertIn("read VISIBLE", output)
            self.assertIn("nested_write_denied", output)
            self.assertIn("root_write_ok", output)
            self.assertFalse((nested / "nope").exists())
            self.assertEqual("good", (self.root / "root_can_write").read_text())
        finally:
            runtime.close()

    @unittest.skipUnless(platform.system() == "Darwin", "Real Seatbelt integration requires macOS")
    def test_short_shell_is_manager_sandboxed_with_independent_directory_grants(self):
        # The workspace is read-only; a separate explicitly writable directory
        # must remain writable, while the read-only grant must reject writes.
        runtime = ClientRuntime(self._config(job_sandbox={
            "paths": [
                {"path": str(self.readonly), "access": "ro"},
                {"path": str(self.writable), "access": "rw"},
            ],
            "network": {"mode": "none"},
        }))
        try:
            code = (
                "import pathlib;"
                "p=pathlib.Path;"
                "print(p(" + repr(str(self.readonly / "example.txt")) + ").read_text());"
                "\nfor path in (" + repr(str(self.root / "no_write")) + ","
                + repr(str(self.readonly / "no_write")) + "):"
                "\n try:p(path).write_text('bad');print('unsafe-write')"
                "\n except OSError:print('write-denied')"
                "\np(" + repr(str(self.writable / "created.txt")) + ").write_text('EXTRA_WRITE');print('extra-write-ok')"
            )
            runtime.tasks.dispatch("task_start", {
                "task_id": "&Shrt&",
                "argv": [sys.executable, "-c", code],
                "timeout_seconds": 12, "interactive": False,
            })
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                task = runtime.tasks.dispatch("task_get", {"task_id": "&Shrt&"})
                if not task["running"]:
                    break
                time.sleep(.05)
            self.assertFalse(task["running"])
            self.assertEqual(
                0, task["exit_code"],
                base64.b64decode(task.get("output", "")).decode(errors="replace")
                + "\nManager log: "
                + ((self.state / "manager.log").read_text(errors="replace")
                   if (self.state / "manager.log").exists() else "(missing)"),
            )
            output = base64.b64decode(task["output"]).decode()
            self.assertIn("REFERENCE", output)
            self.assertEqual(2, output.count("write-denied"))
            self.assertIn("extra-write-ok", output)
            self.assertNotIn("unsafe-write", output)
            self.assertEqual("EXTRA_WRITE", (self.writable / "created.txt").read_text())
            self.assertFalse((self.root / "no_write").exists())
            self.assertFalse((self.readonly / "no_write").exists())
        finally:
            runtime.close()
        # Closing the Client doesn't stop the shared Manager.
        self.assertTrue(self.state.joinpath("jobs.sqlite3").is_file())


if __name__ == "__main__":
    unittest.main()

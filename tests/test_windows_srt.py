"""Windows Sandbox Runtime adapter tests; no false claim of native isolation on macOS."""
from __future__ import annotations

import json
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.auth.tokens import PathGrant
from openkapsel.job_sandbox import prepare_job
from openkapsel import windows_srt


class WindowsSrtTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-windows-srt-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "manager"
        self.state.mkdir()
        self.extra = self.base / "extra"
        self.extra.mkdir()
        self.secret = self.workspace / "secret"
        self.secret.mkdir()

    def _settings(self, mode="none", domains=(), writable=True, grants=()):
        return windows_srt.srt_settings(
            root=self.workspace, writable=writable, grants=list(grants),
            hidden=[self.secret], mode=mode, domains=list(domains),
        )

    def test_read_write_hidden_and_optional_grant_policy(self):
        settings = self._settings(grants=(
            PathGrant(str(self.extra), True),
            PathGrant(str(self.workspace / "readonly"), True),
        ))
        self.assertEqual([], settings["network"]["allowedDomains"])
        self.assertEqual([], settings["network"]["deniedDomains"])
        fs = settings["filesystem"]
        self.assertEqual([str(self.workspace)], fs["allowWrite"])
        self.assertEqual([str(self.workspace), str(self.extra),
                          str(self.workspace / "readonly")], fs["allowRead"])
        self.assertIn(str(self.workspace / "readonly"), fs["denyWrite"])
        self.assertIn(str(self.secret), fs["denyRead"])
        self.assertIn(str(self.secret), fs["denyWrite"])

    def test_independent_readonly_root_and_extra_write_grant(self):
        cfg = self._settings(
            writable=False, grants=(PathGrant(str(self.extra), False),),
        )
        self.assertEqual([str(self.extra)], cfg["filesystem"]["allowWrite"])
        self.assertEqual([str(self.workspace), str(self.extra)],
                         cfg["filesystem"]["allowRead"])

    def test_domain_rule_expansion_preserves_apex_and_subdomain(self):
        cfg = self._settings(
            mode="domain_allowlist",
            domains=["example.org", ".github.com", ".github.com", ".example.org"],
        )
        self.assertEqual(
            ["example.org", "github.com", "*.github.com", "*.example.org"],
            cfg["network"]["allowedDomains"],
        )
        self.assertNotIn("*", cfg["network"]["allowedDomains"])

    def test_full_network_refused_instead_of_silently_blocking(self):
        with self.assertRaisesRegex(ValueError, "cannot enforce.*full"):
            self._settings(mode="full")
        with patch.object(windows_srt, "_resolve_global_cli") as find:
            with self.assertRaisesRegex(ValueError, "cannot enforce.*full"):
                windows_srt.launch_windows_srt(
                    argv=["cmd.exe", "/c", "echo hi"], environment={},
                    job_dir=self.state, root=self.workspace, writable=True,
                    grants=[], hidden=[], mode="full", domains=[],
                )
            find.assert_not_called()
        self.assertFalse((self.state / "srt-settings.json").exists())

    def _fake_package(self, version="0.0.79"):
        node = self.base / "Node.exe"
        node.touch()
        npm = self.base / "npm.cmd"
        npm.touch()
        package = self.base / "global" / "@anthropic-ai" / "sandbox-runtime"
        (package / "dist").mkdir(parents=True, exist_ok=True)
        (package / "dist" / "cli.js").write_text("// test source")
        (package / "package.json").write_text(json.dumps({
            "name": "@anthropic-ai/sandbox-runtime", "version": version,
        }))
        return node, npm, package

    def test_launcher_uses_node_not_untrusted_cmd_shim_and_private_policy_file(self):
        node, npm, package = self._fake_package()
        def resolve(executable):
            return str({"node": node, "npm": npm}.get(executable)) if executable in {"node", "npm"} else None
        with patch.object(windows_srt.shutil, "which", side_effect=resolve), patch.object(
            windows_srt.subprocess, "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, stdout="v22.12.0"),
                subprocess.CompletedProcess([], 0, stdout=str(self.base / "global")),
            ],
        ):
            argv, env = windows_srt.launch_windows_srt(
                argv=["cmd.exe", "/d", "/c", "echo", "hello world"],
                environment={"PATH": "a-test-path"},
                job_dir=self.state, root=self.workspace, writable=True,
                grants=[], hidden=[self.secret], mode="none", domains=[],
            )
        self.assertEqual(str(node), argv[0])
        self.assertEqual(str(package / "dist" / "cli.js"), argv[1])
        self.assertEqual("--settings", argv[2])
        self.assertEqual(str(self.state / "srt-settings.json"), argv[3])
        self.assertEqual("-c", argv[4])
        self.assertIn('"hello world"', argv[5])
        self.assertEqual("a-test-path", env["PATH"])
        self.assertEqual([], json.loads((self.state / "srt-settings.json").read_text())["network"]["allowedDomains"])

    def test_missing_node_or_npm_is_explicit_failure(self):
        with patch.object(windows_srt.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Node.js"):
                windows_srt._resolve_global_cli(writable_dirs=())

    def test_outdated_node_and_package_are_rejected(self):
        node, npm, package = self._fake_package()
        def locate(binary):
            return str({"node": node, "npm": npm}.get(binary))
        with patch.object(windows_srt.shutil, "which", side_effect=locate):
            with patch.object(windows_srt.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, stdout="v20.0.0")):
                with self.assertRaisesRegex(RuntimeError, ">=22.12"):
                    windows_srt._resolve_global_cli(writable_dirs=())
            (package / "package.json").write_text(json.dumps({
                "name": "@anthropic-ai/sandbox-runtime", "version": "0.0.30",
            }))
            with patch.object(windows_srt.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], 0, stdout="v22.12.0"),
                subprocess.CompletedProcess([], 0, stdout=str(self.base / "global")),
            ]):
                with self.assertRaisesRegex(RuntimeError, "missing/incompatible"):
                    windows_srt._resolve_global_cli(writable_dirs=())

    def test_srt_executable_inside_writable_workspace_is_rejected(self):
        node, npm, package = self._fake_package()
        with patch.object(windows_srt.shutil, "which", side_effect=lambda n: str(node) if n == "node" else str(npm)):
            with patch.object(windows_srt.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], 0, stdout="v22.12.0"),
                subprocess.CompletedProcess([], 0, stdout=str(self.base / "global")),
            ]):
                with self.assertRaisesRegex(RuntimeError, "writable sandbox"):
                    windows_srt._resolve_global_cli(writable_dirs=(self.base,))

    def test_manager_preparation_owns_and_cleans_up_job_settings(self):
        with patch("openkapsel.job_sandbox.platform.system", return_value="Windows"):
            with patch.object(windows_srt, "_resolve_global_cli", return_value=("node.exe", "cli.js")):
                prepared = prepare_job(
                    {"type": "srt_windows", "root": str(self.workspace),
                     "network_mode": "domain_allowlist",
                     "allowed_domains": [".example.com"],
                     "writable": True, "hidden_paths": [str(self.secret)]},
                    ["cmd.exe", "/c", "echo test"], str(self.workspace),
                    {"PATH": "safe"}, self.state,
                )
        directory = prepared.temp_dir
        try:
            self.assertIsNotNone(directory)
            cfg = json.loads((directory / "srt-settings.json").read_text())
            self.assertEqual(["example.com", "*.example.com"],
                             cfg["network"]["allowedDomains"])
            self.assertEqual("node.exe", prepared.argv[0])
        finally:
            prepared.cleanup()
        self.assertFalse(directory.exists())

    @unittest.skipUnless(
        platform.system() == "Windows"
        and os.environ.get("OPENKAPSEL_REAL_WINDOWS_SRT_TESTS") == "1",
        "real SRT Windows integration must run on provisioned Windows host",
    )
    def test_real_windows_sandbox_user_and_filesystem_isolation(self):
        # This is ONLY enabled on a provisioned native Windows test host.
        # Exercise actual SRT and Windows security APIs; never count mocks as
        # evidence that native Windows isolation works.
        safe = self.workspace / "allowed.txt"
        safe.write_text("INSIDE-SANDBOX-WORKSPACE")
        outside = self.base / "private.txt"
        outside.write_text("MUST-NOT-ESCAPE")
        spec = {
            "type": "srt_windows", "root": str(self.workspace),
            "writable": False, "network_mode": "none",
        }
        identity = prepare_job(spec, ["whoami.exe"], str(self.workspace),
                               dict(os.environ), self.state)
        try:
            result = subprocess.run(
                identity.argv, cwd=self.workspace, env=identity.environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("srt-sandbox", result.stdout.lower())
        finally:
            identity.cleanup()
        files = prepare_job(
            spec,
            ["cmd.exe", "/d", "/c", f'type "{safe}" & type "{outside}"'],
            str(self.workspace), dict(os.environ), self.state,
        )
        try:
            result = subprocess.run(
                files.argv, cwd=self.workspace, env=files.environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=60,
            )
            self.assertIn("INSIDE-SANDBOX-WORKSPACE", result.stdout)
            self.assertNotIn("MUST-NOT-ESCAPE", result.stdout)
        finally:
            files.cleanup()


if __name__ == "__main__":
    unittest.main()

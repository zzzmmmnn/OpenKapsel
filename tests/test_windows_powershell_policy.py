"""Strict Windows PowerShell fallback security checks (portable unit coverage)."""
from __future__ import annotations

import base64
import errno
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.client_runtime.shared_job_tasks import SharedClientTasks
from openkapsel.client_runtime.windows_powershell_policy import (
    SimplePowerShell, _checked_path, execute_simple_powershell,
    parse_simple_powershell,
)


class PowerShellParserTests(unittest.TestCase):
    def test_allowed_commands(self):
        cases = {
            "pwd": ("pwd", ".", ""),
            "Get-Location": ("pwd", ".", ""),
            "ls": ("list", ".", ""),
            "Get-ChildItem -LiteralPath 'folder one'": ("list", "folder one", ""),
            "Get-Item file.txt": ("stat", "file.txt", ""),
            "cat -LiteralPath file.txt": ("read", "file.txt", ""),
            "Test-Path '.\\file.txt'": ("exists", ".\\file.txt", ""),
            "Set-Content -LiteralPath file.txt -Value 'hello world'": ("write", "file.txt", "hello world"),
            "Add-Content -LiteralPath file.txt -Value hello": ("append", "file.txt", "hello"),
            "New-Item -ItemType Directory -LiteralPath folder": ("mkdir", "folder", ""),
            "Remove-Item -LiteralPath file.txt": ("remove", "file.txt", ""),
            'powershell.exe -NoProfile -NonInteractive -Command "Get-ChildItem ."':
                ("list", ".", ""),
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                found = parse_simple_powershell(command)
                self.assertIsNotNone(found)
                self.assertEqual(expected, (found.operation, found.path, found.value))

    def test_unsafe_and_ambiguous_syntax_requires_approval(self):
        cases = (
            "Get-Process", "whoami", "cmd /c dir", "powershell -EncodedCommand Zg==",
            "Get-ChildItem; Start-Process cmd",
            "Get-ChildItem | Invoke-Expression",
            "Get-Content $(Get-Item secret)",
            "Get-Content $env:USERPROFILE",
            "Get-Content `Get-Process",
            'Get-Content "%USERPROFILE%\\secret"',
            'Get-Content "file"; Remove-Item file',
            "Get-Content *", "Get-Content [a-z]", "Get-Content file > outside",
            "Get-Content file\nGet-Content secret",
            "Get-Content -Path file", "Get-Content -LiteralPath file -Raw",
            "Set-Content file -Value unsafe",
            "Set-Content -LiteralPath file -Value ok -Force",
            "Remove-Item -LiteralPath folder -Recurse",
            "New-Item -ItemType Directory -Path dir",
            "Get-ChildItem -LiteralPath ''",
            "powershell -NoProfile -File script.ps1",
        )
        for command in cases:
            with self.subTest(command=command):
                self.assertIsNone(parse_simple_powershell(command))


class PowerShellFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-ps-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = (Path(self.temp.name) / "export").resolve()
        self.root.mkdir()
        # Windows production uses WindowsClientFiles/WindowsPaths with native
        # no-reparse handles; the base ClientFiles uses POSIX dir_fd traversal.
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)
        self.addCleanup(self.files.close)
        (self.root / "existing.txt").write_text("OLD")
        (self.root / "sub").mkdir()
        self.outside = Path(self.temp.name) / "outside.txt"
        self.outside.write_text("PRIVATE")

    def execute(self, command, *, rules=()):
        parsed = parse_simple_powershell(command)
        self.assertIsNotNone(parsed)
        return execute_simple_powershell(self.files, self.root, parsed, rules=rules)

    def test_in_scope_reads_and_writes(self):
        self.assertIn("existing.txt", self.execute("Get-ChildItem"))
        self.assertEqual("OLD", self.execute("Get-Content -LiteralPath existing.txt"))
        self.assertEqual("True\n", self.execute("Test-Path -LiteralPath existing.txt"))
        self.assertEqual("False\n", self.execute("Test-Path -LiteralPath absent"))
        self.execute("Set-Content -LiteralPath existing.txt -Value fresh")
        self.assertEqual("fresh\n", (self.root / "existing.txt").read_text())
        self.execute("Add-Content -LiteralPath existing.txt -Value next")
        self.assertEqual("fresh\nnext\n", (self.root / "existing.txt").read_text())
        self.execute("Set-Content -LiteralPath new.txt -Value created")
        self.assertEqual("created\n", (self.root / "new.txt").read_text())
        self.execute("Add-Content -LiteralPath other-new.txt -Value first")
        self.assertEqual("first\n", (self.root / "other-new.txt").read_text())
        self.execute("New-Item -ItemType Directory -LiteralPath newdir")
        self.assertTrue((self.root / "newdir").is_dir())
        self.execute("Remove-Item -LiteralPath existing.txt")
        self.assertFalse((self.root / "existing.txt").exists())

    def test_outside_dotdot_and_symlink_are_denied(self):
        for raw in ("../outside.txt", str(self.outside)):
            with self.subTest(path=raw), self.assertRaises(OSError):
                self.execute("Get-Content -LiteralPath '" + raw + "'")
        shortcut = self.root / "alias"
        shortcut.symlink_to(self.outside)
        with self.assertRaises(OSError):
            self.execute("Get-Content -LiteralPath alias")
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "inside").symlink_to(self.root / "existing.txt")
        with self.assertRaises(OSError):
            self.execute("Get-Content -LiteralPath nested/inside")

    def test_denies_readonly_and_internal_paths(self):
        protected = self.root / ".openkapsel"
        protected.mkdir()
        (protected / "secret.txt").write_text("SECRET")
        with self.assertRaises(OSError):
            self.execute("Get-Content -LiteralPath .openkapsel/secret.txt")
        rules = [SimpleNamespace(path=str(self.root / "sub"), access="ro")]
        self.execute("Set-Content -LiteralPath existing.txt -Value allow", rules=rules)
        with self.assertRaises(OSError):
            self.execute("Set-Content -LiteralPath sub/new.txt -Value denied", rules=rules)
        rules = [SimpleNamespace(path=str(self.root / "sub"), access="deny")]
        with self.assertRaises(OSError):
            self.execute("Get-ChildItem -LiteralPath sub", rules=rules)

    def test_readonly_export_blocks_file_writes(self):
        self.files.writable = False
        self.assertEqual("OLD", self.execute("Get-Content existing.txt"))
        with self.assertRaises(OSError):
            self.execute("Set-Content -LiteralPath existing.txt -Value forbidden")


class WindowsApprovalTasksTests(PowerShellFilesystemTests):
    def setUp(self):
        super().setUp()
        self.tasks = ClientTasks(self.files, enabled=True, sandbox=False, approval_only=True)
        self.addCleanup(self.tasks.close)

    def _finished(self, task_id):
        timeout = time.monotonic() + 4
        while time.monotonic() < timeout:
            result = self.tasks.dispatch("task_get", {"task_id": task_id})
            if not result["running"]:
                return result
            time.sleep(.02)
        self.fail("safe Shell task did not finish")

    def test_safe_task_returns_shell_results_without_spawn(self):
        data = {"task_id": "&S001&", "command": "Get-Content -LiteralPath existing.txt",
                "cwd": ".", "timeout_seconds": 5}
        self.tasks.dispatch("task_start", data)
        result = self._finished("&S001&")
        self.assertEqual(0, result["exit_code"])
        self.assertEqual("shell", result["kind"])
        self.assertEqual("OLD", base64.b64decode(result["output"]).decode())

    def test_unknown_and_outside_commands_rejected_before_task(self):
        for command in ("whoami", "Get-Content ../outside.txt",
                        "Get-Content -LiteralPath alias"):
            if command.endswith("alias") and not (self.root / "alias").exists():
                (self.root / "alias").symlink_to(self.outside)
            with self.subTest(command=command):
                with self.assertRaises(OSError) as ctx:
                    self.tasks.dispatch("task_start", {
                        "task_id": "&S002&", "command": command, "cwd": "."})
                self.assertEqual(errno.EACCES, ctx.exception.errno)
        self.assertEqual({}, self.tasks.tasks)

    def test_no_shell_approval_bypass_via_long_shared_manager_request(self):
        shared = SharedClientTasks(
            self.tasks, url="ws://127.0.0.1/mapping-connect/" + "C"*24,
            home=Path(self.temp.name) / "manager")
        with self.assertRaises(OSError):
            shared.dispatch("task_start", {
                "task_id": "&S003&", "command": "whoami",
                "timeout_seconds": 121})
        self.assertFalse((Path(self.temp.name) / "manager").exists())


if __name__ == "__main__":
    unittest.main()

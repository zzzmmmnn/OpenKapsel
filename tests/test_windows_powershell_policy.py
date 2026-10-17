"""Strict Windows PowerShell fallback security checks (portable unit coverage)."""
from __future__ import annotations

import base64
import errno
import os
import subprocess
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

    def file_alias(self, alias, target):
        if os.name == "nt":
            # Junctions exercise native reparse rejection without requiring
            # SeCreateSymbolicLinkPrivilege or changing host security policy.
            subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(target.parent)],
                           check=True, capture_output=True)
            return alias / target.name
        alias.symlink_to(target)
        return alias

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
        shortcut = self.file_alias(shortcut, self.outside)
        with self.assertRaises(OSError):
            self.execute("Get-Content -LiteralPath '" + str(shortcut.relative_to(self.root)) + "'")
        nested = self.root / "nested"
        nested.mkdir()
        inside = self.file_alias(nested / "inside", self.root / "existing.txt")
        with self.assertRaises(OSError):
            self.execute("Get-Content -LiteralPath '" + str(inside.relative_to(self.root)) + "'")

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


    def test_windows_device_names_and_ads_denied_before_file_io(self):
        # _checked_path is intentionally testable on POSIX too: Windows
        # names must fail before any ClientFiles/WindowsPaths operation.
        from unittest.mock import patch

        bad = (
            "NUL", "nul.txt", "CON", "con.log", "PRN", "AUX", "COM1",
            "com9.txt", "LPT1", "lpt9.log", "COM¹", "com².txt",
            "LPT³", "CONIN$", "CONOUT$", "CLOCK$", "NUL .txt",
            "sub/CON", "sub/nul.txt", "sub/a.txt:stream",
            "existing.txt:stream", "existing.txt::$DATA",
            "sub/trailing. ", "sub/trailing.", "sub/trailing ",
            "sub/bad<name", "sub/bad\x01name",
        )
        for name in bad:
            with self.subTest(path=name):
                with patch.object(self.files, "path", side_effect=AssertionError("IO path was reached")):
                    for write in (False, True):
                        with self.assertRaises(OSError) as ctx:
                            _checked_path(self.files, self.root, name, write=write)
                        self.assertEqual(errno.EACCES, ctx.exception.errno)

    def test_normal_similar_names_stay_usable(self):
        for name in ("console.txt", "communications.txt", "COM10.txt",
                     "LPT10", "auxiliary", "ordinary.name", "sub/notes.txt"):
            with self.subTest(path=name):
                path, relative = _checked_path(self.files, self.root, name, write=True)
                self.assertEqual(self.root / name, path)
                self.assertEqual(name, relative)

    @unittest.skipUnless(os.name == "nt", "requires native WindowsPaths")
    def test_windows_file_rpc_and_native_guard_also_reject_devices_and_ads(self):
        for name in ("NUL", "con.txt", "COM¹", "LPT³.log", "existing.txt:stream",
                     "sub/bad. "):
            with self.subTest(path=name):
                with self.assertRaises(OSError):
                    self.files.path(name)
                with self.assertRaises(OSError):
                    with self.files.paths.guard(self.root / name):
                        self.fail("unsafe name entered WindowsPaths.guard")


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
        alias = self.file_alias(self.root / "alias", self.outside)
        for command in ("whoami", "Get-Content ../outside.txt",
                        "Get-Content -LiteralPath '" + str(alias.relative_to(self.root)) + "'",
                        "Get-Content -LiteralPath NUL",
                        "Get-Content -LiteralPath COM¹",
                        "Get-Content -LiteralPath existing.txt:stream",
                        "Set-Content -LiteralPath existing.txt:stream -Value unsafe"):
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

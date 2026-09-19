"""Portable Git argv validation and real client execution tests."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_files import ClientFiles
from openkapsel.client_tasks import ClientTasks
from openkapsel.errors import ApiError
from openkapsel.git_operations import GIT_OPERATIONS, git_arguments


def make_repo(root):
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    git("init")
    git("config", "user.name", "Test User")
    git("config", "user.email", "test@example.invalid")
    git("config", "commit.gpgsign", "false")
    (root / "source.txt").write_text("original\n", encoding="utf-8")
    git("add", "source.txt")
    git("commit", "-m", "Initial fixture")
    return git


class GitArgumentTests(unittest.TestCase):
    def test_reject_options_and_outside_paths(self):
        for options in ({"revision": "--output=/tmp/leak"}, {"revision": "HEAD\x00bad"},
                        {"paths": ["../secret"]}, {"paths": ["/etc/passwd"]},
                        {"paths": [":(top)**"]}, {"staged": "false"},
                        {"to_revision": "HEAD"}, {"arbitrary": "--exec=bad"},
                        {"revision": "\ud800"}, {"paths": ["\ud800"]}):
            with self.assertRaises(ApiError, msg=str(options)):
                git_arguments("diff", options)
        for limit in (True, 0, 201):
            with self.assertRaises(ApiError):
                git_arguments("log", {"limit": limit})

    def test_arguments_remain_literal_and_external_helpers_disabled(self):
        value = "a' $(touch injected); file\n.txt"
        argv = git_arguments("diff", {"paths": [value]})
        self.assertEqual(["--", value], argv[-2:])
        self.assertIn("--no-ext-diff", argv)
        self.assertIn("--no-textconv", argv)
        self.assertIn("core.fsmonitor=false", argv)


@unittest.skipUnless(shutil.which("git"), "Git required")
class GitClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)
        self.tasks = ClientTasks(self.files, enabled=True, sandbox=False)
        self.git = make_repo(self.root)

    def tearDown(self):
        self.tasks.close()
        self.files.close()
        self.temp.cleanup()

    def call(self, operation, options=None):
        result = self.tasks.git(operation, {"options": options or {}})
        self.assertFalse(result["running"], result)
        self.assertEqual(0, result["exit_code"], result)
        return result

    def test_all_six_operations_and_staged_changes(self):
        (self.root / "source.txt").write_text("modified\n", encoding="utf-8")
        for operation in GIT_OPERATIONS:
            result = self.call(operation)
            self.assertTrue(result["output"], operation)
        self.assertIn("+modified", self.call("diff")["output"])
        self.assertEqual("", self.call("diff", {"staged": True})["output"])
        self.git("add", "source.txt")
        self.assertIn("+modified", self.call("diff", {"staged": True})["output"])
        self.assertIn("original", self.call("show", {"revision": "HEAD:source.txt"})["output"])
        self.assertEqual("", self.call("ls_files", {"paths": ["missing"]})["output"])

    def test_policy_output_budget_and_bad_revision(self):
        self.tasks.enabled = False
        with self.assertRaises(OSError):
            self.tasks.git("status", {})
        self.tasks.enabled = True
        self.files.writable = False
        with self.assertRaises(OSError):
            self.tasks.git("status", {})
        self.files.writable = True
        result = self.tasks.git("show", {"options": {"revision": "not-a-real-ref"}})
        self.assertNotEqual(0, result["exit_code"])
        (self.root / "source.txt").write_text("x" * 100000, encoding="utf-8")
        result = self.call("diff")
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["output"].encode()), 65536)
        self.assertEqual(65536, result["next_offset"])

    def test_git_uses_existing_task_launcher_and_local_limits(self):
        with patch.object(self.tasks, "_start", wraps=self.tasks._start) as start:
            self.tasks.max_seconds = 5
            self.call("status")
            args = start.call_args.args[1]
            self.assertEqual(5, args["timeout_seconds"])
            self.assertEqual("git", args["argv"][0])

    def test_repository_diff_helpers_are_not_invoked(self):
        self.git("config", "diff.external", "nonexistent-openkapsel-diff-helper")
        self.git("config", "diff.custom.textconv", "nonexistent-openkapsel-textconv-helper")
        self.git("config", "core.fsmonitor", "nonexistent-openkapsel-fsmonitor-helper")
        (self.root / ".gitattributes").write_text("*.txt diff=custom\n", encoding="utf-8")
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        self.assertIn("+changed", self.call("diff")["output"])
        self.assertNotIn("nonexistent-openkapsel", self.call("status")["output"])

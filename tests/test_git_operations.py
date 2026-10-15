"""Portable Git argv validation and real client execution tests."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.errors import ApiError
from openkapsel.files.git_operations import GIT_READ_OPERATIONS, git_arguments


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

    @unittest.skipUnless(shutil.which("git"), "Git required")
    def test_git_config_parser_disables_filters_and_rejects_includes(self):
        from openkapsel.files.git_read import _check_local_config
        executable = shutil.which("git")
        environment = {"PATH": os.environ.get("PATH", ""),
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        self.assertEqual([], _check_local_config(
            executable, "[core]\n    fsmonitor = false\n", environment, Path.cwd(), 3))
        overrides = _check_local_config(executable,
            '[filter\t"evil"]\n  clean = echo fake\n  process = helper\n',
            environment, Path.cwd(), 3)
        self.assertIn("filter.evil.clean=", overrides)
        self.assertIn("filter.evil.process=", overrides)
        self.assertIn("filter.evil.required=false", overrides)
        with self.assertRaises(ApiError):
            _check_local_config(executable,
                '[includeIf "gitdir:~/"]\n  path = /tmp/private\n',
                environment, Path.cwd(), 3)

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
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=False)
        self.tasks = ClientTasks(self.files, enabled=False, sandbox=False)
        self.git = make_repo(self.root)

    def tearDown(self):
        self.tasks.close()
        self.files.close()
        self.temp.cleanup()

    def call(self, operation, options=None):
        response = self.files.dispatch("rpc", {
            "family": "git",
            "operation": operation,
            "args": {"options": options or {}},
        })
        self.assertEqual(200, response["status"], response)
        result = response["body"]
        self.assertFalse(result["running"], result)
        self.assertEqual(0, result["exit_code"], result)
        return result

    def test_all_six_operations_and_staged_changes(self):
        (self.root / "source.txt").write_text("modified\n", encoding="utf-8")
        for operation in GIT_READ_OPERATIONS:
            result = self.call(operation)
            self.assertTrue(result["output"], operation)
        self.assertIn("+modified", self.call("diff")["output"])
        self.assertEqual("", self.call("diff", {"staged": True})["output"])
        self.git("add", "source.txt")
        self.assertIn("+modified", self.call("diff", {"staged": True})["output"])
        self.assertIn("original", self.call("show", {"revision": "HEAD:source.txt"})["output"])
        self.assertEqual("", self.call("ls_files", {"paths": ["missing"]})["output"])

    def test_policy_output_budget_and_bad_revision(self):
        with self.assertRaises(OSError):
            self.tasks.dispatch("task_start", {"task_id": "denied123", "argv": ["git", "status"]})
        from openkapsel.files.git_read import inspect_git
        try:
            inspect_git(self.files.paths, self.root, "show", {"revision": "bad-ref"})
        except ApiError as exc:
            if exc.status != 422:
                raise
            self.assertEqual("git_failed", exc.code)
        else:
            self.fail("unknown revision must fail")
        response = self.files.dispatch("rpc", {
            "family": "git", "operation": "show",
            "args": {"options": {"revision": "bad-ref"}},
        })
        self.assertEqual(422, response["status"], response)
        (self.root / "source.txt").write_text("x" * 100000, encoding="utf-8")
        result = self.call("diff")
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["output"].encode()), 65536)

    def test_untrusted_repository_helper_config_is_rejected_without_execution(self):
        marker = self.root / "injected"
        self.git("config", "filter.evil.clean", "touch injected")
        self.git("config", "diff.external", "touch injected")
        self.git("config", "include.path", str(self.root / "malicious-config"))
        (self.root / ".gitattributes").write_text("*.txt filter=evil diff=evil\n", encoding="utf-8")
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        for operation in ("diff", "status", "log", "show"):
            response = self.files.dispatch("rpc", {
                "family": "git", "operation": operation, "args": {},
            })
            self.assertEqual(409, response["status"], response)
            self.assertEqual("git_unsafe_config", response["error"]["code"])
        self.assertFalse(marker.exists())

    def test_large_ignored_worktree_needs_no_copy_and_alt_store_is_denied(self):
        (self.root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        large = self.root / ".venv" / "large-sparse.bin"
        large.parent.mkdir()
        with large.open("wb") as stream:
            stream.truncate(140 * 1024 * 1024)
        output = self.call("status")["output"]
        self.assertIn(".gitignore", output)
        self.assertNotIn(".venv", output)
        self.assertNotIn("snapshot_bytes", self.call("status"))
        alternate = self.root / ".git/objects/info/alternates"
        alternate.write_text(str(self.root.parent), encoding="utf-8")
        result = self.files.dispatch("rpc", {
            "family": "git", "operation": "log", "args": {},
        })
        self.assertEqual("git_unsupported_layout", result["error"]["code"])

    def test_ignored_symlinks_and_tracked_symlinks_work_like_git(self):
        (self.root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        (self.root / ".venv").mkdir()
        try:
            (self.root / ".venv" / "python").symlink_to(
                self.root.parent / "nonexistent-external-target")
            (self.root / "source-link").symlink_to("source.txt")
        except (NotImplementedError, OSError):
            self.skipTest("symlinks unavailable on this host")
        self.git("add", "source-link")
        self.assertIn("source-link", self.call("status")["output"])
        self.assertNotIn(".venv", self.call("status")["output"])
        self.assertIn("source-link", self.call("ls_files")["output"])
        self.assertIn("source-link", self.call("diff", {"staged": True})["output"])
        (self.root / "application.lock").write_text("data", encoding="utf-8")
        self.assertIn("application.lock", self.call("status")["output"])

    def test_fsmonitor_is_disabled_without_rejecting_normal_config(self):
        self.git("config", "core.fsmonitor", "nonexistent-openkapsel-fsmonitor-helper")
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        self.assertIn("+changed", self.call("diff")["output"])
        self.assertNotIn("nonexistent-openkapsel", self.call("status")["output"])

    def test_diff_and_filter_helpers_disabled_without_rejecting_repo(self):
        marker = self.root / "helper-ran"
        self.git("config", "diff.custom.textconv", "touch helper-ran")
        self.git("config", "filter.evil.clean", "touch helper-ran")
        self.git("config", "filter.evil.process", "touch helper-ran")
        self.git("config", "filter.evil.required", "true")
        (self.root / ".gitattributes").write_text("*.txt diff=custom filter=evil\n", encoding="utf-8")
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        self.assertIn("+changed", self.call("diff")["output"])
        self.assertIn("source.txt", self.call("status")["output"])
        self.assertFalse(marker.exists())

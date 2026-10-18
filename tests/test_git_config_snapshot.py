"""Git writes must use the checked config even if the repository mutates before Git starts."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.errors import ApiError
from openkapsel.files.git_write import _snapshot_git_common_dir, mutate_git


@unittest.skipUnless(shutil.which("git"), "Git required")
class GitConfigSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ok-git-config-race-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "Snapshot Test")
        self.run_git("config", "user.email", "test@example.invalid")
        self.run_git("config", "commit.gpgsign", "false")
        (self.root / "a.txt").write_text("original\n", encoding="utf-8")
        self.run_git("add", "a.txt")
        self.run_git("commit", "-m", "Initial")
        self.gitdir = self.root / ".git"
        self.files = SimpleNamespace(
            root=self.root,
            path=lambda _cwd: self.root,
            paths=SimpleNamespace(open=lambda path, flags: os.open(path, flags)),
        )

    def run_git(self, *args, env=None):
        result = subprocess.run(
            ["git", "-C", str(self.root), *args], env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(0, result.returncode, (args, result.stderr))
        return result.stdout

    def test_after_validation_both_config_and_attributes_can_change_without_exec(self):
        marker = self.root / "filter-executed"
        (self.root / "a.txt").write_text("modified\n", encoding="utf-8")
        # Start with no filter so a before-run validator MUST accept this repo.
        self.assertNotIn("filter.pwn", (self.gitdir / "config").read_text())
        payload = (
            "import sys,pathlib; "
            f"pathlib.Path({str(marker)!r}).write_text('executed'); "
            "sys.stdout.buffer.write(sys.stdin.buffer.read())"
        )
        malicious = (f"[filter \"pwn\"]\n"
                     f"    clean = {shlex.quote(sys.executable)} -c {shlex.quote(payload)}\n")

        class Task:
            def write(self, _value):
                pass

            def run_process(inner, argv, *, cwd=None, env=None):
                # Exact TOCTOU boundary: validation and secure snapshot are
                # complete, but the actual native Git subprocess has not run.
                forged_config = self.root / "incoming-config"
                forged_config.write_text(
                    (self.gitdir / "config").read_text() + "\n" + malicious,
                    encoding="utf-8",
                )
                os.replace(forged_config, self.gitdir / "config")
                forged_attributes = self.root / "incoming-attributes"
                forged_attributes.write_text(
                    "*.txt filter=pwn\n", encoding="utf-8",
                )
                os.replace(forged_attributes, self.root / ".gitattributes")
                self.assertIn("GIT_COMMON_DIR", env,
                              "Git must use a trusted config snapshot")
                safe_path = Path(env["GIT_COMMON_DIR"]) / "config"
                self.assertNotIn("filter.pwn", safe_path.read_text())
                actual = subprocess.run(
                    argv, cwd=cwd, env=env, capture_output=True, timeout=15,
                )
                self.assertEqual(0, actual.returncode, actual.stderr)
                return actual.returncode

        result = mutate_git(self.files, "add", {"paths": ["a.txt"]}, Task())
        self.assertEqual("add", result["operation"])
        self.assertFalse(marker.exists(),
                         "attacker-swapped filter executed outside Git validation")
        self.assertEqual("modified\n", self.run_git("show", ":a.txt"))

    def test_snapshot_preserves_real_packed_ref_mutations(self):
        self.run_git("branch", "packed-branch")
        self.run_git("tag", "packed-tag")
        self.run_git("pack-refs", "--all", "--prune")

        class Task:
            def write(self, _value):
                pass

            def run_process(inner, argv, *, cwd=None, env=None):
                process = subprocess.run(
                    argv, cwd=cwd, env=env, capture_output=True, timeout=15,
                )
                self.assertEqual(0, process.returncode, process.stderr)
                return process.returncode

        mutate_git(self.files, "branch_delete", {"name": "packed-branch"}, Task())
        mutate_git(self.files, "tag_delete", {"name": "packed-tag"}, Task())
        output = self.run_git("show-ref")
        self.assertNotIn("packed-branch", output)
        self.assertNotIn("packed-tag", output)

    def test_git_write_operations_still_persist_to_original_repository(self):
        class Task:
            def write(self, _value):
                pass

            def run_process(inner, argv, *, cwd=None, env=None):
                result = subprocess.run(
                    argv, cwd=cwd, env=env, capture_output=True, timeout=15,
                )
                self.assertEqual(0, result.returncode,
                                 (argv, result.stderr))
                return result.returncode

        def write(operation, options):
            outcome = mutate_git(self.files, operation, options, Task())
            self.assertEqual(operation, outcome["operation"])

        (self.root / "a.txt").write_text("changed\n", encoding="utf-8")
        write("add", {"paths": ["a.txt"]})
        write("commit", {"message": "Secure snapshot commit"})
        self.assertIn("Secure snapshot commit", self.run_git("log", "-1", "--oneline"))
        write("branch_create", {"name": "snapshot-temp"})
        self.assertIn("snapshot-temp", self.run_git("branch", "--list"))
        write("branch_delete", {"name": "snapshot-temp"})
        write("tag_create", {"name": "snapshot-tag", "message": "annotation"})
        self.assertIn("snapshot-tag", self.run_git("tag", "--list"))
        write("tag_delete", {"name": "snapshot-tag"})
        (self.root / "a.txt").write_text("stashed\n", encoding="utf-8")
        write("stash_push", {"message": "safe"})
        self.assertEqual("changed\n", (self.root / "a.txt").read_text())
        write("stash_apply", {"index": 0})
        self.assertEqual("stashed\n", (self.root / "a.txt").read_text())
        write("stash_drop", {"index": 0})
        write("restore", {"paths": ["a.txt"]})
        self.assertEqual("changed\n", (self.root / "a.txt").read_text())
        write("checkout", {"revision": "HEAD", "new_branch": "snapshot-branch"})
        self.assertIn("snapshot-branch", self.run_git("branch", "--show-current"))

    def test_read_only_git_uses_same_pinned_config_against_late_swap(self):
        from openkapsel.files import git_read
        (self.root / "a.txt").write_text("modified\n", encoding="utf-8")
        marker = self.root / "read-filter-executed"
        payload = (
            "import sys,pathlib; "
            f"pathlib.Path({str(marker)!r}).write_text('executed'); "
            "sys.stdout.buffer.write(sys.stdin.buffer.read())"
        )
        malicious = (f"[filter \"pwn\"]\n"
                     f"    clean = {shlex.quote(sys.executable)} -c {shlex.quote(payload)}\n")
        original = git_read._check_local_config

        def swap_after_check(*args, **kwargs):
            overrides = original(*args, **kwargs)
            forged_config = self.root / "read-incoming-config"
            forged_config.write_text(
                (self.gitdir / "config").read_text() + "\n" + malicious,
                encoding="utf-8")
            os.replace(forged_config, self.gitdir / "config")
            forged_attrs = self.root / "read-incoming-attributes"
            forged_attrs.write_text("*.txt filter=pwn\n", encoding="utf-8")
            os.replace(forged_attrs, self.root / ".gitattributes")
            return overrides

        with patch.object(git_read, "_check_local_config",
                          side_effect=swap_after_check):
            result = git_read.inspect_git(
                self.files.paths, self.root, "diff",
                {"paths": ["a.txt"]})
        self.assertIn("modified", result["output"])
        self.assertFalse(marker.exists(),
                         "Git read unexpectedly executed a late-added filter")

    def test_failure_to_isolate_config_prevents_git_execution(self):
        from openkapsel.files import git_write

        class NeverRun:
            def write(self, _value):
                pass

            def run_process(self, *_args, **_kwargs):
                raise AssertionError("Git must not run without safe config")

        with patch.object(git_write, "_link_git_shared_store",
                          side_effect=ApiError(
                              503, "git_safety_unavailable",
                              "cannot isolate the Git repository configuration")):
            with self.assertRaises(ApiError) as denied:
                mutate_git(self.files, "add", {"paths": ["a.txt"]}, NeverRun())
            self.assertEqual("git_safety_unavailable", denied.exception.code)


if __name__ == "__main__":
    unittest.main()

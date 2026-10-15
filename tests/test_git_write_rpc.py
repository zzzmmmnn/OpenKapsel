import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.errors import ApiError
from openkapsel.files.git_write import mutate_git
from tests.test_git_operations import make_repo


@unittest.skipUnless(shutil.which("git"), "Git required")
class GitWriteRpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)
        self.tasks = ClientTasks(self.files, enabled=False, max_tasks=2, max_seconds=30)
        self.git = make_repo(self.root)

    def tearDown(self):
        self.tasks.close()
        self.files.close()
        self.temp.cleanup()

    def run_rpc(self, operation, args):
        task_id = "git-" + operation + "-task"
        started = self.tasks.dispatch("task_start", {
            "task_id": task_id,
            "rpc": {"family": "git", "operation": operation, "args": args},
        })
        self.assertEqual("rpc", started["kind"])
        self.assertTrue(started["write"])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = self.tasks.dispatch("task_get", {"task_id": task_id, "offset": 0})
            if not result["running"]:
                self.assertEqual(0, result["exit_code"], result)
                return result
            time.sleep(0.02)
        self.fail(f"Git task did not finish: {operation}")

    def test_add_commit_restore_and_checkout_are_task_mutations(self):
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        self.run_rpc("add", {"paths": ["source.txt"]})
        staged = self.git("diff", "--cached", "--", "source.txt").stdout.decode()
        self.assertIn("+changed", staged)

        self.run_rpc("commit", {"message": "Task commit"})
        self.assertIn("Task commit", self.git("log", "-1", "--format=%s").stdout.decode())

        (self.root / "source.txt").write_text("broken\n", encoding="utf-8")
        self.run_rpc("restore", {"paths": ["source.txt"]})
        self.assertEqual("changed\n", (self.root / "source.txt").read_text(encoding="utf-8"))

        self.run_rpc("checkout", {"revision": "HEAD", "new_branch": "task-branch"})
        self.assertEqual("task-branch", self.git("branch", "--show-current").stdout.decode().strip())

    def test_branch_tag_and_stash_rpc_mutations(self):
        self.run_rpc("branch_create", {"name": "feature/rpc"})
        self.assertIn("feature/rpc", self.git("branch", "--list").stdout.decode())
        self.run_rpc("branch_delete", {"name": "feature/rpc"})
        self.assertNotIn("feature/rpc", self.git("branch", "--list").stdout.decode())

        self.run_rpc("tag_create", {"name": "v-test", "message": "Test release"})
        tag_type = self.git("cat-file", "-t", "refs/tags/v-test").stdout.decode().strip()
        self.assertEqual("tag", tag_type)
        self.run_rpc("tag_delete", {"name": "v-test"})
        self.assertEqual("", self.git("tag", "--list").stdout.decode())

        (self.root / "source.txt").write_text("stashed contents\n", encoding="utf-8")
        self.run_rpc("stash_push", {"message": "RPC checkpoint"})
        self.assertEqual("original\n", (self.root / "source.txt").read_text())
        self.assertIn("RPC checkpoint", self.git("stash", "list").stdout.decode())
        self.run_rpc("stash_apply", {"index": 0})
        self.assertEqual("stashed contents\n", (self.root / "source.txt").read_text())
        self.run_rpc("stash_drop", {"index": 0})
        self.assertEqual("", self.git("stash", "list").stdout.decode())

    def test_stash_pop_restores_and_drops_entry(self):
        (self.root / "source.txt").write_text("one more change\n", encoding="utf-8")
        self.git("stash", "push", "-m", "pop test")
        self.run_rpc("stash_pop", {"index": 0})
        self.assertEqual("one more change\n", (self.root / "source.txt").read_text())
        self.assertEqual("", self.git("stash", "list").stdout.decode())

    def test_branch_delete_fails_if_not_merged(self):
        self.git("checkout", "-b", "unmerged")
        (self.root / "source.txt").write_text("not merged\n", encoding="utf-8")
        self.git("add", "source.txt")
        self.git("commit", "-m", "side commit")
        self.git("checkout", "-")
        # No forced branch deletion is allowed by RPC.
        started = self.tasks.dispatch("task_start", {
            "task_id": "git-branch-delete-unmerged",
            "rpc": {"family": "git", "operation": "branch_delete",
                    "args": {"name": "unmerged"}},
        })
        self.assertTrue(started["write"])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = self.tasks.dispatch(
                "task_get", {"task_id": "git-branch-delete-unmerged", "offset": 0})
            if not result["running"]:
                self.assertNotEqual(0, result["exit_code"], result)
                self.assertIn("unmerged", self.git("branch", "--list").stdout.decode())
                return
            time.sleep(0.02)
        self.fail("branch delete did not finish")

    def test_network_git_operations_use_fixed_argv_and_policy(self):
        self.git("remote", "add", "origin", "https://example.com/repo.git")

        class Task:
            def __init__(self):
                self.calls = []
            def check_cancelled(self):
                pass
            def write(self, value):
                pass
            def run_process(self, argv, *, cwd=None, env=None):
                self.calls.append((list(argv), Path(cwd), dict(env)))
                return 0

        for operation in ("fetch", "pull", "push"):
            task = Task()
            result = mutate_git(
                self.files, operation,
                {"remote": "origin", "_network_mode": "full", "_allowed_domains": []},
                task,
            )
            self.assertEqual(operation, result["operation"])
            argv = task.calls[0][0]
            self.assertIn(operation, argv)
            if operation == "push":
                self.assertIn("--recurse-submodules=no", argv)
                self.assertIn("--no-verify", argv)
                self.assertIn("--no-follow-tags", argv)
                current_branch = self.git("branch", "--show-current").stdout.decode().strip()
                self.assertIn(f"HEAD:refs/heads/{current_branch}", argv)
                self.assertIn("https://example.com/repo.git", argv)
                self.assertNotIn("--force", argv)
                self.assertNotIn("origin", argv)
            else:
                self.assertIn("--no-recurse-submodules", argv)
            self.assertIn("credential.helper=", argv)
            self.assertIn("http.followRedirects=false", argv)
            self.assertNotIn("http.proxy=", argv)
            self.assertEqual("https", task.calls[0][2]["GIT_ALLOW_PROTOCOL"])
            self.assertEqual(str(Path.home()), task.calls[0][2]["HOME"])
            if sys.platform == "darwin":
                self.assertIn("credential.helper=osxkeychain", argv)

        task = Task()
        result = mutate_git(
            self.files, "clone",
            {"cwd": "cloned", "source": "https://example.com/repo.git",
             "_network_mode": "domain_allowlist", "_allowed_domains": ["example.com"]},
            task,
        )
        self.assertEqual("clone", result["operation"])
        self.assertIn("clone", task.calls[0][0])
        self.assertEqual(self.root, task.calls[0][1])

        with self.assertRaises(ApiError) as denied:
            mutate_git(
                self.files, "fetch",
                {"remote": "origin", "_network_mode": "domain_allowlist",
                 "_allowed_domains": ["other.example"]},
                Task(),
            )
        self.assertEqual("git_network_denied", denied.exception.code)

        with self.assertRaises(ApiError) as no_network:
            mutate_git(
                self.files, "clone",
                {"cwd": "blocked", "source": "https://example.com/repo.git",
                 "_network_mode": "none", "_allowed_domains": []},
                Task(),
            )
        self.assertEqual("git_network_denied", no_network.exception.code)

    def test_push_ignores_untrusted_pushurl_and_rejects_unsafe_push(self):
        self.git("remote", "add", "origin", "https://example.com/repo.git")
        self.git("config", "remote.origin.pushurl", "https://malicious.example/redirect.git")

        class Task:
            def __init__(self):
                self.calls = []
            def write(self, _value):
                pass
            def run_process(self, argv, *, cwd=None, env=None):
                self.calls.append((list(argv), dict(env)))
                return 0

        task = Task()
        mutate_git(self.files, "push", {"remote": "origin", "branch": "release/v1",
                   "_network_mode": "domain_allowlist",
                   "_allowed_domains": ["example.com"]}, task)
        argv, env = task.calls[0]
        self.assertIn("https://example.com/repo.git", argv)
        self.assertFalse(any("malicious.example" in value for value in argv))
        self.assertIn("HEAD:refs/heads/release/v1", argv)
        self.assertEqual("https", env["GIT_ALLOW_PROTOCOL"])
        self.assertIn("--no-verify", argv)
        self.assertIn("--no-follow-tags", argv)

        for changes in (
            {"branch": "--force"},
            {"branch": "main:other"},
            {"branch": "../secret"},
            {"_network_mode": "none"},
            {"_network_mode": "domain_allowlist", "_allowed_domains": ["other.example"]},
        ):
            with self.subTest(changes=changes), self.assertRaises(ApiError):
                mutate_git(self.files, "push", {
                    "remote": "origin", "_network_mode": "full", **changes,
                }, Task())

        self.git("checkout", "--detach", "HEAD")
        with self.assertRaises(ApiError) as detached:
            mutate_git(self.files, "push", {"remote": "origin",
                      "_network_mode": "full"}, Task())
        self.assertEqual("git_detached_head", detached.exception.code)

    def test_client_git_network_policy_overrides_remote_rpc_hints(self):
        """Git subprocess policy is selected by the Client, not Server/AI."""
        from unittest.mock import patch
        from openkapsel.client_runtime.client_tasks import RpcTaskContext
        self.git("remote", "add", "origin", "https://example.com/repo.git")
        policy_cases = (
            ("none", (), False),
            ("domain_allowlist", ("other.example",), False),
            ("domain_allowlist", ("example.com",), True),
            ("full", (), True),
        )
        for index, (mode, domains, allowed) in enumerate(policy_cases):
            with self.subTest(mode=mode, domains=domains):
                self.tasks.close()
                self.tasks = ClientTasks(
                    self.files, enabled=False, max_tasks=2, max_seconds=30,
                    git_network_mode=mode, git_allowed_domains=domains,
                )
                processes = []
                def fake_process(_context, argv, *, cwd=None, env=None):
                    processes.append((list(argv), dict(env)))
                    return 0
                with (patch.object(RpcTaskContext, "run_process", fake_process),
                      patch("openkapsel.files.git_write._validate_git_metadata",
                            return_value=(self.root / ".git",
                                          '[remote "origin"]\nurl = https://example.com/repo.git\n')),
                      patch("openkapsel.files.git_write._current_branch",
                            return_value="main")):
                    tid = f"git-policy-{index}"
                    self.tasks.dispatch("task_start", {
                        "task_id": tid,
                        "rpc": {"family": "git", "operation": "push", "args": {
                            "remote": "origin", "_network_mode": "full",
                            "_allowed_domains": ["example.com"],
                        }},
                    })
                    for _ in range(100):
                        result = self.tasks.dispatch("task_get", {"task_id": tid})
                        if not result["running"]:
                            break
                        time.sleep(.01)
                    else:
                        self.fail("Git policy task did not finish")
                if allowed:
                    self.assertEqual(0, result["exit_code"], result)
                    self.assertEqual(1, len(processes))
                else:
                    self.assertEqual(1, result["exit_code"], result)
                    self.assertEqual("git_network_denied", result["error"]["code"])
                    self.assertEqual([], processes)

    def test_network_git_credentials_and_proxy_from_host_but_no_untrusted_helpers(self):
        from unittest.mock import patch
        self.git("remote", "add", "origin", "https://example.com/repo.git")
        class Task:
            def __init__(self):
                self.calls = []
            def write(self, _value):
                pass
            def run_process(self, argv, *, cwd=None, env=None):
                self.calls.append((list(argv), dict(env)))
                return 0
        for operation in ("fetch", "pull", "push", "clone"):
            with self.subTest(operation=operation):
                task = Task()
                args = {"_network_mode": "domain_allowlist",
                        "_allowed_domains": ["example.com"]}
                if operation == "clone":
                    args.update(cwd="newclone", source="https://example.com/repo.git")
                with (patch("openkapsel.files.git_write._safe_credential_helpers",
                            return_value=["manager"]),
                      patch("openkapsel.files.git_write._validate_git_metadata",
                            return_value=(self.root / ".git",
                                          '[remote "origin"]\nurl = https://example.com/repo.git\n')),
                      patch("openkapsel.files.git_write._current_branch",
                            return_value="main"),
                      patch("openkapsel.files.git_write._path_exists", return_value=False),
                      patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:3128"})):
                    if operation == "clone":
                        with patch.object(self.files.paths, "open",
                                          side_effect=lambda *_: os.open(self.root, os.O_RDONLY)):
                            mutate_git(self.files, operation, args, task)
                    else:
                        mutate_git(self.files, operation, args, task)
                argv, env = task.calls[0]
                self.assertIn("credential.helper=", argv)
                self.assertIn("credential.helper=manager", argv)
                self.assertNotIn("http.proxy=", argv)
                self.assertEqual("http://127.0.0.1:3128", env["HTTPS_PROXY"])
                self.assertEqual(str(Path.home()), env["HOME"])
                self.assertEqual(os.devnull, env["GIT_CONFIG_GLOBAL"])
                self.assertEqual("0", env["GIT_TERMINAL_PROMPT"])
                self.assertIn("http.followRedirects=false", argv)
                self.assertIn("http.sslVerify=true", argv)
                self.assertIn("--no-verify", argv) if operation == "push" else None

    def test_git_write_rejects_external_filter_configuration(self):
        self.git("config", "filter.evil.clean", "touch should-not-run")
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        started = self.tasks.dispatch("task_start", {
            "task_id": "git-unsafe-task",
            "rpc": {
                "family": "git",
                "operation": "add",
                "args": {"paths": ["source.txt"]},
            },
        })
        self.assertEqual("rpc", started["kind"])
        self.assertTrue(started["write"])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = self.tasks.dispatch("task_get", {"task_id": "git-unsafe-task", "offset": 0})
            if not result["running"]:
                self.assertEqual(1, result["exit_code"], result)
                self.assertEqual("git_unsafe_config", result["error"]["code"])
                self.assertFalse((self.root / "should-not-run").exists())
                return
            time.sleep(0.02)
        self.fail("unsafe Git task did not finish")


class GitPushCommandPolicyTests(unittest.TestCase):
    """Policy regressions runnable without writable temporary Git fixtures."""

    @unittest.skipUnless(shutil.which("git"), "Git required")
    def test_push_uses_validated_https_not_configured_pushurl(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        class Task:
            argv = None
            env = None

            def write(self, _data):
                pass

            def run_process(self, argv, *, cwd=None, env=None):
                self.argv, self.env = list(argv), dict(env)
                return 0

        root = Path.cwd()
        files = SimpleNamespace(root=root, path=lambda _cwd: root, paths=None)
        config = ('[remote "origin"]\n'
                  'url = https://example.com/repo.git\n'
                  'pushurl = https://other.example.org/redirect.git\n')
        task = Task()
        with (patch("openkapsel.files.git_write._validate_git_metadata",
                    return_value=(root / ".git", config)),
              patch("openkapsel.files.git_write._current_branch", return_value="main")):
            result = mutate_git(files, "push", {
                "remote": "origin", "_network_mode": "domain_allowlist",
                "_allowed_domains": ["example.com"],
            }, task)
        self.assertEqual("push", result["operation"])
        self.assertEqual("https", task.env["GIT_ALLOW_PROTOCOL"])
        self.assertIn("--no-verify", task.argv)
        if sys.platform == "darwin":
            self.assertIn("credential.helper=osxkeychain", task.argv)
        self.assertIn("--no-follow-tags", task.argv)
        self.assertNotIn("http.proxy=", task.argv)
        self.assertIn("--recurse-submodules=no", task.argv)
        self.assertNotIn("--force", task.argv)
        self.assertEqual(
            ["--", "https://example.com/repo.git", "HEAD:refs/heads/main"],
            task.argv[-3:],
        )
        self.assertFalse(any("other.example.org" in value for value in task.argv))

    @unittest.skipUnless(shutil.which("git"), "Git required")
    def test_push_requires_network_policy_and_safe_branch(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        root = Path.cwd()
        files = SimpleNamespace(root=root, path=lambda _cwd: root, paths=None)
        config = '[remote "origin"]\nurl = https://example.com/repo.git\n'

        class Task:
            def write(self, _value):
                pass

            def run_process(self, *_args, **_kwargs):
                self.fail("invalid push must not execute")

        with patch("openkapsel.files.git_write._validate_git_metadata",
                   return_value=(root / ".git", config)):
            for kwargs in (
                {"_network_mode": "none"},
                {"_network_mode": "domain_allowlist", "_allowed_domains": ["other.example.org"]},
                {"_network_mode": "full", "branch": "--force"},
                {"_network_mode": "full", "branch": "other:refs/heads/main"},
            ):
                with self.subTest(kwargs=kwargs), self.assertRaises(ApiError):
                    mutate_git(files, "push", kwargs, Task())


if __name__ == "__main__":
    unittest.main()

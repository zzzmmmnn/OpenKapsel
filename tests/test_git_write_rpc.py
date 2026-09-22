import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks
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


if __name__ == "__main__":
    unittest.main()

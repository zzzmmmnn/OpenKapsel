"""Normal configured external File access; no browser or full approval."""
import base64
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.file_approval import FileApproval
from openkapsel.client_runtime.approved_file_api import ConfiguredFiles
from openkapsel.client_runtime.job_sandbox_config import make_job_sandbox
from openkapsel.errors import ApiError

MARKER = {"configured_client_paths": True}


class ConfiguredClientFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "export"
        self.external = self.base / "微信下載 folder"
        self.root.mkdir()
        self.external.mkdir()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)
        self.sample = self.external / "收到的日誌.txt"
        self.sample.write_text("configured external sample", encoding="utf-8")
        self.files.sandbox_path_rules = (
            SimpleNamespace(path=str(self.external) + "/", access="ro"),)
        self.policy = FileApproval(self.files)

    def tearDown(self):
        self.files.close()
        self.temp.cleanup()

    def call(self, operation, body=None, query=None, write=False):
        return self.policy.execute(operation, {"body": body or {}, "query": query or {},
            "rules": [], "display_root": "/workspace/moe"}, MARKER, write=write)

    def test_read_list_stat_search_and_stream_without_any_grant(self):
        self.assertFalse(self.files.full_approval_active())
        result = self.call("fs_read_files", {"paths": [str(self.sample)]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("configured external sample", result["body"]["items"][0]["content"])
        result = self.call("fs_list", query={"path": [str(self.external)]})
        self.assertEqual(200, result["status"], result)
        self.assertIn(self.sample.name, str(result))
        result = self.call("fs_find", query={"path": [str(self.external)], "query": ["*.txt"], "mode": ["glob"]})
        self.assertEqual(200, result["status"], result)
        self.assertIn(self.sample.name, str(result))
        handle = self.policy.execute("file_stream", {"operation": "open",
            "args": {"path": str(self.sample), "mode": "r"}, "rules": []}, MARKER, write=False)
        data = self.policy.execute("file_stream", {"operation": "read",
            "args": {"handle": handle, "size": 100}, "rules": []}, MARKER, write=False)
        self.assertEqual("configured external sample", base64.b64decode(data).decode())
        self.policy.execute("file_stream", {"operation": "close",
            "args": {"handle": handle}, "rules": []}, MARKER, write=False)

    def test_ro_rejects_writes_rw_allows_and_unconfigured_sibling_rejected(self):
        created = self.external / "created.txt"
        body = {"items": [{"op": "file.create", "path": str(created), "content": "configured write"}]}
        denied = self.call("fs_mutate", body, write=True)
        self.assertEqual(403, denied["status"], denied)
        self.assertFalse(created.exists())
        self.files.sandbox_path_rules[0].access = "rw"
        self.files.writable = False  # Root readonly does not cancel explicit extra rw.
        allowed = self.call("fs_mutate", body, write=True)
        self.assertEqual(200, allowed["status"], allowed)
        self.assertEqual("configured write", created.read_text())
        sibling = self.base / "not-exported.txt"
        sibling.write_text("must stay hidden")
        read = self.call("fs_read_files", {"paths": [str(sibling)]})
        self.assertNotIn("must stay hidden", str(read))
        self.assertFalse(self.files.full_approval_active())

    def test_configured_rw_recoverable_delete(self):
        self.files.sandbox_path_rules[0].access = "rw"
        etag = self.call("fs_stat", query={"path": [str(self.sample)], "fields": ["etag"]})["body"]["etag"]
        result = self.call("fs_mutate", {"items": [{"op": "path.delete",
            "path": str(self.sample), "expected_etag": etag}]}, write=True)
        self.assertEqual(200, result["status"], result)
        self.assertFalse(self.sample.exists())
        self.assertTrue(result["body"]["items"][0]["recycled"])

    def test_nested_protect_deny_config_and_symlink_escape_stay_blocked(self):
        protected, denied = self.external / "protected", self.external / "denied"
        protected.mkdir()
        denied.mkdir()
        for directory in (protected, denied):
            (directory / "secret.txt").write_text("never expose")
        self.files.sandbox_path_rules += (
            SimpleNamespace(path=str(protected) + "/", access="protect"),
            SimpleNamespace(path=str(denied) + "/", access="deny"),
        )
        for directory in (protected, denied):
            read = self.call("fs_read_files", {"paths": [str(directory / "secret.txt")]})
            self.assertNotIn("never expose", str(read))
        self.files.global_protected_paths = (self.sample,)
        read = self.call("fs_read_files", {"paths": [str(self.sample)]})
        self.assertNotIn("configured external sample", str(read))
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_text("symlink escape")
        link = self.external / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            return  # Windows symlink privilege may be unavailable.
        read = self.call("fs_read_files", {"paths": [str(link / "secret")]})
        self.assertNotIn("symlink escape", str(read))

    def test_single_file_rule_does_not_authorize_its_parent_or_sibling(self):
        self.files.sandbox_path_rules = (SimpleNamespace(path=str(self.sample), access="ro"),)
        result = self.call("fs_read_files", {"paths": [str(self.sample)]})
        self.assertEqual("configured external sample", result["body"]["items"][0]["content"])
        other = self.external / "sibling.txt"
        other.write_text("not authorized")
        result = self.call("fs_read_files", {"paths": [str(other)]})
        self.assertNotIn("not authorized", str(result))
        result = self.call("fs_list", query={"path": [str(self.external)]})
        self.assertEqual(403, result["status"], result)

    def test_mixed_file_directory_config_keeps_each_rule_type(self):
        other = self.base / "other-dir"
        other.mkdir()
        config = {"job_sandbox": {"paths": [
            {"path": str(self.sample), "access": "ro"},
            {"path": str(other) + "/", "access": "rw"},
        ]}}
        policy = make_job_sandbox(config, self.files)
        rows = {item["path"]: item["access"] for item in policy["allowed_paths"]}
        self.assertEqual("ro", rows[str(self.sample)])
        self.assertEqual("rw", rows[str(other) + "/"])
        self.files.sandbox_path_rules = tuple(SimpleNamespace(**item) for item in policy["allowed_paths"])
        result = self.call("fs_read_files", {"paths": [str(self.sample)]})
        self.assertEqual("configured external sample", result["body"]["items"][0]["content"])

    def test_configured_status_is_true_only_inside_allowed_scope(self):
        for path, expected in ((self.external, True), (self.base, False)):
            result = self.policy.execute("approval_status", {"path": str(path)}, MARKER, write=False)
            self.assertEqual(expected, result["granted"])

    def test_safe_windows_read_uses_configured_external_path_without_approval(self):
        from openkapsel.client_runtime.client_tasks import ClientTasks
        tasks = ClientTasks(self.files, enabled=True, sandbox=False, approval_only=True,
                            powershell_rules=self.files.sandbox_path_rules)
        try:
            result = tasks.dispatch("task_start", {"task_id": "&Re01&",
                "command": "Get-Content -LiteralPath '" + str(self.sample) + "'"})
            self.assertEqual("safe_shell", tasks.tasks["&Re01&"]["kind"])
            self.assertTrue(tasks.tasks["&Re01&"]["done"].wait(5))
            result = tasks.dispatch("task_get", {"task_id": "&Re01&"})
            self.assertEqual(0, result["exit_code"], result)
            self.assertIn("configured external sample", base64.b64decode(result["output"]).decode())
            with self.assertRaises(OSError):
                tasks.dispatch("task_start", {"task_id": "&Re02&",
                    "command": "Set-Content -LiteralPath '" + str(self.sample) + "' -Value 'blocked'"})
            self.assertEqual("configured external sample", self.sample.read_text(encoding="utf-8"))
        finally:
            tasks.close()

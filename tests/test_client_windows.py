"""Native Windows provider tests; run by the client compatibility CI job."""
import base64
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows native handles required")
class WindowsClientTests(unittest.TestCase):
    def setUp(self):
        from openkapsel.client_windows import WindowsClientFiles
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.export = self.root / "export"
        self.export.mkdir()
        self.files = WindowsClientFiles(self.export, writable=True)

    def tearDown(self):
        self.files.close()
        self.temp.cleanup()

    def test_files_and_recycle(self):
        self.files.dispatch("mkdir", {"path": "sub"})
        h = self.files.dispatch("create", {"path": "sub/file", "mode": "rw"})
        self.files.dispatch("write", {"handle": h, "data": base64.b64encode(b"windows").decode()})
        self.assertEqual(base64.b64decode(self.files.dispatch("read", {"handle": h, "size": 30})), b"windows")
        self.files.dispatch("close", {"handle": h})
        self.assertEqual(self.files.dispatch("stat", {"path": "sub"})["st_mode"] & 0o170000, 0o040000)
        record = self.files.dispatch("recycle", {"path": "sub/file"})
        self.assertEqual(self.files.dispatch("recycle_list", {})["total"], 1)
        self.files.dispatch("recycle_restore", {"recycle_id": record["recycle_id"]})
        self.assertEqual((self.export / "sub/file").read_bytes(), b"windows")
        record = self.files.dispatch("recycle", {"path": "sub/file"})
        self.files.dispatch("recycle_purge", {"recycle_id": record["recycle_id"]})
        self.assertEqual(self.files.dispatch("recycle_list", {})["total"], 0)

    def test_junction_and_special_paths_are_denied(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("private")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(self.export / "junction"), str(outside)], check=True, capture_output=True)
        for path in ("junction/secret", "../outside/secret", "C:/Windows", "NUL", "file:stream", "name."):
            with self.subTest(path=path), self.assertRaises(OSError):
                self.files.dispatch("open", {"path": path})

    def test_native_task_uses_configured_directory(self):
        from openkapsel.client_tasks import ClientTasks
        tasks = ClientTasks(self.files, enabled=True, sandbox=False)
        try:
            row = tasks.dispatch("task_start", {"task_id": "w" * 24, "argv": [sys.executable, "-c", "print('windows-client')"], "cwd": "."})
            for _ in range(100):
                result = tasks.dispatch("task_get", {"task_id": row["task_id"]})
                if result["finished_at"]:
                    break
                time.sleep(.05)
            self.assertEqual(result["exit_code"], 0)
            self.assertIn(b"windows-client", base64.b64decode(result["output"]))
        finally:
            tasks.close()

"""Portable high-level client filesystem RPC tests."""

import errno
import os
import tempfile
import unittest
from pathlib import Path

from openkapsel.client_files import ClientFiles


class ClientFileAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)

    def tearDown(self):
        self.files.close()
        self.temp.cleanup()

    def call(self, operation, body=None, query=None):
        return self.files.dispatch("api_" + operation, {"body": body or {}, "query": query or {}, "display_root": "/workspace/laptop"})

    def test_write_read_conditional_replace_and_native_paths_stay_private(self):
        content = "héllo " + str(self.root)
        result = self.call("fs_write", {"path": "sub/test.txt", "content": content, "create_parents": True})
        self.assertEqual(201, result["status"], result)
        etag = result["body"]["etag"]
        result = self.call("fs_read", query={"path": ["sub/test.txt"]})
        self.assertEqual(content, result["body"]["content"])
        self.assertEqual("/workspace/laptop/sub/test.txt", result["body"]["path"])
        result = self.call("fs_replace", {"path": "sub/test.txt", "old": "héllo", "new": "bye", "expected_etag": '"wrong"'})
        self.assertEqual(412, result["status"])
        self.assertEqual(content, (self.root / "sub/test.txt").read_text())
        result = self.call("fs_replace", {"path": "sub/test.txt", "old": "héllo", "new": "bye", "expected_etag": etag})
        self.assertEqual(200, result["status"], result)
        self.assertTrue((self.root / "sub/test.txt").read_text().startswith("bye"))

    def test_mkdir_move_batch_preconditions_and_recycling(self):
        self.assertEqual(201, self.call("fs_mkdir", {"path": "a/b", "parents": True})["status"])
        self.assertEqual(200, self.call("fs_mkdir", {"path": "a/b", "parents": True, "exist_ok": True})["status"])
        (self.root / "a/b/file").write_text("one two")
        result = self.call("fs_move", {"source": "a/b/file", "destination": "c/file", "create_parents": True})
        self.assertEqual(200, result["status"], result)
        result = self.call("fs_replace_batch", {"items": [{"path": "c/file", "replacements": [
            {"old": "one", "new": "ONE"}, {"old": "two", "new": "TWO"}]}]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("ONE TWO", (self.root / "c/file").read_text())
        result = self.call("fs_delete_batch", {"paths": ["c/file", "missing"]})
        self.assertEqual(409, result["status"], result)
        self.assertTrue((self.root / "c/file").exists())
        result = self.call("fs_delete_batch", {"paths": ["c/file", "a"]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual(2, result["body"]["deleted"])
        self.assertTrue((self.root / ".openkapsel/recycle").is_dir())

    def test_export_confinement_and_readonly_apply_to_high_level_operations(self):
        for value in ("../outside", "/etc/passwd", ".openkapsel/context/db", "a\x00b", "C:\\file"):
            result = self.call("fs_read", query={"path": [value]})
            self.assertGreaterEqual(result["status"], 400, result)
        self.files.writable = False
        with self.assertRaises(OSError) as error:
            self.call("fs_write", {"path": "no", "content": "no"})
        self.assertEqual(errno.EROFS, error.exception.errno)
        self.assertEqual(200, self.call("fs_list", query={"path": ["."]})["status"])

    def test_response_limit_is_structured_and_does_not_break_subsequent_calls(self):
        (self.root / "large").write_bytes(b"x" * (1024 * 1024))
        result = self.call("fs_read", query={"path": ["large"], "limit": [str(1024 * 1024)]})
        self.assertEqual(413, result["status"])
        self.assertEqual("mapping_response_too_large", result["error"]["code"])
        self.assertFalse(result["error"]["details"]["mutation_may_have_completed"])
        self.assertEqual(200, self.call("fs_read", query={"path": ["large"], "limit": ["10"]})["status"])

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows developer mode")
    def test_symlinks_and_internal_files_are_not_exported(self):
        (self.root / "link").symlink_to(self.root.parent)
        (self.root / ".openkapsel").mkdir()
        (self.root / ".openkapsel/secret").write_text("secret")
        result = self.call("fs_tree", query={"path": ["."], "depth": ["2"]})
        self.assertEqual([], result["body"]["tree"]["children"])
        self.assertIn(self.call("fs_read", query={"path": ["link/private"]})["status"], {403, 409})

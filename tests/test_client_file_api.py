"""Portable high-level client filesystem RPC tests."""

import errno
import hashlib
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

    def test_read_many_limits_errors_and_confinement(self):
        (self.root / "a").write_text("abcdef", encoding="utf-8")
        (self.root / "binary").write_bytes(b"\xff")
        result = self.call("fs_read_many", {"paths": ["a", "missing", "binary", "../secret"], "limit": 3})
        self.assertEqual(207, result["status"], result)
        items = result["body"]["items"]
        self.assertEqual("abc", items[0]["content"])
        self.assertEqual(3, items[0]["next_offset"])
        self.assertEqual([200, 404, 415], [item["status"] for item in items[:3]])
        self.assertGreaterEqual(items[3]["status"], 400)
        result = self.call("fs_read_many", {"paths": ["a", "a"], "max_total_chars": 2})
        self.assertEqual(2, result["body"]["total_chars"])
        self.assertEqual("read_budget_exhausted", result["body"]["items"][1]["error"]["code"])
        for body in ({"paths": []}, {"paths": [1]}, {"paths": ["a"], "limit": True}):
            self.assertEqual(400, self.call("fs_read_many", body)["status"])

    def test_search_globs_and_recursive_manifest(self):
        (self.root / "src").mkdir()
        (self.root / "node_modules").mkdir()
        for name in ("src/a.py", "src/a.txt", "node_modules/b.py"):
            (self.root / name).write_text("needle", encoding="utf-8")
        result = self.call("fs_search", query={"path": ["."], "query": ["needle"], "include": ["*.py"], "exclude": ["node_modules"]})
        self.assertEqual(1, result["body"]["match_count"], result)
        self.assertTrue(result["body"]["matches"][0]["path"].endswith("src/a.py"))
        result = self.call("fs_manifest", {"recursive": True, "path": "src", "depth": 1, "include_sha256": True})
        self.assertEqual(200, result["status"], result)
        self.assertEqual(3, result["body"]["total"])
        self.assertEqual(hashlib.sha256(b"needle").hexdigest(), result["body"]["items"][1]["sha256"])
        self.assertEqual(1, self.call("fs_manifest", {"recursive": True, "depth": 0})["body"]["total"])
        self.assertEqual(400, self.call("fs_manifest", {"recursive": True, "items": []})["status"])
        result = self.files.dispatch("api_fs_manifest", {"body": {"recursive": True}, "limits": {"max_tree_nodes": 2}})
        self.assertEqual(2, result["body"]["total"])
        self.assertTrue(result["body"]["truncated"])
        self.assertEqual(400, self.call("fs_search", query={"query": ["x"], "include": [""]})["status"])
        result = self.call("fs_search", query={"query": ["NEEDLE"], "case_sensitive": ["false"],
                                               "regex": ["true"], "include": ["src/*.py"]})
        self.assertEqual(1, result["body"]["match_count"])

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows developer mode")
    def test_symlinks_and_internal_files_are_not_exported(self):
        (self.root / "link").symlink_to(self.root.parent)
        (self.root / ".openkapsel").mkdir()
        (self.root / ".openkapsel/secret").write_text("secret")
        result = self.call("fs_tree", query={"path": ["."], "depth": ["2"]})
        self.assertEqual([], result["body"]["tree"]["children"])
        self.assertIn(self.call("fs_read", query={"path": ["link/private"]})["status"], {403, 409})

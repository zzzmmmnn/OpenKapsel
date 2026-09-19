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
        self.assertEqual(content, (self.root / "sub/test.txt").read_text(encoding="utf-8"))
        result = self.call("fs_replace", {"path": "sub/test.txt", "old": "héllo", "new": "bye", "expected_etag": etag})
        self.assertEqual(200, result["status"], result)
        self.assertTrue((self.root / "sub/test.txt").read_text(encoding="utf-8").startswith("bye"))

    def test_mkdir_move_batch_preconditions_and_recycling(self):
        self.assertEqual(201, self.call("fs_mkdir", {"path": "a/b", "parents": True})["status"])
        self.assertEqual(200, self.call("fs_mkdir", {"path": "a/b", "parents": True, "exist_ok": True})["status"])
        (self.root / "a/b/file").write_text("one two")
        result = self.call("fs_move", {"source": "a/b/file", "destination": "c/file", "create_parents": True})
        self.assertEqual(200, result["status"], result)
        result = self.call("fs_replace_batch", {"items": [{"path": "c/file", "replacements": [
            {"old": "one", "new": "ONE"}, {"old": "two", "new": "TWO"}]}]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("ONE TWO", (self.root / "c/file").read_text(encoding="utf-8"))
        result = self.call("fs_delete_batch", {"paths": ["c/file", "missing"]})
        self.assertEqual(409, result["status"], result)
        self.assertTrue((self.root / "c/file").exists())
        result = self.call("fs_delete_batch", {"paths": ["c/file", "a"]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual(2, result["body"]["deleted"])
        self.assertTrue((self.root / ".openkapsel/recycle").is_dir())

    def test_encodings_newlines_and_exact_replacement_preserve_bytes(self):
        for encoding, text in [("utf-8", "繁體é😀"), ("utf-8-sig", "繁體é😀"),
                               ("utf-16-le", "\ufeff繁體😀"), ("utf-16-be", "\ufeff繁體😀"),
                               ("gb18030", "中文😀"), ("gbk", "中文"), ("big5", "繁體"),
                               ("cp1252", "café"), ("shift_jis", "日本語"), ("latin-1", "café")]:
            with self.subTest(encoding=encoding):
                content = text + "\r\nold\nlast\rEND"
                body = {"path": "encoded.txt", "content": content, "encoding": encoding}
                result = self.call("fs_write", body)
                self.assertIn(result["status"], (200, 201), result)
                raw = content.encode(encoding)
                self.assertEqual(raw, (self.root / "encoded.txt").read_bytes())
                self.assertEqual(len(raw), result["body"]["bytes_written"])
                read = self.call("fs_read", query={"path": ["encoded.txt"], "encoding": [encoding]})
                self.assertEqual(content, read["body"]["content"], read)
                batch = self.call("fs_read_many", {"paths": ["encoded.txt"], "encoding": encoding})
                self.assertEqual(content, batch["body"]["items"][0]["content"], batch)
                replaced = self.call("fs_replace", {"path": "encoded.txt", "old": "\r\nold\n", "new": "\r\nNEW\n", "encoding": encoding})
                self.assertEqual(200, replaced["status"], replaced)
                self.assertEqual(content.replace("old", "NEW").encode(encoding), (self.root / "encoded.txt").read_bytes())
                replaced = self.call("fs_replace_batch", {"items": [{"path": "encoded.txt", "encoding": encoding,
                    "replacements": [{"old": "NEW", "new": "updated"}]}]})
                self.assertEqual(200, replaced["status"], replaced)
                self.assertEqual(content.replace("old", "updated").encode(encoding), (self.root / "encoded.txt").read_bytes())

    def test_invalid_encoding_is_strict_and_does_not_modify_files(self):
        path = self.root / "legacy.txt"
        path.write_bytes(b"caf\xe9\r\n")
        self.assertEqual(415, self.call("fs_read", query={"path": ["legacy.txt"]})["status"])
        self.assertEqual(415, self.call("fs_replace", {"path": "legacy.txt", "old": "caf", "new": "new"})["status"])
        for encoding in ("utf-7", "not-a-codec", None):
            self.assertEqual(400, self.call("fs_write", {"path": "legacy.txt", "content": "new", "encoding": encoding})["status"])
        self.assertEqual(400, self.call("fs_write", {"path": "legacy.txt", "content": "😀", "encoding": "cp1252"})["status"])
        self.assertEqual(400, self.call("fs_replace", {"path": "legacy.txt", "old": "caf", "new": "😀", "encoding": "cp1252"})["status"])
        self.assertEqual(b"caf\xe9\r\n", path.read_bytes())
        self.assertEqual(400, self.call("fs_read", query={"path": ["legacy.txt"], "encoding": ["cp1252"], "byte_offset": ["0"]})["status"])

    def test_crlf_character_cursors_and_batch_encode_preflight(self):
        path = self.root / "crlf.txt"
        path.write_bytes("甲\r\n乙\n".encode("utf-8"))
        first = self.call("fs_read", query={"path": ["crlf.txt"], "limit": ["2"]})["body"]
        self.assertEqual("甲\r", first["content"])
        second = self.call("fs_read", query={"path": ["crlf.txt"], "offset": [str(first["next_offset"])]})["body"]
        self.assertEqual("\n乙\n", second["content"])
        self.assertEqual("甲\r\n乙\n", first["content"] + second["content"])
        (self.root / "ascii.txt").write_bytes(b"old\r\n")
        response = self.call("fs_replace_batch", {"items": [
            {"path": "crlf.txt", "replacements": [{"old": "甲", "new": "新"}]},
            {"path": "ascii.txt", "encoding": "ascii", "replacements": [{"old": "old", "new": "😀"}]},
        ]})
        self.assertEqual(400, response["status"], response)
        self.assertEqual("甲\r\n乙\n".encode("utf-8"), path.read_bytes())
        self.assertEqual(b"old\r\n", (self.root / "ascii.txt").read_bytes())
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

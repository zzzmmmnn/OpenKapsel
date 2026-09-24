"""Portable high-level client filesystem RPC tests."""

import errno
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles


class ClientFileAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)

    def tearDown(self):
        self.files.close()
        self.temp.cleanup()

    def call(self, operation, body=None, query=None):
        return self.files.dispatch("api_" + operation, {"body": body or {}, "query": query or {}, "display_root": "/workspace/laptop"})

    def etag(self, path):
        result = self.call("fs_stat", query={"path": [path], "fields": ["type,size,etag"]})
        self.assertEqual(200, result["status"], result)
        return result["body"]["etag"]

    def test_write_read_conditional_replace_and_native_paths_stay_private(self):
        content = "héllo " + str(self.root)
        self.assertEqual(201, self.call("fs_mkdir", {"path": "sub"})["status"])
        result = self.call("fs_mutate", {"items": [{
            "op": "file.create", "path": "sub/test.txt", "content": content,
        }]})
        self.assertEqual(200, result["status"], result)
        etag = result["body"]["items"][0]["etag"]
        result = self.call("fs_read", query={"path": ["sub/test.txt"]})
        self.assertEqual(content, result["body"]["content"])
        self.assertEqual("/workspace/laptop/sub/test.txt", result["body"]["path"])
        wrong = self.call("fs_mutate", {"items": [{
            "op": "text.replace", "path": "sub/test.txt", "expected_etag": '"wrong"',
            "replacements": [{"old": "héllo", "new": "bye", "expected_count": 1}],
        }]})
        self.assertEqual(412, wrong["status"], wrong)
        self.assertEqual(content, (self.root / "sub/test.txt").read_text(encoding="utf-8"))
        result = self.call("fs_mutate", {"items": [{
            "op": "text.replace", "path": "sub/test.txt", "expected_etag": etag,
            "replacements": [{"old": "héllo", "new": "bye", "expected_count": 1}],
        }]})
        self.assertEqual(200, result["status"], result)
        self.assertTrue((self.root / "sub/test.txt").read_text(encoding="utf-8").startswith("bye"))

    def test_mkdir_move_batch_preconditions_and_recycling(self):
        self.assertEqual(201, self.call("fs_mkdir", {"path": "a/b", "parents": True})["status"])
        self.assertEqual(200, self.call("fs_mkdir", {"path": "a/b", "parents": True, "exist_ok": True})["status"])
        (self.root / "a/b/file").write_text("one two")
        result = self.call("fs_move", {"source": "a/b/file", "destination": "c/file", "create_parents": True})
        self.assertEqual(200, result["status"], result)
        result = self.call("fs_mutate", {"items": [{
            "op": "text.replace", "path": "c/file", "expected_etag": self.etag("c/file"),
            "replacements": [
                {"old": "one", "new": "ONE", "expected_count": 1},
                {"old": "two", "new": "TWO", "expected_count": 1},
            ],
        }]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("ONE TWO", (self.root / "c/file").read_text(encoding="utf-8"))

        stale = self.etag("c/file")
        (self.root / "c/file").write_text("changed")
        result = self.call("fs_mutate", {"items": [
            {"op": "path.delete", "path": "c/file", "expected_etag": stale},
            {"op": "path.delete", "path": "a", "expected_etag": self.etag("a")},
        ]})
        self.assertIn(result["status"], {409, 412}, result)
        self.assertTrue((self.root / "c/file").exists())
        self.assertTrue((self.root / "a").exists())

        result = self.call("fs_mutate", {"items": [
            {"op": "path.delete", "path": "c/file", "expected_etag": self.etag("c/file")},
            {"op": "path.delete", "path": "a", "expected_etag": self.etag("a")},
        ]})
        self.assertEqual(200, result["status"], result)
        self.assertTrue(all(item["recycled"] for item in result["body"]["items"]))
        self.assertFalse((self.root / "c/file").exists())
        self.assertFalse((self.root / "a").exists())
        self.assertTrue((self.root / ".openkapsel/recycle").is_dir())

    def test_encodings_newlines_and_exact_replacement_preserve_bytes(self):
        for encoding, text in [("utf-8", "繁體é😀"), ("utf-8-sig", "繁體é😀"),
                               ("utf-16-le", "\ufeff繁體😀"), ("utf-16-be", "\ufeff繁體😀"),
                               ("gb18030", "中文😀"), ("gbk", "中文"), ("big5", "繁體"),
                               ("cp1252", "café"), ("shift_jis", "日本語"), ("latin-1", "café")]:
            with self.subTest(encoding=encoding):
                path = self.root / "encoded.txt"
                path.unlink(missing_ok=True)
                content = text + "\r\nold\nlast\rEND"
                result = self.call("fs_mutate", {"items": [{
                    "op": "file.create", "path": "encoded.txt", "content": content, "encoding": encoding,
                }]})
                self.assertEqual(200, result["status"], result)
                raw = content.encode(encoding)
                self.assertEqual(raw, path.read_bytes())
                read = self.call("fs_read", query={"path": ["encoded.txt"], "encoding": [encoding]})
                self.assertEqual(content, read["body"]["content"], read)
                batch = self.call("fs_read_many", {"paths": ["encoded.txt"], "encoding": encoding})
                self.assertEqual(content, batch["body"]["items"][0]["content"], batch)
                replaced = self.call("fs_mutate", {"items": [{
                    "op": "text.replace", "path": "encoded.txt", "encoding": encoding,
                    "expected_etag": self.etag("encoded.txt"),
                    "replacements": [{"old": "\r\nold\n", "new": "\r\nNEW\n", "expected_count": 1}],
                }]})
                self.assertEqual(200, replaced["status"], replaced)
                self.assertEqual(content.replace("old", "NEW").encode(encoding), path.read_bytes())
                replaced = self.call("fs_mutate", {"items": [{
                    "op": "text.replace", "path": "encoded.txt", "encoding": encoding,
                    "expected_etag": self.etag("encoded.txt"),
                    "replacements": [{"old": "NEW", "new": "updated", "expected_count": 1}],
                }]})
                self.assertEqual(200, replaced["status"], replaced)
                self.assertEqual(content.replace("old", "updated").encode(encoding), path.read_bytes())

    def test_invalid_encoding_is_strict_and_does_not_modify_files(self):
        path = self.root / "legacy.txt"
        path.write_bytes(b"caf\xe9\r\n")
        self.assertEqual(415, self.call("fs_read", query={"path": ["legacy.txt"]})["status"])
        etag = self.etag("legacy.txt")
        self.assertEqual(415, self.call("fs_mutate", {"items": [{
            "op": "text.replace", "path": "legacy.txt", "expected_etag": etag,
            "replacements": [{"old": "caf", "new": "new"}],
        }]})["status"])
        for encoding in ("utf-7", "not-a-codec", None):
            body = {"op": "file.replace", "path": "legacy.txt", "content": "new",
                    "expected_etag": etag, "encoding": encoding}
            self.assertEqual(400, self.call("fs_mutate", {"items": [body]})["status"])
        self.assertEqual(400, self.call("fs_mutate", {"items": [{
            "op": "file.replace", "path": "legacy.txt", "content": "😀",
            "encoding": "cp1252", "expected_etag": etag,
        }]})["status"])
        self.assertEqual(400, self.call("fs_mutate", {"items": [{
            "op": "text.replace", "path": "legacy.txt", "encoding": "cp1252",
            "expected_etag": etag,
            "replacements": [{"old": "caf", "new": "😀"}],
        }]})["status"])
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
        response = self.call("fs_mutate", {"items": [
            {"op": "text.replace", "path": "crlf.txt", "expected_etag": self.etag("crlf.txt"),
             "replacements": [{"old": "甲", "new": "新"}]},
            {"op": "text.replace", "path": "ascii.txt", "encoding": "ascii",
             "expected_etag": self.etag("ascii.txt"),
             "replacements": [{"old": "old", "new": "😀"}]},
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
            self.call("fs_mutate", {"items": [{"op": "file.create", "path": "no", "content": "no"}]})
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

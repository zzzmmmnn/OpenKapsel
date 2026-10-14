"""Portable high-level client filesystem RPC tests."""

import errno
import hashlib
import os
import tempfile
import time
import unittest
from unittest.mock import patch
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

    def read_one(self, path, **options):
        body = {"paths": [path], **options}
        result = self.call("fs_read_files", body)
        item = result.get("body", {}).get("items", [{}])[0]
        return {"status": item.get("status", result["status"]), "body": item}

    def etag(self, path):
        result = self.call("fs_stat", query={"path": [path], "fields": ["type,size,etag"]})
        self.assertEqual(200, result["status"], result)
        return result["body"]["etag"]

    @unittest.skipIf(os.name == "nt", "POSIX external directory paths")
    def test_rpc_session_external_root_retains_config_and_sandbox_denials(self):
        from types import SimpleNamespace
        import threading
        from openkapsel.client_runtime.client_rpc import ClientRpcSession

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            export, outside = base / "export", base / "outside"
            export.mkdir()
            outside.mkdir()
            config, denied = outside / "client.json", outside / "sandbox-secret.txt"
            config.write_text("CONFIDENTIAL CONFIG")
            denied.write_text("CONFIDENTIAL SANDBOX")
            (outside / "visible.txt").write_text("allowed data")
            files = ClientFiles(export, writable=True, protected_paths=(config,))
            files.sandbox_denied_paths = frozenset({denied})
            session = ClientRpcSession(
                SimpleNamespace(files=files), SimpleNamespace(), threading.Event()
            )
            try:
                self.assertIn(config, session.files.global_protected_paths)
                self.assertIn(denied, session.files.sandbox_denied_paths)
                result = session.files.dispatch("api_fs_list", {
                    "query": {"path": ["."]}, "body": {},
                    "display_root": str(outside), "external_root": str(outside),
                })
                self.assertEqual(200, result["status"], result)
                names = {entry["name"] for entry in result["body"]["entries"]}
                self.assertEqual({"visible.txt"}, names)
                result = session.files.dispatch("api_fs_read_files", {
                    "body": {"paths": ["client.json", "sandbox-secret.txt", "visible.txt"]},
                    "query": {}, "display_root": str(outside), "external_root": str(outside),
                })
                self.assertNotIn("CONFIDENTIAL CONFIG", str(result))
                self.assertNotIn("CONFIDENTIAL SANDBOX", str(result))
                self.assertIn("allowed data", str(result))
            finally:
                session.close()
                files.close()

    @unittest.skipIf(os.name == "nt", "POSIX client realpath approval protocol")
    def test_external_realpath_rpc_and_alias_recheck(self):
        with tempfile.TemporaryDirectory(prefix="kapsel-client-realpath-") as raw:
            base = Path(raw).resolve()
            actual, other = base / "actual", base / "other"
            actual.mkdir()
            other.mkdir()
            (actual / "visible.txt").write_text("VISIBLE", encoding="utf-8")
            (other / "secret.txt").write_text("PRIVATE", encoding="utf-8")
            alias = base / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            self.assertEqual(str(actual), self.files.dispatch(
                "resolve_path", {"path": str(alias), "directory": True}))
            self.assertEqual(str(actual / "new.txt"), self.files.dispatch(
                "resolve_path", {"path": str(alias / "new.txt")}))
            with self.assertRaises(OSError):
                self.files.dispatch("resolve_path", {"path": str(actual) + "/../other"})
            arguments = {
                "external_root": str(actual), "display_root": str(alias),
                "query": {}, "body": {"paths": ["visible.txt"]},
                "external_checks": [{
                    "original": str(alias / "visible.txt"),
                    "resolved": str(actual / "visible.txt"),
                }],
            }
            response = self.files.dispatch("api_fs_read_files", arguments)
            self.assertEqual(200, response["status"], response)
            self.assertIn("VISIBLE", str(response))
            alias.unlink()
            alias.symlink_to(other, target_is_directory=True)
            with self.assertRaises(OSError):
                self.files.dispatch("api_fs_read_files", arguments)
            self.assertEqual(str(other), self.files.dispatch(
                "resolve_path", {"path": str(alias), "directory": True}))

    @unittest.skipIf(os.name == "nt", "POSIX openat no-follow traversal")
    def test_descriptor_root_parent_symlink_swap_cannot_escape(self):
        from openkapsel.files.safe_paths import SafePathAccess, SafePathError

        with tempfile.TemporaryDirectory(prefix="kapsel-root-swap-") as raw:
            base = Path(raw).resolve()
            original, replacement = base / "original", base / "replacement"
            for path in (original / "approved", replacement / "approved"):
                path.mkdir(parents=True)
            (replacement / "approved" / "private.txt").write_text("SECRET")
            scoped_path = original / "approved"
            access = SafePathAccess((scoped_path,))
            original.rename(base / "original-old")
            original.symlink_to(replacement, target_is_directory=True)
            with self.assertRaises(SafePathError):
                fd = access.open(scoped_path / "private.txt", os.O_RDONLY)
                os.close(fd)

    def test_write_read_conditional_replace_and_native_paths_stay_private(self):
        content = "héllo " + str(self.root)
        self.assertEqual(201, self.call("fs_mkdir", {"path": "sub"})["status"])
        result = self.call("fs_mutate", {"items": [{
            "op": "file.create", "path": "sub/test.txt", "content": content,
        }]})
        self.assertEqual(200, result["status"], result)
        etag = result["body"]["items"][0]["etag"]
        result = self.read_one("sub/test.txt")
        self.assertEqual(content, result["body"]["content"])
        self.assertEqual("sub/test.txt", result["body"]["path"])
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
                read = self.read_one("encoded.txt", encoding=encoding)
                self.assertEqual(content, read["body"]["content"], read)
                batch = self.call("fs_read_files", {"paths": ["encoded.txt"], "encoding": encoding})
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
        self.assertEqual(415, self.read_one("legacy.txt")["status"])
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

    def test_crlf_character_cursors_and_batch_encode_preflight(self):
        path = self.root / "crlf.txt"
        path.write_bytes("甲\r\n乙\n".encode("utf-8"))
        first = self.read_one("crlf.txt", limit=2)["body"]
        self.assertEqual("甲\r", first["content"])
        second = self.read_one("crlf.txt", offset=first["next_offset"])["body"]
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
            result = self.read_one(value)
            self.assertGreaterEqual(result["status"], 400, result)
        self.files.writable = False
        with self.assertRaises(OSError) as error:
            self.call("fs_mutate", {"items": [{"op": "file.create", "path": "no", "content": "no"}]})
        self.assertEqual(errno.EROFS, error.exception.errno)
        self.assertEqual(200, self.call("fs_list", query={"path": ["."]})["status"])

    def test_read_files_budget_bounds_large_text_and_supports_continuation(self):
        (self.root / "large").write_bytes(b"x" * (1024 * 1024))
        result = self.read_one("large", limit=1024 * 1024)
        self.assertEqual(200, result["status"])
        self.assertTrue(result["body"]["truncated"])
        self.assertEqual(262144, result["body"]["next_offset"])
        continued = self.read_one("large", offset=result["body"]["next_offset"], limit=10)
        self.assertEqual(200, continued["status"])
        self.assertEqual(10, continued["body"]["length"])

    def test_read_many_limits_errors_and_confinement(self):
        (self.root / "a").write_text("abcdef", encoding="utf-8")
        (self.root / "binary").write_bytes(b"\xff")
        result = self.call("fs_read_files", {"paths": ["a", "missing", "binary", "../secret"], "limit": 3})
        self.assertEqual(207, result["status"], result)
        items = result["body"]["items"]
        self.assertEqual("abc", items[0]["content"])
        self.assertEqual(3, items[0]["next_offset"])
        self.assertEqual([200, 404, 415], [item["status"] for item in items[:3]])
        self.assertGreaterEqual(items[3]["status"], 400)
        result = self.call("fs_read_files", {"paths": ["a", "a"], "max_total_chars": 2})
        self.assertEqual(2, result["body"]["total_chars"])
        self.assertEqual("read_budget_exhausted", result["body"]["items"][1]["error"]["code"])
        for body in ({"paths": []}, {"paths": [1]}, {"paths": ["a"], "limit": True}):
            self.assertEqual(400, self.call("fs_read_files", body)["status"])

    def test_grep_globs_and_recursive_manifest(self):
        (self.root / "src").mkdir()
        (self.root / "node_modules").mkdir()
        for name in ("src/a.py", "src/a.txt", "node_modules/b.py"):
            (self.root / name).write_text("needle", encoding="utf-8")
        result = self.call("fs_grep", query={"path": ["."], "query": ["needle"], "include": ["*.py"], "exclude": ["node_modules"]})
        self.assertEqual(1, result["body"]["match_count"], result)
        self.assertTrue(result["body"]["matches"][0]["path"].endswith("src/a.py"))
        with self.assertRaises(OSError) as legacy:
            self.call(
                "fs_search",
                query={"path": ["src"], "query": ["needle"], "include": ["*.py"]},
            )
        self.assertEqual(errno.ENOSYS, legacy.exception.errno)
        result = self.call("fs_manifest", {"recursive": True, "path": "src", "depth": 1, "include_sha256": True})
        self.assertEqual(200, result["status"], result)
        self.assertEqual(3, result["body"]["total"])
        self.assertEqual(hashlib.sha256(b"needle").hexdigest(), result["body"]["items"][1]["sha256"])
        self.assertEqual(1, self.call("fs_manifest", {"recursive": True, "depth": 0})["body"]["total"])
        self.assertEqual(400, self.call("fs_manifest", {"recursive": True, "items": []})["status"])
        result = self.files.dispatch("api_fs_manifest", {"body": {"recursive": True}, "limits": {"max_tree_nodes": 2}})
        self.assertEqual(2, result["body"]["total"])
        self.assertTrue(result["body"]["truncated"])
        self.assertEqual(400, self.call("fs_grep", query={"query": ["x"], "include": [""]})["status"])
        result = self.call("fs_grep", query={"query": ["NEEDLE"], "case_sensitive": ["false"],
                                               "regex": ["true"], "include": ["src/*.py"]})
        self.assertEqual(1, result["body"]["match_count"])

    def test_grep_deadline_truncates_long_file_scan(self):
        from openkapsel.client_runtime.client_file_api import ClientFileAPI
        for n in range(35):
            (self.root / f"{n:03}.txt").write_text("needle")
        original = ClientFileAPI._open_binary
        def slow_open(handler, path):
            time.sleep(.014)
            return original(handler, path)
        with (patch.object(ClientFileAPI, "GREP_TIMEOUT_SECONDS", .055),
              patch.object(ClientFileAPI, "_open_binary", slow_open)):
            started = time.monotonic()
            result = self.call("fs_grep", query={"query": ["needle"],
                "max_results": ["100"]})
        self.assertEqual(200, result["status"], result)
        self.assertTrue(result["body"]["truncated"], result)
        self.assertLess(result["body"]["files_searched"], 35)
        self.assertLess(time.monotonic() - started, .5)

    def test_grep_deadline_stops_empty_directory_walk(self):
        from openkapsel.client_runtime.client_file_api import ClientFileAPI
        for n in range(35):
            (self.root / f"dir{n:03}").mkdir()
        original = ClientFileAPI._directory_entries
        def slow_entries(handler, path):
            time.sleep(.014)
            return original(handler, path)
        with (patch.object(ClientFileAPI, "GREP_TIMEOUT_SECONDS", .055),
              patch.object(ClientFileAPI, "_directory_entries", slow_entries)):
            started = time.monotonic()
            result = self.call("fs_grep", query={"query": ["not-found"],
                "depth": ["2"]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual(0, result["body"]["match_count"])
        self.assertTrue(result["body"]["truncated"], result)
        self.assertLess(time.monotonic() - started, .5)

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows developer mode")
    def test_symlinks_and_internal_files_are_not_exported(self):
        (self.root / "link").symlink_to(self.root.parent)
        (self.root / ".openkapsel").mkdir()
        (self.root / ".openkapsel/secret").write_text("secret")
        result = self.call("fs_tree", query={"path": ["."], "depth": ["2"]})
        self.assertEqual([], result["body"]["tree"]["children"])
        self.assertIn(self.read_one("link/private")["status"], {403, 409})

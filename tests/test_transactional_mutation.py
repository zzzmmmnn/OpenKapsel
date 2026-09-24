"""Transactional mutation and large-file range API tests."""

from __future__ import annotations

import base64
import errno
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.files.mutation import (
    LARGE_FILE_WINDOW_MAX_BYTES,
    STANDARD_FILE_MAX_BYTES,
)


class TransactionalMutationTests(unittest.TestCase):
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
        return self.files.dispatch(
            "api_" + operation,
            {
                "body": body or {},
                "query": query or {},
                "display_root": "/workspace/laptop",
            },
        )

    def etag(self, path):
        result = self.call(
            "fs_stat",
            query={"path": [path], "fields": ["type,size,etag"]},
        )
        self.assertEqual(200, result["status"], result)
        return result["body"]["etag"]

    def test_multi_file_exact_mutation_commits_together(self):
        (self.root / "a.py").write_text("old A\n", encoding="utf-8")
        (self.root / "b.py").write_text("old B old B\n", encoding="utf-8")
        result = self.call(
            "fs_mutate",
            {
                "items": [
                    {
                        "op": "text.replace",
                        "path": "a.py",
                        "expected_etag": self.etag("a.py"),
                        "replacements": [
                            {"old": "old A", "new": "new A", "expected_count": 1}
                        ],
                    },
                    {
                        "op": "text.replace",
                        "path": "b.py",
                        "expected_etag": self.etag("b.py"),
                        "replacements": [
                            {"old": "old B", "new": "new B", "expected_count": 2}
                        ],
                    },
                ]
            },
        )
        self.assertEqual(200, result["status"], result)
        self.assertTrue(result["body"]["committed"])
        self.assertEqual(2, result["body"]["changed"])
        self.assertEqual("new A\n", (self.root / "a.py").read_text(encoding="utf-8"))
        self.assertEqual("new B new B\n", (self.root / "b.py").read_text(encoding="utf-8"))
        self.assertFalse(list(self.root.glob(".*.openkapsel-*")))

    def test_preflight_failure_changes_nothing(self):
        (self.root / "a.py").write_text("old A\n", encoding="utf-8")
        (self.root / "b.py").write_text("old B\n", encoding="utf-8")
        before_a = (self.root / "a.py").read_bytes()
        before_b = (self.root / "b.py").read_bytes()
        result = self.call(
            "fs_mutate",
            {
                "items": [
                    {
                        "op": "text.replace",
                        "path": "a.py",
                        "expected_etag": self.etag("a.py"),
                        "replacements": [
                            {"old": "old A", "new": "new A", "expected_count": 1}
                        ],
                    },
                    {
                        "op": "text.replace",
                        "path": "b.py",
                        "expected_etag": self.etag("b.py"),
                        "replacements": [
                            {"old": "old B", "new": "new B", "expected_count": 2}
                        ],
                    },
                ]
            },
        )
        self.assertEqual(409, result["status"], result)
        self.assertEqual(before_a, (self.root / "a.py").read_bytes())
        self.assertEqual(before_b, (self.root / "b.py").read_bytes())
        self.assertFalse(list(self.root.glob(".*.openkapsel-*")))

    def test_stale_etag_changes_nothing(self):
        (self.root / "a").write_text("old A", encoding="utf-8")
        (self.root / "b").write_text("old B", encoding="utf-8")
        etag_a = self.etag("a")
        stale_b = self.etag("b")
        (self.root / "b").write_text("someone else", encoding="utf-8")
        before_a = (self.root / "a").read_bytes()
        before_b = (self.root / "b").read_bytes()
        result = self.call(
            "fs_mutate",
            {
                "items": [
                    {
                        "op": "text.replace",
                        "path": "a",
                        "expected_etag": etag_a,
                        "replacements": [{"old": "old A", "new": "new A"}],
                    },
                    {
                        "op": "text.replace",
                        "path": "b",
                        "expected_etag": stale_b,
                        "replacements": [{"old": "old B", "new": "new B"}],
                    },
                ]
            },
        )
        self.assertIn(result["status"], {409, 412}, result)
        self.assertEqual(before_a, (self.root / "a").read_bytes())
        self.assertEqual(before_b, (self.root / "b").read_bytes())

    def test_commit_failure_rolls_back_already_published_files(self):
        (self.root / "a").write_text("old A", encoding="utf-8")
        (self.root / "b").write_text("old B", encoding="utf-8")
        body = {
            "items": [
                {
                    "op": "text.replace",
                    "path": "a",
                    "expected_etag": self.etag("a"),
                    "replacements": [{"old": "old A", "new": "new A"}],
                },
                {
                    "op": "text.replace",
                    "path": "b",
                    "expected_etag": self.etag("b"),
                    "replacements": [{"old": "old B", "new": "new B"}],
                },
            ]
        }
        original = self.files.paths.rename
        calls = 0

        def flaky(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError(errno.EIO, "injected commit failure")
            return original(*args, **kwargs)

        with patch.object(self.files.paths, "rename", side_effect=flaky):
            result = self.call("fs_mutate", body)
        self.assertGreaterEqual(result["status"], 400, result)
        self.assertEqual("old A", (self.root / "a").read_text())
        self.assertEqual("old B", (self.root / "b").read_text())
        self.assertFalse(list(self.root.glob(".*.openkapsel-*")))

    def test_rollback_refuses_to_overwrite_concurrent_external_change(self):
        (self.root / "a").write_text("old A", encoding="utf-8")
        (self.root / "b").write_text("old B", encoding="utf-8")
        body = {
            "items": [
                {
                    "op": "text.replace",
                    "path": "a",
                    "expected_etag": self.etag("a"),
                    "replacements": [{"old": "old A", "new": "new A"}],
                },
                {
                    "op": "text.replace",
                    "path": "b",
                    "expected_etag": self.etag("b"),
                    "replacements": [{"old": "old B", "new": "new B"}],
                },
            ]
        }
        original = self.files.paths.rename
        calls = 0

        def race_then_fail(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                (self.root / "a").write_text("external", encoding="utf-8")
                raise OSError(errno.EIO, "injected failure after external writer")
            return original(*args, **kwargs)

        with patch.object(self.files.paths, "rename", side_effect=race_then_fail):
            result = self.call("fs_mutate", body)
        self.assertEqual(500, result["status"], result)
        self.assertEqual("mutation_rollback_failed", result["error"]["code"])
        self.assertEqual("external", (self.root / "a").read_text())
        self.assertEqual("old B", (self.root / "b").read_text())
        self.assertTrue(list(self.root.glob(".*.openkapsel-transfer-txn-*")))

    def test_create_replace_structured_patch_and_dry_run(self):
        (self.root / "whole.txt").write_text("before", encoding="utf-8")
        (self.root / "config.json").write_text(
            '{"server":{"port":8000},"enabled":true}\n',
            encoding="utf-8",
        )
        body = {
            "items": [
                {
                    "op": "file.create",
                    "path": "new.txt",
                    "content": "created\n",
                },
                {
                    "op": "file.replace",
                    "path": "whole.txt",
                    "expected_etag": self.etag("whole.txt"),
                    "content": "after",
                },
                {
                    "op": "structured.patch",
                    "path": "config.json",
                    "expected_etag": self.etag("config.json"),
                    "operations": [
                        {"op": "test", "path": "/server/port", "value": 8000},
                        {"op": "replace", "path": "/server/port", "value": 9000},
                        {"op": "remove", "path": "/enabled"},
                    ],
                },
            ],
            "dry_run": True,
        }
        preview = self.call("fs_mutate", body)
        self.assertEqual(200, preview["status"], preview)
        self.assertFalse(preview["body"]["committed"])
        self.assertFalse((self.root / "new.txt").exists())
        self.assertEqual("before", (self.root / "whole.txt").read_text())
        self.assertIn('"port":8000', (self.root / "config.json").read_text())

        body["dry_run"] = False
        committed = self.call("fs_mutate", body)
        self.assertEqual(200, committed["status"], committed)
        self.assertEqual("created\n", (self.root / "new.txt").read_text())
        self.assertEqual("after", (self.root / "whole.txt").read_text())
        config = (self.root / "config.json").read_text()
        self.assertIn('"port":9000', config)
        self.assertNotIn('"enabled"', config)

    def test_search_returns_etag_for_direct_mutation(self):
        (self.root / "a.py").write_text("needle\n", encoding="utf-8")
        result = self.call(
            "fs_search",
            query={"path": ["."], "query": ["needle"]},
        )
        self.assertEqual(200, result["status"], result)
        match = result["body"]["matches"][0]
        self.assertEqual(self.etag("a.py"), match["etag"])
        self.assertEqual(len(b"needle\n"), match["size"])

    def make_large(self, name="large.bin"):
        path = self.root / name
        with path.open("wb") as handle:
            handle.write(b"0123456789abcdef")
            handle.truncate(STANDARD_FILE_MAX_BYTES + 1)
        return path

    def test_large_file_rejected_by_ordinary_content_apis(self):
        self.make_large()
        for operation, body, query in (
            ("fs_read", None, {"path": ["large.bin"], "limit": ["16"]}),
            (
                "fs_mutate",
                {
                    "items": [
                        {
                            "op": "file.replace",
                            "path": "large.bin",
                            "expected_etag": self.etag("large.bin"),
                            "content": "small",
                        }
                    ]
                },
                None,
            ),
        ):
            with self.subTest(operation=operation):
                result = self.call(operation, body, query)
                self.assertEqual(413, result["status"], result)
                self.assertEqual("large_file_api_required", result["error"]["code"])

    def test_delete_is_transactional_recoverable_and_allows_large_paths(self):
        (self.root / "victim.txt").write_text("remove me", encoding="utf-8")
        (self.root / "folder").mkdir()
        (self.root / "folder/child.txt").write_text("child", encoding="utf-8")
        self.make_large("large-delete.bin")
        result = self.call("fs_mutate", {"items": [
            {"op": "path.delete", "path": "victim.txt", "expected_etag": self.etag("victim.txt")},
            {"op": "path.delete", "path": "folder", "expected_etag": self.etag("folder")},
            {"op": "path.delete", "path": "large-delete.bin", "expected_etag": self.etag("large-delete.bin")},
        ]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual(3, result["body"]["changed"])
        for item in result["body"]["items"]:
            self.assertTrue(item["deleted"])
            self.assertTrue(item["recycled"])
            self.assertIsInstance(item["recycle_id"], str)
        self.assertFalse((self.root / "victim.txt").exists())
        self.assertFalse((self.root / "folder").exists())
        self.assertFalse((self.root / "large-delete.bin").exists())

        for item in result["body"]["items"]:
            restored = self.files.dispatch("recycle_restore", {"recycle_id": item["recycle_id"]})
            self.assertTrue(restored["restored"])
        self.assertEqual("remove me", (self.root / "victim.txt").read_text(encoding="utf-8"))
        self.assertEqual("child", (self.root / "folder/child.txt").read_text(encoding="utf-8"))
        self.assertGreater((self.root / "large-delete.bin").stat().st_size, STANDARD_FILE_MAX_BYTES)

    def test_delete_recycle_failure_rolls_back_prior_recycled_paths(self):
        from openkapsel.files.recycle import RecycleBin

        (self.root / "a.txt").write_text("A", encoding="utf-8")
        (self.root / "b.txt").write_text("B", encoding="utf-8")
        body = {"items": [
            {"op": "path.delete", "path": "a.txt", "expected_etag": self.etag("a.txt")},
            {"op": "path.delete", "path": "b.txt", "expected_etag": self.etag("b.txt")},
        ]}
        original = RecycleBin.recycle
        calls = 0

        def flaky(recycle, path, *, original_path=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, "injected recycle failure")
            return original(recycle, path, original_path=original_path)

        with patch.object(RecycleBin, "recycle", autospec=True, side_effect=flaky):
            result = self.call("fs_mutate", body)

        self.assertGreaterEqual(result["status"], 400, result)
        self.assertEqual("A", (self.root / "a.txt").read_text(encoding="utf-8"))
        self.assertEqual("B", (self.root / "b.txt").read_text(encoding="utf-8"))
        self.assertFalse(list(self.root.glob(".*.openkapsel-transfer-txn-*")))
        listing = self.files.dispatch("recycle_list", {"offset": 0, "limit": 100})
        self.assertEqual(0, listing["total"], listing)

    def test_delete_stale_etag_and_overlapping_paths_change_nothing(self):
        (self.root / "folder").mkdir()
        (self.root / "folder/child.txt").write_text("old", encoding="utf-8")
        stale = self.etag("folder/child.txt")
        (self.root / "folder/child.txt").write_text("new", encoding="utf-8")
        result = self.call("fs_mutate", {"items": [{
            "op": "path.delete", "path": "folder/child.txt", "expected_etag": stale,
        }]})
        self.assertIn(result["status"], {409, 412}, result)
        self.assertTrue((self.root / "folder/child.txt").exists())

        result = self.call("fs_mutate", {"items": [
            {"op": "path.delete", "path": "folder", "expected_etag": self.etag("folder")},
            {"op": "text.replace", "path": "folder/child.txt", "expected_etag": self.etag("folder/child.txt"),
             "replacements": [{"old": "new", "new": "changed"}]},
        ]})
        self.assertEqual(400, result["status"], result)
        self.assertEqual("new", (self.root / "folder/child.txt").read_text(encoding="utf-8"))

    def test_large_file_range_read_and_equal_length_replace(self):
        path = self.make_large()
        read = self.call(
            "fs_read_large",
            {"path": "large.bin", "offset": 4, "length": 6},
        )
        self.assertEqual(200, read["status"], read)
        body = read["body"]
        self.assertEqual(b"456789", base64.b64decode(body["data_base64"]))
        self.assertEqual(hashlib.sha256(b"456789").hexdigest(), body["range_sha256"])
        original_size = path.stat().st_size

        replaced = self.call(
            "fs_replace_large",
            {
                "path": "large.bin",
                "offset": 4,
                "length": 6,
                "data_base64": base64.b64encode(b"ABCDEF").decode("ascii"),
                "expected_etag": body["etag"],
                "expected_range_sha256": body["range_sha256"],
            },
        )
        self.assertEqual(200, replaced["status"], replaced)
        self.assertEqual(original_size, path.stat().st_size)
        with path.open("rb") as handle:
            self.assertEqual(b"0123ABCDEFabcdef"[0:16], handle.read(16))

        current = self.call(
            "fs_read_large",
            {"path": "large.bin", "offset": 4, "length": 6},
        )["body"]
        with path.open("rb") as handle:
            before = handle.read(16)
        bad_hash = self.call(
            "fs_replace_large",
            {
                "path": "large.bin",
                "offset": 4,
                "length": 6,
                "data_base64": base64.b64encode(b"UVWXYZ").decode("ascii"),
                "expected_etag": current["etag"],
                "expected_range_sha256": "0" * 64,
            },
        )
        self.assertEqual(409, bad_hash["status"], bad_hash)
        with path.open("rb") as handle:
            self.assertEqual(before, handle.read(16))

        wrong_length = self.call(
            "fs_replace_large",
            {
                "path": "large.bin",
                "offset": 4,
                "length": 6,
                "data_base64": base64.b64encode(b"short").decode("ascii"),
                "expected_etag": current["etag"],
                "expected_range_sha256": current["range_sha256"],
            },
        )
        self.assertEqual(400, wrong_length["status"], wrong_length)
        self.assertEqual(original_size, path.stat().st_size)

    def test_large_file_api_requires_large_file_and_bounded_window(self):
        (self.root / "small.bin").write_bytes(b"abc")
        result = self.call(
            "fs_read_large",
            {"path": "small.bin", "offset": 0, "length": 3},
        )
        self.assertEqual(400, result["status"], result)
        self.assertEqual("large_file_required", result["error"]["code"])
        self.make_large()
        result = self.call(
            "fs_read_large",
            {
                "path": "large.bin",
                "offset": 0,
                "length": LARGE_FILE_WINDOW_MAX_BYTES + 1,
            },
        )
        self.assertEqual(400, result["status"], result)


if __name__ == "__main__":
    unittest.main()

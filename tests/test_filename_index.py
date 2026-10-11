"""Shared Server/Client SQLite filename index, scope, glob and incremental refresh."""
from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
import types
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_file_api import ClientFileAPI
from openkapsel.files.file_handlers import FileHandlersMixin
from openkapsel.files.filename_index import (
    FilenameIndex, _Statx, _linux_statx, private_database,
)
from openkapsel.rpc_plugins.file_search import plugin


class SharedFilenameIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.src = self.root / "src"
        self.src.mkdir()
        for name in ("test1.py", "testA.py", "test12.py", "Alpha%_.md"):
            (self.src / name).write_text(name)
        (self.root / ".openkapsel").mkdir()
        (self.root / ".openkapsel" / "private.py").write_text("hidden")
        (self.src / "link.py").symlink_to(self.src / "test1.py")
        self.index = FilenameIndex(self.root, self.base / "state" / "index.sqlite3")
        self.addCleanup(self.index.close)
        self.index.rebuild()
        self.index._ready.set()

    def search(self, query, *, glob=False, scope=None, **kwargs):
        return self.index.search(
            scope or self.root, query, glob=glob, **kwargs
        )

    def test_metadata_size_utc_nanoseconds_and_incremental_refresh(self):
        file = self.src / "test1.py"
        timestamp_ns = 1_700_000_000_123_456_789
        os.utime(file, ns=(timestamp_ns, timestamp_ns))
        self.index.apply({(2, str(file))})
        with self.index._db:
            row = self.index._db.execute(
                "SELECT created_utc_ns,modified_utc_ns,size_bytes FROM entries WHERE path=?",
                ("src/test1.py",),
            ).fetchone()
        self.assertEqual(timestamp_ns, row[1])
        self.assertEqual(len("test1.py"), row[2])
        if row[0] is not None:
            self.assertIsInstance(row[0], int)
            self.assertGreater(row[0], 0)

        file.write_text("now has more bytes")
        self.index.apply({(2, str(file))})
        updated = self.index._db.execute(
            "SELECT modified_utc_ns,size_bytes FROM entries WHERE path=?",
            ("src/test1.py",),
        ).fetchone()
        self.assertEqual(file.stat().st_mtime_ns, updated[0])
        self.assertEqual(len("now has more bytes"), updated[1])

    def test_linux_statx_real_birth_time_without_ctime_substitution(self):
        def fake_statx(_dirfd, _path, _flags, mask, pointer):
            result = ctypes.cast(pointer, ctypes.POINTER(_Statx)).contents
            result.mask = mask
            result.dev_major = 8
            result.dev_minor = 1
            result.mode = 0o100644
            result.size = 4321
            result.mtime.seconds = 1_700_000_000
            result.mtime.nanoseconds = 1234
            result.btime.seconds = 1_600_000_000
            result.btime.nanoseconds = 5678
            return 0

        with patch("openkapsel.files.filename_index._statx_function",
                   return_value=fake_statx):
            device, mode, size, modified, created = _linux_statx(self.src)
        self.assertEqual(os.makedev(8, 1), device)
        self.assertEqual(0o100644, mode)
        self.assertEqual(4321, size)
        self.assertEqual(1_700_000_000_000_001_234, modified)
        self.assertEqual(1_600_000_000_000_005_678, created)

        def fake_without_birth(_dirfd, _path, _flags, mask, pointer):
            result = ctypes.cast(pointer, ctypes.POINTER(_Statx)).contents
            result.mask = mask & ~0x0800
            result.mtime.seconds = 1_700_000_000
            return 0

        with patch("openkapsel.files.filename_index._statx_function",
                   return_value=fake_without_birth):
            self.assertIsNone(_linux_statx(self.src)[4])

    def test_windows_creation_timestamp_uses_birth_or_legacy_ctime_not_posix(self):
        from openkapsel.files.filename_index import _metadata
        from openkapsel.files.find_order import stat_item
        info = SimpleNamespace(
            st_dev=1, st_mode=0o100644, st_size=9,
            st_mtime_ns=1_800_000_000_123_456_789,
            st_ctime_ns=1_700_000_000_111_111_111,
        )
        with patch("openkapsel.files.filename_index._linux_statx",
                   return_value=None), patch(
            "openkapsel.files.filename_index.os", SimpleNamespace(name="nt")
        ), patch.object(Path, "lstat", return_value=info):
            self.assertEqual(
                (1, 0o100644, 9, info.st_mtime_ns, info.st_ctime_ns),
                _metadata(self.root / "legacy.txt"),
            )
        with patch("openkapsel.files.find_order.os",
                   SimpleNamespace(name="nt")):
            self.assertEqual(info.st_ctime_ns,
                             stat_item("legacy.txt", "file", info)["created_utc_ns"])
        # When st_birthtime_ns is provided, prefer it to legacy st_ctime.
        info.st_birthtime_ns = 1_650_000_000_000_000_000
        with patch("openkapsel.files.filename_index._linux_statx",
                   return_value=None), patch(
            "openkapsel.files.filename_index.os", SimpleNamespace(name="nt")
        ), patch.object(Path, "lstat", return_value=info):
            self.assertEqual(info.st_birthtime_ns, _metadata(self.root)[4])

    def test_windows_junction_and_private_names_are_never_indexed(self):
        from openkapsel.files import filename_index as module
        (self.root / "reparse").mkdir()
        (self.root / "reparse" / "hidden.txt").write_text("hidden")
        (self.root / ".RECYCLE").mkdir()
        (self.root / ".RECYCLE" / "secret.txt").write_text("secret")
        original_lstat = Path.lstat
        def fake_lstat(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if path.name == "reparse":
                return SimpleNamespace(
                    st_file_attributes=0x400, st_dev=info.st_dev,
                    st_mode=info.st_mode, st_size=info.st_size,
                    st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns,
                )
            return info
        with patch("openkapsel.files.filename_index.os",
                   SimpleNamespace(name="nt", scandir=os.scandir)), patch.object(
            Path, "lstat", side_effect=fake_lstat, autospec=True
        ):
            names = [row[0] for row in self.index._entries(self.index.root)]
        self.assertNotIn("reparse", names)
        self.assertNotIn("reparse/hidden.txt", names)
        self.assertNotIn(".RECYCLE", names)
        self.assertNotIn(".RECYCLE/secret.txt", names)

    def test_private_database_is_outside_the_export(self):
        self.assertEqual(0o600, self.index.database.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.index.database.parent.stat().st_mode & 0o777)
        with self.assertRaises(ValueError):
            private_database(self.root, self.root / "index.sqlite3")

    def test_literal_and_glob_semantics(self):
        self.assertEqual(3, self.search("test")["result_count"])
        self.assertEqual(2, self.search("test?.py", glob=True)["result_count"])
        self.assertEqual(1, self.search("test[0-9].py", glob=True)["result_count"])
        self.assertEqual(3, self.search("*.py", glob=True)["result_count"])
        self.assertEqual(1, self.search("alpha%_", case_sensitive=False)["result_count"])
        self.assertEqual(0, self.search("alpha%_", case_sensitive=True)["result_count"])
        self.assertEqual(1, self.search("Alpha%_", case_sensitive=True)["result_count"])
        self.assertEqual(0, self.search("private.py")["result_count"])
        self.assertEqual(0, self.search("link.py")["result_count"])

    def test_scope_pagination_and_deleted_files(self):
        self.assertEqual(0, self.search("*.py", glob=True, scope=self.src / "missing")["result_count"])
        page = self.search("*.py", glob=True, scope=self.src, limit=1)
        self.assertTrue(page["truncated"])
        self.assertEqual(1, len(page["results"]))
        self.assertNotEqual(page["results"], self.search("*.py", glob=True, scope=self.src, offset=1, limit=1)["results"])
        removed = self.src / "test1.py"
        removed.unlink()
        self.index.apply({(3, str(removed))})
        self.assertEqual(2, self.search("test")["result_count"])
        added = self.src / "new.py"
        added.write_text("new")
        self.index.apply({(1, str(added))})
        self.assertEqual(3, self.search("*.py", glob=True)["result_count"])

    def test_directory_move_reindexes_children(self):
        destination = self.root / "renamed"
        self.src.rename(destination)
        self.index.apply({(3, str(self.src)), (1, str(destination))})
        matches = self.search("test")
        self.assertEqual(3, matches["result_count"])
        self.assertTrue(all(item["path"].startswith("renamed/") for item in matches["results"]))

    def test_indexed_server_excludes_registered_mapping_and_storage_roots(self):
        native = self.root / "native-newest.txt"
        mapped = self.root / "remote-map"
        cloud = self.root / "cloud-drive"
        mapped.mkdir()
        cloud.mkdir()
        native.write_text("native")
        (mapped / "newest-mapped.txt").write_text("remote")
        (cloud / "newest-cloud.txt").write_text("cloud")
        for path, timestamp in (
            (native, 2_000_000_001), (mapped / "newest-mapped.txt", 2_000_000_004),
            (cloud / "newest-cloud.txt", 2_000_000_005),
        ):
            os.utime(path, (timestamp, timestamp))
        self.index.rebuild()
        # All three roots are physically on the same device. Filtering must
        # be by registered mount boundaries rather than st_dev alone.
        manager = SimpleNamespace(
            store=SimpleNamespace(list=lambda: [{"id": "mapped"}]),
            mount_path=lambda row: mapped,
        )
        storage = SimpleNamespace(
            store=SimpleNamespace(mappings=lambda: [{"id": "cloud"}]),
            mapping_path=lambda row: cloud,
        )
        class NativeServerFind(FileHandlersMixin):
            def __init__(self, root, index):
                self.root = root
                self.server = SimpleNamespace(filename_index=index, mappings=manager,
                                              storage_providers=storage)
            def _resolve_path(self, path):
                return self.root / path
            def _file_stat(self, path):
                return path.lstat()
            @staticmethod
            def _is_hidden_internal_path(_parent, _candidate):
                return False

        handler = NativeServerFind(self.root, self.index)
        top = handler._try_indexed_find(
            query="*", path=".", max_results=5,
            case_sensitive=False, timeout_seconds=5,
            mode="glob", sort_by="modified", sort_order="desc",
            file_type="file",
        )
        self.assertIn("native-newest.txt", [Path(x["path"]).name for x in top["results"]])
        self.assertFalse(any(
            "remote-map" in x["path"] or "cloud-drive" in x["path"]
            for x in top["results"]
        ))
        direct = handler._try_indexed_find(
            query="*", path="remote-map", max_results=5,
            case_sensitive=False, timeout_seconds=5,
            mode="glob", sort_by="modified", sort_order="desc",
            file_type="file",
        )
        self.assertIsNone(direct)  # explicitly scoped remote search uses its own backend
        sql = (
            "SELECT e.path FROM entries e WHERE 1=1 AND e.kind=? "
            "AND e.path != ? AND NOT (e.path >= ? AND e.path < ?) "
            "ORDER BY e.modified_utc_ns DESC,e.path DESC LIMIT 11"
        )
        plan = list(self.index._db.execute("EXPLAIN QUERY PLAN " + sql,
                   ("file", "remote-map", "remote-map/", "remote-map/􏿿")))
        self.assertTrue(any("entries_modified_order" in row[3] for row in plan))

    def test_native_server_and_client_file_find_use_same_semantics(self):
        class ServerFind(FileHandlersMixin):
            def __init__(self, root, index):
                self.server = SimpleNamespace(filename_index=index, mappings=None,
                                              storage_providers=None)
                self.root = root

            def _resolve_path(self, path):
                return self.root / path

            def _file_stat(self, path):
                return path.lstat()

            @staticmethod
            def _is_hidden_internal_path(_parent, _candidate):
                return False

        handler = ServerFind(self.root, self.index)
        native = handler._try_indexed_find(
            query="test?.py", path="src", max_results=100,
            case_sensitive=False, timeout_seconds=5, mode="glob"
        )
        self.assertEqual(2, native["result_count"])
        files = ClientFiles(self.root, rpc_registry=object(),
                            rpc_capabilities={"file_search": {"state": "unsupported"}})
        portable = ClientFileAPI.dispatch(
            files, "fs_find",
            {"query": {"query": ["test?.py"], "mode": ["glob"], "path": ["src"]}},
        )
        self.assertEqual(200, portable["status"], portable)
        self.assertEqual(2, portable["body"]["result_count"])

    def test_background_watcher_replays_later_changes(self):
        gate = threading.Event()
        new_file = self.src / "arriving.txt"
        watcher_options = {}

        def fake_watch(_root, *, stop_event, **kwargs):
            watcher_options.update(kwargs)
            yield set()  # first timeout proves watch registration
            gate.wait(timeout=3)
            if not stop_event.is_set():
                yield {(1, str(new_file))}
            while not stop_event.is_set():
                stop_event.wait(0.02)
                yield set()

        self.index._ready.clear()
        fake_module = types.SimpleNamespace(watch=fake_watch)
        with patch.dict(sys.modules, {"watchfiles": fake_module}):
            with patch("openkapsel.files.filename_index.watcher_available", return_value=True):
                self.assertTrue(self.index.start())
            deadline = time.monotonic() + 4
            while not self.index.ready and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(self.index.ready, "initial scan did not become ready")
            self.assertIs(watcher_options.get("ignore_permission_denied"), True)
            new_file.write_text("new")
            gate.set()
            deadline = time.monotonic() + 4
            while self.search("arriving")["result_count"] == 0 and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(1, self.search("arriving")["result_count"])

    def test_rpc_filters_private_scope_and_supports_glob(self):
        files = ClientFiles(self.root, rpc_registry=object(), rpc_capabilities={"stub": {}})
        files.filename_index = self.index
        files._index_owned = False
        result = plugin.dispatch(files, "search", {
            "query": "test?.py", "mode": "glob", "path": "src"
        })
        self.assertEqual(200, result["status"], result)
        self.assertEqual(2, result["body"]["returned"])
        self.assertTrue(all(item["path"].startswith("src/") for item in result["body"]["results"]))
        with self.assertRaises(ValueError):
            private_database(self.root, self.src / "bad.db")


if __name__ == "__main__":
    unittest.main()

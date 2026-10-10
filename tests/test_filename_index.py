"""Shared Server/Client SQLite filename index, scope, glob and incremental refresh."""
from __future__ import annotations

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
from openkapsel.files.filename_index import FilenameIndex, private_database
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

        def fake_watch(_root, *, stop_event, **kwargs):
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

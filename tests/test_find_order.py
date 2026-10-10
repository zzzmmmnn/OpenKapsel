"""Top-N search ordering across indexed, native and recursive file backends."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_file_api import ClientFileAPI
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.files.find_order import TopResults
from openkapsel.files.filename_index import FilenameIndex
from openkapsel.rpc_plugins.file_search import plugin


class TopResultsTests(unittest.TestCase):
    def test_top_n_matches_complete_global_sort(self):
        rows = [{"path": f"dir/f{i:02}.py", "type": "file",
                 "size_bytes": (i * 13) % 17,
                 "modified_utc_ns": 1_700_000_000_000_000_000 + i * 10}
                for i in range(80)]
        for field in ("name", "path", "size", "modified"):
            for order in ("asc", "desc"):
                rank = TopResults(10, field, order)
                for item in rows:
                    rank.add(item)
                from openkapsel.files.find_order import sort_key
                expected = sorted(rows, key=lambda x: sort_key(x, field),
                                  reverse=order == "desc")[:10]
                self.assertEqual(expected, rank.results(), (field, order))
                self.assertTrue(rank.truncated)


class SortableFindTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "workspace"
        self.root.mkdir()
        self.src = self.root / "src"
        self.src.mkdir()
        for i in range(25):
            path = self.src / f"doc{i:02}.txt"
            path.write_bytes(b"x" * (i + 1))
            changed = (1_700_000_000 + i) * 1_000_000_000
            os.utime(path, ns=(changed, changed))
        (self.src / "nested").mkdir()
        self.index = FilenameIndex(self.root, self.root.parent / "private" / "db.sqlite3")
        self.addCleanup(self.index.close)
        self.index.rebuild()
        self.index._ready.set()

    def test_default_limit_is_fifty_explicit_limit_can_reach_thousand(self):
        # Test both public fs_find and client file_search RPC defaults and caps.
        for i in range(25, 80):
            file = self.src / f"doc{i:02}.txt"
            file.write_text("x")
        self.index.rebuild()
        files = ClientFiles(self.root, rpc_registry=object(),
                            rpc_capabilities={"dummy": {}})
        files.filename_index = self.index
        files._index_owned = False

        direct = ClientFileAPI.dispatch(files, "fs_find", {"query": {}})
        self.assertEqual(200, direct["status"], direct)
        self.assertEqual(50, direct["body"]["max_results"])
        self.assertEqual(50, len(direct["body"]["results"]))
        self.assertTrue(direct["body"]["truncated"])

        requested = ClientFileAPI.dispatch(files, "fs_find", {
            "query": {"max_results": ["75"]}
        })
        self.assertEqual(200, requested["status"], requested)
        self.assertEqual(75, requested["body"]["result_count"])
        self.assertEqual(75, requested["body"]["max_results"])

        over = ClientFileAPI.dispatch(files, "fs_find", {
            "query": {"max_results": ["1001"]}
        })
        self.assertEqual(400, over["status"], over)

        default_rpc = plugin.dispatch(files, "search", {})
        self.assertEqual(200, default_rpc["status"], default_rpc)
        self.assertEqual(50, len(default_rpc["body"]["results"]))
        self.assertTrue(default_rpc["body"]["truncated"])

        explicit_rpc = plugin.dispatch(files, "search", {"limit": 1000})
        self.assertEqual(200, explicit_rpc["status"], explicit_rpc)
        self.assertEqual(82, len(explicit_rpc["body"]["results"]))
        over_rpc = plugin.dispatch(files, "search", {"limit": 1001})
        self.assertEqual(400, over_rpc["status"], over_rpc)

    def test_sqlite_newest_ten_files_are_global_top_ten(self):
        rows = self.index.search(self.root, "*", glob=True,
                                 sort_by="modified", sort_order="desc",
                                 file_type="file", limit=10)
        self.assertEqual([f"src/doc{i:02}.txt" for i in range(24, 14, -1)],
                         [item["path"] for item in rows["results"]])
        self.assertTrue(rows["truncated"])
        self.assertEqual(10, rows["result_count"])
        self.assertTrue(all("modified_utc_ns" in item and "size_bytes" in item
                            for item in rows["results"]))

    def test_sqlite_name_path_size_and_reverse(self):
        for field, order, first in [
            ("size", "asc", "doc00.txt"),
            ("size", "desc", "doc24.txt"),
            ("name", "desc", "doc24.txt"),
            ("path", "asc", "doc00.txt"),
            ("modified", "asc", "doc00.txt"),
        ]:
            result = self.index.search(self.root, "*.txt", glob=True,
                                       sort_by=field, sort_order=order,
                                       file_type="file", limit=1)
            self.assertEqual(first, Path(result["results"][0]["path"]).name,
                             (field, order))

    def test_recursive_top_n_compares_every_file_and_excludes_directories(self):
        files = ClientFiles(self.root, rpc_registry=object(), rpc_capabilities={"dummy": {}})
        # Without a client index this takes the recursive path.
        payload = ClientFileAPI.dispatch(files, "fs_find", {
            "query": {"sort_by": ["modified"], "sort_order": ["desc"],
                      "file_type": ["file"], "max_results": ["10"]}
        })
        self.assertEqual(200, payload["status"], payload)
        rows = payload["body"]["results"]
        self.assertEqual([f"doc{i:02}.txt" for i in range(24, 14, -1)],
                         [Path(item["path"]).name for item in rows])
        self.assertEqual(10, payload["body"]["result_count"])
        self.assertTrue(payload["body"]["truncated"])

    def test_everything_ipc_native_modified_sort_fetches_only_top_n_plus_one(self):
        files = ClientFiles(self.root, rpc_registry=object(),
                            rpc_capabilities={"dummy": {}})
        examined = []
        def sorted_candidates(_scope, _query, **kwargs):
            self.assertEqual("modified", kwargs["sort_by"])
            self.assertEqual("desc", kwargs["sort_order"])
            self.assertEqual(11, kwargs["batch_size"])
            for i in range(24, -1, -1):
                examined.append(i)
                yield str(self.src / f"doc{i:02}.txt")

        with patch("openkapsel.rpc_plugins.file_search._platform_backend",
                   return_value=("everything_ipc", None)), patch(
            "openkapsel.rpc_plugins.file_search.everything_ipc.query_paths",
            side_effect=sorted_candidates,
        ):
            response = plugin.dispatch(files, "search", {
                "sort_by": "modified", "sort_order": "desc",
                "file_type": "file", "limit": 10,
            })
        self.assertEqual(200, response["status"], response)
        self.assertEqual([f"src/doc{i:02}.txt" for i in range(24, 14, -1)],
                         [item["path"] for item in response["body"]["results"]])
        self.assertEqual(11, len(examined))
        self.assertTrue(response["body"]["truncated"])

    def test_macos_indexed_rpc_ranks_candidates_from_entire_backend(self):
        files = ClientFiles(self.root, rpc_registry=object(), rpc_capabilities={"dummy": {}})
        candidates = [str(self.src / f"doc{i:02}.txt") for i in range(25)]
        with patch("openkapsel.rpc_plugins.file_search._platform_backend",
                   return_value=("mdfind", "/usr/bin/mdfind")), patch(
            "openkapsel.rpc_plugins.file_search._nul_paths",
            return_value=iter(candidates),
        ):
            response = plugin.dispatch(files, "search", {
                "sort_by": "modified", "sort_order": "desc", "file_type": "file",
                "limit": 10,
            })
        self.assertEqual(200, response["status"], response)
        self.assertEqual([f"src/doc{i:02}.txt" for i in range(24, 14, -1)],
                         [item["path"] for item in response["body"]["results"]])
        self.assertTrue(response["body"]["truncated"])


if __name__ == "__main__":
    unittest.main()

"""macOS Spotlight best-first time/size windows and exact Top N integration."""
from __future__ import annotations

import os
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins.file_search import plugin
from openkapsel.rpc_plugins.file_search.spotlight_adaptive import (
    _SIZE_START, metadata_windows,
)


def _match_range(expression: str, *, size: int, mtime: int) -> bool:
    """Tiny test-only evaluator for Spotlight metadata comparisons."""
    def cmp_value(actual, op, expected):
        return {"==": lambda: actual == expected,
                "<": lambda: actual < expected,
                ">": lambda: actual > expected,
                "<=": lambda: actual <= expected,
                ">=": lambda: actual >= expected}[op]()
    for operator, value in re.findall(r"kMDItemFSSize\s*(==|>=|<=|>|<)\s*(\d+)", expression):
        if not cmp_value(size, operator, int(value)):
            return False
    for operator, iso in re.findall(
        r"kMDItemFSContentChangeDate\s*(>=|<=|>|<)\s*\$time\.iso\(([^)]+)\)",
        expression,
    ):
        expected = int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())
        if not cmp_value(mtime, operator, expected):
            return False
    return True


class SpotlightWindowTests(unittest.TestCase):
    def test_size_ascending_starts_empty_then_256_and_doubles(self):
        it = metadata_windows("size", "asc")
        self.assertEqual((("kMDItemFSSize == 0",), False), next(it))
        self.assertEqual((
            ("kMDItemFSSize > 0", "kMDItemFSSize <= 256"), False
        ), next(it))
        self.assertEqual((
            ("kMDItemFSSize > 256", "kMDItemFSSize <= 512"), False
        ), next(it))
        self.assertTrue(list(metadata_windows("size", "asc"))[-1][1])

    def test_size_descending_starts_200_gib_and_halves(self):
        it = metadata_windows("size", "desc")
        self.assertEqual(((f"kMDItemFSSize >= {_SIZE_START}",), False), next(it))
        self.assertEqual((
            (f"kMDItemFSSize >= {_SIZE_START // 2}",
             f"kMDItemFSSize < {_SIZE_START}"), False
        ), next(it))
        all_windows = list(metadata_windows("size", "desc"))
        self.assertEqual((("kMDItemFSSize < 1",), True), all_windows[-1])

    def test_timestamp_both_directions_have_distinct_disjoint_ranges(self):
        now = 1_780_000_000
        desc = list(metadata_windows("modified", "desc", now_seconds=now))
        asc = list(metadata_windows("modified", "asc", now_seconds=now))
        self.assertIn("1971-01-01T00:00:00Z", asc[0][0][0])
        self.assertTrue(desc[0][0][0].startswith("kMDItemFSContentChangeDate >="))
        self.assertTrue(desc[-1][1])
        self.assertTrue(asc[-1][1])
        self.assertLess(len(desc), 30)
        self.assertLess(len(asc), 30)
        # Every bucket includes each test timestamp exactly once.
        for windows in (desc, asc):
            for when in (-2_000_000_000, 0, 900_000_000, now-3000, now+1000):
                matches = [
                    i for i, (preds, _) in enumerate(windows)
                    if _match_range(" && ".join(preds), size=8, mtime=when)
                ]
                self.assertEqual(1, len(matches), (when, matches))


class SpotlightAdaptiveSearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.data = self.root / "project"
        self.data.mkdir()
        self.files = ClientFiles(self.root, rpc_registry=object(),
                                 rpc_capabilities={"dummy": {}})
        self.now = 1_800_000_000
        self.candidates = []
        for name, size, mod in (
            ("empty-a.txt", 0, self.now-3600),
            ("empty-b.txt", 0, self.now-7200),
            ("tiny.txt", 80, self.now-2*86_400),
            ("small.txt", 256, self.now-7*86_400),
            ("mid.txt", 1_024, self.now-30*86_400),
            ("large.txt", 1_048_576, self.now-100*86_400),
            ("nontxt.jpg", 9_999_999, self.now-180*86_400),
        ):
            path = self.data / name
            path.write_bytes(b"x"*size)
            os.utime(path, (mod, mod))
            self.candidates.append(path)

    def _run(self, *, limit=2, sort_by="size", order="asc", query="*.txt"):
        seen_queries = []
        def fake_paths(command, backend, timeout):
            self.assertEqual("mdfind", backend)
            self.assertGreater(timeout, 0)
            expression = command[-1]
            seen_queries.append(expression)
            from fnmatch import fnmatchcase
            return iter([
                str(path) for path in self.candidates
                if fnmatchcase(path.name, query) and _match_range(
                    expression, size=path.stat().st_size,
                    mtime=int(path.stat().st_mtime),
                )
            ])
        with patch("openkapsel.rpc_plugins.file_search._platform_backend",
                   return_value=("mdfind", "/usr/bin/mdfind")), patch(
            "openkapsel.rpc_plugins.file_search._nul_paths",
            side_effect=fake_paths,
        ), patch(
            "openkapsel.rpc_plugins.file_search.spotlight_adaptive.time.time",
            return_value=self.now,
        ):
            result = plugin.dispatch(self.files, "search", {
                "path": "project", "query": query, "mode": "glob",
                "sort_by": sort_by, "sort_order": order,
                "file_type": "file", "limit": limit,
            })
        self.assertEqual(200, result["status"], result)
        return result["body"], seen_queries

    def test_smallest_two_are_both_empty_without_scanning_larger_sizes(self):
        result, queries = self._run(limit=2)
        self.assertEqual(["empty-a.txt", "empty-b.txt"],
                         [Path(item["path"]).name for item in result["results"]])
        self.assertEqual(1, len(queries))
        self.assertIn("kMDItemFSSize == 0", queries[0])
        self.assertTrue(result["truncated"])

    def test_size_ascending_first_zero_then_256(self):
        result, queries = self._run(limit=3)
        self.assertEqual(["empty-a.txt", "empty-b.txt", "tiny.txt"],
                         [Path(item["path"]).name for item in result["results"]])
        self.assertEqual(2, len(queries))
        self.assertIn("kMDItemFSSize > 0", queries[1])
        self.assertIn("kMDItemFSSize <= 256", queries[1])

    def test_size_descending_starts_at_200_gib_until_matching_candidates(self):
        result, queries = self._run(sort_by="size", order="desc", limit=2)
        self.assertEqual(["large.txt", "mid.txt"],
                         [Path(item["path"]).name for item in result["results"]])
        self.assertIn(str(_SIZE_START), queries[0])
        self.assertGreater(len(queries), 3)

    def test_newest_two_only_scans_recent_window(self):
        result, queries = self._run(sort_by="modified", order="desc", limit=2)
        self.assertEqual(["empty-a.txt", "empty-b.txt"],
                         [Path(item["path"]).name for item in result["results"]])
        self.assertEqual(1, len(queries))

    def test_oldest_two_searches_forward_from_epoch(self):
        result, queries = self._run(sort_by="modified", order="asc", limit=2)
        self.assertEqual(["large.txt", "mid.txt"],
                         [Path(item["path"]).name for item in result["results"]])
        self.assertIn("1971-01-01T00:00:00Z", queries[0])
        self.assertGreater(len(queries), 3)

    def test_window_expansion_respects_exact_glob_and_finds_all_when_needed(self):
        result, queries = self._run(sort_by="size", order="asc", limit=10,
                                    query="*small.txt")
        self.assertEqual(["small.txt"],
                         [Path(item["path"]).name for item in result["results"]])
        self.assertFalse(result["truncated"])
        self.assertGreater(len(queries), 3)


if __name__ == "__main__":
    unittest.main()

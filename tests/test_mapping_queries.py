"""Root queries stop at mapping boundaries and merge coarse client results."""

import hashlib
import os
import sys
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from tests import test_mapping_rpc_first as fixture


@unittest.skipIf(os.name == "nt", "server runs on POSIX")
class MappingQueryTests(unittest.TestCase):
    request = fixture.RpcOnlyHTTPTests.request
    api = fixture.RpcOnlyHTTPTests.api
    tearDown = fixture.RpcOnlyHTTPTests.tearDown
    second_mapping = fixture.RpcOnlyHTTPTests.second_mapping

    def setUp(self):
        fixture.RpcOnlyHTTPTests.setUp(self)
        (self.scope / "hello.txt").unlink()  # Remove the HTTP fixture's sample.
        self.session.capabilities["file_stream"] = {"version": 1, "search_prefix": True}

    def grep(self, **query):
        return self.api("/fs/query/grep?" + urlencode(dict(path=".", query="needle", **query), doseq=True))

    def find(self, **query):
        return self.api(
            "/fs/query/find?"
            + urlencode(dict(path=".", query="needle", **query), doseq=True)
        )

    def test_root_list_is_virtual_even_when_provider_offline(self):
        (self.scope / "local.txt").write_text("local")
        self.session.closed = True
        status, result = self.api("/fs/query/list?path=.&limit=1")
        self.assertEqual(200, status, result)
        self.assertEqual(2, result["total"])
        self.assertTrue(result["truncated"])
        self.assertEqual("laptop", result["entries"][0]["name"])
        self.assertTrue(result["entries"][0]["is_mapping"])
        self.assertEqual([], self.calls)

    def test_root_grep_sends_one_rpc_per_mapping(self):
        for index in range(10):
            (self.export / f"{index}.txt").write_text("needle\n" + "x" * 10000)
        (self.scope / "local.txt").write_text("needle")
        second = self.second_mapping()
        (second / "remote.txt").write_text("needle")
        second_session = self.server.mappings.sessions[self.extra[0][0]["id"]]
        with patch.object(second_session, "call", wraps=second_session.call) as remote:
            status, result = self.grep()
        self.assertEqual(200, status, result)
        self.assertEqual(12, result["match_count"])
        self.assertEqual(12, result["files_searched"])
        self.assertEqual(["api_fs_grep"], [op for op, _ in self.calls])
        self.assertEqual(1, remote.call_count)
        self.assertEqual("api_fs_grep", remote.call_args.args[0])
        self.assertNotIn(str(self.export), str(result))

    def test_mapping_grep_requires_canonical_fs_grep(self):
        (self.export / "legacy.txt").write_text("needle")
        file_rpc = self.session.capabilities["rpc"]["file"]
        file_rpc["operations"] = [
            operation for operation in file_rpc["operations"] if operation != "fs_grep"
        ]
        before = len(self.calls)
        status, result = self.api("/fs/query/grep?path=laptop&query=needle")
        self.assertEqual(409, status, result)
        self.assertEqual("mapping_rpc_unsupported", result["error"]["code"])
        self.assertEqual(before, len(self.calls))


    def test_root_find_newest_files_excludes_mapping_even_when_newer(self):
        # An unscoped newest-N search only searches native Server files.
        # Mappings must be explicitly queried by their own path.
        self.files.rpc_capabilities.pop("file_search", None)
        local_old = self.scope / "local-old.txt"
        local_new = self.scope / "local-new.txt"
        mapped_newest = self.export / "mapped-newest.txt"
        mapped_old = self.export / "mapped-old.txt"
        for path, timestamp in (
            (local_old, 1_700_000_001),
            (local_new, 1_700_000_003),
            (mapped_newest, 1_700_000_004),
            (mapped_old, 1_700_000_002),
        ):
            path.write_text("x")
            os.utime(path, (timestamp, timestamp))
        # On Linux the native SQLite index receives inotify/watchfiles
        # changes asynchronously. A ready index may not have consumed these
        # file creations and utime updates immediately. Wait for the REAL
        # HTTP search to reflect them; do not rebuild or mock the index.
        expected = ["local-new.txt", "local-old.txt"]
        deadline = time.monotonic() + 20
        while True:
            status, result = self.api(
                "/fs/query/find?path=.&sort_by=modified&sort_order=desc"
                "&file_type=file&max_results=2"
            )
            self.assertEqual(200, status, result)
            names = [Path(item["path"]).name for item in result["results"]]
            # Require the actual Linux indexed backend, not a recursive
            # fallback that could conceal a stopped watcher.
            indexed = not sys.platform.startswith("linux") or result["backend"] == "sqlite_watch"
            if indexed and names == expected:
                break
            if time.monotonic() >= deadline:
                self.fail(f"native newest-file index failed to converge: {result}")
            time.sleep(0.05)
        self.assertEqual(expected, names)
        self.assertEqual([], self.calls)
        self.assertFalse(result["truncated"])
        self.assertTrue(all(item["type"] == "file" for item in result["results"]))
        self.assertTrue(all("modified_utc_ns" in item for item in result["results"]))

    def test_native_root_excludes_storage_provider_and_explicit_scope_searches_it(self):
        from types import SimpleNamespace

        cloud = self.scope / "cloud"
        cloud.mkdir()
        (cloud / "Needle-cloud.txt").write_text("external", encoding="utf-8")
        index = getattr(self.server, "filename_index", None)
        requires_index = sys.platform.startswith("linux")
        if requires_index:
            # Linux Server is expected to have a live watcher. This test
            # must FAIL if startup silently falls back to recursive search.
            from openkapsel.files.filename_index import watcher_available
            self.assertTrue(watcher_available(), "Linux watchfiles dependency missing")
            self.assertIsNotNone(index, "Linux native index failed to initialize")
            self.assertIsNotNone(index._worker, "Linux index worker never started")
            self.assertIsNotNone(index._watcher, "Linux watcher never started")
            deadline = time.monotonic() + 12
            while not index.ready and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(index.ready, "Linux native index did not become ready")
            self.assertTrue(index._watcher.is_alive(), "Linux native watcher has stopped")
        (self.scope / "Needle-local.txt").write_text("native", encoding="utf-8")
        storage = SimpleNamespace(
            store=SimpleNamespace(mappings=lambda: [{"workspace": self.scope.name, "name": "cloud"}]),
            mapping_path=lambda _row: cloud,
            check_path=lambda *_args, **_kwargs: None,
        )
        with patch.object(self.server, "storage_providers", storage, create=True):
            # The watcher applies mutations asynchronously: poll the actual
            # HTTP search until the native index observes the new file. Do
            # not replace this with index.rebuild(), which bypasses inotify.
            deadline = time.monotonic() + 12
            while True:
                status, broad = self.find()
                self.assertEqual(200, status, broad)
                names = [Path(item["path"]).name for item in broad["results"]]
                if ((not requires_index or broad["backend"] == "sqlite_watch")
                        and names == ["Needle-local.txt"]):
                    break
                if time.monotonic() >= deadline:
                    self.fail(f"native watcher did not index new file: {broad}")
                time.sleep(0.05)
            self.assertEqual(["Needle-local.txt"], names)
            if requires_index:
                self.assertEqual("sqlite_watch", broad["backend"])
            # Both the indexed native search and the recursive fallback must
            # exclude registered storage roots from an unscoped query.
            with patch.object(self.server, "filename_index", None):
                status, recursive = self.find()
                self.assertEqual(200, status, recursive)
                self.assertEqual("recursive", recursive["backend"])
                self.assertEqual(["Needle-local.txt"],
                                 [Path(item["path"]).name for item in recursive["results"]])
            status, scoped = self.api("/fs/query/find?path=cloud&query=Needle")
            self.assertEqual(200, status, scoped)
            self.assertEqual(["Needle-cloud.txt"],
                             [Path(item["path"]).name for item in scoped["results"]])

    def test_mapping_find_prefers_indexed_file_search(self):
        nested = self.export / "nested"
        nested.mkdir()
        wanted = nested / "Needle-config.toml"
        wanted.write_text("x")
        # The test exercises indexed-search preference, not host backend discovery.
        # CI runners may not have watchfiles/mdfind/Everything, so advertise the mocked
        # backend explicitly before dispatching fs_find.
        self.files.rpc_capabilities["file_search"] = {"state": "available"}
        with (patch("openkapsel.rpc_plugins.file_search._platform_backend",
                    return_value=("mdfind", "/mock/mdfind")),
              patch("openkapsel.rpc_plugins.file_search._backend_paths",
                    return_value=("mock-index", iter([str(wanted)]))) as indexed):
            status, result = self.api(
                "/fs/query/find?path=laptop&query=needle&timeout_seconds=5"
            )
        self.assertEqual(200, status, result)
        self.assertEqual("mock-index", result["backend"])
        self.assertFalse(result["timed_out"])
        self.assertEqual(1, len(result["results"]))
        self.assertTrue(
            result["results"][0]["path"].endswith(
                "/laptop/nested/Needle-config.toml"
            )
        )
        self.assertEqual(["api_fs_find"], [op for op, _ in self.calls])
        indexed.assert_called_once()
        self.assertLessEqual(indexed.call_args.args[3], 5.0)

    def test_root_find_omits_mapping_and_recursively_falls_back_without_index(self):
        self.files.rpc_capabilities.pop("file_search", None)
        (self.export / "nested").mkdir()
        (self.export / "nested" / "Needle-remote.txt").write_text("x")
        (self.scope / "Needle-local.txt").write_text("x")
        # Disable the *server-native* index, not only the mapped client's
        # file_search RPC. Otherwise Linux's asynchronous watcher may not
        # have indexed Needle-local.txt yet and this does not test fallback.
        with patch.object(self.server, "filename_index", None):
            status, result = self.find(timeout_seconds=5)
        self.assertEqual(200, status, result)
        self.assertEqual("recursive", result["backend"])
        self.assertEqual(
            {"Needle-local.txt"},
            {Path(item["path"]).name for item in result["results"]},
        )
        self.assertFalse(result["timed_out"])
        self.assertEqual([], self.calls)

    def test_grep_depth_filters_regex_and_limits(self):
        (self.export / "nested").mkdir()
        (self.export / "a.py").write_text("Needle")
        (self.export / "skip.txt").write_text("needle")
        (self.export / "nested/b.py").write_text("needle")
        status, result = self.grep(depth=0)
        self.assertEqual(200, status, result)
        self.assertEqual(0, result["match_count"])
        self.assertEqual([], self.calls)
        status, result = self.grep(depth=1, case_sensitive="false", include="*.py")
        self.assertEqual(1, result["match_count"], result)
        self.assertTrue(result["matches"][0]["path"].endswith("/laptop/a.py"))
        for include, exclude, count in (("laptop/*.py", [], 2),
                                         ("lap*/*.py", ["laptop/nested"], 1),
                                         ("*/nested/*.py", [], 1),
                                         ("*.py", ["laptop/*"], 0)):
            with self.subTest(include=include, exclude=exclude):
                status, result = self.grep(depth=2, case_sensitive="false", regex="true",
                                             include=include, exclude=exclude)
                self.assertEqual(200, status, result)
                self.assertEqual(count, result["match_count"], result)
                self.assertNotIn("unavailable_mappings", result)
        self.calls.clear()
        status, result = self.grep(exclude="laptop")
        self.assertEqual(0, result["match_count"], result)
        self.assertEqual([], self.calls)
        (self.scope / "first.txt").write_text("needle")
        status, result = self.grep(case_sensitive="false", max_results=2)
        self.assertEqual(2, result["match_count"], result)
        self.assertTrue(result["truncated"])
        self.assertEqual(["1"], self.calls[-1][1]["query"]["max_results"])

    def test_tree_and_hashed_manifest_use_coarse_queries(self):
        (self.export / "nested").mkdir()
        (self.export / "nested/data.txt").write_text("remote data")
        status, result = self.api("/fs/query/tree?path=.&depth=3")
        self.assertEqual(200, status, result)
        self.assertEqual(4, result["node_count"])
        node = result["tree"]["children"][0]
        self.assertEqual("laptop", node["name"])
        self.assertTrue(node["is_mapping"])
        self.assertEqual(["api_fs_tree"], [op for op, _ in self.calls])
        self.calls.clear()
        status, result = self.api("/fs/query/manifest", {"path": ".", "recursive": True,
                                                 "depth": 3, "include_sha256": True})
        self.assertEqual(200, status, result)
        self.assertEqual(4, result["total"])
        remote_file = result["items"][-1]
        self.assertEqual(hashlib.sha256(b"remote data").hexdigest(), remote_file["sha256"])
        self.assertEqual(["api_fs_manifest"], [op for op, _ in self.calls])

    def test_recursive_tree_and_manifest_keep_inaccessible_siblings(self):
        from openkapsel.errors import ApiError
        from openkapsel.files.file_support import FileOperationSupportMixin

        (self.scope / "lost+found").mkdir()
        (self.scope / "visible").mkdir()
        (self.scope / "visible" / "ok.txt").write_text("ok")

        original = FileOperationSupportMixin._directory_entries

        def guarded(handler, path):
            if path.name == "lost+found":
                raise ApiError(403, "path_access_denied", "permission denied")
            return original(handler, path)

        with patch.object(FileOperationSupportMixin, "_directory_entries", guarded):
            status, result = self.api("/fs/query/tree?path=.&depth=3")
            self.assertEqual(200, status, result)
            children = {item["name"]: item for item in result["tree"]["children"]}
            denied = children["lost+found"]
            self.assertTrue(denied["unavailable"])
            self.assertEqual("directory", denied["type"])
            self.assertEqual("path_access_denied", denied["error"]["code"])
            self.assertEqual("ok.txt", children["visible"]["children"][0]["name"])

            status, manifest = self.api(
                "/fs/query/manifest",
                {"path": ".", "recursive": True, "depth": 3},
            )
            self.assertEqual(200, status, manifest)
            by_name = {item["name"]: item for item in manifest["items"]}
            self.assertTrue(by_name["lost+found"]["unavailable"])
            self.assertEqual("path_access_denied", by_name["lost+found"]["error"]["code"])
            self.assertIn("ok.txt", by_name)

    def test_tree_depth_and_node_budget_are_global(self):
        (self.export / "a").write_text("a")
        (self.export / "b").write_text("b")
        (self.scope / "z-local").write_text("local")
        status, result = self.api("/fs/query/tree?path=.&depth=0")
        self.assertEqual(1, result["node_count"], result)
        self.assertEqual([], self.calls)
        status, result = self.api("/fs/query/tree?path=.&depth=1")
        self.assertEqual(3, result["node_count"], result)
        self.assertNotIn("children", result["tree"]["children"][0])
        # Config is immutable; temporarily replace the request-facing view.
        from dataclasses import replace
        with patch.object(self.server, "config", replace(self.server.config, max_tree_nodes=3)):
            for endpoint, body in (("/fs/query/tree?path=.&depth=2", None),
                                   ("/fs/query/manifest", {"path": ".", "recursive": True, "depth": 2})):
                status, result = self.api(endpoint, body)
                self.assertEqual(200, status, result)
                self.assertTrue(result["truncated"])
                self.assertEqual(3, result.get("node_count", result.get("total")))
                self.assertEqual(2, self.calls[-1][1]["limits"]["max_tree_nodes"])

    def test_disabled_offline_and_old_clients_are_not_silently_scanned(self):
        (self.export / "a").write_text("needle")
        (self.scope / "local").write_text("needle")
        for capabilities, closed, code in (({"rpc": {"file": {"state": "disabled"}}}, False, "mapping_rpc_disabled"),
                                           ({}, False, "mapping_rpc_unsupported"),
                                           ({}, True, "mapping_offline")):
            with self.subTest(code=code):
                self.session.capabilities = capabilities
                self.session.closed = closed
                self.calls.clear()
                with patch("openkapsel.mapping.mapping_manager.time.sleep") as sleep:
                    status, result = self.grep()
                    self.assertEqual(200, status, result)
                    self.assertEqual(1, result["match_count"])
                    self.assertTrue(result["truncated"])
                    self.assertEqual(code, result["unavailable_mappings"][0]["error"]["code"])
                    status, result = self.api("/fs/query/tree?path=.&depth=2")
                self.assertEqual(code, result["tree"]["children"][0]["error"]["code"])
                self.assertEqual([], self.calls)
                self.assertEqual(2 if closed else 0, sleep.call_count)

    def test_path_filters_require_feature_from_old_clients(self):
        self.session.capabilities.pop("file_stream")
        status, result = self.grep(include="laptop/*.py")
        self.assertEqual(200, status, result)
        self.assertEqual("mapping_client_upgrade_required", result["unavailable_mappings"][0]["error"]["code"])
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()

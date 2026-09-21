"""Root queries stop at mapping boundaries and merge coarse client results."""

import hashlib
import os
import unittest
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

    def search(self, **query):
        return self.api("/fs/search?" + urlencode(dict(path=".", query="needle", **query), doseq=True))

    def test_root_list_is_virtual_even_when_provider_offline(self):
        (self.scope / "local.txt").write_text("local")
        self.session.closed = True
        status, result = self.api("/fs/list?path=.&limit=1")
        self.assertEqual(200, status, result)
        self.assertEqual(2, result["total"])
        self.assertTrue(result["truncated"])
        self.assertEqual("laptop", result["entries"][0]["name"])
        self.assertTrue(result["entries"][0]["is_mapping"])
        self.assertEqual([], self.calls)

    def test_root_search_sends_one_rpc_per_mapping(self):
        for index in range(10):
            (self.export / f"{index}.txt").write_text("needle\n" + "x" * 10000)
        (self.scope / "local.txt").write_text("needle")
        second = self.second_mapping()
        (second / "remote.txt").write_text("needle")
        second_session = self.server.mappings.sessions[self.extra[0][0]["id"]]
        with patch.object(second_session, "call", wraps=second_session.call) as remote:
            status, result = self.search()
        self.assertEqual(200, status, result)
        self.assertEqual(12, result["match_count"])
        self.assertEqual(12, result["files_searched"])
        self.assertEqual(["api_fs_search"], [op for op, _ in self.calls])
        self.assertEqual(1, remote.call_count)
        self.assertEqual("api_fs_search", remote.call_args.args[0])
        self.assertNotIn(str(self.export), str(result))

    def test_search_depth_filters_regex_and_limits(self):
        (self.export / "nested").mkdir()
        (self.export / "a.py").write_text("Needle")
        (self.export / "skip.txt").write_text("needle")
        (self.export / "nested/b.py").write_text("needle")
        status, result = self.search(depth=0)
        self.assertEqual(200, status, result)
        self.assertEqual(0, result["match_count"])
        self.assertEqual([], self.calls)
        status, result = self.search(depth=1, case_sensitive="false", include="*.py")
        self.assertEqual(1, result["match_count"], result)
        self.assertTrue(result["matches"][0]["path"].endswith("/laptop/a.py"))
        for include, exclude, count in (("laptop/*.py", [], 2),
                                         ("lap*/*.py", ["laptop/nested"], 1),
                                         ("*/nested/*.py", [], 1),
                                         ("*.py", ["laptop/*"], 0)):
            with self.subTest(include=include, exclude=exclude):
                status, result = self.search(depth=2, case_sensitive="false", regex="true",
                                             include=include, exclude=exclude)
                self.assertEqual(200, status, result)
                self.assertEqual(count, result["match_count"], result)
                self.assertNotIn("unavailable_mappings", result)
        self.calls.clear()
        status, result = self.search(exclude="laptop")
        self.assertEqual(0, result["match_count"], result)
        self.assertEqual([], self.calls)
        (self.scope / "first.txt").write_text("needle")
        status, result = self.search(case_sensitive="false", max_results=2)
        self.assertEqual(2, result["match_count"], result)
        self.assertTrue(result["truncated"])
        self.assertEqual(["1"], self.calls[-1][1]["query"]["max_results"])

    def test_tree_and_hashed_manifest_use_coarse_queries(self):
        (self.export / "nested").mkdir()
        (self.export / "nested/data.txt").write_text("remote data")
        status, result = self.api("/fs/tree?path=.&depth=3")
        self.assertEqual(200, status, result)
        self.assertEqual(4, result["node_count"])
        node = result["tree"]["children"][0]
        self.assertEqual("laptop", node["name"])
        self.assertTrue(node["is_mapping"])
        self.assertEqual(["api_fs_tree"], [op for op, _ in self.calls])
        self.calls.clear()
        status, result = self.api("/fs/manifest", {"path": ".", "recursive": True,
                                                 "depth": 3, "include_sha256": True})
        self.assertEqual(200, status, result)
        self.assertEqual(4, result["total"])
        remote_file = result["items"][-1]
        self.assertEqual(hashlib.sha256(b"remote data").hexdigest(), remote_file["sha256"])
        self.assertEqual(["api_fs_manifest"], [op for op, _ in self.calls])

    def test_recursive_tree_and_manifest_keep_inaccessible_siblings(self):
        from openkapsel.errors import ApiError
        from openkapsel.file_support import FileOperationSupportMixin

        (self.scope / "lost+found").mkdir()
        (self.scope / "visible").mkdir()
        (self.scope / "visible" / "ok.txt").write_text("ok")

        original = FileOperationSupportMixin._directory_entries

        def guarded(handler, path):
            if path.name == "lost+found":
                raise ApiError(403, "path_access_denied", "permission denied")
            return original(handler, path)

        with patch.object(FileOperationSupportMixin, "_directory_entries", guarded):
            status, result = self.api("/fs/tree?path=.&depth=3")
            self.assertEqual(200, status, result)
            children = {item["name"]: item for item in result["tree"]["children"]}
            denied = children["lost+found"]
            self.assertTrue(denied["unavailable"])
            self.assertEqual("directory", denied["type"])
            self.assertEqual("path_access_denied", denied["error"]["code"])
            self.assertEqual("ok.txt", children["visible"]["children"][0]["name"])

            status, manifest = self.api(
                "/fs/manifest",
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
        status, result = self.api("/fs/tree?path=.&depth=0")
        self.assertEqual(1, result["node_count"], result)
        self.assertEqual([], self.calls)
        status, result = self.api("/fs/tree?path=.&depth=1")
        self.assertEqual(3, result["node_count"], result)
        self.assertNotIn("children", result["tree"]["children"][0])
        # Config is immutable; temporarily replace the request-facing view.
        from dataclasses import replace
        with patch.object(self.server, "config", replace(self.server.config, max_tree_nodes=3)):
            for endpoint, body in (("/fs/tree?path=.&depth=2", None),
                                   ("/fs/manifest", {"path": ".", "recursive": True, "depth": 2})):
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
                status, result = self.search()
                self.assertEqual(200, status, result)
                self.assertEqual(1, result["match_count"])
                self.assertTrue(result["truncated"])
                self.assertEqual(code, result["unavailable_mappings"][0]["error"]["code"])
                status, result = self.api("/fs/tree?path=.&depth=2")
                self.assertEqual(code, result["tree"]["children"][0]["error"]["code"])
                self.assertEqual([], self.calls)

    def test_path_filters_require_feature_from_old_clients(self):
        self.session.capabilities.pop("file_stream")
        status, result = self.search(include="laptop/*.py")
        self.assertEqual(200, status, result)
        self.assertEqual("mapping_client_upgrade_required", result["unavailable_mappings"][0]["error"]["code"])
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()

"""Cross-platform indexed file_search RPC behavior and Everything QUERY2 protocol."""

import re
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.errors import ApiError
from openkapsel.rpc_plugins import load_server_rpc_registry
from openkapsel.files.filename_index import _literal_run
from openkapsel.rpc_plugins.file_search import (
    _spotlight_glob_pattern, _spotlight_glob_query, plugin,
)
from openkapsel.rpc_plugins.file_search.everything_ipc import (
    REQUEST_FULL_PATH,
    SORT_DATE_MODIFIED_DESCENDING,
    build_query2,
    build_scope_regex,
    parse_list2,
    query_paths,
)


class EverythingIpcProtocolTests(unittest.TestCase):
    def test_query2_wire_layout_is_unicode_and_bounded(self):
        payload = build_query2(
            0x12345678,
            "配置.txt",
            search_flags=0x0C,
            offset=7,
            max_results=25,
            reply_message=0x11223344,
        )
        header = struct.unpack_from("<IIIIIII", payload, 0)
        self.assertEqual(
            (0x12345678, 0x11223344, 0x0C, 7, 25, REQUEST_FULL_PATH, 1),
            header,
        )
        self.assertEqual("配置.txt\x00", payload[28:].decode("utf-16-le"))

    def test_parse_list2_full_path(self):
        path = r"C:\work\src\alpha.txt"
        encoded = path.encode("utf-16-le")
        data_offset = 28
        payload = (
            struct.pack("<IIIII", 1, 1, 0, REQUEST_FULL_PATH, 1)
            + struct.pack("<II", 0, data_offset)
            + struct.pack("<I", len(path))
            + encoded
            + b"\x00\x00"
        )
        paths, total = parse_list2(payload)
        self.assertEqual(1, total)
        self.assertEqual([path], paths)

    def test_scope_regex_is_literal_and_stays_below_scope(self):
        pattern = re.compile(build_scope_regex(r"C:\Root[1]", "a+b"), re.IGNORECASE)
        self.assertRegex(r"C:\Root[1]\sub\xxa+bzz.txt", pattern)
        self.assertRegex(r"C:\Root[1]\a+b.md", pattern)
        self.assertNotRegex(r"C:\RootX1\a+b.md", pattern)
        self.assertNotRegex(r"C:\Root[1]\sub\other.txt", pattern)

    def test_everything_native_date_modified_descending_sort_and_11_result_query(self):
        from openkapsel.rpc_plugins.file_search.everything_ipc import _query_page

        captured = []
        def page(query, **kwargs):
            captured.append((query, kwargs))
            return ([f"C:/work/f{i}.txt" for i in range(kwargs["offset"],
                    min(kwargs["offset"] + kwargs["max_results"], 15))], 15)

        with patch("openkapsel.rpc_plugins.file_search.everything_ipc._query_page",
                   side_effect=page):
            paths = list(query_paths(
                r"C:\work", "*", mode="glob", sort_by="modified",
                sort_order="desc", batch_size=11,
            ))
        self.assertEqual(15, len(paths))
        self.assertEqual([0, 11], [item[1]["offset"] for item in captured])
        self.assertEqual([11, 11], [item[1]["max_results"] for item in captured])
        self.assertTrue(all(item[1]["sort_type"] == SORT_DATE_MODIFIED_DESCENDING
                            for item in captured))

    def test_everything_glob_translates_to_pcre_filename_match(self):
        pattern = build_scope_regex(r"C:\Root", "test[0-9]?.py", mode="glob")
        self.assertIn("test[0-9]", pattern)
        self.assertIn("(?s:", pattern)
        self.assertIn(r"^C:\\Root", pattern)

    def test_glob_hint_excludes_metacharacters_and_bracket_classes(self):
        self.assertEqual("config", _literal_run("*config?.py", True))
        self.assertEqual("test", _literal_run("test[0-9].py", True))


class SpotlightGlobTests(unittest.TestCase):
    def test_glob_converts_unsupported_operators_to_wider_wildcards(self):
        self.assertEqual("test*.py", _spotlight_glob_pattern("test[0-9]?.py"))
        self.assertEqual("image*.jpg", _spotlight_glob_pattern("image[!ab].jpg"))
        self.assertEqual("plain*.md", _spotlight_glob_pattern("plain*.md"))
        self.assertEqual("foo*bar", _spotlight_glob_pattern("foo[[]bar"))
        self.assertEqual(
            'kMDItemFSName == "file\\"*.txt"cd',
            _spotlight_glob_query('file"?.txt'),
        )

    def test_macos_glob_uses_mdfind_index_and_exact_postfilter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            scope = root / "project"
            scope.mkdir()
            for name in ("test1.py", "testA.py", "test12.py", "not-test.txt"):
                (scope / name).write_text("test", encoding="utf-8")
            files = ClientFiles(
                root, rpc_registry=object(),
                rpc_capabilities={"dummy": {"state": "available"}},
            )
            candidates = (str(scope / name) for name in
                          ("test1.py", "testA.py", "test12.py", "not-test.txt"))
            with patch(
                "openkapsel.rpc_plugins.file_search._platform_backend",
                return_value=("mdfind", "/usr/bin/mdfind"),
            ), patch(
                "openkapsel.rpc_plugins.file_search._nul_paths",
                return_value=iter(candidates),
            ) as native:
                result = plugin.dispatch(
                    files, "search",
                    {"query": "test[0-9].py", "mode": "glob", "path": "project"},
                )
            self.assertEqual(200, result["status"], result)
            self.assertEqual(
                ["project/test1.py"], [x["path"] for x in result["body"]["results"]],
            )
            self.assertEqual(4, result["body"]["results"][0]["size_bytes"])
            cmd = native.call_args.args[0]
            self.assertEqual(
                ["/usr/bin/mdfind", "-0", "-onlyin", str(scope),
                 'kMDItemFSName == "test*.py"cd'], cmd,
            )

class FileSearchRpcTests(unittest.TestCase):
    @staticmethod
    def _files(root):
        return ClientFiles(
            root,
            rpc_registry=object(),
            rpc_capabilities={"dummy": {"state": "available"}},
        )

    def test_search_filters_scope_private_paths_and_literal_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = root / "project"
            nested = scope / "src"
            nested.mkdir(parents=True)
            wanted = nested / "Alpha[1].txt"
            wanted.write_text("ok", encoding="utf-8")
            wrong_name = nested / "Alpha1.txt"
            wrong_name.write_text("no", encoding="utf-8")
            outside = root / "Alpha[1]-outside.txt"
            outside.write_text("no", encoding="utf-8")
            private_dir = scope / ".openkapsel"
            private_dir.mkdir()
            private = private_dir / "Alpha[1]-private.txt"
            private.write_text("no", encoding="utf-8")
            temporary = scope / ".Alpha[1].openkapsel-put-deadbeef"
            temporary.write_text("no", encoding="utf-8")

            files = self._files(root)
            candidates = [
                str(wanted),
                str(wrong_name),
                str(outside),
                str(private),
                str(temporary),
            ]
            with patch(
                "openkapsel.rpc_plugins.file_search._backend_paths",
                return_value=("mock", iter(candidates)),
            ):
                result = plugin.dispatch(
                    files,
                    "search",
                    {"query": "alpha[1]", "path": "project", "limit": 20},
                )
            self.assertEqual(200, result["status"])
            self.assertEqual(
                ["project/src/Alpha[1].txt"],
                [x["path"] for x in result["body"]["results"]],
            )
            self.assertFalse(result["body"]["truncated"])

    def test_search_offset_limit_and_case_sensitive_postfilter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = root / "p"
            scope.mkdir()
            paths = []
            for name in ("Needle-A.txt", "Needle-B.txt", "needle-c.txt"):
                path = scope / name
                path.write_text(name, encoding="utf-8")
                paths.append(str(path))
            files = self._files(root)
            with patch(
                "openkapsel.rpc_plugins.file_search._backend_paths",
                return_value=("mock", iter(paths)),
            ):
                result = plugin.dispatch(
                    files,
                    "search",
                    {
                        "query": "Needle",
                        "path": "p",
                        "case_sensitive": True,
                        "offset": 1,
                        "limit": 1,
                    },
                )
            self.assertEqual(200, result["status"])
            self.assertEqual("p/Needle-B.txt", result["body"]["results"][0]["path"])
            self.assertFalse(result["body"]["truncated"])
            self.assertIsNone(result["body"]["next_offset"])

    def test_search_timeout_returns_partial_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = root / "p"
            scope.mkdir()
            wanted = scope / "Needle.txt"
            wanted.write_text("x", encoding="utf-8")
            files = self._files(root)

            def paths():
                yield str(wanted)
                raise ApiError(
                    504,
                    "file_search_timeout",
                    "indexed search timed out; narrow the query or scope",
                )

            with patch(
                "openkapsel.rpc_plugins.file_search._backend_paths",
                return_value=("mock", paths()),
            ) as backend:
                result = plugin.dispatch(
                    files,
                    "search",
                    {"query": "needle", "path": "p"},
                )
            self.assertEqual(200, result["status"])
            self.assertTrue(result["body"]["timed_out"])
            self.assertTrue(result["body"]["truncated"])
            self.assertEqual(5.0, result["body"]["timeout_seconds"])
            self.assertEqual("p/Needle.txt", result["body"]["results"][0]["path"])
            self.assertEqual(5.0, backend.call_args.args[3])

    def test_filename_query_rejects_path_separators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = self._files(root)
            response = plugin.dispatch(files, "search", {"query": "a/b"})
            self.assertEqual(400, response["status"])
            self.assertEqual("invalid_data_arguments", response["error"]["code"])

    def test_server_registry_exposes_same_family(self):
        registry = load_server_rpc_registry()
        try:
            self.assertIn("file_search", registry.families)
            self.assertFalse(registry.operation_spec("file_search", "search")["write"])
        finally:
            registry.close()


if __name__ == "__main__":
    unittest.main()

"""Cross-platform indexed file_search RPC behavior and Everything QUERY2 protocol."""

import re
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins import load_server_rpc_registry
from openkapsel.rpc_plugins.file_search import _plocate_pattern, plugin
from openkapsel.rpc_plugins.file_search.everything_ipc import (
    REQUEST_FULL_PATH,
    build_query2,
    build_scope_regex,
    parse_list2,
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

    def test_plocate_glob_metacharacters_are_escaped(self):
        self.assertEqual(r"abc\*\?\[x\]", _plocate_pattern("abc*?[x]"))


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
                [{"path": "project/src/Alpha[1].txt", "type": "file"}],
                result["body"]["results"],
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

"""Archive RPC plugin and local/mapped preview integration."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins.archive import supported_extensions
from tests import test_oauth


class ArchivePluginTests(unittest.TestCase):
    def test_all_registered_stdlib_archive_formats_can_be_previewed(self):
        archive_names = {name for name, _description in shutil.get_archive_formats()}
        unpack_names = {name for name, _extensions, _description in shutil.get_unpack_formats()}
        formats = sorted(archive_names & unpack_names)
        self.assertIn("zip", formats)
        self.assertIn("gztar", formats)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "folder").mkdir()
            (source / "hello.txt").write_text("hello archive", encoding="utf-8")
            (source / "folder" / "nested.txt").write_text("nested", encoding="utf-8")
            files = ClientFiles(root, writable=False)
            try:
                for format_name in formats:
                    with self.subTest(format=format_name):
                        archive = Path(shutil.make_archive(str(root / ("sample-" + format_name)), format_name, root_dir=source))
                        relative = archive.relative_to(root).as_posix()
                        listed = files.dispatch("archive_list", {"path": relative, "limit": 100})
                        self.assertEqual(200, listed["status"], listed)
                        names = {item["name"] for item in listed["body"]["entries"]}
                        self.assertIn("hello.txt", names)
                        self.assertIn("folder", names)

                        read = files.dispatch("archive_read", {
                            "path": relative,
                            "member": "hello.txt",
                            "limit": 1024,
                            "encoding": "utf-8",
                        })
                        self.assertEqual(200, read["status"], read)
                        self.assertEqual("hello archive", read["body"]["content"])
                        self.assertTrue(read["body"]["eof"])
            finally:
                files.close()

        extensions = supported_extensions()
        self.assertIn(".zip", extensions)
        self.assertIn(".tar.gz", extensions)

    def test_archive_preview_never_reads_link_members_as_files(self):
        if os.name == "nt":
            self.skipTest("symlink archive fixture uses POSIX mode bits")
        import io
        import tarfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "links.tar"
            with tarfile.open(archive, "w") as handle:
                data = b"real"
                regular = tarfile.TarInfo("real.txt")
                regular.size = len(data)
                handle.addfile(regular, io.BytesIO(data))
                link = tarfile.TarInfo("link.txt")
                link.type = tarfile.SYMTYPE
                link.linkname = "real.txt"
                handle.addfile(link)
            files = ClientFiles(root, writable=False)
            try:
                listed = files.dispatch("archive_list", {"path": "links.tar"})
                entries = {item["name"]: item for item in listed["body"]["entries"]}
                self.assertEqual("link", entries["link.txt"]["type"])
                read = files.dispatch("archive_read", {"path": "links.tar", "member": "link.txt"})
                self.assertEqual(400, read["status"])
                self.assertEqual("archive_member_not_file", read["error"]["code"])
            finally:
                files.close()


@unittest.skipIf(os.name == "nt", "server runs on POSIX")
class ArchiveHTTPTests(unittest.TestCase):
    request = test_oauth.OAuthHTTPTests.request
    rpc = test_oauth.OAuthHTTPTests.rpc

    def setUp(self):
        test_oauth.OAuthHTTPTests.setUp(self)
        self.base = "/kapsel/w/" + self.record.token
        self.root = self.server.config.root / self.record.path_prefix
        self.export = Path(self.temp.name) / "archive-export"
        self.export.mkdir()
        self.files = ClientFiles(self.export, writable=False)
        self.row, _ = self.server.mappings.store.create(
            self.record.path_prefix, "laptop", writable=False, allow_exec=False
        )
        self.mount = self.server.mappings.mount_path(self.row)
        self.mount.mkdir()
        self.calls = []

        def call(op, args):
            self.calls.append(op)
            return self.files.dispatch(op, args)

        self.session = SimpleNamespace(
            closed=False, ready=True,
            capabilities={"rpc": self.files.rpc_capabilities},
            call=call,
            close=lambda: None,
        )
        self.server.mappings.sessions[self.row["id"]] = self.session

    def tearDown(self):
        self.server.mappings.sessions.clear()
        self.server.mappings.store.delete(self.row["id"])
        self.files.close()
        test_oauth.OAuthHTTPTests.tearDown(self)

    @staticmethod
    def make_zip(path):
        import zipfile
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("docs/readme.txt", "mapped preview")
            archive.writestr("root.txt", "root")

    def get_json(self, endpoint):
        status, _, raw = self.request("GET", self.base + endpoint)
        return status, json.loads(raw)

    def test_local_archive_keeps_generic_rpc_surface_and_adds_server_execution(self):
        archive = self.root / "local.zip"
        self.make_zip(archive)
        status, body = self.get_json("/archive/list?path=local.zip")
        self.assertEqual(200, status, body)
        self.assertEqual("server", body["location"])
        self.assertEqual({"docs", "root.txt"}, {item["name"] for item in body["entries"]})

        status, body = self.get_json("/archive/read?path=local.zip&member=docs/readme.txt")
        self.assertEqual(200, status, body)
        self.assertEqual("mapped preview", body["content"])

        conn = self.server.static_mcp.create(self.record.app_id, self.record.path_prefix, "Archive reads")
        self.mcp = "/kapsel/mcp-connect/" + conn["id"] + "/mcp"
        status, payload = self.rpc(conn["secret"], "tools/list")
        self.assertEqual(200, status, payload)
        names = {tool["name"] for tool in payload["result"]["tools"]}
        self.assertIn("rpc", names)
        self.assertNotIn("archive_list", names)
        self.assertNotIn("archive_read", names)

        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {
                "family": "archive", "operation": "list",
                "args": {"path": "local.zip", "limit": 100},
            },
        })
        self.assertEqual(200, status, payload)
        self.assertFalse(payload["result"]["isError"], payload)
        result = payload["result"]["structuredContent"]
        self.assertEqual("server", result["location"])
        self.assertEqual({"docs", "root.txt"}, {
            item["name"] for item in result["result"]["entries"]
        })

        status, payload = self.rpc(conn["secret"], "tools/call", {
            "name": "rpc",
            "arguments": {
                "family": "archive", "operation": "read",
                "args": {"path": "local.zip", "member": "docs/readme.txt"},
            },
        })
        self.assertEqual(200, status, payload)
        self.assertFalse(payload["result"]["isError"], payload)
        self.assertEqual(
            "mapped preview",
            payload["result"]["structuredContent"]["result"]["content"],
        )

    def test_mapped_archive_uses_plugin_and_never_fuse_fallbacks(self):
        archive = self.export / "mapped.zip"
        self.make_zip(archive)

        status, body = self.get_json("/archive/list?path=laptop/mapped.zip")
        self.assertEqual(200, status, body)
        self.assertEqual("client", body["location"])
        self.assertEqual(["archive_list"], self.calls)
        self.assertFalse((self.mount / "mapped.zip").exists())

        status, body = self.get_json("/archive/read?path=laptop/mapped.zip&member=docs/readme.txt")
        self.assertEqual(200, status, body)
        self.assertEqual("mapped preview", body["content"])
        self.assertEqual(["archive_list", "archive_read"], self.calls)

        self.session.capabilities["rpc"]["archive"] = {
            "state": "available",
            "version": 1,
            "operations": ["list", "read", "create"],
            "read_only": False,
            "operation_specs": {
                "list": {"write": False},
                "read": {"write": False},
                "create": {"write": True},
            },
        }
        status, body = self.get_json("/archive/list?path=laptop/mapped.zip")
        self.assertEqual(200, status, body)
        self.assertEqual("client", body["location"])
        self.assertEqual(["archive_list", "archive_read", "archive_list"], self.calls)

        self.session.capabilities["rpc"]["archive"] = {
            "state": "disabled",
            "reason": "client_config",
            "version": 1,
            "operations": ["list", "read"],
            "read_only": True,
        }
        status, body = self.get_json("/archive/list?path=laptop/mapped.zip")
        self.assertEqual(403, status, body)
        self.assertEqual("mapping_rpc_disabled", body["error"]["code"])
        self.assertEqual(["archive_list", "archive_read", "archive_list"], self.calls)

        self.server.mappings.sessions.pop(self.row["id"])
        status, body = self.get_json("/archive/list?path=laptop/mapped.zip")
        self.assertEqual(503, status, body)
        self.assertEqual("mapping_offline", body["error"]["code"])
        self.assertEqual(["archive_list", "archive_read", "archive_list"], self.calls)


if __name__ == "__main__":
    unittest.main()

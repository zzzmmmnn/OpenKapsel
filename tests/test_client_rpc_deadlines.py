"""Real synchronous Client RPC deadline and mutation safety regressions."""
import base64
import errno
import threading
from types import SimpleNamespace
import hashlib
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_file_api import ClientFileAPI
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.rpc_deadline import deadline_scope
from openkapsel.rpc_plugins.archive import _zip_entry_type
from openkapsel.rpc_plugins.tabular.csv_stream import CSVStream


class ClientDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        cls = ClientFiles
        import os
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            cls = WindowsClientFiles
        self.files = cls(self.root, writable=True)

    def tearDown(self):
        self.files.close()
        self.temp.cleanup()

    def call(self, op, *, query=None, body=None):
        return self.files.dispatch("api_" + op, {
            "query": query or {}, "body": body or {}, "display_root": "/mapped",
        })

    @staticmethod
    def slow(fn, delay=.03):
        def run(*args, **kwargs):
            time.sleep(delay)
            return fn(*args, **kwargs)
        return run

    def test_fs_list_tree_manifest_time_out_during_directory_traversal(self):
        (self.root / "nested").mkdir()
        (self.root / "nested" / "text.txt").write_text("text")
        original = ClientFileAPI._directory_entries
        with patch.object(ClientFileAPI, "_directory_entries", self.slow(original)):
            for name, query, body in (
                ("fs_list", {"path": ["."]}, {}),
                ("fs_tree", {"path": ["."], "depth": ["2"]}, {}),
                ("fs_manifest", {}, {"recursive": True, "depth": 2}),
            ):
                with self.subTest(name=name):
                    with patch.dict(ClientFileAPI.RPC_TIMEOUT_SECONDS, {name: .015}):
                        result = self.call(name, query=query, body=body)
                    self.assertEqual(504, result["status"], result)
                    self.assertEqual("client_rpc_timeout", result["error"]["code"])

    def test_batch_file_read_and_large_range_read_time_out(self):
        for name in ("a.txt", "b.txt"):
            (self.root / name).write_text("text")
        original = ClientFileAPI._open_binary
        with patch.object(ClientFileAPI, "_open_binary", self.slow(original)):
            with patch.dict(ClientFileAPI.RPC_TIMEOUT_SECONDS, {"fs_read_files": .015}):
                result = self.call("fs_read_files", body={"paths": ["a.txt", "b.txt"]})
            self.assertEqual(504, result["status"], result)
            with patch("openkapsel.files.mutation.require_large_file_size"):
                with patch.dict(ClientFileAPI.RPC_TIMEOUT_SECONDS, {"fs_read_large": .015}):
                    result = self.call("fs_read_large", body={"path": "a.txt", "offset": 0, "length": 2})
            self.assertEqual(504, result["status"], result)

    def test_mutation_deadline_expires_before_commit_and_creates_nothing(self):
        import openkapsel.files.mutation as mutation
        original = mutation._plan_item
        with patch.object(mutation, "_plan_item", self.slow(original)):
            with patch.dict(ClientFileAPI.RPC_TIMEOUT_SECONDS, {"fs_mutate": .015}):
                result = self.call("fs_mutate", body={"items": [
                    {"op": "file.create", "path": "should-not-exist.txt", "content": "payload"}
                ]})
        self.assertEqual(504, result["status"], result)
        self.assertFalse((self.root / "should-not-exist.txt").exists())
        self.assertFalse(list(self.root.glob("*.openkapsel-*")))

    def test_large_range_deadline_expires_before_first_write(self):
        p = self.root / "existing.bin"
        p.write_bytes(b"ABCDEFGH")
        stat = self.call("fs_stat", query={"path": ["existing.bin"]})
        tag = stat["body"]["etag"]
        before = p.read_bytes()
        import openkapsel.files.mutation as mutation
        with patch.object(mutation, "require_large_file_size"):
            # Delay a prewrite verification step. Timeout must stop before the
            # first seek/write, leaving the original content intact.
            original = ClientFileAPI._file_stat
            with patch.object(ClientFileAPI, "_file_stat", self.slow(original)):
                with patch.dict(ClientFileAPI.RPC_TIMEOUT_SECONDS,
                                {"fs_replace_large": .015}):
                    result = self.call("fs_replace_large", body={
                        "path": "existing.bin", "offset": 0, "length": 4,
                        "expected_etag": tag, "expected_range_sha256": hashlib.sha256(before[:4]).hexdigest(),
                        "data_base64": base64.b64encode(b"ZZZZ").decode(),
                    })
        self.assertEqual(504, result["status"], result)
        self.assertEqual(before, p.read_bytes())

    def test_low_level_directory_timeout_uses_etimedout(self):
        from openkapsel.client_runtime.client_rpc import ClientRpcSession
        from openkapsel.client_runtime import client_files
        from openkapsel.errors import ApiError
        # A slow low-level provider directory read should have a bounded
        # lifetime and communicate ETIMEDOUT, not EINVAL, over Mapping RPC.
        (self.root / "visible.txt").write_text("visible")
        actual = self.files._dispatch
        def slow_list(op, args):
            if op == "list":
                time.sleep(.03)
            return actual(op, args)
        real_scope = deadline_scope
        with (patch.object(self.files, "_dispatch", slow_list),
              patch.object(client_files, "deadline_scope",
                           lambda seconds, cancelled=None: real_scope(.015, cancelled))):
            with self.assertRaises(ApiError) as exc:
                self.files.dispatch("list", {"path": "."})
        self.assertEqual(504, exc.exception.status)

        session = ClientRpcSession(SimpleNamespace(files=self.files),
                                   SimpleNamespace(), threading.Event())
        try:
            with patch.object(session.files, "dispatch",
                              side_effect=ApiError(504, "client_rpc_timeout", "timed out")):
                response = session._dispatch({"id": "probe", "op": "list",
                                              "args": {"path": "."}})
            self.assertEqual(errno.ETIMEDOUT, response["error"]["errno"])
        finally:
            session.close()

    def test_mutation_commit_finishes_after_deadline_to_preserve_atomicity(self):
        # The time budget is checked before publication, never between
        # linked rename steps in an already-committing transaction.
        original = self.files.paths.rename
        def slow_publish(*args, **kwargs):
            time.sleep(.03)
            return original(*args, **kwargs)
        with patch.object(self.files.paths, "rename", slow_publish):
            with patch.dict(ClientFileAPI.RPC_TIMEOUT_SECONDS, {"fs_mutate": .015}):
                result = self.call("fs_mutate", body={"items": [
                    {"op": "file.create", "path": "committed.txt", "content": "complete"},
                ]})
        self.assertEqual(200, result["status"], result)
        self.assertEqual("complete", (self.root / "committed.txt").read_text())

    def test_archive_list_and_read_respect_client_deadline(self):
        archive = self.root / "data.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for n in range(8):
                z.writestr(f"{n:02}.txt", "sample")
        def slow_kind(info):
            time.sleep(.025)
            return _zip_entry_type(info)
        from openkapsel.rpc_plugins.archive import plugin
        with patch("openkapsel.rpc_plugins.archive._zip_entry_type", side_effect=slow_kind):
            with deadline_scope(.015):
                result = plugin.dispatch(self.files, "list", {"path": "data.zip"})
        self.assertEqual(504, result["status"], result)
        import openkapsel.rpc_plugins.archive as archive_module
        name = archive_module._member_name
        with patch.object(archive_module, "_member_name", side_effect=self.slow(name)):
            with deadline_scope(.015):
                result = plugin.dispatch(self.files, "read", {
                    "path": "data.zip", "member": "07.txt",
                })
        self.assertEqual(504, result["status"], result)

    def test_tabular_inspect_and_read_respect_deadline(self):
        (self.root / "data.csv").write_text("id,value\n1,a\n2,b\n3,c\n")
        from openkapsel.rpc_plugins.tabular import plugin
        original = CSVStream.next_row
        with patch.object(CSVStream, "next_row", self.slow(original)):
            for op in ("inspect", "read"):
                with self.subTest(op=op):
                    with deadline_scope(.015):
                        result = plugin.dispatch(self.files, op, {"path": "data.csv"})
                    self.assertEqual(504, result["status"], result)


if __name__ == "__main__":
    unittest.main()

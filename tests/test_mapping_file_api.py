"""File API equivalence and one-RPC routing without needing a FUSE mount."""

import errno
import hashlib
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.client_files import ClientFiles
from openkapsel.mapping_transport import FILE_API_OPERATIONS
from openkapsel.server import WorkspaceRequestHandler
from openkapsel.errors import ApiError
from tests import test_oauth




@unittest.skipIf(os.name == "nt", "server runs on POSIX")
class MappingFileHTTPTests(unittest.TestCase):
    request = test_oauth.OAuthHTTPTests.request

    def setUp(self):
        test_oauth.OAuthHTTPTests.setUp(self)
        self.base = "/kapsel/w/" + self.record.token
        self.headers = {"Authorization": "Bearer " + self.record.control_token, "Content-Type": "application/json"}
        status, _, raw = self.request("POST", self.base + "/context", json.dumps({"type": "plan", "taskname": "rpc", "content": "Test file RPC"}), self.headers)
        self.assertEqual(201, status, raw)
        self.plan = json.loads(raw)["id"]
        self.export = Path(self.temp.name) / "export"
        self.export.mkdir()
        self.files = ClientFiles(self.export, writable=True)
        self.row, _ = self.server.mappings.store.create(self.record.path_prefix, "laptop", writable=True)
        self.mount = self.server.mappings.mount_path(self.row)
        self.mount.mkdir()
        self.calls = []
        def call(op, args):
            self.calls.append((op, args))
            return self.files.dispatch(op, args)
        self.session = SimpleNamespace(closed=False, capabilities={"file_api": {"version": 3, "operations": sorted(FILE_API_OPERATIONS)}}, call=call, close=lambda: None)
        self.server.mappings.sessions[self.row["id"]] = self.session

    def tearDown(self):
        self.server.mappings.sessions.clear()
        # No FUSE worker was started by this fixture.
        self.server.mappings.store.delete(self.row["id"])
        self.files.close()
        test_oauth.OAuthHTTPTests.tearDown(self)

    def api(self, endpoint, body=None):
        if body is not None:
            body = dict(body, plan_id=self.plan, taskname="rpc", message="Test mapped file operation")
        status, _, raw = self.request("POST" if body is not None else "GET", self.base + endpoint,
                                       json.dumps(body) if body is not None else None, self.headers)
        return status, json.loads(raw)

    def test_list_stat_hash_search_and_tree_each_use_one_rpc(self):
        (self.export / "folder").mkdir()
        data = b"needle\n" * 200000
        (self.export / "folder/large.txt").write_bytes(data)
        for endpoint in ("/fs/list?path=laptop", "/fs/stat?path=laptop/folder/large.txt&fields=sha256,size,etag",
                         "/fs/search?path=laptop&query=needle&max_results=2", "/fs/tree?path=laptop&depth=2",
                         "/fs/read?path=laptop/folder/large.txt&limit=10"):
            before = len(self.calls)
            status, body = self.api(endpoint)
            self.assertEqual(200, status, body)
            self.assertEqual(before + 1, len(self.calls))
            self.assertTrue(self.calls[-1][0].startswith("api_"))
            self.assertNotIn(str(self.export), json.dumps(body))
            if "sha256" in body:
                self.assertEqual(hashlib.sha256(data).hexdigest(), body["sha256"])

    def test_batch_manifest_and_mutation_context_remain_intact(self):
        status, body = self.api("/fs/write", {"path": "laptop/a", "content": "hello"})
        self.assertEqual(201, status, body)
        self.assertTrue((self.export / "a").exists())
        self.assertFalse((self.mount / "a").exists())
        self.assertIn("context_id", body)
        status, body = self.api("/fs/manifest", {"items": [{"path": "laptop/a"}, {"path": "laptop/missing"}], "include_sha256": True})
        self.assertEqual(200, status, body)
        self.assertEqual(["laptop/a", "laptop/missing"], [item["path"] for item in body["items"]])
        self.assertEqual("api_fs_manifest", self.calls[-1][0])
        status, body = self.api("/fs/delete/batch", {"paths": ["laptop/a"]})
        self.assertEqual(200, status, body)
        self.assertEqual("laptop", body["items"][0]["root"])

    def test_new_read_operations_are_single_rpc_and_read_token_accessible(self):
        (self.export / "a.py").write_text("needle")
        self.headers = {"Content-Type": "application/json"}
        for endpoint, body in (("/fs/read_many", {"paths": ["laptop/a.py"]}),
                               ("/fs/manifest", {"recursive": True, "path": "laptop", "include_sha256": True}),
                               ("/fs/search?path=laptop&query=needle&include=*.py", None)):
            before = len(self.calls)
            status, result = self.api(endpoint, body)
            self.assertEqual(200, status, result)
            self.assertEqual(before + 1, len(self.calls))
        self.session.capabilities["file_api"]["version"] = 1
        self.assertFalse(self.server.mappings.supports_file_api(self.row["id"], "fs_manifest", min_version=2))
        # Simulate the old client's FUSE view and ensure filters are not silently
        # sent to a client which cannot implement them.
        (self.mount / "a.py").write_text("needle")
        (self.mount / "b.txt").write_text("needle")
        before = len(self.calls)
        status, result = self.api("/fs/search?path=laptop&query=needle&include=*.py")
        self.assertEqual(200, status, result)
        self.assertEqual(1, result["match_count"])
        self.assertEqual(before, len(self.calls))

    def test_file_rpc_disabled_can_fallback_but_offline_and_mapping_disabled_do_not(self):
        (self.mount / "fallback").write_text("fuse")
        self.session.capabilities = {
            "rpc": {
                "file": {
                    "state": "disabled",
                    "reason": "client_config",
                    "version": 3,
                    "operations": sorted(FILE_API_OPERATIONS),
                }
            }
        }
        status, body = self.api("/fs/list?path=laptop")
        self.assertEqual(200, status, body)
        self.assertEqual(["fallback"], [entry["name"] for entry in body["entries"]])
        self.assertEqual([], self.calls)

        self.server.mappings.sessions.pop(self.row["id"])
        status, body = self.api("/fs/list?path=laptop")
        self.assertEqual(503, status, body)
        self.assertEqual("mapping_offline", body["error"]["code"])

        self.server.mappings.sessions[self.row["id"]] = self.session
        self.server.mappings.store.update(self.row["id"], enabled=False)
        status, body = self.api("/fs/list?path=laptop")
        self.assertEqual(403, status, body)
        self.assertEqual("mapping_disabled", body["error"]["code"])

    def test_fuse_and_direct_rpc_etags_share_client_identity(self):
        (self.export / "a").write_text("same file")
        actual = (self.export / "a").stat()
        # FUSE synthesizes device/inode values, while timestamps describe the
        # provider's file. Binary/preview and mixed-root paths must agree with RPC.
        synthetic = SimpleNamespace(st_dev=actual.st_dev + 1, st_ino=actual.st_ino + 1,
                                    st_size=actual.st_size, st_mtime=actual.st_mtime,
                                    st_ctime=actual.st_ctime, st_mtime_ns=actual.st_mtime_ns)
        handler = object.__new__(WorkspaceRequestHandler)
        handler.server = self.server
        self.assertNotEqual(handler._stat_etag(actual), handler._stat_etag(synthetic))
        self.assertEqual(handler._stat_etag(actual), handler._path_etag(self.mount / "a", synthetic))
        (self.export / "a").write_text("changed file")
        with self.assertRaises(ApiError) as error:
            handler._path_etag(self.mount / "a", synthetic)
        self.assertEqual(error.exception.code, "path_changed")

    def test_missing_context_readonly_mapping_and_protected_paths_are_rejected_before_rpc(self):
        status, _, _ = self.request("POST", self.base + "/fs/write", json.dumps({"path": "laptop/a", "content": "x"}), self.headers)
        self.assertEqual(400, status)
        for path in ("laptop", "laptop/.openkapsel/private"):
            status, _ = self.api("/fs/write", {"path": path, "content": "x"})
            self.assertEqual(403, status)
        self.server.mappings.store.update(self.row["id"], writable=False)
        self.assertEqual(403, self.api("/fs/write", {"path": "laptop/a", "content": "x"})[0])
        with self.assertRaises(OSError) as error:
            self.server.mappings.call(self.row["id"], "api_fs_write", {"body": {"path": "a", "content": "x"}})
        self.assertEqual(errno.EROFS, error.exception.errno)
        self.assertEqual([], self.calls)

    def test_old_client_falls_back_before_send_but_ambiguous_write_is_never_replayed(self):
        self.session.capabilities = {}
        (self.mount / "fallback").write_text("old transport")
        status, body = self.api("/fs/list?path=laptop")
        self.assertEqual(200, status, body)
        self.assertEqual("fallback", body["entries"][0]["name"])
        self.assertEqual([], self.calls)
        self.session.capabilities = {"file_api": {"version": 3, "operations": sorted(FILE_API_OPERATIONS)}}
        original = self.session.call
        def ambiguous(op, args):
            original(op, args)
            raise OSError(errno.ETIMEDOUT, "result unknown")
        with patch.object(self.session, "call", side_effect=ambiguous):
            status, _ = self.api("/fs/write", {"path": "laptop/a", "content": "once"})
        self.assertEqual(503, status)
        self.assertEqual(1, len(self.calls))
        self.assertEqual("once", (self.export / "a").read_text())
        self.assertFalse((self.mount / "a").exists())

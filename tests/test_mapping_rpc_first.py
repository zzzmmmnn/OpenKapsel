"""RPC-first regression coverage: native mounts must not service file APIs."""

import base64
import errno
import hashlib
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from openkapsel.execution.api_workers import ApiWorker, ApiWorkerError
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.mapping.mapping_io import WorkspaceFiles, stream_stat
from openkapsel.mapping.mapping_manager import MappingManager
from openkapsel.server import WorkspaceRequestHandler
from tests import test_mapping_file_api as fixture


class RpcOnlyHTTPTests(unittest.TestCase):
    request = fixture.MappingFileHTTPTests.request
    api = fixture.MappingFileHTTPTests.api

    def setUp(self):
        fixture.MappingFileHTTPTests.setUp(self)
        self.session.generation = "test-generation"
        self.scope = self.server.tokens.scope_root(self.record)
        self.server.mappings.fuse_enabled = False
        self.no_mount = patch.object(self.server.mappings, "mount", side_effect=AssertionError("file API attempted FUSE"))
        self.no_mount.start()
        self.mount.chmod(0)
        self.extra = []

    def tearDown(self):
        self.no_mount.stop()
        for row, provider in self.extra:
            self.server.mappings.store.delete(row["id"])
            provider.close()
        self.mount.chmod(0o700)
        fixture.MappingFileHTTPTests.tearDown(self)

    def handler(self):
        value = object.__new__(WorkspaceRequestHandler)
        value.server = self.server
        value.token_record = self.record
        value.token_scope_root = self.scope
        return value

    def raw(self, method, endpoint, data=None, headers=None):
        extra = {"OpenKapsel-Plan-Id": str(self.plan), "OpenKapsel-Taskname": "rpc",
                 "OpenKapsel-Message": "RPC-only binary test"}
        return self.request(method, self.base + endpoint, data,
                            dict(self.headers, **extra, **(headers or {})))

    def transfer_done(self, result):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = self.server.file_transfers.get(result["id"], self.scope)
            if job["state"] != "running":
                self.assertEqual("completed", job["state"], job.get("error"))
                return job
            time.sleep(.01)
        self.fail("transfer did not complete")

    def second_mapping(self):
        export = Path(self.temp.name) / "second-export"
        export.mkdir()
        provider = ClientFiles(export, writable=True)
        row, _ = self.server.mappings.store.create(self.record.path_prefix, "second", writable=True)
        self.server.mappings.prepare(row)
        session = SimpleNamespace(closed=False, ready=True, capabilities=self.session.capabilities,
                                  generation="second-generation", call=provider.dispatch, close=lambda: None)
        self.server.mappings.sessions[row["id"]] = session
        self.extra.append((row, provider))
        return export

    def test_root_listing_tree_manifest_search_and_mixed_reads(self):
        (self.export / "remote.txt").write_text("remote needle\r\n")
        (self.scope / "local.txt").write_text("local needle")
        status, listing = self.api("/fs/list?path=.")
        self.assertEqual(200, status, listing)
        entry = next(e for e in listing["entries"] if e["name"] == "laptop")
        self.assertTrue(entry["is_mapping"])
        status, result = self.api("/fs/tree?path=.&depth=2")
        self.assertEqual(200, status, result)
        self.assertIn("remote.txt", json.dumps(result))
        status, result = self.api("/fs/search?path=.&query=needle")
        self.assertEqual(200, status, result)
        self.assertEqual(2, result["match_count"])
        status, result = self.api("/fs/read_many", {"paths": ["local.txt", "laptop/remote.txt"], "max_total_chars": 100})
        self.assertEqual(200, status, result)
        self.assertEqual(["local needle", "remote needle\r\n"], [i["content"] for i in result["items"]])
        status, result = self.api("/fs/manifest", {"recursive": True, "path": ".", "include_sha256": True})
        self.assertEqual(200, status, result)
        self.assertIn(hashlib.sha256(b"remote needle\r\n").hexdigest(), json.dumps(result))
        self.session.closed = True
        status, result = self.api("/fs/tree?path=.&depth=2")
        self.assertEqual(200, status, result)
        self.assertIn('"unavailable": true', json.dumps(result))

    def test_download_range_head_static_preview_and_mcp_helpers(self):
        data = bytes(range(256)) * 1200
        (self.export / "data.bin").write_bytes(data)
        status, headers, body = self.raw("GET", "/fs/content?path=laptop/data.bin", headers={"Range": "bytes=131070-131080"})
        self.assertEqual(206, status, body[:100])
        self.assertEqual(data[131070:131081], body)
        status, headers, body = self.raw("HEAD", "/fs/content?path=laptop/data.bin")
        self.assertEqual(200, status)
        self.assertEqual(b"", body)
        handler = self.handler()
        info = handler._mcp_prepare_download({"path": "laptop/data.bin"})
        self.assertEqual(len(data), info["size"])
        chunk = handler._mcp_read_binary_chunk({"path": "laptop/data.bin", "offset": 131070, "length": 100})
        self.assertEqual(data[131070:131170], base64.b64decode(chunk["data_base64"]))
        self.record = self.server.tokens.update(self.record.token, can_preview=True)
        (self.export / "index.html").write_text("<h1>RPC preview</h1>")
        handler = self.handler()
        target = handler._mcp_web_preview_url({"path": "laptop"})
        self.assertEqual("directory", target["type"])
        handler.headers = {}
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler._handle_web_preview("/web/laptop/", "/web/laptop/", "", head_only=False)
        self.assertEqual(b"<h1>RPC preview</h1>", handler.wfile.getvalue())

    def test_direct_upload_and_resumable_commit(self):
        data = bytes(range(256)) * 1100
        digest = hashlib.sha256(data).hexdigest()
        status, _, body = self.raw("PUT", "/fs/content?path=laptop/direct.bin", data,
                                   {"Content-Type": "application/octet-stream", "X-Content-SHA256": digest})
        self.assertEqual(201, status, body)
        self.assertEqual(data, (self.export / "direct.bin").read_bytes())
        status, result = self.api("/uploads", {"path": "laptop/resumed.bin", "size": len(data), "sha256": digest})
        self.assertEqual(201, status, result)
        upload = result["upload_id"]
        self.server.uploads.append(upload, self.record.token, 0, io.BytesIO(data), len(data))
        spool = Path(self.server.uploads.get(upload, self.record.token).temp_path)
        status, _, raw = self.raw("POST", "/uploads/" + upload + "/commit")
        result = json.loads(raw)
        self.assertEqual(201, status, result)
        self.assertEqual(data, (self.export / "resumed.bin").read_bytes())
        self.assertFalse(spool.exists())
        status, _, body = self.raw("PUT", "/fs/content?path=laptop/direct.bin", b"bad", {"Content-Type": "application/octet-stream"})
        self.assertEqual(409, status, body)
        self.assertEqual(data, (self.export / "direct.bin").read_bytes())

    def test_upload_checksum_failure_and_mapping_identity_change(self):
        status, _, body = self.raw("PUT", "/fs/content?path=laptop/bad", b"bad",
                                   {"Content-Type": "application/octet-stream", "X-Content-SHA256": "0" * 64})
        self.assertEqual(422, status, body)
        self.assertFalse((self.export / "bad").exists())
        self.assertFalse(list(self.export.glob("*.openkapsel-put-*")))
        status, result = self.api("/uploads", {"path": "laptop/later", "size": 1})
        self.assertEqual(201, status, result)
        upload = result["upload_id"]
        self.server.uploads.append(upload, self.record.token, 0, io.BytesIO(b"x"), 1)
        self.server.mappings.store.update(self.row["id"], name="renamed")
        status, _, raw = self.raw("POST", "/uploads/" + upload + "/commit")
        result = json.loads(raw)
        self.assertEqual(409, status, result)
        self.assertEqual("upload_mapping_changed", result["error"]["code"])
        self.server.mappings.store.update(self.row["id"], name="laptop")

    def test_copy_move_between_local_and_two_mappings(self):
        second = self.second_mapping()
        (self.export / "dir").mkdir()
        data = b"remote-data" * 50000
        (self.export / "dir/data").write_bytes(data)
        for source, destination in (("laptop/dir", "local-copy"), ("local-copy", "second/copy"),
                                    ("second/copy", "laptop/returned")):
            status, result = self.api("/fs/copy", {"source": source, "destination": destination})
            self.assertEqual(202, status, result)
            self.transfer_done(result)
        self.assertEqual(data, (second / "copy/data").read_bytes())
        self.assertEqual(data, (self.export / "returned/data").read_bytes())
        status, result = self.api("/fs/move", {"source": "laptop/returned", "destination": "moved"})
        self.assertEqual(202, status, result)
        self.transfer_done(result)
        self.assertFalse((self.export / "returned").exists())
        self.assertEqual(data, (self.scope / "moved/data").read_bytes())

    def test_mixed_replace_and_delete_preserve_preflight(self):
        (self.export / "a").write_text("old remote")
        (self.scope / "b").write_text("old local")
        items = [{"path": "laptop/a", "replacements": [{"old": "old", "new": "new"}]},
                 {"path": "b", "replacements": [{"old": "missing", "new": "new"}]}]
        status, result = self.api("/fs/replace/batch", {"items": items})
        self.assertEqual(409, status, result)
        self.assertEqual("old remote", (self.export / "a").read_text())
        items[1]["replacements"][0]["old"] = "old"
        status, result = self.api("/fs/replace/batch", {"items": items})
        self.assertEqual(200, status, result)
        self.assertEqual("new remote", (self.export / "a").read_text())
        self.assertEqual("new local", (self.scope / "b").read_text())
        status, result = self.api("/fs/delete/batch", {"paths": ["laptop/a", "missing"]})
        self.assertEqual(409, status, result)
        self.assertTrue((self.export / "a").exists())
        status, result = self.api("/fs/delete/batch", {"paths": ["laptop/a", "b"]})
        self.assertEqual(200, status, result)
        self.assertFalse((self.export / "a").exists())

    def test_share_snapshot_and_import_without_native_descriptors(self):
        (self.export / "folder").mkdir()
        (self.export / "folder/data").write_bytes(b"snapshot")
        handler = self.handler()
        from openkapsel.mapping.mapping_shares import create_share, import_share
        record, _ = create_share(handler, self.mount / "folder")
        (self.export / "folder/data").write_bytes(b"modified")
        import_share(handler, record.id, self.mount / "imported")
        self.assertEqual(b"snapshot", (self.export / "imported/data").read_bytes())
        self.assertEqual(1, record.file_count)
        self.assertEqual(8, record.size_bytes)

    def test_generation_fencing_readonly_and_old_client(self):
        (self.export / "a").write_text("unchanged")
        files = WorkspaceFiles(self.server.mappings, (self.scope,))
        files.stat(self.mount / "a")
        before = len(self.calls)
        self.session.generation = "replacement"
        with self.assertRaises(OSError) as error:
            files.rename(self.mount / "a", self.mount / "b")
        self.assertEqual(errno.ESTALE, error.exception.errno)
        self.assertEqual(before, len(self.calls))
        self.server.mappings.store.update(self.row["id"], writable=False)
        status, _, body = self.raw("PUT", "/fs/content?path=laptop/x", b"x", {"Content-Type": "application/octet-stream"})
        self.assertEqual(403, status, body)
        self.session.capabilities = {}
        self.assertEqual(409, self.api("/fs/read?path=laptop/a")[0])
        self.assertTrue((self.export / "a").exists())

    def test_api_resolution_and_private_state_do_not_mount(self):
        self.record = self.server.tokens.update(self.record.token, can_preview=True, network_mode="none")
        (self.export / "api").mkdir()
        (self.export / "api/app.py").write_text("app = None")
        handler = self.handler()
        target = handler._resolve_web_api_target("/web/laptop/api/ping")
        self.assertEqual(self.mount, target.app_root)
        layout, mapped = self.server.api_workers._app_layout(self.mount, self.server.config.api_worker_dir / "mapped-test")
        self.assertTrue(mapped)
        self.assertNotIn(str(self.export), str(layout.root))
        self.assertFalse((self.export / ".openkapsel").exists())
        self.assertEqual(0, len(self.server.mappings.mount_references))


class NativeExecutionTests(unittest.TestCase):
    request = RpcOnlyHTTPTests.request
    api = RpcOnlyHTTPTests.api
    handler = RpcOnlyHTTPTests.handler
    setUp = RpcOnlyHTTPTests.setUp
    tearDown = RpcOnlyHTTPTests.tearDown

    def test_api_worker_owns_lease_not_each_http_connection(self):
        manager = self.server.mappings
        api = self.server.api_workers
        process = Mock(pid=None)
        process.poll.return_value = None
        process.terminate.side_effect = lambda: setattr(process.poll, "return_value", 0)
        process.wait.return_value = 0
        def ensure(record, workspace, root_path, key, mount_lease=None):
            self.assertGreater(manager.mount_references.get(self.row["id"], 0), 0)
            if key not in api._workers:
                api._workers[key] = ApiWorker(record.app_id, process,
                    api.worker_root / "test.sock", (), time.monotonic(), io.BytesIO(),
                    mount_lease=mount_lease)
            return api._workers[key]
        with patch.object(manager, "mount"), patch.object(api, "_ensure_native", side_effect=ensure):
            first = api.connection(self.record, self.mount, "/api", "lease-test")
            first.close()
            self.assertEqual(1, manager.mount_references[self.row["id"]])
            second = api.connection(self.record, self.mount, "/api", "lease-test")
            second.close()
            self.assertEqual(1, manager.mount_references[self.row["id"]])
            api.stop(self.record.app_id)
        self.assertFalse(manager.mount_references)
        self.assertFalse(self.session.closed)
        with patch.object(manager, "mount"), patch.object(api, "_ensure_native", side_effect=ApiWorkerError("startup failed")):
            with self.assertRaises(ApiWorkerError):
                api.connection(self.record, self.mount, "/api", "failed")
        self.assertFalse(manager.mount_references)

    def test_api_masks_undeclared_mappings(self):
        record = self.server.tokens.update(self.record.token, network_mode="none")
        api = self.server.api_workers
        worker_dir = api.worker_root / "mask-test"
        with patch("openkapsel.execution.api_workers.apparmor_restricts_user_namespaces", return_value=False):
            argv = api._sandbox_argv(record, self.scope, worker_dir, worker_dir / "app.sock", "/api")
        triples = [argv[i:i + 3] for i in range(len(argv) - 2)]
        self.assertIn(["--ro-bind", str(self.server.mappings.empty_view()), str(self.mount)], triples)
        self.assertFalse(self.server.mappings.mount_references)

    def test_server_dependencies_fail_before_launch_and_never_fall_back_to_client(self):
        self.record = self.server.tokens.update(self.record.token, shell_mode="full")
        with patch.object(self.server.mappings, "mount", side_effect=OSError(errno.ENOTSUP, "native disabled")), patch.object(self.server.tasks, "start") as start:
            for cwd, dependencies in (("laptop", []), (".", ["laptop"])):
                status, result = self.api("/shell/exec", {"command": "echo test", "cwd": cwd,
                    "target": "server", "mount_mappings": dependencies})
                self.assertEqual(503, status, result)
            start.assert_not_called()
        self.assertFalse(any(op == "task_start" for op, args in self.calls))
        self.assertFalse(self.server.mappings.mount_references)

    def test_aliases_stay_rpc_and_preview_cannot_alias_private_api_source(self):
        (self.scope / "alias").symlink_to("laptop")
        status, result = self.api("/fs/mkdir", {"path": "alias/new"})
        self.assertIn(status, (200, 201), result)
        self.assertTrue((self.export / "new").is_dir())
        status, result = self.api("/fs/write", {"path": "alias/new/a", "content": "rpc"})
        self.assertEqual(201, status, result)
        self.assertEqual("rpc", (self.export / "new/a").read_text())
        status, result = self.api("/git/status?path=.")
        self.assertEqual(409, status, result)
        self.assertEqual("git_mapping_boundary", result["error"]["code"])
        self.record = self.server.tokens.update(self.record.token, can_preview=True)
        (self.export / "api").mkdir()
        (self.export / "api/app.py").write_text("private")
        (self.scope / "public").symlink_to("laptop/api")
        from openkapsel.errors import ApiError
        with self.assertRaises(ApiError) as caught:
            self.handler()._handle_web_preview("/web/public/app.py", "/web/public/app.py", "", head_only=False)
        self.assertEqual("preview_not_found", caught.exception.code)


class MappingLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name).resolve()
        self.root = base / "workspaces"
        self.scope = self.root / "project"
        self.scope.mkdir(parents=True)
        self.manager = MappingManager(self.root, base / "state", enabled=True, mount_idle_seconds=0)
        self.row, self.secret = self.manager.store.create("project", "laptop", writable=True)
        self.manager.prepare(self.row)
        self.session = SimpleNamespace(closed=False, ready=True, capabilities={"file_api": {}}, generation="g", call=lambda *a: None)
        self.session.close = lambda: setattr(self.session, "closed", True)
        self.manager.sessions[self.row["id"]] = self.session

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def test_registration_and_restart_do_not_require_fuse_or_broker(self):
        for index in range(20):
            row, _ = self.manager.store.create("project", "extra" + str(index))
            self.manager.prepare(row)
        self.assertEqual(21, len(self.manager.store.list()))
        self.assertIsNone(self.manager.ipc)
        self.assertFalse(self.manager.workers)
        self.assertFalse(self.manager.socket_path.exists())
        with patch("openkapsel.mapping.mapping_manager.sys.platform", "darwin"), patch("openkapsel.mapping.mapping_manager.subprocess.Popen", side_effect=AssertionError("eager FUSE")):
            other = MappingManager(self.root, self.manager.store.path.parent, enabled=True)
            self.assertIsNone(other.ipc)
            other.close()

    def test_reference_counting_and_unmount_keeps_rpc_session(self):
        with patch.object(self.manager, "mount") as mount:
            first = self.manager.acquire([self.row])
            second = self.manager.acquire([self.row])
        self.assertEqual(2, self.manager.mount_references[self.row["id"]])
        with self.assertRaises(OSError):
            self.manager.rename(self.row["id"], "busy")
        first.close()
        first.close()
        self.assertEqual(1, self.manager.mount_references[self.row["id"]])
        second.close()
        self.assertFalse(self.manager.mount_references)
        self.assertIs(self.session, self.manager.sessions[self.row["id"]])
        self.assertFalse(self.session.closed)

    def test_acquire_failure_rolls_back_and_disabled_native_mounts_are_explicit(self):
        row, _ = self.manager.store.create("project", "second")
        self.manager.prepare(row)
        self.manager.sessions[row["id"]] = self.session
        with patch.object(self.manager, "mount", side_effect=[None, OSError(errno.EIO, "mount failed")]):
            with self.assertRaises(OSError):
                self.manager.acquire([self.row, row])
        self.assertFalse(self.manager.mount_references)
        self.manager.fuse_enabled = False
        with self.assertRaises(OSError) as error:
            self.manager.acquire([self.row])
        self.assertEqual(errno.ENOTSUP, error.exception.errno)
        self.assertFalse(self.session.closed)

    def test_active_limit_is_not_a_configuration_limit(self):
        self.manager.max_active_mounts = 1
        process = Mock()
        process.poll.return_value = None
        process.terminate.side_effect = lambda: setattr(process.poll, "return_value", 0)
        self.manager.workers["occupied"] = process
        with patch("openkapsel.mapping.mapping_manager.sys.platform", "linux"):
            with self.assertRaises(OSError) as error:
                self.manager.acquire([self.row])
        self.assertEqual(errno.EBUSY, error.exception.errno)
        self.manager.workers.pop("occupied")
        self.assertIsNone(self.manager.ipc)

    def test_dependency_names_are_scoped_and_cwd_is_automatic(self):
        self.assertEqual([self.row], self.manager.execution_mappings("project", self.scope / "laptop/sub"))
        self.assertEqual([self.row], self.manager.execution_mappings("project", self.scope, ["laptop"]))
        for value in (["foreign"], "laptop", [None]):
            with self.assertRaises(ValueError):
                self.manager.execution_mappings("project", self.scope, value)


if __name__ == "__main__":
    unittest.main()

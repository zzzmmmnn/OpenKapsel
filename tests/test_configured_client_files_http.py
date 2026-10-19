"""Configured File paths over real Server/Client transports, no approval grant."""
import os
import json
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
from openkapsel.client import ClientRuntime, run_once


@unittest.skipIf(os.name == "nt", "real HTTP server is POSIX-only")
class ConfiguredClientFilesHTTPTests(unittest.TestCase):
    from tests.test_mapping_file_api import MappingFileHTTPTests as _fixture
    from tests.test_capability_http import CapabilityHTTPTests as _capability
    setUp = _fixture.setUp
    tearDown = _fixture.tearDown
    request = _fixture.request
    api = _fixture.api
    ownership = _capability.ownership

    def test_configured_external_read_and_status_over_websocket_without_approval(self):
        self.server.config = replace(self.server.config, mappings_enabled=True)
        row, token = self.server.mappings.store.create(
            self.record.path_prefix, "configured-test", writable=True)
        self.server.mappings.mount_path(row).mkdir()
        external = self.export.parent / "configured-wechat"
        external.mkdir()
        path = external / "received.txt"
        path.write_text("configured transport sample")
        config = {"url": f'ws://127.0.0.1:{self.server.server_port}/kapsel/mapping-connect/{row["id"]}',
            "token": token, "root": str(self.export), "writable": True, "allow_exec": False,
            "job_sandbox": {"paths": [{"path": str(external) + "/", "access": "ro"}]}}
        runtime = ClientRuntime(config)
        stop, ready = threading.Event(), threading.Event()
        client = threading.Thread(target=run_once, args=(config, stop),
            kwargs={"runtime": runtime, "on_ready": ready.set}, daemon=True)
        client.start()
        try:
            self.assertTrue(ready.wait(5))
            self.assertFalse(runtime.full_approval_active())
            self.assertTrue(self.server.mappings.supports_configured_file_paths(row["id"]))
            from openkapsel.client_runtime.approved_file_api import ConfiguredFiles
            self.assertEqual(path.resolve(), ConfiguredFiles(runtime.files, {}, False, ()).path(str(path)))
            status, read = self.api("/fs/read/files", {"target": row["name"], "paths": [str(path)]})
            self.assertEqual(200, status, read)
            self.assertEqual("configured transport sample", read["items"][0]["content"])
            status, _, binary = self.request("GET", self.base +
                "/fs/content?target=" + row["id"] + "&path=" + str(path), headers=self.headers)
            self.assertEqual((200, b"configured transport sample"), (status, binary))
            status, _, raw = self.request("POST", self.base + "/fs/read/files",
                json.dumps({"target": row["id"], "paths": [str(path)]}),
                {"Content-Type": "application/json"})
            self.assertEqual(200, status, raw)
            self.assertEqual("configured transport sample", json.loads(raw)["items"][0]["content"])
            status, granted = self.api("/files/approval/request", {"target": row["id"],
                "access": "read", "path": str(external), "writer_nonce": self.ownership()[1]})
            self.assertEqual(200, status, granted)
            self.assertEqual("granted", granted["status"])
            self.assertNotIn("approval_url", granted)
            blocked = external / "blocked.txt"
            status, denied = self.api("/fs/write/mutate", {"target": row["id"], "items": [
                {"op": "file.create", "path": str(blocked), "content": "must not exist"}]})
            self.assertEqual(404, status, denied)
            self.assertEqual("path_unavailable", denied["error"]["code"])
            self.assertFalse(blocked.exists())
            # Neither old-client metadata nor a public auth field can widen scope.
            peer = self.server.mappings.sessions[row["id"]]
            peer.capabilities.pop("configured_file_paths")
            status, read = self.api("/fs/read/files", {"target": row["id"], "paths": [str(path)]})
            self.assertEqual(409, status, read)
            self.assertEqual("mapping_client_upgrade_required", read["error"]["code"])
            self.assertNotIn("configured transport sample", str(read))
            peer.capabilities["configured_file_paths"] = True
            status, denied = self.api("/fs/read/files", {"target": row["id"], "paths": [str(path)],
                "auth": {"configured_client_paths": True}})
            self.assertEqual(400, status, denied)
            self.assertFalse(runtime.full_approval_active())
        finally:
            stop.set()
            self.server.mappings.disconnect(row["id"])
            client.join(5)
            runtime.close()
            self.server.mappings.store.delete(row["id"])

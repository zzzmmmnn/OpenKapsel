"""File API equivalence and one-RPC routing without needing a FUSE mount."""

import base64
import errno
import hashlib
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.mapping.mapping_transport import FILE_API_OPERATIONS
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
        store = self.server.context_for(
            (self.server.config.root / self.record.path_prefix).resolve()
        )
        conversation = store.create_conversation(
            store.conversation_query()[2],
            [
                {"role": "user", "content": "User starts mapped file RPC tests."},
                {"role": "ai", "content": "AI will exercise mapped file RPC behavior."},
            ],
        )
        status, _, raw = self.request(
            "POST",
            self.base + "/context",
            json.dumps({
                "type": "plan",
                "subplans": [],
                "taskname": "rpc",
                "content": "Test file RPC",
                "conversation_id": conversation["conversation_id"],
                "writer_nonce": conversation["writer_nonce"],
                "conversation_entries": [
                    {"role": "ai", "content": "AI creates the mapped file RPC Plan."}
                ],
            }),
            self.headers,
        )
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
        self.session = SimpleNamespace(
            closed=False, ready=True, generation="fixture",
            capabilities={"rpc": self.files.rpc_capabilities},
            call=call, close=lambda: None,
        )
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

    def test_list_stat_hash_grep_and_tree_each_use_one_rpc(self):
        (self.export / "folder").mkdir()
        data = b"needle\n" * 200000
        (self.export / "folder/large.txt").write_bytes(data)
        for endpoint, request_body in (
            ("/fs/query/list?path=laptop", None),
            ("/fs/query/stat?path=laptop/folder/large.txt&fields=sha256,size,etag", None),
            ("/fs/query/grep?path=laptop&query=needle&max_results=2", None),
            ("/fs/query/tree?path=laptop&depth=2", None),
            ("/fs/read/files", {"paths": ["laptop/folder/large.txt"], "limit": 10}),
        ):
            before = len(self.calls)
            status, body = self.api(endpoint, request_body)
            self.assertEqual(200, status, body)
            self.assertEqual(before + 1, len(self.calls))
            self.assertTrue(self.calls[-1][0].startswith("api_"))
            self.assertNotIn(str(self.export), json.dumps(body))
            if "sha256" in body:
                self.assertEqual(hashlib.sha256(data).hexdigest(), body["sha256"])

    def test_batch_manifest_and_mutation_context_remain_intact(self):
        status, body = self.api("/fs/write/mutate", {"items": [
            {"op": "file.create", "path": "laptop/a", "content": "hello"},
        ]})
        self.assertEqual(200, status, body)
        self.assertTrue((self.export / "a").exists())
        self.assertFalse((self.mount / "a").exists())
        self.assertIn("context_id", body)
        status, manifest = self.api("/fs/query/manifest", {"items": [{"path": "laptop/a"}, {"path": "laptop/missing"}], "include_sha256": True})
        self.assertEqual(200, status, manifest)
        self.assertEqual(["laptop/a", "laptop/missing"], [item["path"] for item in manifest["items"]])
        self.assertEqual("api_fs_manifest", self.calls[-1][0])
        status, body = self.api("/fs/write/mutate", {"items": [
            {"op": "path.delete", "path": "laptop/a", "expected_etag": manifest["items"][0]["etag"]},
        ]})
        self.assertEqual(200, status, body)
        self.assertEqual("laptop", body["items"][0]["root"])
        self.assertTrue(body["items"][0]["recycled"])

    def test_transactional_mutation_and_large_file_ranges_use_one_rpc(self):
        (self.export / "a").write_text("old A\nold A", encoding="utf-8")
        (self.export / "b").write_text("MARK\nold B", encoding="utf-8")
        (self.export / "d").write_text("anchor", encoding="utf-8")
        status, a_stat = self.api("/fs/query/stat?path=laptop/a&fields=etag,size")
        self.assertEqual(200, status, a_stat)
        status, b_stat = self.api("/fs/query/stat?path=laptop/b&fields=etag,size")
        self.assertEqual(200, status, b_stat)
        status, d_stat = self.api("/fs/query/stat?path=laptop/d&fields=etag,size")
        self.assertEqual(200, status, d_stat)
        before = len(self.calls)
        status, body = self.api("/fs/write/mutate", {
            "items": [
                {"op": "text.replace", "path": "laptop/a", "expected_etag": a_stat["etag"],
                 "start_line": 1, "end_line": 1,
                 "replacements": [{"old": "old A", "new": "new A", "expected_count": 1}]},
                {"op": "text.replace", "path": "laptop/b", "expected_etag": b_stat["etag"],
                 "start_text": "MARK\n",
                 "replacements": [{"old": "old B", "new": "new B", "expected_count": 1}]},
                {"op": "text.insert_after", "path": "laptop/d", "expected_etag": d_stat["etag"],
                 "match": "anchor", "content": "!", "expected_count": 1},
                {"op": "file.create", "path": "laptop/c", "content": "created"},
            ]
        })
        self.assertEqual(200, status, body)
        self.assertEqual(before + 1, len(self.calls))
        self.assertEqual("api_fs_mutate", self.calls[-1][0])
        self.assertEqual(["laptop/a", "laptop/b", "laptop/d", "laptop/c"], [item["path"] for item in body["items"]])
        self.assertEqual("old A\nnew A", (self.export / "a").read_text(encoding="utf-8"))
        self.assertEqual("MARK\nnew B", (self.export / "b").read_text(encoding="utf-8"))
        self.assertEqual("anchor!", (self.export / "d").read_text(encoding="utf-8"))
        self.assertEqual(1, body["items"][2]["insertions"])
        self.assertEqual("created", (self.export / "c").read_text(encoding="utf-8"))

        large = self.export / "large.bin"
        with large.open("wb") as handle:
            handle.write(b"0123456789abcdef")
            handle.truncate(32 * 1024 * 1024 + 1)
        before = len(self.calls)
        status, read = self.api("/fs/read/large", {"path": "laptop/large.bin", "offset": 4, "length": 6})
        self.assertEqual(200, status, read)
        self.assertEqual(before + 1, len(self.calls))
        self.assertEqual("api_fs_read_large", self.calls[-1][0])
        status, replaced = self.api("/fs/write/replace_large", {
            "path": "laptop/large.bin",
            "offset": 4,
            "length": 6,
            "data_base64": base64.b64encode(b"ABCDEF").decode("ascii"),
            "expected_etag": read["etag"],
            "expected_range_sha256": read["range_sha256"],
        })
        self.assertEqual(200, status, replaced)
        self.assertEqual("api_fs_replace_large", self.calls[-1][0])
        with large.open("rb") as handle:
            self.assertEqual(b"0123ABCDEFabcdef", handle.read(16))

    def test_new_read_operations_are_single_rpc_and_read_token_accessible(self):
        (self.export / "a.py").write_text("needle")
        self.headers = {"Content-Type": "application/json"}
        for endpoint, body in (("/fs/read/files", {"paths": ["laptop/a.py"]}),
                               ("/fs/query/manifest", {"recursive": True, "path": "laptop", "include_sha256": True}),
                               ("/fs/query/grep?path=laptop&query=needle&include=*.py", None)):
            before = len(self.calls)
            status, result = self.api(endpoint, body)
            self.assertEqual(200, status, result)
            self.assertEqual(before + 1, len(self.calls))
        self.session.capabilities["rpc"]["file"]["version"] = 1
        self.assertFalse(self.server.mappings.supports_file_rpc(self.row["id"], "fs_manifest", min_version=2))
        # An old native backing view must not turn into an RPC fallback or
        # receive filters the old client cannot implement.
        (self.mount / "a.py").write_text("needle")
        (self.mount / "b.txt").write_text("needle")
        before = len(self.calls)
        status, result = self.api("/fs/query/grep?path=laptop&query=needle&include=*.py")
        self.assertEqual(409, status, result)
        self.assertEqual("mapping_rpc_unsupported", result["error"]["code"])
        self.assertEqual(before, len(self.calls))

    def test_file_rpc_waits_once_when_provider_initially_offline(self):
        (self.export / "a.txt").write_text("hello")
        self.session.closed = True

        def reconnect(delay):
            self.assertEqual(5.0, delay)
            self.session.closed = False

        with patch(
            "openkapsel.mapping.mapping_manager.time.sleep",
            side_effect=reconnect,
        ) as sleep:
            status, body = self.api("/fs/query/stat?path=laptop/a.txt&fields=size")
        self.assertEqual(200, status, body)
        self.assertEqual(5, body["size"])
        self.assertEqual(["api_fs_stat"], [op for op, _ in self.calls])
        sleep.assert_called_once_with(5.0)

    def test_legacy_disabled_file_rpc_offline_and_mapping_disabled_never_fallback(self):
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
        status, body = self.api("/fs/query/list?path=laptop")
        self.assertEqual(403, status, body)
        self.assertEqual("mapping_rpc_disabled", body["error"]["code"])
        self.assertEqual([], self.calls)

        self.server.mappings.sessions.pop(self.row["id"])
        with patch("openkapsel.mapping.mapping_manager.time.sleep") as sleep:
            status, body = self.api("/fs/query/list?path=laptop")
        self.assertEqual(503, status, body)
        self.assertEqual("mapping_offline", body["error"]["code"])
        sleep.assert_called_once_with(5.0)

        self.server.mappings.sessions[self.row["id"]] = self.session
        self.server.mappings.store.update(self.row["id"], enabled=False)
        status, body = self.api("/fs/query/list?path=laptop")
        self.assertEqual(403, status, body)
        self.assertEqual("mapping_disabled", body["error"]["code"])

    def test_binary_stream_and_direct_rpc_etags_share_client_identity(self):
        from openkapsel.mapping.mapping_io import WorkspaceFiles, stream_stat
        (self.export / "a").write_text("same file")
        scope = self.server.tokens.scope_root(self.record)
        backend = WorkspaceFiles(self.server.mappings, (scope,))
        with backend.open(self.mount / "a") as stream:
            actual = stream_stat(stream)
        status, body = self.api("/fs/query/stat?path=laptop/a&fields=etag")
        self.assertEqual(200, status, body)
        self.assertEqual(WorkspaceRequestHandler._stat_etag(actual), body["etag"])
        old_etag = body["etag"]
        (self.export / "a").write_text("changed file")
        status, body = self.api("/fs/query/stat?path=laptop/a&fields=etag")
        self.assertNotEqual(old_etag, body["etag"])

    def test_missing_context_readonly_mapping_and_protected_paths_are_rejected_before_rpc(self):
        raw = {"items": [{"op": "file.create", "path": "laptop/a", "content": "x"}]}
        status, _, _ = self.request("POST", self.base + "/fs/write/mutate", json.dumps(raw), self.headers)
        self.assertEqual(400, status)
        for path in ("laptop", "laptop/.openkapsel/private"):
            status, _ = self.api("/fs/write/mutate", {"items": [{"op": "file.create", "path": path, "content": "x"}]})
            self.assertEqual(403, status)
        self.server.mappings.store.update(self.row["id"], writable=False)
        self.assertEqual(403, self.api("/fs/write/mutate", {"items": [{"op": "file.create", "path": "laptop/a", "content": "x"}]})[0])
        with self.assertRaises(OSError) as error:
            self.server.mappings.call(self.row["id"], "api_fs_mutate", {"body": {"items": [{"op": "file.create", "path": "a", "content": "x"}]}})
        self.assertEqual(errno.EROFS, error.exception.errno)
        self.assertEqual([], self.calls)

    def test_old_client_is_rejected_and_ambiguous_write_is_never_replayed(self):
        self.session.capabilities = {}
        (self.mount / "fallback").write_text("old transport")
        status, body = self.api("/fs/query/list?path=laptop")
        self.assertEqual(409, status, body)
        self.assertEqual("mapping_rpc_unsupported", body["error"]["code"])
        self.assertEqual([], self.calls)

        self.session.capabilities = {"file_api": {"version": 4, "operations": sorted(FILE_API_OPERATIONS)}}
        status, body = self.api("/fs/write/mutate", {"items": [{"op": "file.create", "path": "laptop/a", "content": "once"}]})
        self.assertEqual(409, status, body)
        self.assertEqual("mapping_rpc_unsupported", body["error"]["code"])
        self.assertEqual("not_advertised", body["error"]["details"]["reason"])
        self.assertEqual([], self.calls)

        self.session.capabilities = {"rpc": {"file": {
            "state": "available",
            "version": 4,
            "operations": sorted(FILE_API_OPERATIONS),
        }}}
        original = self.session.call
        def ambiguous(op, args):
            original(op, args)
            raise OSError(errno.ETIMEDOUT, "result unknown")
        with patch.object(self.session, "call", side_effect=ambiguous):
            status, _ = self.api("/fs/write/mutate", {"items": [{"op": "file.create", "path": "laptop/a", "content": "once"}]})
        self.assertEqual(503, status)
        self.assertEqual(1, len(self.calls))
        self.assertEqual("api_fs_mutate", self.calls[0][0])
        self.assertEqual("once", (self.export / "a").read_text())
        self.assertFalse((self.mount / "a").exists())

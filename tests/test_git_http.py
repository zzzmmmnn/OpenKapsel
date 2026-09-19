"""Read-only Git REST/MCP and mapping RPC authorization."""
import json
import os
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace
from openkapsel.client_files import ClientFiles
from tests import test_oauth
from tests.test_git_operations import make_repo


@unittest.skipIf(os.name == "nt" or not shutil.which("git"), "POSIX server and Git required")
class GitHTTPTests(unittest.TestCase):
    request = test_oauth.OAuthHTTPTests.request

    def setUp(self):
        test_oauth.OAuthHTTPTests.setUp(self)
        self.record = self.server.tokens.update(self.record.token, can_write=False, shell_mode="none")
        self.base = "/kapsel/w/" + self.record.token
        self.root = self.server.config.root / self.record.path_prefix
        make_repo(self.root)

    def tearDown(self):
        test_oauth.OAuthHTTPTests.tearDown(self)

    def test_read_url_git_and_readonly_mcp_tools(self):
        for op in ("status", "diff", "log", "show", "ls_files", "diff_stat"):
            status, _, raw = self.request("GET", self.base + "/git/" + op)
            self.assertEqual(200, status, raw)
        conn = self.server.static_mcp.create(self.record.app_id, "project", "Reads")
        for name, args in (("git_log", {}), ("read_files", {"paths": ["source.txt"]}),
                           ("file_manifest", {"recursive": True, "depth": 1}),
                           ("search_files", {"query": "original", "include": ["*.txt"], "exclude": [".git"]})):
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
            _, _, raw = self.request("POST", "/kapsel/mcp-connect/" + conn["id"] + "/mcp", json.dumps(body),
                                    {"Authorization": "Bearer " + conn["secret"], "Content-Type": "application/json"})
            self.assertFalse(json.loads(raw)["result"]["isError"], raw)
        self.server.tokens.update(self.record.token, can_read=False)
        self.assertEqual(403, self.request("GET", self.base + "/git/status")[0])

    def test_mapping_git_one_rpc_without_exec_or_write(self):
        export = Path(self.temp.name) / "export"
        export.mkdir()
        make_repo(export)
        files = ClientFiles(export, writable=False)
        row, _ = self.server.mappings.store.create(self.record.path_prefix, "laptop", writable=False, allow_exec=False)
        calls = []
        def call(op, args):
            calls.append(op)
            return files.dispatch(op, args)
        session = SimpleNamespace(closed=False, capabilities={"git_api": {"version": 2, "read_only": True}}, call=call)
        self.server.mappings.sessions[row["id"]] = session
        try:
            status, _, raw = self.request("GET", self.base + "/git/log?path=laptop")
            self.assertEqual(200, status, raw)
            self.assertEqual(["git_log"], calls)
            self.assertIn("Initial fixture", json.loads(raw)["output"])
            session.capabilities = {"git_api": {"version": 1, "enabled": True}}
            self.assertEqual(409, self.request("GET", self.base + "/git/status?path=laptop")[0])
            self.assertEqual(["git_log"], calls)
        finally:
            self.server.mappings.sessions.clear()
            self.server.mappings.store.delete(row["id"])
            files.close()

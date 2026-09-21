"""Real REST/MCP batch creation and backward-compatible permission tests."""
from __future__ import annotations

import json
import http.client
import unittest
from unittest.mock import patch

from openkapsel.errors import ApiError
from openkapsel.server import WorkspaceRequestHandler
from tests import test_oauth as fixture


class PlanCreationHTTPTests(unittest.TestCase):
    request = fixture.OAuthHTTPTests.request
    tearDown = fixture.OAuthHTTPTests.tearDown

    def setUp(self):
        fixture.OAuthHTTPTests.setUp(self)
        connection = self.server.static_mcp.create(self.record.app_id, "project", "Plan tests")
        self.mcp = "/kapsel/mcp-connect/" + connection["id"] + "/mcp"
        self.secret = connection["secret"]
        self.store = self.server.context_for(self.server.config.root / "project")
        self.body = {"type": "plan", "taskname": "feature", "content": "Implement the feature", "subplans": [
            {"ref": "code", "content": "Implement", "scope_paths": ["src"]},
            {"ref": "tests", "content": "Verify", "memory_tags": ["tests"]},
        ]}

    @property
    def base(self):
        return "/kapsel/w/" + self.record.token

    def rest(self, method, suffix, body=None, *, authorized=True):
        headers = {"Content-Type": "application/json"}
        if authorized:
            headers["Authorization"] = "Bearer " + self.record.control_token
        status, _, raw = self.request(method, self.base + suffix, json.dumps(body) if body is not None else None, headers)
        return status, json.loads(raw)

    def mcp_call(self, method, params=None, *, request_number=1):
        body = {"jsonrpc": "2.0", "id": request_number, "method": method}
        if params is not None:
            body["params"] = params
        status, _, raw = self.request("POST", self.mcp, json.dumps(body), {
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25", "Authorization": "Bearer " + self.secret,
        })
        return status, json.loads(raw)

    def count(self):
        return self.store.query(limit=200)[1]

    def test_rest_creates_one_tree_and_one_merged_memory_hint(self):
        previous = self.store.add("plan", "Earlier unfinished root", taskname="earlier")
        self.store.add("plan", "Earlier child", taskname="earlier", plan_id=previous)
        memory = self.server.memory_for(self.server.config.root / "project")
        related = memory.create(category="convention", title="Relevant source tests", content="Test source changes", tags=["tests"], paths=["src"], plan_id=previous)
        with patch.object(memory, "related", wraps=memory.related) as lookup:
            status, created = self.rest("POST", "/context", self.body)
        self.assertEqual(201, status, created)
        lookup.assert_called_once()
        self.assertEqual([related["memory_id"]], [m["memory_id"] for m in created["related_memory"]])
        self.assertEqual([previous], [p["id"] for p in created["unfinished_root_plans"]])
        self.assertEqual(2, len(created["subplans"]))
        self.assertTrue(all("related_memory" not in c and "content" not in c for c in created["subplans"]))
        status, tree = self.rest("GET", f'/context/plans/{created["id"]}/tree')
        self.assertEqual(200, status)
        self.assertEqual([0, 1, 1], [p["depth"] for p in tree["plans"]])
        child = created["subplans"][0]["id"]
        status, written = self.rest("POST", "/fs/write", {"path": "batch.txt", "content": "works", "plan_id": child, "taskname": "feature", "message": "Use the returned child ID"})
        self.assertIn(status, (200, 201), written)
        status, tree = self.rest("GET", f'/context/plans/{created["id"]}/tree')
        self.assertTrue(any(e["plan_id"] == child and e["type"] == "operation" for e in tree["entries"]))

    def test_rest_and_mcp_share_retry_ids_without_repeating_creations(self):
        body = dict(self.body, request_id="cross-protocol")
        status, first = self.rest("POST", "/context", body)
        self.assertEqual(201, status, first)
        self.assertFalse(first["replayed"])
        status, replay = self.rest("POST", "/context", body)
        self.assertEqual(200, status, replay)
        self.assertTrue(replay["replayed"])
        status, rpc = self.mcp_call("tools/call", {"name": "add_context", "arguments": body}, request_number=99)
        self.assertEqual(200, status, rpc)
        self.assertFalse(rpc["result"]["isError"], rpc)
        result = rpc["result"]["structuredContent"]
        self.assertTrue(result["replayed"])
        self.assertEqual(first["id"], result["id"])
        self.assertEqual(first["subplans"], result["subplans"])
        self.assertEqual(3, self.count())
        status, bad = self.rest("POST", "/context", dict(body, content="Different"))
        self.assertEqual(409, status, bad)
        self.assertEqual("context_request_conflict", bad["error"]["code"])
        status, rpc = self.mcp_call("tools/call", {"name": "add_context", "arguments": dict(body, content="Different")})
        self.assertTrue(rpc["result"]["isError"], rpc)
        self.assertEqual("context_request_conflict", rpc["result"]["structuredContent"]["error"]["code"])
        self.assertEqual(3, self.count())

    def test_lost_http_response_recovers_original_batch_instead_of_duplicating_it(self):
        body = dict(self.body, request_id="lost-response")
        send = WorkspaceRequestHandler._send_json
        receipts = []
        def drop_reply(handler, status, payload, *args, **kwargs):
            if handler.path.endswith("/context") and payload.get("request_id") == "lost-response":
                receipts.append(payload)
                handler.close_connection = True
                return  # The transaction committed; deliberately send no HTTP response.
            return send(handler, status, payload, *args, **kwargs)
        with patch.object(WorkspaceRequestHandler, "_send_json", drop_reply):
            with self.assertRaises(http.client.RemoteDisconnected):
                self.rest("POST", "/context", body)
        self.assertEqual(1, len(receipts))
        self.assertEqual(3, self.count())
        status, replay = self.rest("POST", "/context", body)
        self.assertEqual(200, status, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(receipts[0]["id"], replay["id"])
        self.assertEqual(receipts[0]["subplans"], replay["subplans"])
        self.assertEqual(3, self.count())

    def test_retry_survives_control_credential_rotation(self):
        body = dict(self.body, request_id="rotate-credentials")
        status, first = self.rest("POST", "/context", body)
        self.assertEqual(201, status, first)
        original_actor = self.record.actor_id
        self.server.tokens.renew_credentials(self.record.token)
        self.record = self.server.tokens.get_by_app_id(self.record.app_id)
        self.assertEqual(original_actor, self.record.actor_id)
        status, replay = self.rest("POST", "/context", body)
        self.assertEqual(200, status, replay)
        self.assertEqual(first["id"], replay["id"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(3, self.count())

    def test_mcp_creation_and_nested_item_validation(self):
        status, reply = self.mcp_call("tools/call", {"name": "add_context", "arguments": self.body})
        self.assertEqual(200, status, reply)
        result = reply["result"]["structuredContent"]
        self.assertEqual(["code", "tests"], [c["ref"] for c in result["subplans"]])
        self.assertEqual(["feature", "feature"], [c["taskname"] for c in result["subplans"]])
        count = self.count()
        for child in ("not-an-object", {"content": "x", "plan_id": result["id"]}, {"content": "x", "subplans": []}, {"content": " "}):
            status, reply = self.mcp_call("tools/call", {"name": "add_context", "arguments": dict(self.body, subplans=[child])})
            self.assertTrue(reply["result"]["isError"], reply)
            self.assertEqual(count, self.count())

    def test_all_invalid_metadata_fails_before_any_plan_is_inserted(self):
        for fields in ({"scope_paths": ["/outside"]}, {"memory_tags": [None]},
                       {"subplans": [{"content": "valid"}, {"content": "invalid", "taskname": "x" * 33}]},
                       {"subplans": None}, {"request_id": None}):
            status, error = self.rest("POST", "/context", dict(self.body, **fields))
            self.assertEqual(400, status, error)
            self.assertEqual(0, self.count())
        memory = self.server.memory_for(self.server.config.root / "project")
        with patch.object(memory, "related", side_effect=ApiError(503, "memory_unavailable", "test failure")):
            status, error = self.rest("POST", "/context", self.body)
        self.assertEqual(503, status, error)
        self.assertEqual(0, self.count())

    def test_control_permission_is_unchanged_and_notes_remain_single_entries(self):
        status, denied = self.rest("POST", "/context", self.body, authorized=False)
        self.assertEqual(401, status, denied)
        self.assertEqual(0, self.count())
        self.server.tokens.update(self.record.token, can_write=False, shell_mode="none")
        status, created = self.rest("POST", "/context", self.body)
        self.assertEqual(201, status, created)
        note = {"type": "note", "content": "A note", "taskname": "feature", "plan_id": created["id"]}
        for extra in ({"subplans": []}, {"request_id": "notes-not-supported"}):
            status, denied = self.rest("POST", "/context", dict(note, **extra))
            self.assertEqual(400, status, denied)
        self.assertEqual(3, self.count())
        status, saved = self.rest("POST", "/context", note)
        self.assertEqual(201, status, saved)
        self.assertEqual("note", saved["type"])
        self.assertNotIn("subplans", saved)
        status, singleton = self.rest("POST", "/context", {"type": "plan", "taskname": "old-client", "content": "Legacy singleton"})
        self.assertEqual(201, status, singleton)
        self.assertEqual([], singleton["subplans"])
        self.assertNotIn("replayed", singleton)

    def test_discovery_and_mcp_publish_matching_extension_schemas(self):
        status, discovery = self.rest("GET", "/discovery/context")
        self.assertEqual(200, status, discovery)
        creation = discovery["capabilities"]["context"]["plan_creation"]
        self.assertTrue(creation["atomic_subplans"])
        self.assertEqual(64, creation["max_direct_subplans"])
        status, listed = self.mcp_call("tools/list")
        self.assertEqual(200, status, listed)
        tool = next(t for t in listed["result"]["tools"] if t["name"] == "add_context")
        schema = tool["inputSchema"]["properties"]
        for name, extension in discovery["endpoints"]["context_add"]["plan_extension_schema"].items():
            self.assertEqual(extension, schema[name])
        self.assertFalse(schema["subplans"]["items"]["additionalProperties"])
        self.assertEqual(["content"], schema["subplans"]["items"]["required"])
        self.assertFalse(tool["annotations"]["idempotentHint"])


if __name__ == "__main__":
    unittest.main()

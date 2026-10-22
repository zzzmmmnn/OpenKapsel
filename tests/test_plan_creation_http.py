"""Real REST/MCP batch creation and backward-compatible permission tests."""
from __future__ import annotations

import copy

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
        conversation = self.store.create_conversation(
            self.store.conversation_query()[2],
            [
                {"role": "user", "content": "User requests the feature test Plan."},
                {"role": "ai", "content": "AI will create and verify the feature Plan."},
            ]
        )
        self.conversation_id = conversation["conversation_id"]
        self.writer_nonce = conversation["writer_nonce"]
        self.body = {
            "type": "plan",
            "taskname": "feature",
            "content": "Implement the feature",
            "conversation_id": self.conversation_id,
            "writer_nonce": self.writer_nonce,
            "conversation_entries": [
                {"role": "ai", "content": "AI creates this feature Plan batch."}
            ],
            "todos": [
                {"ref": "code", "content": "Implement", "scope_paths": ["src"]},
                {"ref": "tests", "content": "Verify", "memory_tags": ["tests"]},
            ],
        }

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
        related = memory.create(content="Test source changes", tags=["tests", "source", "plan", "relevance"], path="server:src", plan_id=previous)
        with patch.object(memory, "related", wraps=memory.related) as lookup:
            status, created = self.rest("POST", "/context", self.body)
        self.assertEqual(201, status, created)
        lookup.assert_called_once()
        self.assertEqual([related["memory_id"]], [m["memory_id"] for m in created["related_memory"]])
        self.assertEqual([previous], [p["id"] for p in created["unfinished_root_plans"]])
        self.assertEqual(2, len(created["todos"]))
        self.assertTrue(all("related_memory" not in c and "content" not in c for c in created["todos"]))
        status, tree = self.rest("GET", f'/context/plans/{created["id"]}/tree')
        self.assertEqual(200, status)
        self.assertEqual([0, 1, 1], [p["depth"] for p in tree["plans"]])
        child = created["todos"][0]["id"]
        status, written = self.rest("POST", "/fs/write/mutate", {"items": [{"op": "file.create", "path": "batch.txt", "content": "works"}], "plan_id": child, "taskname": "feature", "message": "Use the returned child ID"})
        self.assertEqual(200, status, written)
        status, tree = self.rest("GET", f'/context/plans/{created["id"]}/tree')
        self.assertTrue(any(e["plan_id"] == child and e["type"] == "operation" for e in tree["entries"]))

    def test_rest_legacy_subplans_alias_replays_as_todos_across_protocols(self):
        legacy = dict(self.body, request_id="legacy-rest-alias")
        legacy["subplans"] = legacy.pop("todos")
        status, created = self.rest("POST", "/context", legacy)
        self.assertEqual(201, status, created)
        self.assertEqual(["code", "tests"], [item["ref"] for item in created["todos"]])
        self.assertNotIn("subplans", created)
        modern = dict(self.body, request_id="legacy-rest-alias")
        status, replay = self.rest("POST", "/context", modern)
        self.assertEqual(200, status, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(created["todos"], replay["todos"])
        status, rpc = self.mcp_call("tools/call", {"name": "context_add", "arguments": modern})
        self.assertEqual(200, status, rpc)
        self.assertFalse(rpc["result"]["isError"], rpc)
        self.assertTrue(rpc["result"]["structuredContent"]["replayed"])
        self.assertEqual(created["id"], rpc["result"]["structuredContent"]["id"])
        self.assertEqual(3, self.count())

    def test_rest_rejects_both_todo_names_and_mcp_rejects_legacy_field(self):
        for old_value in ([], [{"content": "Legacy step"}], None):
            with self.subTest(old_value=old_value):
                both = dict(self.body, subplans=old_value)
                status, error = self.rest("POST", "/context", both)
                self.assertEqual(400, status, error)
                self.assertEqual("invalid_context_entry", error["error"]["code"])
                self.assertIn("either todos or subplans", error["error"]["message"])
                self.assertEqual(0, self.count())
        old = dict(self.body)
        old["subplans"] = old.pop("todos")
        status, rpc = self.mcp_call("tools/call", {"name": "context_add", "arguments": old})
        self.assertEqual(200, status, rpc)
        if "error" in rpc:
            self.assertEqual(-32602, rpc["error"]["code"])
        else:
            self.assertTrue(rpc["result"]["isError"], rpc)
        self.assertEqual(0, self.count())

    def test_rest_and_mcp_complete_todos_through_normal_plan_update(self):
        status, created = self.rest("POST", "/context", self.body)
        self.assertEqual(201, status, created)
        self.assertEqual(2, len(created["todos"]))
        finish = {
            "taskname": "feature", "expected_revision": 1, "status": "completed",
            "conversation_id": self.conversation_id, "writer_nonce": self.writer_nonce,
            "conversation_entries": [{"role": "ai", "content": "Verified todo step."}],
            "debrief": {"items": [], "outcome": "succeeded", "memory_actions": [],
                        "memory_feedback": [], "memory_conflicts": []},
        }
        status, root_error = self.rest("PATCH", f"/context/plans/{created['id']}", finish)
        self.assertEqual(400, status, root_error)
        first, second = (node["id"] for node in created["todos"])
        status, completed = self.rest("PATCH", f"/context/plans/{first}", finish)
        self.assertEqual(200, status, completed)
        self.assertEqual("completed", completed["status"])
        self.assertEqual(first, completed["id"])
        self.assertEqual(2, completed["revision"])
        status, rpc = self.mcp_call("tools/call", {
            "name": "context_plan_update", "arguments": dict(finish, id=second),
        })
        self.assertEqual(200, status, rpc)
        self.assertFalse(rpc["result"]["isError"], rpc)
        self.assertEqual("completed", rpc["result"]["structuredContent"]["status"])
        status, root = self.rest("PATCH", f"/context/plans/{created['id']}", finish)
        self.assertEqual(200, status, root)
        self.assertEqual("completed", root["status"])

    def test_rest_and_mcp_share_retry_ids_without_repeating_creations(self):
        body = dict(self.body, request_id="cross-protocol")
        status, first = self.rest("POST", "/context", body)
        self.assertEqual(201, status, first)
        self.assertFalse(first["replayed"])
        status, replay = self.rest("POST", "/context", body)
        self.assertEqual(200, status, replay)
        self.assertTrue(replay["replayed"])
        status, rpc = self.mcp_call("tools/call", {"name": "context_add", "arguments": body}, request_number=99)
        self.assertEqual(200, status, rpc)
        self.assertFalse(rpc["result"]["isError"], rpc)
        result = rpc["result"]["structuredContent"]
        self.assertTrue(result["replayed"])
        self.assertEqual(first["id"], result["id"])
        self.assertEqual(first["todos"], result["todos"])
        self.assertEqual(3, self.count())
        status, bad = self.rest("POST", "/context", dict(body, content="Different"))
        self.assertEqual(409, status, bad)
        self.assertEqual("context_request_conflict", bad["error"]["code"])
        status, rpc = self.mcp_call("tools/call", {"name": "context_add", "arguments": dict(body, content="Different")})
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
        self.assertEqual(receipts[0]["todos"], replay["todos"])
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
        status, reply = self.mcp_call("tools/call", {"name": "context_add", "arguments": self.body})
        self.assertEqual(200, status, reply)
        result = reply["result"]["structuredContent"]
        self.assertEqual(["code", "tests"], [c["ref"] for c in result["todos"]])
        self.assertEqual(["feature", "feature"], [c["taskname"] for c in result["todos"]])
        count = self.count()
        for child in ("not-an-object", {"content": "x", "plan_id": result["id"]}, {"content": "x", "todos": []}, {"content": " "}):
            status, reply = self.mcp_call("tools/call", {"name": "context_add", "arguments": dict(self.body, todos=[child])})
            self.assertTrue(reply["result"]["isError"], reply)
            self.assertEqual(count, self.count())

    def test_plan_explicit_status_is_rejected_by_rest_and_mcp(self):
        bodies = [
            dict(self.body, status="completed"),
            dict(self.body, todos=[{"content": "Child", "status": "cancelled"}]),
        ]
        for index, body in enumerate(bodies):
            with self.subTest(protocol="rest", case=index):
                status, error = self.rest("POST", "/context", body)
                self.assertEqual(400, status, error)
                self.assertIn("does not accept status", error["error"]["message"])
                self.assertEqual(0, self.count())
            with self.subTest(protocol="mcp", case=index):
                status, reply = self.mcp_call(
                    "tools/call",
                    {"name": "context_add", "arguments": body},
                )
                self.assertEqual(200, status, reply)
                if index == 0:
                    self.assertEqual(-32602, reply["error"]["code"])
                else:
                    self.assertTrue(reply["result"]["isError"], reply)
                    self.assertIn(
                        "does not accept status",
                        reply["result"]["structuredContent"]["error"]["message"],
                    )
                self.assertEqual(0, self.count())

    def test_all_invalid_metadata_fails_before_any_plan_is_inserted(self):
        for fields in ({"scope_paths": ["/outside"]}, {"memory_tags": [None]},
                       {"todos": [{"content": "valid"}, {"content": "invalid", "taskname": "x" * 33}]},
                       {"todos": None}, {"request_id": None}):
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
        for extra in ({"todos": []}, {"request_id": "notes-not-supported"}):
            status, denied = self.rest("POST", "/context", dict(note, **extra))
            self.assertEqual(400, status, denied)
        self.assertEqual(3, self.count())
        status, saved = self.rest("POST", "/context", note)
        self.assertEqual(201, status, saved)
        self.assertEqual("note", saved["type"])
        self.assertNotIn("todos", saved)
        singleton_body = {
            "type": "plan",
            "taskname": "singleton",
            "content": "Conversation-owned singleton",
            "conversation_id": self.conversation_id,
            "writer_nonce": self.writer_nonce,
            "conversation_entries": [
                {"role": "ai", "content": "AI creates the singleton Plan."}
            ],
        }
        status, missing = self.rest("POST", "/context", singleton_body)
        self.assertEqual(400, status, missing)
        self.assertIn("root plan creation requires todos", missing["error"]["message"])

        status, singleton = self.rest(
            "POST",
            "/context",
            dict(singleton_body, todos=[]),
        )
        self.assertEqual(201, status, singleton)
        self.assertEqual([], singleton["todos"])
        self.assertNotIn("replayed", singleton)

    def test_completed_plan_is_immutable_over_rest_and_mcp(self):
        # A terminal Plan cannot be reopened, edited, or cancelled through
        # either public adapter. Its existing completion debrief is preserved.
        status, created = self.rest("POST", "/context", dict(self.body, todos=[]))
        self.assertEqual(201, status, created)
        finish = {
            "taskname": "feature",
            "expected_revision": created["revision"],
            "status": "completed",
            "conversation_id": self.conversation_id,
            "writer_nonce": self.writer_nonce,
            "conversation_entries": [{"role": "ai", "content": "This Plan is finished."}],
            "debrief": {"items": [], "outcome": "succeeded",
                        "memory_actions": [], "memory_feedback": [], "memory_conflicts": []},
        }
        status, done = self.rest("PATCH", f"/context/plans/{created['id']}", finish)
        self.assertEqual(200, status, done)
        self.assertEqual("completed", done["status"])
        self.assertEqual(2, done["revision"])
        before = self.store.query(entry_id=created["id"])[0][0]
        for args in (
            {"status": "in_progress"},
            {"status": "cancelled"},
            {"content": "Change completed content"},
            {"status": "completed", "debrief": finish["debrief"]},
        ):
            request = {k: v for k, v in finish.items() if k != "status" and k != "debrief"}
            request["expected_revision"] = done["revision"]
            request.update(args)
            expected_error = ("plan is already completed" if args.get("status") == "completed"
                              else "completed plan cannot be modified")
            with self.subTest(adapter="rest", args=args):
                status, error = self.rest("PATCH", f"/context/plans/{created['id']}", request)
                self.assertEqual(400, status, error)
                self.assertEqual("invalid_context_entry", error["error"]["code"])
                self.assertIn(expected_error, error["error"]["message"])
            with self.subTest(adapter="mcp", args=args):
                rpc = dict(request, id=created["id"])
                status, reply = self.mcp_call("tools/call",
                    {"name": "context_plan_update", "arguments": rpc})
                self.assertEqual(200, status, reply)
                self.assertTrue(reply["result"]["isError"], reply)
                self.assertIn(expected_error,
                    reply["result"]["structuredContent"]["error"]["message"])
        self.assertEqual(before, self.store.query(entry_id=created["id"])[0][0])
        self.assertEqual("succeeded", self.store.plan_debrief(created["id"])["outcome"])

    def test_discovery_and_mcp_publish_matching_extension_schemas(self):
        status, discovery = self.rest("GET", "/discovery/context")
        self.assertEqual(200, status, discovery)
        creation = discovery["capabilities"]["context"]["plan_creation"]
        self.assertIn("context_plan_update", creation["todo_completion"])
        self.assertIn("PATCH /context/plans/<todo_id>", creation["todo_completion"])
        self.assertIn("debrief", creation["todo_completion"])
        self.assertTrue(creation["atomic_todos"])
        self.assertEqual(64, creation["max_direct_todos"])
        self.assertTrue(creation["creation_status_must_be_omitted"])
        self.assertEqual("in_progress", creation["creation_status_initial"])
        self.assertTrue(creation["subplan_root_immutable"])
        self.assertTrue(creation["subplan_creation_requires_in_progress_root"])
        self.assertTrue(
            discovery["capabilities"]["context"][
                "plan_completion_requires_no_in_progress_descendants"
            ]
        )
        status, listed = self.mcp_call("tools/list")
        self.assertEqual(200, status, listed)
        tool = next(t for t in listed["result"]["tools"] if t["name"] == "context_add")
        schema = tool["inputSchema"]["properties"]
        self.assertNotIn("status", schema)
        for name, extension in discovery["endpoints"]["context"]["operations"]["add"]["plan_extension_schema"].items():
            if name == "conversation_entries":
                # MCP tools/list omits duplicated prose; Discovery retains the full contract.
                extension = copy.deepcopy(extension)
                extension["items"]["properties"]["content"].pop("description", None)
            self.assertEqual(extension, schema[name])
        self.assertNotIn("subplans", schema)
        self.assertNotIn('"subplans"', json.dumps(discovery, ensure_ascii=False))
        self.assertIn("actionable todo checklist", schema["todos"]["description"])
        self.assertIn("executable action", schema["todos"]["items"]["properties"]["content"]["description"])
        self.assertFalse(schema["todos"]["items"]["additionalProperties"])
        self.assertEqual(["content"], schema["todos"]["items"]["required"])
        self.assertNotIn("status", schema["todos"]["items"]["properties"])
        self.assertFalse(tool["annotations"]["idempotentHint"])


if __name__ == "__main__":
    unittest.main()

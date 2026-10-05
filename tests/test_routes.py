from __future__ import annotations

import unittest

from openkapsel.api.mcp import ALL_TOOLS, tools_for
from openkapsel.context.memory_contracts import memory_actions_schema
from openkapsel.routes import ENDPOINTS, discovery_keys, match_endpoint
from openkapsel.auth.tokens import TokenRecord


class EndpointContractTests(unittest.TestCase):
    def test_method_patterns_are_unique_and_context_metadata_is_complete(self) -> None:
        seen: set[tuple[str, str]] = set()
        for endpoint in ENDPOINTS:
            self.assertTrue(endpoint.methods)
            self.assertTrue(endpoint.handler.startswith("_handle_"))
            self.assertIsNotNone(endpoint.discovery_key)
            for method in endpoint.methods:
                identity = (method, endpoint.pattern.pattern)
                self.assertNotIn(identity, seen)
                seen.add(identity)
                if endpoint.context_mode != "none":
                    self.assertIsNotNone(endpoint.context_operation(method))
            if endpoint.context_mode in {"deferred", "header"}:
                self.assertTrue(endpoint.control_required)

    def test_matching_covers_exact_and_parameterized_routes(self) -> None:
        cases = {
            ("GET", "/discovery/files"): (
                "discovery_section",
                {"section": "files"},
            ),
            ("POST", "/fs/read/files"): ("fs_read_files", {}),
            ("PUT", "/env"): ("environment_replace", {}),
            ("PUT", "/fs/content"): ("fs_content_put", {}),
            ("PATCH", "/upload/chunk/upload_123"): (
                "upload_chunk",
                {"upload_id": "upload_123"},
            ),
            ("POST", "/upload/cancel/upload_123"): (
                "upload_cancel",
                {"upload_id": "upload_123"},
            ),
            ("POST", "/upload/commit/upload_123"): (
                "upload_commit",
                {"upload_id": "upload_123"},
            ),
            ("GET", "/context/plans/42/tree"): (
                "context_plan_tree",
                {"context_id": "42"},
            ),
            ("GET", "/memory/project"): ("memory_project", {}),
            ("GET", "/memory/mem_abc/revisions"): (
                "memory_revisions",
                {"memory_id": "mem_abc"},
            ),
            ("PATCH", "/memory/mem_abc"): (
                "memory_item_mutate",
                {"memory_id": "mem_abc"},
            ),
            ("DELETE", "/task/task_abc"): (
                "task_kill",
                {"task_id": "task_abc"},
            ),
            ("POST", "/schedule/execute/schedule_abc"): (
                "schedule_execute",
                {"schedule_id": "schedule_abc"},
            ),
            ("POST", "/schedule/pause/schedule_abc"): (
                "schedule_pause",
                {"schedule_id": "schedule_abc"},
            ),
            ("POST", "/schedule/resume/schedule_abc"): (
                "schedule_resume",
                {"schedule_id": "schedule_abc"},
            ),
            ("GET", "/schedule/run/list/schedule_abc"): (
                "schedule_run_list",
                {"schedule_id": "schedule_abc"},
            ),
            ("GET", "/schedule/run/run_abc"): (
                "schedule_run_get",
                {"run_id": "run_abc"},
            ),
            ("GET", "/fs/transfer/abcdefghijklmnopqrstuvwx"): (
                "file_transfer",
                {"target": "abcdefghijklmnopqrstuvwx"},
            ),
            ("POST", "/fs/transfer/cancel/abcdefghijklmnopqrstuvwx"): (
                "file_transfer",
                {"target": "cancel/abcdefghijklmnopqrstuvwx"},
            ),
            ("POST", "/fs/transfer/resume/abcdefghijklmnopqrstuvwx"): (
                "file_transfer",
                {"target": "resume/abcdefghijklmnopqrstuvwx"},
            ),
        }
        for request, expected in cases.items():
            with self.subTest(request=request):
                matched = match_endpoint(*request)
                self.assertIsNotNone(matched)
                endpoint, route_match = matched
                self.assertEqual(expected[0], endpoint.name)
                self.assertEqual(expected[1], route_match.groupdict())
        self.assertIsNone(match_endpoint("GET", "/fs/read/text"))
        self.assertIsNone(match_endpoint("DELETE", "/share/delete/share_abc"))
        self.assertIsNone(match_endpoint("DELETE", "/upload/cancel/upload_123"))
        self.assertIsNone(match_endpoint("POST", "/task/kill/task_abc"))
        self.assertIsNone(match_endpoint("POST", "/schedule/schedule_abc/run"))
        self.assertIsNone(match_endpoint("POST", "/schedule/schedule_abc/pause"))
        self.assertIsNone(match_endpoint("POST", "/schedule/schedule_abc/resume"))
        self.assertIsNone(match_endpoint("GET", "/schedule/schedule_abc/runs"))
        self.assertIsNone(match_endpoint("POST", "/fs/transfer/abcdefghijklmnopqrstuvwx/cancel"))
        self.assertIsNone(match_endpoint("POST", "/fs/transfer/abcdefghijklmnopqrstuvwx/resume"))
        self.assertIsNone(match_endpoint("GET", "/uploads/a"))
        self.assertIsNone(match_endpoint("GET", "/mapping/abcdefghijklmnopqrstuvwx/tasks"))
        self.assertIsNone(match_endpoint("POST", "/mapping/abcdefghijklmnopqrstuvwx/tasks/task_abc/kill"))

    def test_every_routed_endpoint_has_a_discovery_key(self) -> None:
        self.assertEqual(
            {endpoint.discovery_key for endpoint in ENDPOINTS},
            set(discovery_keys()),
        )

    def test_mcp_update_plan_uses_shared_memory_action_contract(self) -> None:
        update_plan = next(tool for tool in ALL_TOOLS if tool["name"] == "context_plan_update")
        self.assertEqual(
            {"id", "expected_revision", "taskname"},
            set(update_plan["inputSchema"]["required"]),
        )
        actual = update_plan["inputSchema"]["properties"]["debrief"]["properties"]
        self.assertEqual(memory_actions_schema(), actual["memory_actions"])

        variants = actual["memory_actions"]["items"]["oneOf"]
        update = next(item for item in variants if item["properties"]["action"]["const"] == "update")
        self.assertEqual(
            {"action", "memory_id", "expected_revision"},
            set(update["required"]),
        )
        self.assertEqual(4, update["minProperties"])
        self.assertNotIn("anyOf", update)
        self.assertEqual(
            {"action", "memory_id", "expected_revision", "content", "tags", "path"},
            set(update["properties"]),
        )

    def test_discovery_exposes_discovery_sections(self) -> None:
        tool = next(tool for tool in ALL_TOOLS if tool["name"] == "discovery")
        section = tool["inputSchema"]["properties"]["section"]
        self.assertEqual(
            {"main", "files", "context", "memory", "shell", "schedules", "web", "sharing", "full"},
            set(section["enum"]),
        )

    def test_schedule_mcp_tools_require_separate_permission_and_shell(self) -> None:
        base = dict(token="read", name="test", created_at="2026-01-01T00:00:00+00:00")
        names = {
            tool["name"]
            for tool in tools_for(
                TokenRecord(**base, shell_mode="restricted", can_schedule=True),
                True,
            )
        }
        self.assertTrue({"schedule_read", "schedule_write", "schedule_control"} <= names)
        disabled = {
            tool["name"]
            for tool in tools_for(
                TokenRecord(**base, shell_mode="restricted", can_schedule=False),
                True,
            )
        }
        self.assertTrue(
            {"schedule_read", "schedule_write", "schedule_control"}.isdisjoint(disabled)
        )


if __name__ == "__main__":
    unittest.main()

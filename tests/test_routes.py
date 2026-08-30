from __future__ import annotations

import unittest

from openkapsel.mcp import ALL_TOOLS
from openkapsel.memory_contracts import memory_actions_schema
from openkapsel.routes import ENDPOINTS, discovery_keys, match_endpoint


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
            ("GET", "/fs/read"): ("fs_read", {}),
            ("PUT", "/fs/content"): ("fs_content_put", {}),
            ("PATCH", "/uploads/upload_123"): (
                "upload_chunk",
                {"upload_id": "upload_123"},
            ),
            ("POST", "/uploads/upload_123/commit"): (
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
            ("POST", "/tasks/task_abc/kill"): (
                "task_kill",
                {"task_id": "task_abc"},
            ),
        }
        for request, expected in cases.items():
            with self.subTest(request=request):
                matched = match_endpoint(*request)
                self.assertIsNotNone(matched)
                endpoint, route_match = matched
                self.assertEqual(expected[0], endpoint.name)
                self.assertEqual(expected[1], route_match.groupdict())
        self.assertIsNone(match_endpoint("POST", "/fs/read"))
        self.assertIsNone(match_endpoint("GET", "/uploads/a/extra"))

    def test_every_routed_endpoint_has_a_discovery_key(self) -> None:
        self.assertEqual(
            {endpoint.discovery_key for endpoint in ENDPOINTS},
            set(discovery_keys()),
        )

    def test_mcp_update_plan_uses_shared_memory_action_contract(self) -> None:
        update_plan = next(tool for tool in ALL_TOOLS if tool["name"] == "update_plan")
        actual = update_plan["inputSchema"]["properties"]["debrief"]["properties"]
        self.assertEqual(memory_actions_schema(), actual["memory_actions"])

    def test_workspace_info_exposes_discovery_sections(self) -> None:
        tool = next(tool for tool in ALL_TOOLS if tool["name"] == "workspace_info")
        section = tool["inputSchema"]["properties"]["section"]
        self.assertEqual(
            {"main", "files", "context", "memory", "shell", "web", "sharing", "full"},
            set(section["enum"]),
        )


if __name__ == "__main__":
    unittest.main()

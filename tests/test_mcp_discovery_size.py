"""Size budgets for what an MCP client loads: tools/list, instructions and Discovery.

Sizes are UTF-8 bytes of compact JSON as served through the MCP endpoint, taking
the larger of a no-Shell and a full-Shell Token. Discovery is measured per
section; the full document is not budgeted. MCP tools are grouped by the name
prefix before the first underscore (fs_*, context_*, ...).

When a budget fails, shrink the text first. Raise a budget only for content that
must grow, and keep it about 5% above the new size.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from openkapsel.api.discovery_sections import SECTION_NAMES
from tests import test_oauth

MCP_BUDGETS = {
    "instructions": 1_200,
    "tools_list": 44_900,
    "tools:fs": 18_800,
    "tools:context": 11_600,
    "tools:memory": 4_700,
    "tools:conversation": 4_100,
    "tools:rpc": 2_100,
    "tools:recycle": 1_600,
    "tools:capability": 1_500,
    "tools:discovery": 900,
}

DISCOVERY_BUDGETS = {
    "main": 3_500,
    "files": 14_200,
    "context": 9_200,
    "memory": 6_200,
    "paths": 1_100,
    "rpc": 5_900,
    "network": 500,
    "mcp": 2_000,
    "shell": 11_600,
    "schedules": 2_500,
    "web": 5_100,
    "sharing": 2_900,
    "authentication": 2_100,
    "errors": 1_000,
}

# The MCP discovery tool does not serve the REST-only transport section.
MCP_DISCOVERY_SECTIONS = tuple(name for name in SECTION_NAMES if name != "transport")


def size(value) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


class McpDiscoverySizeTests(unittest.TestCase):
    setUp = test_oauth.OAuthHTTPTests.setUp
    tearDown = test_oauth.OAuthHTTPTests.tearDown
    request = test_oauth.OAuthHTTPTests.request
    rpc = test_oauth.OAuthHTTPTests.rpc

    def call(self, secret, method, params=None):
        status, payload = self.rpc(secret, method, params)
        self.assertEqual(200, status, payload)
        self.assertIn("result", payload, payload)
        return payload["result"]

    def measure(self, record) -> tuple[dict[str, int], dict[str, int]]:
        conn = self.server.static_mcp.create(record.app_id, record.path_prefix, "Size budget")
        self.mcp = "/kapsel/mcp-connect/" + conn["id"] + "/mcp"
        secret = conn["secret"]
        mcp: dict[str, int] = {}
        init = self.call(secret, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "size-test", "version": "1"},
        })
        mcp["instructions"] = size(init.get("instructions", ""))
        tools = self.call(secret, "tools/list")["tools"]
        mcp["tools_list"] = size(tools)
        for tool in tools:
            key = "tools:" + tool["name"].split("_", 1)[0]
            mcp[key] = mcp.get(key, 0) + size(tool)
        discovery: dict[str, int] = {}
        for section in ("main",) + MCP_DISCOVERY_SECTIONS:
            arguments = {} if section == "main" else {"section": section}
            result = self.call(secret, "tools/call", {"name": "discovery", "arguments": arguments})
            self.assertFalse(result.get("isError"), result)
            discovery[section] = size(result["structuredContent"])
        return mcp, discovery

    def test_mcp_and_discovery_stay_within_budget(self):
        (Path(self.temp.name) / "workspace" / "full").mkdir()
        full = self.server.tokens.create(
            name="Full", path_prefix="full", shell_mode="full", expires_at=None,
            can_read=True, can_write=True,
        )
        measured = [self.measure(self.record), self.measure(full)]
        problems = []
        for label, budgets, index in (("mcp", MCP_BUDGETS, 0), ("discovery", DISCOVERY_BUDGETS, 1)):
            actual: dict[str, int] = {}
            for sizes in measured:
                for key, value in sizes[index].items():
                    actual[key] = max(actual.get(key, 0), value)
            for key in sorted(actual.keys() - budgets.keys()):
                problems.append(f"{label} {key}: {actual[key]} bytes has no budget")
            for key in sorted(budgets.keys() - actual.keys()):
                problems.append(f"{label} {key}: budget exists but nothing was measured")
            for key in sorted(actual.keys() & budgets.keys()):
                if actual[key] > budgets[key]:
                    problems.append(f"{label} {key}: {actual[key]} bytes > budget {budgets[key]}")
        self.assertEqual([], problems, "\n" + "\n".join(problems))


if __name__ == "__main__":
    unittest.main()

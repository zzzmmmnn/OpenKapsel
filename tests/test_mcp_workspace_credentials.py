from __future__ import annotations

import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from tests import test_oauth


class McpWorkspaceCredentialsTests(unittest.TestCase):
    setUp = test_oauth.OAuthHTTPTests.setUp
    tearDown = test_oauth.OAuthHTTPTests.tearDown
    request = test_oauth.OAuthHTTPTests.request
    form = test_oauth.OAuthHTTPTests.form
    authorize = test_oauth.OAuthHTTPTests.authorize
    rpc = test_oauth.OAuthHTTPTests.rpc

    def call_tool(self, bearer: str, name: str):
        status, payload = self.rpc(
            bearer, "tools/call", {"name": name, "arguments": {}}
        )
        self.assertEqual(200, status, payload)
        return payload["result"]

    def tool_names(self, bearer: str):
        status, payload = self.rpc(bearer, "tools/list")
        self.assertEqual(200, status, payload)
        return {tool["name"]: tool for tool in payload["result"]["tools"]}

    def make_due(self):
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.server.tokens.update(
            current.token,
            credentials_expires_at=(
                datetime.now(timezone.utc) + timedelta(hours=1)
            ).isoformat(),
        )
        return self.server.tokens.get_by_app_id(self.record.app_id)

    def assert_current_export(self, result, record, *, rotated):
        self.assertFalse(result["isError"], result)
        value = result["structuredContent"]
        self.assertEqual(record.control_token, value["control_token"])
        self.assertEqual(record.credentials_expires_at, value["credentials_expires_at"])
        self.assertEqual(rotated, value["rotated"])
        self.assertEqual(record.credentials_valid, value["credentials_valid"])
        self.assertTrue(value["workspace_url"].endswith("/w/" + record.token + "/"))
        self.assertNotIn("read_token", value)
        return value

    def test_oauth_exports_current_rest_credentials_and_rotates_only_when_due(self):
        oauth, _, _ = self.authorize()
        bearer = oauth["access_token"]

        tools = self.tool_names(bearer)
        self.assertIn("get_workspace_credentials", tools)
        self.assertIn("renew_workspace_credentials", tools)
        self.assertTrue(tools["get_workspace_credentials"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["renew_workspace_credentials"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["renew_workspace_credentials"]["annotations"]["destructiveHint"])

        current = self.server.tokens.get_by_app_id(self.record.app_id)
        exported = self.assert_current_export(
            self.call_tool(bearer, "get_workspace_credentials"), current, rotated=False
        )
        old_url = exported["workspace_url"]
        old_control = current.control_token

        not_due = self.call_tool(bearer, "renew_workspace_credentials")
        self.assertTrue(not_due["isError"], not_due)
        self.assertEqual(
            "credentials_renewal_not_due",
            not_due["structuredContent"]["error"]["code"],
        )
        unchanged = self.server.tokens.get_by_app_id(self.record.app_id)
        self.assertEqual(current.token, unchanged.token)
        self.assertEqual(old_control, unchanged.control_token)

        due = self.make_due()
        renewed_result = self.call_tool(bearer, "renew_workspace_credentials")
        renewed = self.server.tokens.get_by_app_id(self.record.app_id)
        value = self.assert_current_export(renewed_result, renewed, rotated=True)
        self.assertNotEqual(due.token, renewed.token)
        self.assertNotEqual(due.control_token, renewed.control_token)
        self.assertNotEqual(old_url, value["workspace_url"])

        # Old REST credentials are gone, while the OAuth connection survives.
        self.assertEqual(404, self.request("GET", urlsplit(old_url).path)[0])
        self.assertEqual(200, self.rpc(bearer, "tools/list")[0])
        path = urlsplit(value["workspace_url"]).path + "context"
        status, _, _ = self.request(
            "GET", path, headers={"Authorization": "Bearer " + renewed.control_token}
        )
        self.assertEqual(200, status)

        again = self.assert_current_export(
            self.call_tool(bearer, "get_workspace_credentials"),
            renewed,
            rotated=False,
        )
        self.assertEqual(value["workspace_url"], again["workspace_url"])

    def test_static_mcp_exports_and_renews_without_changing_static_secret(self):
        conn = self.server.static_mcp.create(
            self.record.app_id, "project", "Credential bridge"
        )
        self.mcp = "/kapsel/mcp-connect/" + conn["id"] + "/mcp"
        bearer = conn["secret"]
        self.assertIn("get_workspace_credentials", self.tool_names(bearer))

        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.assert_current_export(
            self.call_tool(bearer, "get_workspace_credentials"), current, rotated=False
        )

        due = self.make_due()
        renewed = self.call_tool(bearer, "renew_workspace_credentials")
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.assert_current_export(renewed, current, rotated=True)
        self.assertNotEqual(due.control_token, current.control_token)
        self.assertEqual(conn["secret"], self.server.static_mcp.get(conn["id"])["secret"])
        self.assertEqual(200, self.rpc(bearer, "tools/list")[0])

    def test_expired_rest_credentials_can_be_exported_but_not_self_renewed(self):
        oauth, _, _ = self.authorize()
        bearer = oauth["access_token"]
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.server.tokens.update(
            current.token,
            credentials_expires_at=(
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat(),
        )
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        exported = self.assert_current_export(
            self.call_tool(bearer, "get_workspace_credentials"), current, rotated=False
        )
        self.assertFalse(exported["credentials_valid"])

        renewal = self.call_tool(bearer, "renew_workspace_credentials")
        self.assertTrue(renewal["isError"])
        self.assertEqual(
            "credentials_cannot_be_renewed",
            renewal["structuredContent"]["error"]["code"],
        )
        self.assertEqual(200, self.rpc(bearer, "tools/list")[0])

    def test_workspace_info_advertises_export_without_leaking_credentials(self):
        oauth, _, _ = self.authorize()
        bearer = oauth["access_token"]
        status, payload = self.rpc(
            bearer,
            "tools/call",
            {"name": "workspace_info", "arguments": {"section": "full"}},
        )
        self.assertEqual(200, status, payload)
        structured = payload["result"]["structuredContent"]
        auth = structured["authentication"]
        self.assertEqual("get_workspace_credentials", auth["workspace_credentials"]["export_tool"])
        self.assertEqual("renew_workspace_credentials", auth["workspace_credentials"]["renew_tool"])
        encoded = json.dumps(structured)
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        for secret in (current.token, current.control_token, current.preview_token):
            self.assertNotIn(secret, encoded)

    def test_concurrent_mcp_renewal_has_one_rotation(self):
        oauth, _, _ = self.authorize()
        bearer = oauth["access_token"]
        due = self.make_due()

        import concurrent.futures
        def renew(_):
            return self.call_tool(bearer, "renew_workspace_credentials")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(renew, range(2)))
        successful = [r for r in results if not r["isError"]]
        conflicts = [r for r in results if r["isError"]]
        self.assertEqual(1, len(successful))
        self.assertEqual(1, len(conflicts))
        self.assertEqual(
            "credentials_renewal_not_due",
            conflicts[0]["structuredContent"]["error"]["code"],
        )
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.assertNotEqual(due.token, current.token)


if __name__ == "__main__":
    unittest.main()

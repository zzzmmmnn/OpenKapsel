"""Invariants of the single request authentication layer."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.routes import CONNECTION_ROUTE_PATTERN
from openkapsel.server import WorkspaceRequestHandler
from openkapsel.server_runtime.authentication import PRINCIPAL_METHODS, RequestPrincipal

ROOT = Path(__file__).resolve().parents[1]


class AuthenticationLayerTests(unittest.TestCase):
    def handler(self):
        return object.__new__(WorkspaceRequestHandler)

    def test_control_flag_is_derived_only_from_principal(self):
        handler = self.handler()
        self.assertFalse(handler.control_authorized)
        record = SimpleNamespace(token="t")
        handler._set_principal(record, Path("."), control=False, method="url_token")
        self.assertFalse(handler.control_authorized)
        self.assertIs(record, handler.token_record)
        handler._set_principal(record, Path("."), control=True, method="bearer_control")
        self.assertTrue(handler.control_authorized)
        with self.assertRaises(AttributeError):
            handler.control_authorized = False

    def test_principal_rejects_unknown_authentication_method(self):
        with self.assertRaises(ValueError):
            RequestPrincipal(None, Path("."), True, "cookie")
        self.assertIn("signed_native", PRINCIPAL_METHODS)

    def test_connection_route_policy(self):
        allowed = ("mcp", "transfer/fs/content", "transfer/upload/status/a",
                   "transfer/upload/chunk/a", "transfer/upload/commit/a", "transfer/upload/cancel/a")
        denied = ("transfer/upload/create", "transfer/upload/chunk/a/b", "fs/query/list", "shell/exec")
        for route in allowed:
            self.assertTrue(re.fullmatch(CONNECTION_ROUTE_PATTERN, route), route)
        for route in denied:
            self.assertIsNone(re.fullmatch(CONNECTION_ROUTE_PATTERN, route), route)

    def test_identity_is_only_assigned_by_the_authentication_layer(self):
        sources = [*(ROOT / "openkapsel/server_runtime").glob("*.py"),
                   *(ROOT / "openkapsel/auth").glob("*.py"),
                   *(ROOT / "openkapsel/api").glob("*.py")]
        for path in sources:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotRegex(text, r"\.control_authorized\s*=(?!=)")
        for name in ("auth/oauth_handlers.py", "auth/static_mcp.py"):
            text = (ROOT / "openkapsel" / name).read_text(encoding="utf-8")
            self.assertIn("self._set_principal(", text)
            self.assertIn("CONNECTION_ROUTE_PATTERN", text)

    def test_bare_transfer_entrance_is_gone(self):
        dispatch = (ROOT / "openkapsel/server_runtime/dispatch.py").read_text(encoding="utf-8")
        self.assertNotIn('"/transfer', dispatch)


if __name__ == "__main__":
    unittest.main()

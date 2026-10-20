"""Browser-only capability approval error rendering (no network sockets needed)."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from openkapsel.auth.admin_handlers import AdminHandlersMixin
from openkapsel.errors import ApiError


class _ApprovalBrowserHandler(AdminHandlersMixin):
    def __init__(self, failure):
        self.failure = failure
        self.response = None
        self.calls = []
        self.server = SimpleNamespace(config=SimpleNamespace(admin_enabled=True))

    def _handle_capability_approval(self, method, ticket, query):
        self.calls.append((method, ticket, query))
        raise self.failure

    def _send_html(self, status, document, **kwargs):
        self.response = (status, document, kwargs)


class ApprovalBrowserErrorTests(unittest.TestCase):
    def show(self, failure, *, path="/capability/TICKET", method="POST"):
        handler = _ApprovalBrowserHandler(failure)
        handler._dispatch_user_page(method, path, "utm_source=external")
        self.assertEqual([(method, "TICKET", "utm_source=external")], handler.calls)
        status, document, options = handler.response
        self.assertEqual(status, failure.status)
        self.assertTrue(document.startswith("<!doctype html>"))
        self.assertEqual(options["script_src"], "'none'")
        self.assertNotIn("Cache-Control", options["headers"])  # _send_html sets it itself
        self.assertEqual(options["headers"]["Referrer-Policy"], "no-referrer")
        self.assertIn("No new access was granted", document)
        self.assertNotIn("client_message", document)
        self.assertNotIn("mapping_operation_failed", document)
        return document

    def test_invalid_client_scope_is_friendly_html_for_current_and_legacy_links(self):
        error = ApiError(400, "mapping_operation_failed", "client operation failed",
                         {"errno": 22, "client_message": "SECRET-CLIENT-DIAGNOSTIC"})
        for path in ("/capability/TICKET", "/admin/capability/TICKET"):
            with self.subTest(path=path):
                body = self.show(error, path=path)
                self.assertIn("Client declined this approval", body)
                self.assertIn("absolute deny", body)
                self.assertIn("reserved", body)
                self.assertNotIn("SECRET-CLIENT-DIAGNOSTIC", body)

    def test_other_client_failure_is_generic_and_does_not_leak_paths(self):
        error = ApiError(503, "mapping_operation_failed", "raw failure",
                         {"errno": 113, "client_message": "/Users/SECRET/config"})
        body = self.show(error)
        self.assertIn("Client could not complete the approval", body)
        self.assertIn("Check its connection", body)
        self.assertNotIn("/Users/SECRET", body)

    def test_expired_target_and_browser_verification_have_distinct_messages(self):
        variants = [
            (ApiError(400, "approval_unavailable", "internal"), "Approval link unavailable"),
            (ApiError(409, "approval_target_unavailable", "internal"), "Approval target unavailable"),
            (ApiError(403, "csrf_failed", "secret"), "Approval verification failed"),
            (ApiError(403, "password_incorrect", "secret"), "Approval verification failed"),
            (ApiError(403, "path_access_denied", "secret"), "Approval not permitted"),
        ]
        for error, heading in variants:
            with self.subTest(code=error.code):
                self.assertIn(heading, self.show(error))


if __name__ == "__main__":
    unittest.main()

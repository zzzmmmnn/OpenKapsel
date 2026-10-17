"""Opaque function approval storage and callback-merging behavior."""
import tempfile
import threading
from unittest.mock import patch
import unittest

from openkapsel.auth.function_grants import FunctionGrants


class FunctionGrantsTests(unittest.TestCase):
    def setUp(self):
        self.store = FunctionGrants()

    def test_function_controls_scope_merging(self):
        first = self.store.request("token", 3, "mapping", "fs.write",
                                   {"path": "/home/user1"})
        self.assertEqual({"paths": ["/home/user1"]},
                         self.store.approve(first, seconds=600, grant=lambda old, request: {
                             "paths": [request["path"]]
                         }))
        second = self.store.request("token", 3, "mapping", "fs.write",
                                    {"path": "/home/user2"})
        def merge(old, request):
            return {"paths": sorted([*old["paths"], request["path"]])}
        merged = self.store.approve(second, seconds=600, grant=merge)
        self.assertEqual({"paths": ["/home/user1", "/home/user2"]}, merged)
        merged["paths"].clear()  # Returned JSON cannot mutate server storage.
        self.assertEqual({"paths": ["/home/user1", "/home/user2"]},
                         self.store.current("token", 3, "mapping", "fs.write"))
        self.assertIsNone(self.store.current("token", 4, "mapping", "fs.write"))
        self.assertIsNone(self.store.current("token", 3, "server", "fs.write"))
        self.assertIsNone(self.store.current("token", 3, "mapping", "fs.read"))

    def test_failed_grant_does_not_mutate_or_consume_ticket(self):
        first = self.store.request("token", 2, "server", "shell.exec", {"command": "id"})
        def rejected(old, request):
            raise PermissionError("not permitted")
        with self.assertRaises(PermissionError):
            self.store.approve(first, seconds=600, grant=rejected)
        self.assertIsNotNone(self.store.pending(first))
        self.assertIsNone(self.store.current("token", 2, "server", "shell.exec"))
        auth = self.store.approve(first, seconds=600,
                                  grant=lambda old, request: {"permitted": True})
        self.assertEqual({"permitted": True}, auth)
        self.assertIsNone(self.store.pending(first))
        with self.assertRaises(ValueError):
            self.store.approve(first, seconds=600, grant=lambda old, request: None)

    def test_isolation_expiry_revoke_and_json_shape(self):
        self.store.request("other", 2, "server", "x.y", {"test": 1})
        ticket = self.store.request("token", 2, "server", "x.y", {"test": 2})
        self.store.approve(ticket, seconds=60, grant=lambda old, req: {"ok": req["test"]})
        self.store.revoke_workspace("token")
        self.assertIsNone(self.store.current("token", 2, "server", "x.y"))
        self.assertEqual(1, len(self.store.pending_requests))
        with self.assertRaises((TypeError, ValueError)):
            self.store.request("token", 2, "server", "x.y", {"bad": object()})

    def test_password_verification_does_not_block_revoke_or_resurrect_ticket(self):
        ticket = self.store.request("token", 1, "server", "x.y", {})
        entered, release = threading.Event(), threading.Event()
        errors = []
        def verify(owner):
            entered.set()
            if not release.wait(5):
                raise AssertionError("verification was not released")
            return True
        def attempt():
            try:
                self.store.password_attempt(ticket, verify)
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=attempt)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            revoked = threading.Event()
            revoker = threading.Thread(target=lambda: (self.store.revoke_workspace("token"), revoked.set()))
            revoker.start()
            try:
                self.assertTrue(revoked.wait(2), "password verification held the grant lock")
            finally:
                release.set()
                revoker.join(5)
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], ValueError)
        self.assertIsNone(self.store.pending(ticket))
        self.assertIsNone(self.store.current("token", 1, "server", "x.y"))

    def test_expiry_and_revoke_during_callback_cannot_publish_authorization(self):
        with patch("openkapsel.auth.function_grants.time.monotonic", return_value=100):
            ticket = self.store.request("token", 1, "server", "x.y", {})
            self.store.approve(ticket, seconds=60, grant=lambda old, request: {"value": True})
        with patch("openkapsel.auth.function_grants.time.monotonic", return_value=161):
            self.assertIsNone(self.store.current("token", 1, "server", "x.y"))
        ticket = self.store.request("token", 1, "server", "x.y", {})
        def callback(old, request):
            self.store.revoke_workspace("token")
            return {"value": True}
        with self.assertRaises(ValueError):
            self.store.approve(ticket, seconds=60, grant=callback)
        self.assertIsNone(self.store.current("token", 1, "server", "x.y"))

    def test_staged_confirmation_cannot_overwrite_a_concurrent_grant(self):
        def merge(old, request):
            return [*(old or []), request]
        first = self.store.request("token", 1, "server", "x.y", "one")
        self.store.approve(first, seconds=600, grant=merge)
        second = self.store.request("token", 1, "server", "x.y", "two")
        self.assertEqual(["one", "two"], self.store.prepare_confirmation(
            second, browser="verified-browser", seconds=600, grant=merge))
        self.assertEqual(["one"], self.store.current("token", 1, "server", "x.y"))
        self.assertIsNone(self.store.confirmation(second, "different-browser"))
        third = self.store.request("token", 1, "server", "x.y", "three")
        self.store.approve(third, seconds=600, grant=merge)
        with self.assertRaises(ValueError):
            self.store.approve(second, browser="verified-browser", seconds=600, grant=merge)
        self.assertEqual(["one", "three"], self.store.current("token", 1, "server", "x.y"))
        self.assertIsNotNone(self.store.pending(second))


if __name__ == "__main__":
    unittest.main()

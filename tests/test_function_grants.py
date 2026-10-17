"""Independent Client-owned function grant expiry, validation and browser safety."""
import threading
import unittest
from unittest.mock import patch

from openkapsel.auth.function_grants import FunctionGrants


def add_path(old, request, seconds, *, client_clock=None):
    """Generic function policy; Server must not interpret 'path'."""
    grants = list((old or {}).get("grants", []))
    grants.append({"path": request["path"], "expires_at": client_clock() + seconds,
                   "client_metadata": {"untouched": ["yes"]}})
    return {"grants": grants, "extension": {"owned": "client"}}


class FunctionGrantsTests(unittest.TestCase):
    def setUp(self):
        self.store = FunctionGrants()

    def test_client_fields_immutable_and_grants_expire_independently(self):
        now = [100.0]
        client = lambda: 100000 + now[0]
        callback = lambda old, req, sec: add_path(old, req, sec, client_clock=client)
        with patch("openkapsel.auth.function_grants.time.monotonic", side_effect=lambda: now[0]):
            first = self.store.request("token", 3, "mapping", "fs.write", {"path": "/a"})
            original = self.store.approve(first, seconds=600, grant=callback)
            old_stamp = original["grants"][0]["expires_at"]
            now[0] = 400.0
            second = self.store.request("token", 3, "mapping", "fs.write", {"path": "/b"})
            combined = self.store.approve(second, seconds=1800, grant=callback)
            self.assertEqual(old_stamp, combined["grants"][0]["expires_at"])
            self.assertEqual(["/a", "/b"], [g["path"] for g in combined["grants"]])
            combined["grants"].clear()
            now[0] = 700.0  # Client A expired, Server retains it for 60s.
            self.assertEqual(2, len(self.store.current("token", 3, "mapping", "fs.write")["grants"]))
            now[0] = 760.0  # Exactly 60s later, Server prunes A.
            active = self.store.current("token", 3, "mapping", "fs.write")
            self.assertEqual(["/b"], [g["path"] for g in active["grants"]])
            self.assertEqual({"owned": "client"}, active["extension"])
            self.assertEqual({"untouched": ["yes"]}, active["grants"][0]["client_metadata"])
            now[0] = 2260.0
            self.assertIsNone(self.store.current("token", 3, "mapping", "fs.write"))
            self.assertEqual([], self.store.list_grants("token"))

    def test_clock_jump_on_second_approval_does_not_extend_first(self):
        now = [10.0]
        offset = [10000]
        client = lambda: now[0] + offset[0]
        callback = lambda old, req, seconds: add_path(old, req, seconds, client_clock=client)
        with patch("openkapsel.auth.function_grants.time.monotonic", side_effect=lambda: now[0]):
            a = self.store.request("t", 1, "server", "demo.write", {"path": "one"})
            self.store.approve(a, seconds=600, grant=callback)
            now[0] = 30
            offset[0] = 70000  # Client clock shifts backwards radically but stays valid Unix time.
            b = self.store.request("t", 1, "server", "demo.write", {"path": "two"})
            self.store.approve(b, seconds=1800, grant=callback)
            now[0] = 611
            auth = self.store.current("t", 1, "server", "demo.write")
            self.assertEqual(["one", "two"], [item["path"] for item in auth["grants"]])
            now[0] = 670
            auth = self.store.current("t", 1, "server", "demo.write")
            self.assertEqual(["two"], [item["path"] for item in auth["grants"]])
            now[0] = 1890
            self.assertIsNone(self.store.current("t", 1, "server", "demo.write"))

    def test_explicit_renewal_does_not_extend_unrelated_grants(self):
        now = [10]
        def renewal(old, request, seconds):
            grants = [g for g in (old or {}).get("grants", []) if g["path"] != request["path"]]
            return {"grants": [*grants, {"path": request["path"], "expires_at": 80000 + now[0] + seconds}]}
        with patch("openkapsel.auth.function_grants.time.monotonic", side_effect=lambda: now[0]):
            for when, target, duration in ((10, "/a", 600), (50, "/b", 60), (70, "/a", 1800)):
                now[0] = when
                ticket = self.store.request("t", 0, "c", "f.g", {"path": target})
                self.store.approve(ticket, seconds=duration, grant=renewal)
            now[0] = 111  # B has expired on the Client, but not the Server.
            self.assertEqual(["/b", "/a"], [g["path"] for g in
                self.store.current("t", 0, "c", "f.g")["grants"]])
            now[0] = 170
            self.assertEqual(["/a"], [g["path"] for g in
                self.store.current("t", 0, "c", "f.g")["grants"]])
            now[0] = 1930
            self.assertIsNone(self.store.current("t", 0, "c", "f.g"))

    def test_invalid_schema_fails_closed_and_does_not_consume_ticket(self):
        malformed = [
            None, [], {"paths": ["legacy"]}, {"grants": None},
            {"grants": [1]}, {"grants": [{}]},
            {"grants": [{"expires_at": True}]},
            {"grants": [{"expires_at": "tomorrow"}]},
            {"grants": [{"expires_at": float("nan")}]},
            {"grants": [{"expires_at": float("inf")}]},
            {"grants": []},
        ]
        ticket = self.store.request("t", 0, "server", "demo.write", {})
        for auth in malformed:
            with self.subTest(auth=auth), self.assertRaises((ValueError, TypeError)):
                self.store.approve(ticket, seconds=600, grant=lambda old, req, sec: auth)
            self.assertIsNotNone(self.store.pending(ticket))
            self.assertIsNone(self.store.current("t", 0, "server", "demo.write"))
        good = {"grants": [{"expires_at": 123456, "opaque": True}]}
        self.assertEqual(good, self.store.approve(
            ticket, seconds=600, grant=lambda old, req, sec: good))
        self.assertIsNone(self.store.pending(ticket))

    def test_revoke_and_isolation(self):
        callback = lambda old, req, sec: {"grants": [
            {"expires_at": 88888, "allowed": req["value"]}]}
        ticket = self.store.request("a", 2, "target", "demo.write", {"value": 1})
        self.store.approve(ticket, seconds=60, grant=callback)
        for binding in (("b", 2, "target", "demo.write"),
                        ("a", 3, "target", "demo.write"),
                        ("a", 2, "other", "demo.write"),
                        ("a", 2, "target", "demo.read")):
            self.assertIsNone(self.store.current(*binding))
        self.store.revoke("a", 2, "target", "demo.write")
        self.assertIsNone(self.store.current("a", 2, "target", "demo.write"))
        other = self.store.request("a", 2, "target", "demo.write", {"value": 2})
        self.store.revoke_workspace("a")
        self.assertIsNone(self.store.pending(other))

    def test_staged_confirmation_revalidates_scope_ignoring_time_only(self):
        now = [100]
        path = ["/canonical"]
        def grant(old, request, seconds):
            return {"grants": [{"expires_at": now[0] + 9999 + seconds,
                                "path": path[0]}], "extra": ["unchanged"]}
        with patch("openkapsel.auth.function_grants.time.monotonic", side_effect=lambda: now[0]):
            ticket = self.store.request("t", 1, "server", "demo.write", {"path": "/alias"})
            proposal = self.store.prepare_confirmation(ticket, browser="b", seconds=600, grant=grant)
            now[0] += 5
            self.assertNotEqual(proposal, grant(None, {}, 600))
            self.assertEqual("/canonical", self.store.approve(
                ticket, seconds=600, browser="b", grant=grant)["grants"][0]["path"])
            ticket2 = self.store.request("t", 1, "server", "demo.write", {"path": "/alias"})
            self.store.prepare_confirmation(ticket2, browser="b", seconds=600, grant=grant)
            path[0] = "/swapped"
            with self.assertRaises(ValueError):
                self.store.approve(ticket2, seconds=600, browser="b", grant=grant)
            self.assertIsNotNone(self.store.pending(ticket2))
            self.assertEqual("/canonical", self.store.current(
                "t", 1, "server", "demo.write")["grants"][0]["path"])

    def test_staged_confirmation_cannot_overwrite_concurrent_grant(self):
        now = [100]
        callback = lambda old, req, sec: {"grants": [*(old or {}).get("grants", []),
            {"expires_at": now[0] + sec, "path": req["path"]}]}
        with patch("openkapsel.auth.function_grants.time.monotonic", side_effect=lambda: now[0]):
            first = self.store.request("t", 1, "server", "demo.write", {"path": "one"})
            self.store.approve(first, seconds=600, grant=callback)
            second = self.store.request("t", 1, "server", "demo.write", {"path": "two"})
            self.store.prepare_confirmation(second, browser="browser", seconds=600, grant=callback)
            third = self.store.request("t", 1, "server", "demo.write", {"path": "three"})
            self.store.approve(third, seconds=600, grant=callback)
            with self.assertRaises(ValueError):
                self.store.approve(second, seconds=600, browser="browser", grant=callback)
            self.assertEqual(["one", "three"], [g["path"] for g in
                self.store.current("t", 1, "server", "demo.write")["grants"]])

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

    def test_revoke_during_callback_never_publishes(self):
        ticket = self.store.request("token", 1, "server", "x.y", {})
        def callback(old, request, seconds):
            self.store.revoke_workspace("token")
            return {"grants": [{"expires_at": 90000, "allowed": True}]}
        with self.assertRaises(ValueError):
            self.store.approve(ticket, seconds=600, grant=callback)
        self.assertIsNone(self.store.current("token", 1, "server", "x.y"))


if __name__ == "__main__":
    unittest.main()

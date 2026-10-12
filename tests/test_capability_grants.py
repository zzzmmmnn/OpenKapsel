"""Regression tests for memory-only Workspace capability approvals."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.auth.capability_grants import CapabilityGrants


class CapabilityGrantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "passwords.sqlite3"
        self.store = CapabilityGrants(self.path)
        self.workspace = "project-a"
        self.store.set_password(self.workspace, "passphrase-for-test-123")

    def test_legacy_directory_passwords_are_not_token_credentials(self):
        import sqlite3
        from openkapsel.auth.security import hash_password
        legacy_password = "legacy-directory-password-123"
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE workspace_passwords ("
                       "workspace TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
            db.execute("INSERT INTO workspace_passwords VALUES (?,?)",
                       ("shared-directory", hash_password(legacy_password)))
        reopened = CapabilityGrants(self.path)
        self.assertFalse(reopened.configured("shared-directory"))
        self.assertFalse(reopened.configured("token-a"))
        reopened.set_password("token-a", "token-a-secret-456")
        self.assertTrue(reopened.verify_workspace_password("token-a", "token-a-secret-456"))
        self.assertFalse(reopened.verify_workspace_password("token-a", legacy_password))
        self.assertFalse(reopened.verify_workspace_password("token-b", "token-a-secret-456"))

    def test_default_approval_scoped_by_workspace_conversation_target_capability(self):
        ticket = self.store.request(self.workspace, 12, "server", "shell.elevated")
        self.assertFalse(self.store.granted(self.workspace, 12, "server", "shell.elevated"))
        self.store.approve(ticket, "passphrase-for-test-123")
        self.assertTrue(self.store.granted(self.workspace, 12, "server", "shell.elevated"))
        for scope, conversation, target, capability in (
            (self.workspace, 13, "server", "shell.elevated"),
            (self.workspace, 12, "mapping-a", "shell.elevated"),
            ("project-b", 12, "server", "shell.elevated"),
            (self.workspace, 12, "server", "files.write"),
        ):
            self.assertFalse(self.store.granted(scope, conversation, target, capability))
        with self.assertRaisesRegex(ValueError, "already used"):
            self.store.approve(ticket, "passphrase-for-test-123")

    def test_pending_five_minutes_and_grant_expiry(self):
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100):
            ticket = self.store.request(self.workspace, 1, "server", "shell.elevated")
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=401):
            self.assertIsNone(self.store.pending(ticket))
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=500):
            ticket = self.store.request(self.workspace, 1, "server", "shell.elevated")
            self.store.approve(ticket, "passphrase-for-test-123", 60)
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=559):
            self.assertTrue(self.store.granted(self.workspace, 1, "server", "shell.elevated"))
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=560):
            self.assertFalse(self.store.granted(self.workspace, 1, "server", "shell.elevated"))

    def test_repeated_requests_independent(self):
        one = self.store.request(self.workspace, 1, "server", "shell.elevated")
        two = self.store.request(self.workspace, 1, "server", "shell.elevated")
        self.assertNotEqual(one, two)
        self.assertIsNotNone(self.store.pending(one))
        self.assertIsNotNone(self.store.pending(two))
        self.store.approve(one, "passphrase-for-test-123")
        self.assertIsNotNone(self.store.pending(two))

    def test_failed_password_attempt_limited(self):
        ticket = self.store.request(self.workspace, 1, "server", "shell.elevated")
        for _ in range(5):
            with self.assertRaises(PermissionError):
                self.store.approve(ticket, "bad-password")
        self.assertIsNone(self.store.pending(ticket))
        self.assertFalse(self.store.granted(self.workspace, 1, "server", "shell.elevated"))

    def test_password_change_revokes_all_pending_and_active(self):
        one = self.store.request(self.workspace, 1, "server", "shell.elevated")
        self.store.approve(one, "passphrase-for-test-123")
        two = self.store.request(self.workspace, 2, "mapping-a", "files.write")
        self.store.set_password(self.workspace, "new-password-for-test-456")
        self.assertFalse(self.store.granted(self.workspace, 1, "server", "shell.elevated"))
        self.assertIsNone(self.store.pending(two))
        self.assertTrue(self.store.verify_workspace_password(self.workspace, "new-password-for-test-456"))
        self.assertFalse(self.store.verify_workspace_password(self.workspace, "passphrase-for-test-123"))

    def test_only_password_persists_restart(self):
        ticket = self.store.request(self.workspace, 1, "server", "shell.elevated")
        self.store.approve(ticket, "passphrase-for-test-123")
        fresh = CapabilityGrants(self.path)
        self.assertTrue(fresh.configured(self.workspace))
        self.assertFalse(fresh.granted(self.workspace, 1, "server", "shell.elevated"))
        pending = self.store.request(self.workspace, 2, "server", "shell.elevated")
        self.assertIsNone(fresh.pending(pending))
        cookie = "b" * 43
        self.assertFalse(fresh.verify_browser(pending, cookie, self.store.browser_proof(pending, cookie)))

    def test_invalid_expiry_and_unknown_capabilities(self):
        ticket = self.store.request(self.workspace, 1, "server", "shell.elevated")
        for seconds in (0, 10, 86401, True, 2.5):
            with self.assertRaises(ValueError):
                self.store.approve(ticket, "passphrase-for-test-123", seconds)
        with self.assertRaises(ValueError):
            self.store.request(self.workspace, 1, "server", "superuser")

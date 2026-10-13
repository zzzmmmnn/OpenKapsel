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

    def test_six_character_workspace_approval_password(self):
        from openkapsel.auth.security import hash_password

        # Administrator hashes retain their separate 12-character minimum.
        with self.assertRaisesRegex(ValueError, "at least 12"):
            hash_password("abc123")

        self.store.set_password(self.workspace, "abc123")
        self.assertTrue(self.store.verify_workspace_password(self.workspace, "abc123"))
        ticket = self.store.request(self.workspace, 19, "server", "files.read")
        self.store.approve(ticket, "abc123")
        self.assertTrue(self.store.granted(self.workspace, 19, "server", "files.read"))

        for invalid in ("abc12", "z" * 1025):
            with self.subTest(length=len(invalid)):
                with self.assertRaisesRegex(ValueError, "6-1024"):
                    self.store.set_password(self.workspace, invalid)
        self.assertTrue(self.store.verify_workspace_password(self.workspace, "abc123"))

    def test_password_setup_link_expiry_rotation_consumption_and_token_isolation(self):
        workspace = self.workspace
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100):
            first = self.store.create_password_setup_link(workspace)
            other = self.store.create_password_setup_link("token-b")
            replacement = self.store.create_password_setup_link(workspace)
            self.assertIsNone(self.store.password_setup_workspace(first))
            self.assertEqual(workspace, self.store.password_setup_workspace(replacement))
            self.assertEqual("token-b", self.store.password_setup_workspace(other))
            with self.assertRaisesRegex(ValueError, "match"):
                self.store.consume_password_setup_link(replacement, "newpass", "different")
            self.assertEqual(workspace, self.store.password_setup_workspace(replacement))
            with self.assertRaisesRegex(ValueError, "6-1024"):
                self.store.consume_password_setup_link(replacement, "short", "short")
            self.assertEqual(workspace, self.store.password_setup_workspace(replacement))
            self.assertEqual(workspace, self.store.consume_password_setup_link(replacement, "abcdef", "abcdef"))
            self.assertIsNone(self.store.password_setup_workspace(replacement))
            self.assertEqual("token-b", self.store.password_setup_workspace(other))
        self.assertTrue(self.store.verify_workspace_password(workspace, "abcdef"))
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100):
            expiring = self.store.create_password_setup_link(workspace)
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100 + 900):
            self.assertIsNone(self.store.password_setup_workspace(expiring))
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100):
            unused = self.store.create_password_setup_link(workspace)
        self.store.set_password(workspace, "new-password-xyz")
        self.assertIsNone(self.store.password_setup_workspace(unused))
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100):
            self.assertIsNotNone(self.store.password_setup_workspace(other))

    def test_path_scoped_approval_rejects_dotdot_at_store_boundary(self):
        with self.assertRaisesRegex(ValueError, "invalid approval path"):
            self.store.request(
                self.workspace, 9, "server", "files.read",
                "/approved/../private",
            )
        ticket = self.store.request(
            self.workspace, 9, "server", "files.read", "/approved"
        )
        self.store.approve(ticket, "passphrase-for-test-123")
        self.assertIsNone(self.store.granted_path(
            self.workspace, 9, "server", "files.read",
            "/approved/../private.txt",
        ))
        self.assertEqual("/approved", self.store.granted_path(
            self.workspace, 9, "server", "files.read", "/approved/public.txt"
        ))

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

    def test_pending_quota_is_32_per_token_not_global(self):
        from openkapsel.auth.capability_grants import MAX_PENDING_PER_TOKEN

        self.assertEqual(32, MAX_PENDING_PER_TOKEN)
        token_a = self.workspace
        token_b = "another-token-same-directory"
        tickets_a = [
            self.store.request(token_a, 1, "server", "shell.elevated")
            for _ in range(MAX_PENDING_PER_TOKEN)
        ]
        self.assertEqual(MAX_PENDING_PER_TOKEN, len(set(tickets_a)))
        with self.assertRaisesRegex(RuntimeError, "too many pending"):
            self.store.request(token_a, 2, "server", "shell.elevated")
        tickets_b = [
            self.store.request(token_b, 1, "server", "shell.elevated")
            for _ in range(MAX_PENDING_PER_TOKEN)
        ]
        self.assertEqual(MAX_PENDING_PER_TOKEN, len(set(tickets_b)))
        with self.assertRaisesRegex(RuntimeError, "too many pending"):
            self.store.request(token_b, 2, "server", "shell.elevated")
        self.assertEqual(64, len(self.store.pending_requests))

        # Approving one Token A request releases only Token A capacity.
        self.store.approve(tickets_a[0], "passphrase-for-test-123")
        replacement = self.store.request(token_a, 3, "server", "shell.elevated")
        self.assertIsNotNone(self.store.pending(replacement))
        with self.assertRaisesRegex(RuntimeError, "too many pending"):
            self.store.request(token_b, 3, "server", "shell.elevated")

        # Revocation frees only the associated Token's pending tickets.
        self.store.revoke_workspace(token_b)
        self.assertEqual(MAX_PENDING_PER_TOKEN, len(self.store.pending_requests))
        self.assertIsNotNone(
            self.store.request(token_b, 4, "server", "shell.elevated")
        )
        with self.assertRaisesRegex(RuntimeError, "too many pending"):
            self.store.request(token_a, 4, "server", "shell.elevated")

    def test_pending_quota_recovers_from_expiration(self):
        from openkapsel.auth.capability_grants import MAX_PENDING_PER_TOKEN

        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=100):
            tickets = [
                self.store.request(self.workspace, 1, "server", "shell.elevated")
                for _ in range(MAX_PENDING_PER_TOKEN)
            ]
            with self.assertRaisesRegex(RuntimeError, "too many pending"):
                self.store.request(self.workspace, 1, "server", "shell.elevated")
        with patch("openkapsel.auth.capability_grants.time.monotonic", return_value=401):
            new_ticket = self.store.request(self.workspace, 1, "server", "shell.elevated")
            self.assertIsNone(self.store.pending(tickets[0]))
            self.assertEqual(1, len(self.store.pending_requests))
            self.assertIsNotNone(self.store.pending(new_ticket))

    def test_no_global_pending_quota_across_many_tokens(self):
        from openkapsel.auth.capability_grants import MAX_PENDING_PER_TOKEN

        for index in range(17):
            token = f"token-{index}"
            for _ in range(MAX_PENDING_PER_TOKEN):
                self.store.request(token, 0, "server", "shell.elevated")
        self.assertEqual(544, len(self.store.pending_requests))
        self.assertIsNotNone(
            self.store.request("token-18", 0, "server", "shell.elevated")
        )

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

"""No authentication path accepts globally salted one-round SHA-256."""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from openkapsel.auth.capability_grants import CapabilityGrants
from openkapsel.auth.security import (
    hash_password, is_password_hash_supported, verify_password,
)


class PasswordHashSecurityTests(unittest.TestCase):
    def test_legacy_digest_is_rejected_for_all_passwords(self):
        password = "a-correct-long-password"
        old = hashlib.sha256(("openkapsel_1.0\0" + password).encode()).hexdigest()
        self.assertFalse(is_password_hash_supported(old))
        self.assertFalse(is_password_hash_supported(old.upper()))
        self.assertFalse(verify_password(password, old))
        self.assertFalse(verify_password(password, old.upper()))
        new = hash_password(password)
        self.assertTrue(is_password_hash_supported(new))
        self.assertTrue(verify_password(password, new))

    def test_legacy_workspace_password_cannot_authorize_until_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CapabilityGrants(Path(directory) / "capabilities.sqlite3")
            workspace = "token-app-id-1234"
            password = "workspace-pass-123"
            old = hashlib.sha256(("openkapsel_1.0\0" + password).encode()).hexdigest()
            with sqlite3.connect(store.path) as db:
                db.execute(
                    "INSERT INTO token_passwords(token_app_id, password_hash) VALUES(?, ?)",
                    (workspace, old))
            self.assertTrue(store.configured(workspace))
            self.assertFalse(store.verify_workspace_password(workspace, password))
            store.set_password(workspace, password)
            self.assertTrue(store.verify_workspace_password(workspace, password))
            with sqlite3.connect(store.path) as db:
                row = db.execute(
                    "SELECT password_hash FROM token_passwords WHERE token_app_id=?",
                    (workspace,)).fetchone()
            self.assertTrue(row[0].startswith("pbkdf2_sha256$"))
            self.assertNotEqual(row[0], old)


if __name__ == "__main__":
    unittest.main()

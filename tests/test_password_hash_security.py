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
    @unittest.skipIf(__import__("os").name == "nt", "POSIX file modes")
    def test_workspace_password_sqlite_created_mode_0600_even_under_umask_022(self):
        import os
        import stat
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "workspace-passwords.sqlite3"
            previous = os.umask(0o022)
            try:
                store = CapabilityGrants(db_path)
            finally:
                os.umask(previous)
            self.assertEqual(0o600, stat.S_IMODE(db_path.stat().st_mode))
            store.set_password("test-app-id", "correct-workspace-password")
            self.assertTrue(store.verify_workspace_password("test-app-id", "correct-workspace-password"))
            self.assertEqual(0o600, stat.S_IMODE(db_path.stat().st_mode))

    @unittest.skipIf(__import__("os").name == "nt", "POSIX file modes")
    def test_existing_world_readable_password_database_is_repaired(self):
        import os
        import stat
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "workspace-passwords.sqlite3"
            first = CapabilityGrants(db_path)
            first.set_password("token-one", "a-secure-password")
            os.chmod(db_path, 0o644)
            self.assertEqual(0o644, stat.S_IMODE(db_path.stat().st_mode))
            recovered = CapabilityGrants(db_path)
            self.assertEqual(0o600, stat.S_IMODE(db_path.stat().st_mode))
            self.assertTrue(recovered.verify_workspace_password("token-one", "a-secure-password"))
            self.assertEqual(0o600, stat.S_IMODE(db_path.stat().st_mode))

    @unittest.skipIf(__import__("os").name == "nt", "POSIX file modes")
    def test_existing_world_readable_sqlite_wal_and_shm_are_repaired(self):
        import os
        import stat
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workspace-passwords.sqlite3"
            grants = CapabilityGrants(path)
            grants.set_password("token-wal", "a-secure-password")
            with sqlite3.connect(path) as writer:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("INSERT INTO token_passwords VALUES (?, ?)",
                               ("extra-token", "test-stored-record"))
                writer.commit()
                wal = Path(str(path) + "-wal")
                shm = Path(str(path) + "-shm")
                self.assertTrue(wal.exists(), "test must create real SQLite WAL")
                self.assertTrue(shm.exists(), "test must create real SQLite SHM")
                for item in (path, wal, shm):
                    os.chmod(item, 0o644)
                    self.assertEqual(0o644, stat.S_IMODE(item.stat().st_mode))
                repaired = CapabilityGrants(path)
                self.assertTrue(repaired.verify_workspace_password(
                    "token-wal", "a-secure-password"))
                for item in (path, wal, shm):
                    self.assertEqual(0o600, stat.S_IMODE(item.stat().st_mode))

    @unittest.skipIf(__import__("os").name == "nt", "POSIX link behavior")
    def test_password_database_rejects_symlink_and_hardlink_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.sqlite3"
            CapabilityGrants(victim)
            symlink = root / "fake-symlink.sqlite3"
            symlink.symlink_to(victim)
            with self.assertRaises((ValueError, OSError)):
                CapabilityGrants(symlink)
            hardlink = root / "fake-hardlink.sqlite3"
            hardlink.hardlink_to(victim)
            with self.assertRaises((ValueError, OSError)):
                CapabilityGrants(hardlink)

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

"""Run the actual installer pre-shutdown admin credential preflight, not a mock."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from openkapsel.auth.security import hash_password


ROOT = Path(__file__).resolve().parent.parent
MARKER = '/usr/bin/python3 - "$SOURCE_DIR" "$CONFIG_FILE" "$MIGRATE_FROM" <<\'PY\'\n'


class InstallerPasswordPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        content = (ROOT / "install.sh").read_text(encoding="utf-8")
        if content.count(MARKER) != 1:
            raise AssertionError("expected one admin password validation before safe shutdown")
        cls.preflight_code = content.split(MARKER, 1)[1].split("\nPY\n", 1)[0]
        shutdown = content.index('bash "$SOURCE_DIR/scripts/openkapsel-safe-shutdown"')
        assert content.index(MARKER) < shutdown, "password check must occur before shutdown"

    def check_config(self, payload, *, migrate=False):
        with tempfile.TemporaryDirectory(prefix="openkapsel-password-preflight-") as dirname:
            root = Path(dirname)
            config = root / "config.json"
            migration_dir = root / "migrate"
            if migrate:
                (migration_dir / "state").mkdir(parents=True)
                config = migration_dir / "state/config.json"
            if payload is not None:
                config.write_text(json.dumps(payload), encoding="utf-8")
                original = config.read_bytes()
            else:
                original = None
            live_config = root / "config.json"
            result = subprocess.run(
                [sys.executable, "-c", self.preflight_code, str(ROOT),
                 str(live_config), str(migration_dir) if migrate else ""],
                cwd=str(ROOT), capture_output=True, text=True, check=False,
            )
            if original is not None:
                self.assertEqual(original, config.read_bytes(),
                                 "preflight must not rewrite credentials")
            return result

    def test_pbkdf2_admin_key_accepted_without_rotation(self):
        result = self.check_config({
            "admin": {"username": "admin", "password_hash": hash_password("secure-admin-password")}
        })
        self.assertEqual(0, result.returncode, result.stderr)

    def test_missing_config_allows_new_install(self):
        result = self.check_config(None)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_missing_hash_in_existing_config_fails_closed(self):
        result = self.check_config({"admin": {"username": "admin"}})
        self.assertNotEqual(0, result.returncode)
        self.assertIn("admin.password_hash", result.stderr)

    def test_obsolete_password_sha256_key_is_not_accepted(self):
        payload = {"admin": {"username": "admin",
                             "password_sha256": hash_password("secure-admin-password")}}
        result = self.check_config(payload)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("admin.password_hash", result.stderr)

    def test_weak_digest_under_current_field_is_rejected(self):
        old = hashlib.sha256(b"openkapsel_1.0\0secure-admin-password").hexdigest()
        result = self.check_config({
            "admin": {"username": "admin", "password_hash": old}
        })
        self.assertNotEqual(0, result.returncode)
        self.assertIn("PBKDF2", result.stderr)

    def test_migrating_config_does_not_fallback_to_legacy_key(self):
        result = self.check_config({
            "admin": {"username": "admin",
                      "password_sha256": hash_password("secure-admin-password")}
        }, migrate=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("admin.password_hash", result.stderr)


if __name__ == "__main__":
    unittest.main()

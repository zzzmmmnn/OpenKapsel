from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path

from openkapsel.environment_store import EnvironmentConfigError, EnvironmentStore


class EnvironmentStoreTests(unittest.TestCase):
    def test_per_app_replace_load_and_clear_are_file_backed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            store = EnvironmentStore(workspace)
            first_id = "0123456789abcdef"
            second_id = "fedcba9876543210"

            first = store.replace(
                first_id,
                {"API_KEY": "sec'ret\nline", "MODE": "test"},
                "export READY=yes\n",
            )
            store.replace(second_id, {"API_KEY": "different"}, "")

            self.assertTrue(first.configured)
            self.assertEqual("sec'ret\nline", store.load(first_id).variables["API_KEY"])
            self.assertEqual("different", store.load(second_id).variables["API_KEY"])
            path = workspace / ".openkapsel" / "env" / f"{first_id}.json"
            self.assertTrue(path.is_file())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            shell_file = store.shell_file(first_id)
            self.assertIsNotNone(shell_file)
            assert shell_file is not None
            self.assertEqual(0o600, shell_file.stat().st_mode & 0o777)
            executed = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    f'. "{shell_file}"; printf "%s|%s" "$API_KEY" "$READY"',
                ],
                check=True,
                capture_output=True,
                text=True,
                env={},
            )
            self.assertEqual("sec'ret\nline|yes", executed.stdout)
            self.assertTrue(store.clear(first_id))
            self.assertFalse(shell_file.exists())
            self.assertFalse(store.clear(first_id))
            self.assertFalse(store.load(first_id).configured)
            self.assertTrue(store.load(second_id).configured)

    def test_invalid_reserved_and_unsafe_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EnvironmentStore(Path(directory))
            app_id = "0123456789abcdef"
            for name in ("PATH", "HTTP_PROXY", "OPENKAPSEL_WORKSPACE", "LD_PRELOAD"):
                with self.subTest(name=name), self.assertRaisesRegex(
                    EnvironmentConfigError, "reserved"
                ):
                    store.replace(app_id, {name: "value"}, "")
            with self.assertRaisesRegex(EnvironmentConfigError, "names must match"):
                store.replace(app_id, {"NOT-VALID": "value"}, "")
            with self.assertRaisesRegex(EnvironmentConfigError, "must not contain NUL"):
                store.replace(app_id, {"TOKEN": "bad\x00value"}, "")
            with self.assertRaisesRegex(EnvironmentConfigError, "rc must not contain NUL"):
                store.replace(app_id, {}, "bad\x00rc")

    def test_symlinked_configuration_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            workspace = Path(directory)
            store = EnvironmentStore(workspace)
            app_id = "0123456789abcdef"
            store.replace(app_id, {}, "")
            path = workspace / ".openkapsel" / "env" / f"{app_id}.json"
            path.unlink()
            target = Path(outside) / "secret.json"
            target.write_text("outside", encoding="utf-8")
            path.symlink_to(target)

            with self.assertRaisesRegex(EnvironmentConfigError, "symlink"):
                store.load(app_id)
            with self.assertRaisesRegex(EnvironmentConfigError, "symlink"):
                store.clear(app_id)
            self.assertEqual("outside", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

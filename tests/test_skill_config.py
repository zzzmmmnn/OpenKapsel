from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIRECTORY = (
    Path(__file__).resolve().parents[1] / "skills" / "openkapsel-rest" / "scripts"
)
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import openkapsel_config  # noqa: E402
import openkapsel_http  # noqa: E402


class SkillCredentialConfigTests(unittest.TestCase):
    def _write_env(self, path: Path, *, expiry: str | None = None) -> None:
        lines = [
            "OPENKAPSEL_BASE_URL=https://file.example/kapsel/w/read",
            "OPENKAPSEL_CONTROL_TOKEN=file-control",
        ]
        if expiry:
            lines.append(f"OPENKAPSEL_CREDENTIALS_EXPIRES_AT={expiry}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def test_nearest_project_file_precedes_legacy_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            nested = root / "src" / "nested"
            nested.mkdir(parents=True)
            env_file = root / ".openkapsel.env"
            self._write_env(env_file)
            with patch.dict(
                os.environ,
                {
                    "OPENKAPSEL_BASE_URL": "https://environment.invalid/w/read",
                    "OPENKAPSEL_CONTROL_TOKEN": "environment-control",
                },
                clear=False,
            ):
                resolved = openkapsel_config.resolve_credentials(cwd=nested)
            self.assertEqual("https://file.example/kapsel/w/read", resolved.base_url)
            self.assertEqual("file-control", resolved.control_token)
            self.assertEqual(env_file.resolve(), resolved.env_file)

            explicit = openkapsel_config.resolve_credentials(
                base_url="https://explicit.example/w/read",
                control_token="explicit-control",
                cwd=nested,
            )
            self.assertEqual("https://explicit.example/w/read", explicit.base_url)
            self.assertEqual("explicit-control", explicit.control_token)
            self.assertIsNone(explicit.env_file)

    def test_environment_fallback_and_private_file_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            with patch.dict(
                os.environ,
                {
                    "OPENKAPSEL_BASE_URL": "https://environment.example/w/read",
                    "OPENKAPSEL_CONTROL_TOKEN": "environment-control",
                },
                clear=False,
            ):
                resolved = openkapsel_config.resolve_credentials(cwd=root)
            self.assertEqual("https://environment.example/w/read", resolved.base_url)
            self.assertEqual("environment-control", resolved.control_token)
            self.assertIsNone(resolved.env_file)

            env_file = root / ".openkapsel.env"
            self._write_env(env_file)
            env_file.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                openkapsel_config.resolve_credentials(cwd=root)

    def test_due_credentials_are_renewed_and_atomically_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            env_file = root / ".openkapsel.env"
            self._write_env(env_file)
            old = openkapsel_config.resolve_credentials(cwd=root)
            due = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            renewed_expiry = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
            responses = [
                openkapsel_http.HttpResult(
                    200,
                    {"Content-Type": "application/json"},
                    json.dumps(
                        {"authentication": {"control_token_expires_at": due}}
                    ).encode(),
                ),
                openkapsel_http.HttpResult(
                    200,
                    {"Content-Type": "application/json"},
                    json.dumps(
                        {
                            "read_token": "new-read",
                            "control_token": "new-control",
                            "workspace_url": "https://file.example/kapsel/w/new-read/",
                            "credentials_expires_at": renewed_expiry,
                        }
                    ).encode(),
                ),
            ]
            with patch.object(openkapsel_http, "api_request", side_effect=responses) as request:
                renewed = openkapsel_http.ensure_fresh_credentials(old)
            self.assertEqual(2, request.call_count)
            self.assertEqual("", request.call_args_list[0].args[1])
            self.assertEqual("credentials/renew", request.call_args_list[1].args[1])
            self.assertEqual("https://file.example/kapsel/w/new-read", renewed.base_url)
            self.assertEqual("new-control", renewed.control_token)
            saved = openkapsel_config.read_env_file(env_file)
            self.assertEqual(renewed.base_url, saved[openkapsel_config.BASE_URL_KEY])
            self.assertEqual("new-control", saved[openkapsel_config.CONTROL_TOKEN_KEY])
            self.assertEqual(renewed_expiry, saved[openkapsel_config.EXPIRY_KEY])
            self.assertEqual(0o600, stat.S_IMODE(env_file.stat().st_mode))

    def test_init_writes_current_directory_without_echoing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = Path.cwd()
            output = io.StringIO()
            errors = io.StringIO()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    status = openkapsel_config.main(
                        [
                            "init",
                            "https://workspace.example/kapsel/w/read-token/",
                            "control-token",
                        ]
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(0, status, errors.getvalue())
            payload = json.loads(output.getvalue())
            self.assertEqual("created", payload["action"])
            self.assertNotIn("read-token", output.getvalue())
            self.assertNotIn("control-token", output.getvalue())
            env_file = root / ".openkapsel.env"
            self.assertEqual(0o600, stat.S_IMODE(env_file.stat().st_mode))
            values = openkapsel_config.read_env_file(env_file)
            self.assertEqual(
                "https://workspace.example/kapsel/w/read-token",
                values[openkapsel_config.BASE_URL_KEY],
            )
            self.assertEqual("control-token", values[openkapsel_config.CONTROL_TOKEN_KEY])

            unchanged = openkapsel_config.initialize_env_file(
                "https://workspace.example/kapsel/w/read-token",
                "control-token",
                directory=root,
            )
            self.assertEqual("unchanged", unchanged[1])
            with self.assertRaisesRegex(ValueError, "--force"):
                openkapsel_config.initialize_env_file(
                    "https://workspace.example/kapsel/w/other-read",
                    "other-control",
                    directory=root,
                )
            replaced = openkapsel_config.initialize_env_file(
                "https://workspace.example/kapsel/w/other-read",
                "other-control",
                directory=root,
                force=True,
            )
            self.assertEqual("replaced", replaced[1])

    def test_init_rejects_non_workspace_urls_and_whitespace_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "/w/<READ_TOKEN>"):
                openkapsel_config.initialize_env_file(
                    "https://workspace.example/kapsel/admin",
                    "control",
                    directory=root,
                )
            with self.assertRaisesRegex(ValueError, "no whitespace"):
                openkapsel_config.initialize_env_file(
                    "https://workspace.example/kapsel/w/read",
                    "bad token",
                    directory=root,
                )


if __name__ == "__main__":
    unittest.main()

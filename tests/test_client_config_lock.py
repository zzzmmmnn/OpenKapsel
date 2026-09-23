from __future__ import annotations

import errno
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_config import (
    REEXEC_CONFIG_SHA256_ENV,
    ClientConfigChangedError,
    ClientConfigLock,
    ClientConfigLockedError,
)
from openkapsel.client_runtime.client_files import ClientFiles


class ClientConfigLockTests(unittest.TestCase):
    def make_config(self, directory: str, *, name: str = "client.json") -> Path:
        path = Path(directory) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"url": "ws://localhost/x", "token": "t", "root": directory}))
        if os.name != "nt":
            path.chmod(0o600)
        return path

    def test_config_is_exclusively_locked_for_process_lifetime(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_config(directory)
            first = ClientConfigLock.acquire(path)
            try:
                with self.assertRaises(ClientConfigLockedError):
                    ClientConfigLock.acquire(path)
            finally:
                first.close()

            second = ClientConfigLock.acquire(path)
            second.close()

    def test_automatic_reload_rejects_changed_config_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_config(directory)
            first = ClientConfigLock.acquire(path)
            digest = first.sha256
            first.close()

            path.write_text(json.dumps({
                "url": "ws://localhost/x",
                "token": "changed",
                "root": directory,
                "source_root": "/tmp/untrusted",
            }))
            if os.name != "nt":
                path.chmod(0o600)

            with patch.dict(os.environ, {REEXEC_CONFIG_SHA256_ENV: digest}, clear=False):
                with self.assertRaises(ClientConfigChangedError):
                    ClientConfigLock.acquire(path)

    def test_matching_reload_digest_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_config(directory)
            first = ClientConfigLock.acquire(path)
            digest = first.sha256
            first.close()

            with patch.dict(os.environ, {REEXEC_CONFIG_SHA256_ENV: digest}, clear=False):
                restored = ClientConfigLock.acquire(path)
            try:
                self.assertEqual(digest, restored.sha256)
            finally:
                restored.close()


class ProtectedClientConfigTests(unittest.TestCase):
    def test_active_config_inside_export_is_readable_but_not_mutable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "client.json"
            config.write_text("{}")
            other = root / "other.txt"
            other.write_text("other")
            files = ClientFiles(root, writable=True, protected_paths=(config,))
            try:
                handle = files.dispatch("open", {"path": "client.json", "mode": "r"})
                files.dispatch("close", {"handle": handle})

                for operation, arguments in (
                    ("open", {"path": "client.json", "mode": "w"}),
                    ("truncate", {"path": "client.json", "size": 0}),
                    ("unlink", {"path": "client.json"}),
                    ("rename", {"path": "other.txt", "destination": "client.json"}),
                ):
                    with self.subTest(operation=operation):
                        with self.assertRaises(OSError) as error:
                            files.dispatch(operation, arguments)
                        self.assertEqual(errno.EACCES, error.exception.errno)

                response = files.dispatch(
                    "api_fs_write",
                    {"body": {"path": "client.json", "content": "changed"}},
                )
                self.assertEqual(403, response["status"])
                self.assertEqual("client_config_protected", response["error"]["code"])
                self.assertEqual("{}", config.read_text())
            finally:
                files.close()

    def test_parent_directory_of_active_config_cannot_be_renamed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected_dir = root / "local"
            protected_dir.mkdir()
            config = protected_dir / "client.json"
            config.write_text("{}")
            files = ClientFiles(root, writable=True, protected_paths=(config,))
            try:
                with self.assertRaises(OSError) as error:
                    files.dispatch("rename", {"path": "local", "destination": "moved"})
                self.assertEqual(errno.EACCES, error.exception.errno)
            finally:
                files.close()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import ClientRuntime
from openkapsel.client_runtime.client_config import (
    REEXEC_CONFIG_SHA256_ENV,
    ClientConfigChangedError,
    ClientConfigLock,
    ClientConfigLockedError,
)
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins.archive import archive_create_task


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

    @unittest.skipUnless(os.name == "nt", "Windows sharing-denial semantics")
    def test_windows_lock_denies_other_process_read_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_config(directory)
            locked = ClientConfigLock.acquire(path)
            try:
                denied = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()",
                        str(path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(0, denied.returncode)
            finally:
                locked.close()

            allowed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()",
                    str(path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, allowed.returncode, allowed.stderr)


class ClientConfigSecrecyPolicyTests(unittest.TestCase):
    def test_runtime_rejects_active_config_inside_export_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            root.mkdir()
            config_path = root / "client.json"
            config_path.write_text("{}")
            config = {
                "url": "ws://localhost/x",
                "token": "t",
                "root": str(root),
            }
            with self.assertRaisesRegex(
                ValueError,
                "active client configuration must be outside",
            ):
                ClientRuntime(config, protected_paths=(config_path,))

    def test_ssh_profiles_allow_native_unsandboxed_execution_with_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            root.mkdir()
            config_path = base / "client.json"
            config_path.write_text("{}")
            config = {
                "url": "ws://localhost/x",
                "token": "t",
                "root": str(root),
                "writable": True,
                "allow_exec": True,
                "sandbox": False,
                "ssh": {
                    "profiles": {
                        "prod": {
                            "host": "127.0.0.1",
                            "username": "deploy",
                            "password": "secret",
                        }
                    }
                },
            }
            with self.assertLogs("openkapsel.client", level="WARNING") as logs:
                runtime = ClientRuntime(config, protected_paths=(config_path,))
            try:
                self.assertTrue(runtime.tasks.enabled)
                self.assertFalse(runtime.tasks.sandbox)
                self.assertIn(
                    "SSH profiles are configured",
                    "\n".join(logs.output),
                )
            finally:
                runtime.close()


class ProtectedClientConfigTests(unittest.TestCase):
    def test_active_config_inside_export_is_hidden_and_inaccessible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "client.json"
            config.write_text('{"token":"secret-value"}')
            other = root / "other.txt"
            other.write_text("other")
            files = ClientFiles(root, writable=True, protected_paths=(config,))
            try:
                for operation, arguments in (
                    ("stat", {"path": "client.json"}),
                    ("open", {"path": "client.json", "mode": "r"}),
                    ("open", {"path": "client.json", "mode": "w"}),
                    ("truncate", {"path": "client.json", "size": 0}),
                    ("unlink", {"path": "client.json"}),
                    ("rename", {"path": "other.txt", "destination": "client.json"}),
                ):
                    with self.subTest(operation=operation):
                        with self.assertRaises(OSError) as error:
                            files.dispatch(operation, arguments)
                        self.assertEqual(errno.ENOENT, error.exception.errno)

                listing = files.dispatch("list", {"path": "."})
                self.assertEqual(["other.txt"], listing["names"])

                response = files.dispatch(
                    "api_fs_read",
                    {"query": {"path": ["client.json"]}},
                )
                self.assertEqual(404, response["status"])
                self.assertEqual("path_not_found", response["error"]["code"])

                api_listing = files.dispatch(
                    "api_fs_list",
                    {"query": {"path": ["."]}},
                )
                self.assertEqual(200, api_listing["status"])
                self.assertEqual(
                    ["other.txt"],
                    [entry["name"] for entry in api_listing["body"]["entries"]],
                )

                tree = files.dispatch(
                    "api_fs_tree",
                    {"query": {"path": ["."], "depth": ["2"]}},
                )
                self.assertEqual(200, tree["status"])
                self.assertNotIn("client.json", repr(tree))

                search = files.dispatch(
                    "api_fs_search",
                    {"query": {"path": ["."], "query": ["secret-value"]}},
                )
                self.assertEqual(200, search["status"])
                self.assertEqual([], search["body"]["matches"])

                self.assertEqual('{"token":"secret-value"}', config.read_text())
            finally:
                files.close()

    def test_archive_root_traversal_omits_active_config(self):
        class Task:
            @staticmethod
            def check_cancelled():
                return None

            @staticmethod
            def write(_value):
                return None

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "client.json"
            config.write_text('{"token":"secret-value"}')
            (root / "other.txt").write_text("other")
            files = ClientFiles(root, writable=True, protected_paths=(config,))
            try:
                result = archive_create_task(
                    files,
                    {
                        "destination": "bundle.zip",
                        "sources": ["."],
                        "format": "zip",
                        "overwrite": False,
                    },
                    Task(),
                )
                self.assertEqual("bundle.zip", result["destination"])
                with zipfile.ZipFile(root / "bundle.zip") as archive:
                    names = archive.namelist()
                    self.assertIn("other.txt", names)
                    self.assertNotIn("client.json", names)
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

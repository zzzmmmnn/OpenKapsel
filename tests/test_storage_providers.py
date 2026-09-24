import base64
import errno
import hashlib
import html
import json
import re
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from openkapsel.storage.storage_host import HostStorageProviders
from openkapsel.storage.storage_manager import StorageProviderDeleteWarning, StorageProviderManager
from openkapsel.storage.storage_oauth import StorageOAuthError, StorageOAuthFlows
from openkapsel.storage.storage_sftp import detect_sftp_host_keys
from openkapsel.storage.storage_store import DEFAULT_CACHE_MAX_BYTES, StorageProviderStore
from openkapsel.storage.storage_ui import render_storage_providers
from openkapsel.workspace.workspace_images import WorkspaceImageError


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.active = True
        self.version = "rclone v1.70.0"
        self.rc_stats = {
            "diskCache": {
                "bytesUsed": 0,
                "uploadsQueued": 0,
                "uploadsInProgress": 0,
            }
        }

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        if len(argv) >= 2 and argv[1] == "obscure":
            return Result(stdout="OBSCURED\n")
        if len(argv) >= 2 and argv[1] == "version":
            return Result(stdout=self.version + "\n")
        if len(argv) >= 2 and argv[1] == "rc":
            return Result(stdout=json.dumps(self.rc_stats))
        if "is-active" in argv:
            return Result(returncode=0 if self.active else 3, stdout="active\n" if self.active else "inactive\n")
        return Result()


class FakeHelper:
    enabled = True

    def __init__(self):
        self.calls = []
        self.configured = set()
        self.mounted = set()
        self.binds = set()
        self.pending = {
            "pending": False,
            "uncertain": False,
            "uploads_queued": 0,
            "uploads_in_progress": 0,
            "cache_bytes": 0,
            "reason": "",
        }

    def _request(self, action, **values):
        self.calls.append((action, dict(values)))
        provider_id = values.get("id")
        if action == "storage_probe":
            return {"available": True, "rclone": True, "fusermount": True}
        if action == "storage_configure":
            self.configured.add(provider_id)
            return {"configured": True}
        if action == "storage_mount":
            if provider_id not in self.configured:
                raise RuntimeError("not configured")
            self.mounted.add(provider_id)
            return {"mounted": True}
        if action == "storage_unmount":
            self.mounted.discard(provider_id)
            return {"mounted": False}
        if action == "storage_bind":
            self.binds.add((values["workspace"], values["name"]))
            return {"mapped": True}
        if action == "storage_unbind":
            self.binds.discard((values["workspace"], values["name"]))
            return {"mapped": False}
        if action == "storage_pending":
            return dict(self.pending)
        if action == "storage_status":
            return {
                "configured": provider_id in self.configured,
                "mounted": provider_id in self.mounted,
                "unit_active": provider_id in self.mounted,
                "mappings": {item["id"]: (item["workspace"], item["name"]) in self.binds
                             for item in values.get("mappings", [])},
            }
        if action == "storage_delete":
            self.configured.discard(provider_id)
            self.mounted.discard(provider_id)
            return {"deleted": True}
        raise AssertionError(action)


class StorageOAuthFlowTests(unittest.TestCase):
    def test_authorization_urls_and_state_are_provider_specific(self):
        flows = StorageOAuthFlows()
        redirect = "https://example.test/kapsel/admin/storage-providers/oauth/callback"
        google, google_url = flows.begin(
            session_id="admin-session",
            kind="google_drive",
            client_id="google-id",
            client_secret="google-secret",
            redirect_uri=redirect,
            create_values={"name": "drive"},
        )
        parsed = urlsplit(google_url)
        params = parse_qs(parsed.query)
        self.assertEqual("accounts.google.com", parsed.hostname)
        self.assertEqual(["offline"], params["access_type"])
        self.assertEqual(["consent"], params["prompt"])
        self.assertEqual([redirect], params["redirect_uri"])
        self.assertEqual([google.state], params["state"])

        dropbox, dropbox_url = flows.begin(
            session_id="admin-session",
            kind="dropbox",
            client_id="dropbox-id",
            client_secret="dropbox-secret",
            redirect_uri=redirect,
            create_values={"name": "dropbox"},
        )
        parsed = urlsplit(dropbox_url)
        params = parse_qs(parsed.query)
        self.assertEqual("www.dropbox.com", parsed.hostname)
        self.assertEqual(["offline"], params["token_access_type"])
        self.assertEqual([dropbox.state], params["state"])

        pcloud, pcloud_url = flows.begin(
            session_id="admin-session",
            kind="pcloud",
            client_id="pcloud-id",
            client_secret="pcloud-secret",
            redirect_uri=redirect,
            create_values={"name": "pcloud"},
        )
        parsed = urlsplit(pcloud_url)
        params = parse_qs(parsed.query)
        self.assertEqual("my.pcloud.com", parsed.hostname)
        self.assertEqual([redirect], params["redirect_uri"])
        self.assertEqual([pcloud.state], params["state"])

        onedrive, onedrive_url = flows.begin(
            session_id="admin-session",
            kind="onedrive",
            client_id="onedrive-id",
            client_secret="onedrive-secret",
            redirect_uri=redirect,
            create_values={"name": "onedrive"},
            options={"region": "global"},
        )
        parsed = urlsplit(onedrive_url)
        params = parse_qs(parsed.query)
        self.assertEqual("login.microsoftonline.com", parsed.hostname)
        self.assertEqual("/common/oauth2/v2.0/authorize", parsed.path)
        self.assertIn("Files.ReadWrite", params["scope"][0])
        self.assertIn("offline_access", params["scope"][0])
        self.assertEqual([onedrive.state], params["state"])

        with self.assertRaises(StorageOAuthError):
            flows.consume(google.state, "other-session")
        self.assertEqual(google, flows.consume(google.state, "admin-session"))
        with self.assertRaises(StorageOAuthError):
            flows.consume(google.state, "admin-session")

    def test_exchange_normalizes_provider_response_for_rclone(self):
        flows = StorageOAuthFlows()
        flow, _ = flows.begin(
            session_id="admin-session",
            kind="dropbox",
            client_id="dropbox-id",
            client_secret="dropbox-secret",
            redirect_uri="https://example.test/kapsel/admin/storage-providers/oauth/callback",
            provider_id="provider-id",
        )

        class Response:
            content = b'{"access_token":"ACCESS"}'

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "access_token": "ACCESS",
                    "token_type": "bearer",
                    "refresh_token": "REFRESH",
                    "expires_in": "14400",
                }

        with patch("httpx.post", return_value=Response()) as request:
            token = json.loads(flows.exchange(flow, "authorization-code"))
        self.assertEqual("ACCESS", token["access_token"])
        self.assertEqual("REFRESH", token["refresh_token"])
        self.assertEqual("bearer", token["token_type"])
        self.assertTrue(token["expiry"].endswith("Z"))
        values = request.call_args.kwargs["data"]
        self.assertEqual("dropbox-secret", values["client_secret"])
        self.assertEqual(flow.redirect_uri, values["redirect_uri"])

    def test_pcloud_exchange_uses_callback_hostname_and_nonexpiring_token(self):
        flows = StorageOAuthFlows()
        flow, _ = flows.begin(
            session_id="admin-session",
            kind="pcloud",
            client_id="pcloud-id",
            client_secret="pcloud-secret",
            redirect_uri="https://example.test/kapsel/admin/storage-providers/oauth/callback",
            provider_id="provider-id",
        )

        class Response:
            content = b'{"access_token":"PCLOUD"}'

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "access_token": "PCLOUD",
                    "token_type": "bearer",
                }

        with patch("httpx.post", return_value=Response()) as request:
            credentials = flows.exchange_credentials(
                flow,
                "authorization-code",
                {"hostname": "eapi.pcloud.com", "locationid": "2"},
            )
        self.assertEqual("eapi.pcloud.com", credentials["hostname"])
        token = json.loads(credentials["token"])
        self.assertEqual("PCLOUD", token["access_token"])
        self.assertEqual("0001-01-01T00:00:00Z", token["expiry"])
        self.assertNotIn("refresh_token", token)
        self.assertEqual("https://eapi.pcloud.com/oauth2_token", request.call_args.args[0])
        self.assertEqual("pcloud-secret", request.call_args.kwargs["data"]["client_secret"])
        with self.assertRaises(StorageOAuthError):
            flows._pcloud_hostname("evil.example")
        with self.assertRaisesRegex(StorageOAuthError, "invalid API hostname"):
            flows.exchange_credentials(flow, "authorization-code", {})

    def test_onedrive_exchange_discovers_default_drive(self):
        flows = StorageOAuthFlows()
        flow, _ = flows.begin(
            session_id="admin-session",
            kind="onedrive",
            client_id="onedrive-id",
            client_secret="onedrive-secret",
            redirect_uri="https://example.test/kapsel/admin/storage-providers/oauth/callback",
            provider_id="provider-id",
            options={"region": "global"},
        )

        class TokenResponse:
            content = b'{"access_token":"ONEDRIVE"}'

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "access_token": "ONEDRIVE",
                    "token_type": "Bearer",
                    "refresh_token": "REFRESH",
                    "expires_in": 3600,
                }

        class DriveResponse:
            content = b'{"id":"drive-id","driveType":"business"}'

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "id": "drive-id",
                    "driveType": "business",
                    "name": "OneDrive",
                }

        with (
            patch("httpx.post", return_value=TokenResponse()) as token_request,
            patch("httpx.get", return_value=DriveResponse()) as drive_request,
        ):
            credentials = flows.exchange_credentials(flow, "authorization-code")
        self.assertEqual("global", credentials["region"])
        self.assertEqual("drive-id", credentials["drive_id"])
        self.assertEqual("business", credentials["drive_type"])
        token = json.loads(credentials["token"])
        self.assertEqual("REFRESH", token["refresh_token"])
        self.assertEqual(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            token_request.call_args.args[0],
        )
        self.assertEqual(
            "https://graph.microsoft.com/v1.0/me/drive",
            drive_request.call_args.args[0],
        )
        self.assertEqual(
            "Bearer ONEDRIVE",
            drive_request.call_args.kwargs["headers"]["Authorization"],
        )


class StorageProviderStoreTests(unittest.TestCase):
    def test_store_keeps_only_public_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "storage.sqlite3"
            store = StorageProviderStore(path)
            provider = store.create("Google Drive 測試", "google_drive", remote_path="Projects", writable=True)
            self.assertTrue(provider["writable"])
            self.assertEqual(1 * 1024**3, DEFAULT_CACHE_MAX_BYTES)
            self.assertEqual(DEFAULT_CACHE_MAX_BYTES, provider["cache_max_bytes"])
            self.assertNotIn("credentials", provider)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            mapping = store.add_mapping(provider["id"], "workspace", "drive")
            self.assertEqual("workspace", mapping["workspace"])
            self.assertTrue(store.reserved("workspace", "drive"))
            with self.assertRaises(ValueError):
                store.add_mapping(provider["id"], "workspace", "Google Drive")
            with self.assertRaises(sqlite3.IntegrityError):
                store.add_mapping(provider["id"], "workspace", "drive")

    def test_store_accepts_v2_provider_kinds_without_storing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StorageProviderStore(Path(directory) / "storage.sqlite3")
            for kind in ("pcloud", "onedrive", "webdav", "s3"):
                with self.subTest(kind=kind):
                    provider = store.create(kind, kind)
                    self.assertEqual(kind, provider["kind"])
                    self.assertNotIn("credentials", provider)
            with self.assertRaises(ValueError):
                store.create("unsupported", "mega")


class SFTPHostKeyDetectionTests(unittest.TestCase):
    def test_detect_formats_nondefault_port_and_computes_sha256_fingerprints(self):
        key_one_raw = b"openkapsel-test-ed25519-key"
        key_two_raw = b"openkapsel-test-rsa-key"
        key_one = base64.b64encode(key_one_raw).decode("ascii")
        key_two = base64.b64encode(key_two_raw).decode("ascii")
        calls = []

        def runner(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            return Result(
                stdout=(
                    f"files.example.com ssh-ed25519 {key_one}\n"
                    f"files.example.com ssh-rsa {key_two}\n"
                )
            )

        result = detect_sftp_host_keys(
            "files.example.com",
            2222,
            runner=runner,
            executable="/usr/bin/ssh-keyscan",
        )
        self.assertEqual("files.example.com", result["host"])
        self.assertEqual(2222, result["port"])
        self.assertEqual(2, len(result["keys"]))
        self.assertEqual(
            "SHA256:"
            + base64.b64encode(hashlib.sha256(key_one_raw).digest())
            .decode("ascii")
            .rstrip("="),
            result["keys"][0]["fingerprint_sha256"],
        )
        self.assertIn(
            f"[files.example.com]:2222 ssh-ed25519 {key_one}",
            result["known_hosts"],
        )
        argv, kwargs = calls[0]
        self.assertEqual("/usr/bin/ssh-keyscan", argv[0])
        self.assertEqual("-", argv[-1])
        self.assertEqual("files.example.com\n", kwargs["input"])
        self.assertNotIn("files.example.com", argv)

    def test_detect_rejects_missing_key_and_unsafe_host_input(self):
        def empty_runner(_argv, **_kwargs):
            return Result(stdout="", stderr="scan failed")

        with self.assertRaisesRegex(ValueError, "no SSH host key"):
            detect_sftp_host_keys(
                "files.example.com",
                22,
                runner=empty_runner,
                executable="/usr/bin/ssh-keyscan",
            )
        with self.assertRaisesRegex(ValueError, "whitespace"):
            detect_sftp_host_keys(
                "one.example two.example",
                22,
                runner=empty_runner,
                executable="/usr/bin/ssh-keyscan",
            )


class HostStorageProviderTests(unittest.TestCase):
    def make_host(self, directory):
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "demo").mkdir()
        storage = root / "storage"
        storage.mkdir()
        home = root / "home"
        home.mkdir()
        runner = FakeRunner()
        uid, gid = os.getuid(), os.getgid()
        host = HostStorageProviders(
            workspace, storage, uid, gid, uid, gid, home, runner=runner
        )
        host.rclone = "/usr/bin/rclone"
        host.systemd_run = "/usr/bin/systemd-run"
        host.systemctl = "/usr/bin/systemctl"
        host.mount_command = "/usr/bin/mount"
        host.umount_command = "/usr/bin/umount"
        host.fusermount = "/usr/bin/fusermount3"
        return host, runner

    def test_probe_requires_rclone_160_for_smb(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            rclone = Path(directory) / "rclone"
            fusermount = Path(directory) / "fusermount3"
            rclone.touch()
            fusermount.touch()
            host.rclone = str(rclone)
            host.fusermount = str(fusermount)
            runner.version = "rclone v1.59.2"
            old = host.probe()
            self.assertFalse(old["available"])
            self.assertFalse(old["rclone_version_supported"])
            self.assertIn("1.60.0", old["reason"])
            runner.version = "rclone v1.60.0"
            current = host.probe()
            self.assertTrue(current["available"])
            self.assertEqual("1.60.0", current["rclone_version"])

    def test_provider_root_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            host, _runner = self.make_host(directory)
            provider_id = "d" * 24
            outside = Path(directory) / "outside"
            outside.mkdir()
            (Path(directory) / "storage" / provider_id).symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(Exception, "symbolic link"):
                host.configure(provider_id, "smb", {
                    "host": "server", "user": "guest", "password": "", "domain": "WORKGROUP",
                })

    def test_sftp_config_obscures_password_and_pins_host_key(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            provider_id = "a" * 24
            result = host.configure(provider_id, "sftp", {
                "host": "example.com", "port": 2222, "user": "alice",
                "password": "secret", "private_key": "",
                "known_hosts": "[example.com]:2222 ssh-ed25519 AAAATEST",
            })
            self.assertEqual({"configured": True}, result)
            config = (Path(directory) / "storage" / provider_id / "rclone.conf").read_text()
            self.assertIn("type = sftp", config)
            self.assertIn("pass = OBSCURED", config)
            self.assertNotIn("secret", config)
            self.assertIn("known_hosts_file =", config)
            obscure = next(call for call in runner.calls if call[0][1] == "obscure")
            self.assertEqual("secret\n", obscure[1]["input"])
            self.assertNotIn("secret", " ".join(obscure[0]))

    def test_v2_provider_configs_are_private_and_rclone_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            cases = [
                (
                    "p" * 24,
                    "pcloud",
                    {
                        "client_id": "",
                        "client_secret": "",
                        "token": '{"access_token":"PCLOUD"}',
                        "hostname": "eapi.pcloud.com",
                    },
                    [
                        "type = pcloud",
                        "hostname = eapi.pcloud.com",
                        'token = {"access_token":"PCLOUD"}',
                    ],
                ),
                (
                    "o" * 24,
                    "onedrive",
                    {
                        "client_id": "",
                        "client_secret": "",
                        "token": '{"access_token":"ONEDRIVE"}',
                        "region": "global",
                        "drive_id": "drive-id",
                        "drive_type": "business",
                    },
                    [
                        "type = onedrive",
                        "region = global",
                        "access_scopes = Files.ReadWrite offline_access",
                        "drive_id = drive-id",
                        "drive_type = business",
                        'token = {"access_token":"ONEDRIVE"}',
                    ],
                ),
                (
                    "w" * 24,
                    "webdav",
                    {
                        "url": "https://cloud.example.test/remote.php/dav/files/alice/",
                        "vendor": "nextcloud",
                        "user": "alice",
                        "password": "webdav-secret",
                    },
                    [
                        "type = webdav",
                        "url = https://cloud.example.test/remote.php/dav/files/alice/",
                        "vendor = nextcloud",
                        "user = alice",
                        "pass = OBSCURED",
                    ],
                ),
                (
                    "s" * 24,
                    "s3",
                    {
                        "endpoint": "https://s3.example.test",
                        "region": "us-test-1",
                        "access_key_id": "ACCESS",
                        "secret_access_key": "SECRET",
                        "force_path_style": True,
                        "v2_auth": True,
                    },
                    [
                        "type = s3",
                        "provider = Other",
                        "env_auth = false",
                        "access_key_id = ACCESS",
                        "secret_access_key = SECRET",
                        "region = us-test-1",
                        "endpoint = https://s3.example.test",
                        "force_path_style = true",
                        "v2_auth = true",
                    ],
                ),
            ]
            for provider_id, kind, settings, expected in cases:
                with self.subTest(kind=kind):
                    self.assertEqual(
                        {"configured": True},
                        host.configure(provider_id, kind, settings),
                    )
                    config_path = Path(directory) / "storage" / provider_id / "rclone.conf"
                    config = config_path.read_text()
                    self.assertEqual(0o600, config_path.stat().st_mode & 0o777)
                    for line in expected:
                        self.assertIn(line, config)
                    self.assertNotIn("webdav-secret", config)
            obscure = [
                kwargs
                for argv, kwargs in runner.calls
                if len(argv) >= 2 and argv[1] == "obscure"
            ]
            self.assertTrue(
                any(kwargs.get("input") == "webdav-secret\n" for kwargs in obscure)
            )

    def test_v2_provider_config_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            host, _runner = self.make_host(directory)
            with self.assertRaisesRegex(WorkspaceImageError, "pCloud API hostname"):
                host.configure(
                    "p" * 24,
                    "pcloud",
                    {
                        "token": '{"access_token":"x"}',
                        "hostname": "evil.example",
                    },
                )
            with self.assertRaisesRegex(WorkspaceImageError, "OneDrive drive type"):
                host.configure(
                    "o" * 24,
                    "onedrive",
                    {
                        "token": '{"access_token":"x"}',
                        "region": "global",
                        "drive_id": "drive",
                        "drive_type": "unknown",
                    },
                )
            with self.assertRaisesRegex(WorkspaceImageError, "WebDAV user and password"):
                host.configure(
                    "w" * 24,
                    "webdav",
                    {
                        "url": "https://dav.example",
                        "vendor": "other",
                        "user": "alice",
                        "password": "",
                    },
                )
            with self.assertRaisesRegex(WorkspaceImageError, "S3 force path style"):
                host.configure(
                    "s" * 24,
                    "s3",
                    {
                        "endpoint": "https://s3.example",
                        "access_key_id": "a",
                        "secret_access_key": "b",
                        "force_path_style": "true",
                    },
                )

    def test_mount_is_lazy_vfs_with_bounded_per_provider_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            provider_id = "b" * 24
            _root, mount, _cache, config = host._ensure_provider_dirs(provider_id)
            config.write_text("[provider]\ntype = smb\nhost = server\n")
            with patch("openkapsel.storage.storage_host.os.path.ismount", side_effect=[False, True]):
                self.assertTrue(host.mount(provider_id, "share", False, 4 * 1024**3)["mounted"])
            launch = next(argv for argv, _kwargs in runner.calls if "/usr/bin/rclone" in argv and "mount" in argv)
            self.assertEqual("mount", launch[launch.index("/usr/bin/rclone") + 1])
            self.assertIn("provider:share", launch)
            self.assertIn("--vfs-cache-mode=writes", launch)
            self.assertIn("--vfs-cache-max-size", launch)
            self.assertIn(f"{4 * 1024**3}B", launch)
            self.assertIn("--cache-dir", launch)
            self.assertIn("--rc", launch)
            self.assertIn("--rc-addr", launch)
            self.assertIn(
                f"--property=RuntimeDirectory=openkapsel-storage-{provider_id}",
                launch,
            )
            self.assertIn("--property=RuntimeDirectoryMode=0700", launch)
            self.assertIn(
                f"unix:///run/openkapsel-storage-{provider_id}/rc.sock",
                launch,
            )
            self.assertIn("--read-only", launch)
            self.assertNotIn("sync", launch)
            self.assertNotIn("copy", launch)
            self.assertNotIn("--vfs-cache-mode=full", launch)
            self.assertEqual(mount, Path(launch[launch.index("provider:share") + 1]))

    def test_mount_reuses_active_read_only_fuse_without_rechowning_mountpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            provider_id = "h" * 24
            _root, _mount, _cache, config = host._ensure_provider_dirs(provider_id)
            config.write_text("[provider]\ntype = dropbox\ntoken = {}\n")
            runner.active = True
            with (
                patch("openkapsel.storage.storage_host.os.path.ismount", return_value=True),
                patch.object(
                    host,
                    "_ensure_provider_dirs",
                    side_effect=AssertionError("must not touch an active FUSE mountpoint"),
                ),
            ):
                self.assertEqual(
                    {"mounted": True},
                    host.mount(provider_id, "", False, 1024**3),
                )
            self.assertFalse(any("/usr/bin/rclone" in argv and "mount" in argv for argv, _kwargs in runner.calls))

    def test_pending_uses_private_rc_vfs_stats(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            provider_id = "g" * 24
            host._ensure_provider_dirs(provider_id)
            runner.rc_stats = {
                "diskCache": {
                    "bytesUsed": 987654321,
                    "uploadsQueued": 2,
                    "uploadsInProgress": 1,
                }
            }
            with (
                patch("openkapsel.storage.storage_host.os.path.ismount", return_value=True),
                patch("pathlib.Path.is_socket", return_value=True),
            ):
                pending = host.pending(provider_id)
            self.assertTrue(pending["pending"])
            self.assertFalse(pending["uncertain"])
            self.assertEqual(2, pending["uploads_queued"])
            self.assertEqual(1, pending["uploads_in_progress"])
            self.assertEqual(987654321, pending["cache_bytes"])
            rc_call = next(argv for argv, _kwargs in runner.calls if len(argv) > 1 and argv[1] == "rc")
            self.assertIn("--unix-socket", rc_call)
            self.assertIn("vfs/stats", rc_call)

    def test_stale_mount_is_detached_before_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            runner.active = False
            provider_id = "e" * 24
            _root, _mount, _cache, config = host._ensure_provider_dirs(provider_id)
            config.write_text("[provider]\ntype = smb\nhost = server\n")
            with patch(
                "openkapsel.storage.storage_host.os.path.ismount",
                side_effect=[True, True, False, True],
            ):
                self.assertTrue(host.mount(provider_id, "share", True, 2 * 1024**3)["mounted"])
            owner_unmount = [
                argv for argv, _kwargs in runner.calls
                if "/usr/bin/fusermount3" in argv and "-uz" in argv
            ]
            self.assertEqual(1, len(owner_unmount))
            launches = [
                argv for argv, _kwargs in runner.calls
                if "/usr/bin/rclone" in argv and "mount" in argv
            ]
            self.assertEqual(1, len(launches))

    def test_bind_replaces_stale_mount_from_other_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            provider_id = "f" * 24
            _root, _mount, _cache, _config = host._ensure_provider_dirs(provider_id)
            with (
                patch(
                    "openkapsel.storage.storage_host.os.path.ismount",
                    side_effect=[True, True, False],
                ),
                patch.object(host, "_same_mount", return_value=False),
            ):
                host.bind(provider_id, "demo", "cloud", True)
            commands = [argv for argv, _kwargs in runner.calls]
            stale_unmount = next(i for i, argv in enumerate(commands) if argv[:1] == ["/usr/bin/umount"])
            new_bind = next(i for i, argv in enumerate(commands) if "--bind" in argv)
            self.assertLess(stale_unmount, new_bind)

    def test_bind_is_confined_to_direct_workspace_child(self):
        with tempfile.TemporaryDirectory() as directory:
            host, runner = self.make_host(directory)
            provider_id = "c" * 24
            _root, mount, _cache, _config = host._ensure_provider_dirs(provider_id)
            target = Path(directory) / "workspace" / "demo" / "cloud"
            with patch("openkapsel.storage.storage_host.os.path.ismount", side_effect=lambda path: Path(path) == mount):
                host.bind(provider_id, "demo", "cloud", True)
                with self.assertRaisesRegex(Exception, "invalid workspace"):
                    host.bind(provider_id, "../escape", "cloud", True)
            bind = next(argv for argv, _kwargs in runner.calls if "--bind" in argv)
            self.assertEqual(str(target.resolve()), bind[-1])


class StorageProviderManagerTests(unittest.TestCase):
    def test_startup_reconcile_retries_helper_socket_and_transient_mount_failure(self):
        class FlakyStartupHelper(FakeHelper):
            def __init__(self):
                super().__init__()
                self.probe_failures = 0
                self.mount_failures = 0
                self.probe_attempts = 0
                self.mount_attempts = 0

            def _request(self, action, **values):
                if action == "storage_probe":
                    self.probe_attempts += 1
                    if self.probe_failures:
                        self.probe_failures -= 1
                        raise WorkspaceImageError("helper socket is not ready")
                if action == "storage_mount":
                    self.mount_attempts += 1
                    if self.mount_failures:
                        self.mount_failures -= 1
                        raise WorkspaceImageError("transient provider mount failure")
                return super()._request(action, **values)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            (root / "demo").mkdir()
            helper = FlakyStartupHelper()
            manager = StorageProviderManager(root, Path(directory) / "state", helper)
            manager.workspace_available = lambda workspace: workspace == "demo"
            try:
                provider = manager.create(
                    "dropbox", "dropbox",
                    settings={"token": '{"access_token":"x"}'},
                    cache_max_bytes=DEFAULT_CACHE_MAX_BYTES,
                )
                manager.add_mapping(provider["id"], "demo", "cloud")
                helper.probe_attempts = 0
                helper.mount_attempts = 0
                helper.probe_failures = 2
                helper.mount_failures = 1
                helper.calls.clear()

                with patch.object(manager._closing, "wait", return_value=False) as wait:
                    manager._startup_reconcile()

                self.assertEqual(3, helper.probe_attempts)
                self.assertEqual(2, helper.mount_attempts)
                self.assertIn(provider["id"], helper.mounted)
                self.assertIn(("demo", "cloud"), helper.binds)
                self.assertGreaterEqual(wait.call_count, 3)
            finally:
                manager.close()

    def test_provider_and_workspace_mapping_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            (root / "demo").mkdir()
            state = Path(directory) / "state"
            helper = FakeHelper()
            manager = StorageProviderManager(root, state, helper)
            manager.workspace_available = lambda workspace: workspace == "demo"
            try:
                provider = manager.create(
                    "dropbox", "dropbox", settings={"token": '{"access_token":"x"}'},
                    cache_max_bytes=2 * 1024**3,
                )
                self.assertTrue(provider["status"]["mounted"])
                mapping = manager.add_mapping(provider["id"], "demo", "cloud")
                self.assertIn(("demo", "cloud"), helper.binds)
                listed = manager.get(provider["id"])
                self.assertTrue(listed["status"]["mappings"][mapping["id"]])
                manager.update(provider["id"], enabled=False)
                self.assertNotIn(provider["id"], helper.mounted)
                self.assertNotIn(("demo", "cloud"), helper.binds)
                manager.delete(provider["id"])
                self.assertEqual([], manager.store.list())
            finally:
                manager.close()

    def test_delete_requires_force_when_uploads_are_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            (root / "demo").mkdir()
            helper = FakeHelper()
            manager = StorageProviderManager(root, Path(directory) / "state", helper)
            manager.workspace_available = lambda workspace: workspace == "demo"
            try:
                provider = manager.create(
                    "dropbox", "dropbox",
                    settings={"token": '{"access_token":"x"}'},
                    writable=True,
                    cache_max_bytes=DEFAULT_CACHE_MAX_BYTES,
                )
                manager.add_mapping(provider["id"], "demo", "cloud")
                helper.pending = {
                    "pending": True,
                    "uncertain": False,
                    "uploads_queued": 2,
                    "uploads_in_progress": 1,
                    "cache_bytes": 512 * 1024**2,
                    "reason": "",
                }
                with self.assertRaises(StorageProviderDeleteWarning) as raised:
                    manager.delete(provider["id"])
                self.assertEqual(2, raised.exception.details["uploads_queued"])
                self.assertEqual(1, len(manager.store.list()))
                manager.delete(provider["id"], force=True)
                self.assertEqual([], manager.store.list())
                force_unbind = [
                    values for action, values in helper.calls
                    if action == "storage_unbind" and values.get("name") == "cloud"
                ][-1]
                self.assertTrue(force_unbind["force"])
            finally:
                manager.close()


class StorageProviderPathPolicyTests(unittest.TestCase):
    def test_reserved_mapping_descendants_fail_closed_when_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            (root / "demo").mkdir()
            helper = FakeHelper()
            manager = StorageProviderManager(root, Path(directory) / "state", helper)
            manager.workspace_available = lambda workspace: workspace == "demo"
            try:
                provider = manager.create(
                    "drive", "google_drive",
                    settings={
                        "client_id": "id",
                        "client_secret": "secret",
                        "token": '{"access_token":"x"}',
                    },
                    writable=True,
                    cache_max_bytes=2 * 1024**3,
                )
                mapping = manager.add_mapping(provider["id"], "demo", "cloud")
                descendant = manager.mapping_path(mapping) / "nested" / "file.txt"
                with self.assertRaises(OSError) as raised:
                    manager.check_path(descendant, write=True)
                self.assertEqual(errno.EHOSTDOWN, raised.exception.errno)
                with patch("openkapsel.storage.storage_manager.os.path.ismount", return_value=True):
                    manager.check_path(descendant, write=True)
                    with self.assertRaises(OSError) as root_error:
                        manager.check_path(manager.mapping_path(mapping), write=True, protect_root=True)
                    self.assertEqual(errno.EBUSY, root_error.exception.errno)
            finally:
                manager.close()


class InstallerStorageProviderTests(unittest.TestCase):
    def test_installer_keeps_storage_credentials_owned_by_dedicated_user(self):
        install = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        self.assertIn("STORAGE_USER=openkapsel-storage", install)
        self.assertIn("RCLONE_MIN_VERSION=1.60.0", install)
        self.assertIn("rclone", install)
        self.assertIn("openssh-client", install)
        self.assertIn("user_allow_other", install)
        self.assertIn('-path "$STORAGE_ROOT"', install)
        self.assertIn('-path "$STORAGE_HOME"', install)
        self.assertIn('chown "$STORAGE_USER:$STORAGE_GROUP" "$STORAGE_ROOT" "$STORAGE_HOME"', install)
        self.assertIn('bash "$SOURCE_DIR/scripts/openkapsel-safe-shutdown" --timeout-seconds 300', install)
        self.assertIn('"$SOURCE_DIR/scripts" "$STAGING_DIR/"', install)
        stop_at = install.index('bash "$SOURCE_DIR/scripts/openkapsel-safe-shutdown" --timeout-seconds 300')
        replace_at = install.index('mv -- "$STAGING_DIR" "$INSTALL_DIR"')
        self.assertLess(stop_at, replace_at)

    def test_safe_shutdown_script_is_fail_closed_by_default(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "openkapsel-safe-shutdown").read_text()
        implementation = (root / "openkapsel" / "storage" / "storage_shutdown.py").read_text()
        self.assertIn("/usr/bin/python3", script)
        self.assertIn("uploadsQueued", implementation)
        self.assertIn("uploadsInProgress", implementation)
        self.assertIn("erroredFiles", implementation)
        self.assertIn("--force-recovery", implementation)
        self.assertIn('["umount", str(target)]', implementation)
        self.assertIn('["umount", "-l", str(target)]', implementation)

    def test_systemd_helper_gets_storage_private_paths_and_user(self):
        unit = (Path(__file__).resolve().parents[1] / "systemd" / "openkapsel-images.service").read_text()
        self.assertIn("--storage-root /var/lib/openkapsel-storage/providers", unit)
        self.assertIn("--storage-user openkapsel-storage", unit)
        self.assertIn("--storage-home /var/lib/openkapsel-storage/home", unit)
        self.assertIn("PrivateMounts=false", unit)


class StorageProviderUIRenderTests(unittest.TestCase):
    def test_create_form_only_shows_default_provider_before_javascript_runs(self):
        page = render_storage_providers(
            [],
            [],
            "csrf",
            "/kapsel/admin",
            "https://example.test/kapsel",
            capability={"available": True, "reason": ""},
        )
        self.assertIn(
            '<div data-storage-kind="google_drive" class="span4 storage-credentials">',
            page,
        )
        for kind in ("dropbox", "pcloud", "onedrive", "webdav", "s3", "sftp", "smb"):
            with self.subTest(kind=kind):
                self.assertIn(
                    f'<div data-storage-kind="{kind}" hidden class="span4 storage-credentials">',
                    page,
                )
        self.assertIn('<input disabled name="s3_endpoint"', page)
        self.assertIn('<input disabled name="host"', page)
        self.assertIn('<button disabled type="button" class="secondary"', page)
        self.assertIn("el.hidden=!on", page)
        self.assertIn("x.disabled=!on", page)

    def test_rendered_sftp_script_keeps_newlines_escaped(self):
        page = render_storage_providers(
            [],
            [],
            "csrf",
            "/kapsel/admin",
            "https://example.test/kapsel",
            capability={"available": True, "reason": ""},
        )
        self.assertIn(
            "payload.port+'\\n'+lines.join('\\n')+'\\nVerify these fingerprints",
            page,
        )
        self.assertNotIn("payload.port+'\n'+lines.join('\n')", page)


class StorageProviderHTTPTests(unittest.TestCase):
    def setUp(self):
        from tests import test_oauth
        test_oauth.OAuthHTTPTests.setUp(self)
        self.request = test_oauth.OAuthHTTPTests.request.__get__(self)
        self.form = test_oauth.OAuthHTTPTests.form.__get__(self)
        self.server.storage_providers.helper = FakeHelper()

    def tearDown(self):
        from tests import test_oauth
        test_oauth.OAuthHTTPTests.tearDown(self)

    def test_admin_browser_oauth_creates_provider_and_consumes_state(self):
        status, headers, _ = self.form(
            "/kapsel/admin/login",
            {"username": "admin", "password": "test-password-123"},
        )
        self.assertEqual(303, status)
        self.assertIn("SameSite=Lax", headers["Set-Cookie"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        path = "/kapsel/admin/storage-providers"
        payload = {
            "action": "oauth_start",
            "name": "Google Drive",
            "kind": "google_drive",
            "remote_path": "Projects",
            "cache_gib": "1",
            "writable": "on",
            "client_id": "google-client-id",
            "client_secret": "google-client-secret",
            "csrf": session.csrf,
        }
        status, headers, raw = self.form(path, payload, auth)
        self.assertEqual(200, status, raw)
        self.assertNotIn("Location", headers)
        handoff = raw.decode()
        self.assertIn("location.replace(", handoff)
        match = re.search(r'<a href="([^"]+)">Continue to authorization</a>', handoff)
        self.assertIsNotNone(match)
        authorization = urlsplit(html.unescape(match.group(1)))
        self.assertEqual("accounts.google.com", authorization.hostname)
        params = parse_qs(authorization.query)
        state = params["state"][0]
        redirect_uri = params["redirect_uri"][0]
        self.assertEqual(
            "https://example.test/kapsel/admin/storage-providers/oauth/callback",
            redirect_uri,
        )

        token = (
            '{"access_token":"ACCESS","token_type":"Bearer",'
            '"refresh_token":"REFRESH","expiry":"2030-01-01T00:00:00Z"}'
        )
        callback = urlsplit(redirect_uri).path + "?state=" + state + "&code=oauth-code"
        with patch.object(
            self.server.storage_oauth,
            "exchange_credentials",
            return_value={
                "client_id": "google-client-id",
                "client_secret": "google-client-secret",
                "token": token,
            },
        ):
            status, _, raw = self.request("GET", callback, headers=auth)
        self.assertEqual(200, status, raw)
        page = raw.decode()
        self.assertIn("Storage provider connected with OAuth and mounted.", page)
        self.assertNotIn("google-client-secret", page)
        self.assertNotIn("REFRESH", page)
        providers = self.server.storage_providers.store.list()
        self.assertEqual(1, len(providers))
        self.assertEqual("Google Drive", providers[0]["name"])
        self.assertNotIn("token", providers[0])
        configure = next(
            values for action, values in self.server.storage_providers.helper.calls
            if action == "storage_configure"
        )
        self.assertEqual("google-client-id", configure["settings"]["client_id"])
        self.assertEqual("google-client-secret", configure["settings"]["client_secret"])
        self.assertEqual(token, configure["settings"]["token"])

        status, _, raw = self.request("GET", callback, headers=auth)
        self.assertEqual(200, status, raw)
        self.assertIn("missing, expired, or already used", raw.decode())

    def test_admin_pcloud_oauth_preserves_detected_eu_hostname(self):
        status, headers, _ = self.form(
            "/kapsel/admin/login",
            {"username": "admin", "password": "test-password-123"},
        )
        self.assertEqual(303, status)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        path = "/kapsel/admin/storage-providers"
        status, _, raw = self.form(
            path,
            {
                "action": "oauth_start",
                "name": "pCloud EU",
                "kind": "pcloud",
                "remote_path": "Projects",
                "cache_gib": "1",
                "client_id": "pcloud-id",
                "client_secret": "pcloud-secret",
                "pcloud_hostname": "api.pcloud.com",
                "csrf": session.csrf,
            },
            auth,
        )
        self.assertEqual(200, status, raw)
        match = re.search(
            r'<a href="([^"]+)">Continue to authorization</a>',
            raw.decode(),
        )
        authorization = urlsplit(html.unescape(match.group(1)))
        self.assertEqual("my.pcloud.com", authorization.hostname)
        params = parse_qs(authorization.query)
        state = params["state"][0]
        redirect_uri = params["redirect_uri"][0]
        callback = (
            urlsplit(redirect_uri).path
            + "?state="
            + state
            + "&code=oauth-code&hostname=eapi.pcloud.com&locationid=2"
        )
        token = (
            '{"access_token":"PCLOUD","token_type":"bearer",'
            '"expiry":"0001-01-01T00:00:00Z"}'
        )
        with patch.object(
            self.server.storage_oauth,
            "exchange_credentials",
            return_value={
                "client_id": "pcloud-id",
                "client_secret": "pcloud-secret",
                "hostname": "eapi.pcloud.com",
                "token": token,
            },
        ) as exchange:
            status, _, raw = self.request("GET", callback, headers=auth)
        self.assertEqual(200, status, raw)
        self.assertIn("Storage provider connected with OAuth and mounted.", raw.decode())
        flow, code, callback_values = exchange.call_args.args
        self.assertEqual("pcloud", flow.kind)
        self.assertEqual("oauth-code", code)
        self.assertEqual(
            {"hostname": "eapi.pcloud.com", "locationid": "2"},
            callback_values,
        )
        configure = next(
            values
            for action, values in self.server.storage_providers.helper.calls
            if action == "storage_configure"
        )
        self.assertEqual("pcloud", configure["kind"])
        self.assertEqual("eapi.pcloud.com", configure["settings"]["hostname"])
        self.assertNotIn("PCLOUD", raw.decode())

    def test_admin_storage_provider_credentials_are_write_only(self):
        status, headers, _ = self.form(
            "/kapsel/admin/login",
            {"username": "admin", "password": "test-password-123"},
        )
        self.assertEqual(303, status)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        path = "/kapsel/admin/storage-providers"
        payload = {
            "action": "create", "name": "dropbox", "kind": "dropbox",
            "remote_path": "Projects", "cache_gib": "2", "writable": "on",
            "client_id": "", "client_secret": "",
            "oauth_token": '{"access_token":"STORAGE-SECRET","refresh_token":"REFRESH-SECRET"}',
        }
        self.assertEqual(403, self.form(path, payload, auth)[0])
        payload["csrf"] = session.csrf
        status, _, raw = self.form(path, payload, auth)
        self.assertEqual(200, status, raw)
        page = raw.decode()
        self.assertIn("Storage provider created and mounted.", page)
        self.assertNotIn("STORAGE-SECRET", page)
        self.assertNotIn("REFRESH-SECRET", page)
        providers = self.server.storage_providers.store.list()
        self.assertEqual(1, len(providers))
        provider = providers[0]
        self.assertNotIn("token", provider)
        self.assertEqual("Projects", provider["remote_path"])
        mapping = {
            "action": "add_mapping", "provider_id": provider["id"],
            "workspace": self.record.path_prefix, "mapping_name": "cloud", "csrf": session.csrf,
        }
        status, _, raw = self.form(path, mapping, auth)
        self.assertEqual(200, status, raw)
        self.assertIn("Storage provider mapped into the workspace.", raw.decode())
        self.assertTrue(self.server.storage_providers.path_reserved(self.record.path_prefix, "cloud"))

        helper = self.server.storage_providers.helper
        helper.pending = {
            "pending": True,
            "uncertain": False,
            "uploads_queued": 2,
            "uploads_in_progress": 1,
            "cache_bytes": 256 * 1024**2,
            "reason": "",
        }
        delete = {"action": "delete", "id": provider["id"], "csrf": session.csrf}
        status, _, raw = self.form(path, delete, auth)
        self.assertEqual(200, status, raw)
        page = raw.decode()
        self.assertIn("Storage provider deletion paused:", page)
        self.assertIn("2 queued and 1 in-progress upload", page)
        self.assertIn("Force delete and discard local pending cache", page)
        self.assertEqual(1, len(self.server.storage_providers.store.list()))

        force_delete = {"action": "force_delete", "id": provider["id"], "csrf": session.csrf}
        status, _, raw = self.form(path, force_delete, auth)
        self.assertEqual(200, status, raw)
        self.assertIn("Storage provider forcibly deleted.", raw.decode())
        self.assertEqual([], self.server.storage_providers.store.list())

    def test_admin_webdav_and_s3_fields_reach_private_helper_only(self):
        status, headers, _ = self.form(
            "/kapsel/admin/login",
            {"username": "admin", "password": "test-password-123"},
        )
        self.assertEqual(303, status)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        path = "/kapsel/admin/storage-providers"

        webdav_secret = "WEBDAV-PRIVATE"
        status, _, raw = self.form(
            path,
            {
                "action": "create",
                "name": "Nextcloud",
                "kind": "webdav",
                "remote_path": "Documents",
                "cache_gib": "1",
                "webdav_url": "https://cloud.example.test/remote.php/dav/files/alice/",
                "webdav_vendor": "nextcloud",
                "user": "alice",
                "password": webdav_secret,
                "csrf": session.csrf,
            },
            auth,
        )
        self.assertEqual(200, status, raw)
        self.assertIn("Storage provider created and mounted.", raw.decode())
        self.assertNotIn(webdav_secret, raw.decode())

        s3_secret = "S3-PRIVATE"
        status, _, raw = self.form(
            path,
            {
                "action": "create",
                "name": "Object Store",
                "kind": "s3",
                "remote_path": "bucket/prefix",
                "cache_gib": "1",
                "writable": "on",
                "s3_endpoint": "https://objects.example.test",
                "s3_region": "us-test-1",
                "access_key_id": "ACCESS",
                "secret_access_key": s3_secret,
                "force_path_style": "on",
                "v2_auth": "on",
                "csrf": session.csrf,
            },
            auth,
        )
        self.assertEqual(200, status, raw)
        page = raw.decode()
        self.assertIn("Storage provider created and mounted.", page)
        self.assertNotIn(s3_secret, page)
        self.assertIn("Microsoft OneDrive", page)
        self.assertIn("S3 Compatible", page)
        self.assertIn("WebDAV URL", page)

        configure = [
            values
            for action, values in self.server.storage_providers.helper.calls
            if action == "storage_configure"
        ]
        webdav = next(values for values in configure if values["kind"] == "webdav")
        s3 = next(values for values in configure if values["kind"] == "s3")
        self.assertEqual(webdav_secret, webdav["settings"]["password"])
        self.assertEqual("nextcloud", webdav["settings"]["vendor"])
        self.assertEqual(s3_secret, s3["settings"]["secret_access_key"])
        self.assertTrue(s3["settings"]["force_path_style"])
        self.assertTrue(s3["settings"]["v2_auth"])
        providers = self.server.storage_providers.store.list()
        self.assertEqual({"s3", "webdav"}, {item["kind"] for item in providers})
        for provider in providers:
            self.assertNotIn("settings", provider)
            self.assertNotIn("credentials", provider)

    def test_admin_sftp_detect_requires_explicit_host_key_confirmation(self):
        status, headers, _ = self.form(
            "/kapsel/admin/login",
            {"username": "admin", "password": "test-password-123"},
        )
        self.assertEqual(303, status)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        path = "/kapsel/admin/storage-providers"
        detected = {
            "host": "files.example.com",
            "port": 2222,
            "known_hosts": (
                "[files.example.com]:2222 ssh-ed25519 "
                "T3BlbkthcHNlbFRlc3RIb3N0S2V5"
            ),
            "keys": [
                {
                    "type": "ssh-ed25519",
                    "fingerprint_sha256": "SHA256:examplefingerprint",
                    "known_hosts": (
                        "[files.example.com]:2222 ssh-ed25519 "
                        "T3BlbkthcHNlbFRlc3RIb3N0S2V5"
                    ),
                }
            ],
        }
        with patch.object(
            self.server.storage_providers,
            "detect_sftp_host_keys",
            return_value=detected,
        ) as detect:
            status, _, raw = self.form(
                path,
                {
                    "action": "detect_sftp_host_key",
                    "host": "files.example.com",
                    "port": "2222",
                    "csrf": session.csrf,
                },
                auth,
            )
        self.assertEqual(200, status, raw)
        payload = json.loads(raw)
        self.assertEqual(detected, payload)
        detect.assert_called_once_with("files.example.com", "2222")

        create = {
            "action": "create",
            "name": "SFTP",
            "kind": "sftp",
            "remote_path": "",
            "cache_gib": "1",
            "host": "files.example.com",
            "port": "2222",
            "user": "alice",
            "password": "secret",
            "private_key": "",
            "known_hosts": detected["known_hosts"],
            "csrf": session.csrf,
        }
        status, _, raw = self.form(path, create, auth)
        self.assertEqual(200, status, raw)
        self.assertIn(
            "confirm that you verified and trust the SFTP SSH host-key fingerprint",
            raw.decode(),
        )
        self.assertEqual([], self.server.storage_providers.store.list())

        create["host_key_confirmed"] = "on"
        status, _, raw = self.form(path, create, auth)
        self.assertEqual(200, status, raw)
        self.assertIn("Storage provider created and mounted.", raw.decode())
        providers = self.server.storage_providers.store.list()
        self.assertEqual(1, len(providers))
        configure = next(
            values for action, values in self.server.storage_providers.helper.calls
            if action == "storage_configure"
        )
        self.assertEqual(detected["known_hosts"], configure["settings"]["known_hosts"])

        status, _, raw = self.request("GET", "/kapsel/admin", headers=auth)
        self.assertEqual(200, status, raw)
        page = raw.decode()
        self.assertIn("Detect SSH host key", page)
        self.assertIn("Verify the SHA256 fingerprint independently", page)


if __name__ == "__main__":
    unittest.main()

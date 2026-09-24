import errno
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
from openkapsel.storage.storage_store import DEFAULT_CACHE_MAX_BYTES, StorageProviderStore


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

        with patch("openkapsel.storage.storage_oauth.httpx.post", return_value=Response()) as request:
            token = json.loads(flows.exchange(flow, "authorization-code"))
        self.assertEqual("ACCESS", token["access_token"])
        self.assertEqual("REFRESH", token["refresh_token"])
        self.assertEqual("bearer", token["token_type"])
        self.assertTrue(token["expiry"].endswith("Z"))
        values = request.call_args.kwargs["data"]
        self.assertEqual("dropbox-secret", values["client_secret"])
        self.assertEqual(flow.redirect_uri, values["redirect_uri"])


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
            self.assertIn(str(4 * 1024**3), launch)
            self.assertIn("--cache-dir", launch)
            self.assertIn("--rc", launch)
            self.assertIn("--rc-addr", launch)
            self.assertTrue(any(arg.startswith("unix://") and arg.endswith("/rc.sock") for arg in launch))
            self.assertIn("--read-only", launch)
            self.assertNotIn("sync", launch)
            self.assertNotIn("copy", launch)
            self.assertNotIn("--vfs-cache-mode=full", launch)
            self.assertEqual(mount, Path(launch[launch.index("provider:share") + 1]))

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
        self.assertIn("user_allow_other", install)
        self.assertIn('-path "$STORAGE_ROOT"', install)
        self.assertIn('-path "$STORAGE_HOME"', install)
        self.assertIn('chown "$STORAGE_USER:$STORAGE_GROUP" "$STORAGE_ROOT" "$STORAGE_HOME"', install)

    def test_systemd_helper_gets_storage_private_paths_and_user(self):
        unit = (Path(__file__).resolve().parents[1] / "systemd" / "openkapsel-images.service").read_text()
        self.assertIn("--storage-root /var/lib/openkapsel/storage-providers", unit)
        self.assertIn("--storage-user openkapsel-storage", unit)
        self.assertIn("--storage-home /var/lib/openkapsel/storage-home", unit)
        self.assertIn("PrivateMounts=false", unit)


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
        with patch.object(self.server.storage_oauth, "exchange", return_value=token):
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


if __name__ == "__main__":
    unittest.main()

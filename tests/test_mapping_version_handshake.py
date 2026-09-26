from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from openkapsel import __version__
from openkapsel.client import (
    ClientReloadRequired,
    ClientVersionRequired,
    _periodic_reload_check,
    _reload_decision,
)
from openkapsel.client_runtime.client_reload import ClientReloadState, LocalSource, exec_local_source
from openkapsel.mapping.mapping_transport import (
    MAPPING_HANDSHAKE_VERSION,
    MINIMUM_MAPPING_CLIENT_VERSION,
    ProviderSession,
    SERVER_SOURCE_FINGERPRINT,
)
from openkapsel.source_fingerprint import (
    CLIENT_FILES,
    SERVER_FILES,
    SHARED_FILES,
    guarded_source_files,
    project_root,
    source_fingerprint,
)


class FingerprintTests(unittest.TestCase):
    def copy_manifest(self, root: Path):
        source = project_root()
        for relative in set(SHARED_FILES + SERVER_FILES + CLIENT_FILES):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)

    def test_fingerprints_are_full_sha256_base64_and_deterministic(self):
        server = source_fingerprint(project_root(), "server")
        client = source_fingerprint(project_root(), "client")
        for value in (server, client):
            self.assertEqual(44, len(value))
            self.assertEqual(32, len(base64.b64decode(value, validate=True)))
        self.assertEqual(server, source_fingerprint(project_root(), "server"))
        self.assertEqual(client, source_fingerprint(project_root(), "client"))

    def test_shared_and_side_specific_files_change_expected_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_manifest(root)
            base_server = source_fingerprint(root, "server")
            base_client = source_fingerprint(root, "client")

            shared = root / "openkapsel/mapping/mapping_transport.py"
            shared.write_bytes(shared.read_bytes() + b"\n# fingerprint shared change\n")
            self.assertNotEqual(base_server, source_fingerprint(root, "server"))
            self.assertNotEqual(base_client, source_fingerprint(root, "client"))

            self.copy_manifest(root)
            server_only = root / "openkapsel/mapping/mapping_manager.py"
            server_only.write_bytes(server_only.read_bytes() + b"\n# server change\n")
            self.assertNotEqual(base_server, source_fingerprint(root, "server"))
            self.assertEqual(base_client, source_fingerprint(root, "client"))

            self.copy_manifest(root)
            client_only = root / "openkapsel/client_runtime/client_tasks.py"
            client_only.write_bytes(client_only.read_bytes() + b"\n# client change\n")
            self.assertEqual(base_server, source_fingerprint(root, "server"))
            self.assertNotEqual(base_client, source_fingerprint(root, "client"))

    def test_manifest_coverage_and_missing_file_fail_closed(self):
        root = project_root()
        self.assertFalse(guarded_source_files(root, "server") - set(SHARED_FILES + SERVER_FILES))
        self.assertFalse(guarded_source_files(root, "client") - set(SHARED_FILES + CLIENT_FILES))
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)
            self.copy_manifest(copy)
            (copy / CLIENT_FILES[-1]).unlink()
            with self.assertRaises(FileNotFoundError):
                source_fingerprint(copy, "client")


class ReloadDecisionTests(unittest.TestCase):
    class Runtime:
        def __init__(self, active=False):
            self.client_fingerprint = "R" * 44
            self.pending_reload = False
            self.active = active

        def has_active_tasks(self):
            return self.active

    class State:
        def __init__(self, last_server=None, last_check=None):
            self.last_server_fingerprint = last_server
            self.last_source_check_at = time.time() if last_check is None else last_check
            self.source_checks = 0

        def mark_source_checked(self):
            self.last_source_check_at = time.time()
            self.source_checks += 1

    def test_local_source_defaults_to_running_project_root_and_allows_override(self):
        from openkapsel.client_runtime.client_reload import inspect_local_source

        current = inspect_local_source({"auto_reload": True})
        self.assertIsNotNone(current)
        self.assertEqual(project_root(), current.root)
        self.assertEqual(source_fingerprint(project_root(), "client"), current.fingerprint)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            FingerprintTests().copy_manifest(root)
            override = inspect_local_source({
                "auto_reload": True,
                "source_root": str(root),
            })
            self.assertIsNotNone(override)
            self.assertEqual(root.resolve(), override.root)

    def test_required_version_reloads_suitable_changed_source(self):
        runtime = self.Runtime()
        source = LocalSource(Path("/source"), "9.0.0", "L" * 44)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            with self.assertRaises(ClientReloadRequired) as error:
                _reload_decision({}, runtime, None, "S" * 44, "9.0.0")
        self.assertTrue(error.exception.required)

    def test_required_version_without_usable_source_stays_incompatible(self):
        runtime = self.Runtime()
        with patch("openkapsel.client.inspect_local_source", return_value=None):
            with self.assertRaises(ClientVersionRequired):
                _reload_decision({}, runtime, None, "S" * 44, "9.0.0")

    def test_server_change_and_24h_refresh_reload_only_changed_local_source(self):
        runtime = self.Runtime()
        source = LocalSource(Path("/source"), __version__, "L" * 44)
        state = self.State(last_server="A" * 44)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            with self.assertRaises(ClientReloadRequired) as error:
                _reload_decision({}, runtime, state, "B" * 44, MINIMUM_MAPPING_CLIENT_VERSION)
        self.assertFalse(error.exception.required)

        runtime = self.Runtime()
        state = self.State(last_server="B" * 44, last_check=time.time() - 86401)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            with self.assertRaises(ClientReloadRequired):
                _reload_decision({}, runtime, state, "B" * 44, MINIMUM_MAPPING_CLIENT_VERSION)

    def test_optional_reload_defers_while_task_is_active(self):
        runtime = self.Runtime(active=True)
        source = LocalSource(Path("/source"), __version__, "L" * 44)
        state = self.State(last_server="A" * 44)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            _reload_decision({}, runtime, state, "B" * 44, MINIMUM_MAPPING_CLIENT_VERSION)
        self.assertTrue(runtime.pending_reload)

    def test_periodic_refresh_detects_changed_source_on_healthy_connection(self):
        runtime = self.Runtime()
        source = LocalSource(Path("/source"), __version__, "L" * 44)
        state = self.State(last_server="B" * 44, last_check=time.time() - 86401)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            self.assertTrue(
                _periodic_reload_check(
                    {"auto_reload": True}, runtime, state, MINIMUM_MAPPING_CLIENT_VERSION
                )
            )
        self.assertTrue(runtime.pending_reload)
        self.assertEqual(1, state.source_checks)

    def test_periodic_refresh_unchanged_source_advances_check_clock(self):
        runtime = self.Runtime()
        source = LocalSource(Path("/source"), __version__, runtime.client_fingerprint)
        state = self.State(last_server="B" * 44, last_check=time.time() - 86401)
        with patch("openkapsel.client.inspect_local_source", return_value=source) as inspect:
            self.assertFalse(
                _periodic_reload_check(
                    {"auto_reload": True}, runtime, state, MINIMUM_MAPPING_CLIENT_VERSION
                )
            )
            self.assertFalse(
                _periodic_reload_check(
                    {"auto_reload": True}, runtime, state, MINIMUM_MAPPING_CLIENT_VERSION
                )
            )
        self.assertEqual(1, inspect.call_count)
        self.assertEqual(1, state.source_checks)
        self.assertFalse(runtime.pending_reload)

    def test_required_reload_backoff_persists_and_ready_resets(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "client.json"
            config.write_text("{}")
            state = ClientReloadState(config)
            self.assertEqual([0, 60, 120, 300, 300],
                             [state.next_required_delay() for _ in range(5)])
            restored = ClientReloadState(config)
            self.assertEqual(5, restored.required_reload_attempts)
            restored.mark_ready("S" * 44)
            self.assertEqual(0, ClientReloadState(config).required_reload_attempts)
            if os.name != "nt":
                self.assertEqual(0, state.path.stat().st_mode & 0o077)

    def test_reload_state_persists_when_fchmod_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "client.json"
            config.write_text("{}")
            with patch("openkapsel.client_runtime.client_reload.os.fchmod", None, create=True):
                state = ClientReloadState(config)
                self.assertEqual(0, state.next_required_delay())
                state.mark_ready("W" * 44)
                restored = ClientReloadState(config)
            self.assertEqual("W" * 44, restored.last_server_fingerprint)
            self.assertEqual(0, restored.required_reload_attempts)

    def test_exec_bootstrap_forces_configured_source_ahead_of_cwd(self):
        source = LocalSource(Path("/trusted/OpenKapsel"), __version__, "L" * 44)
        config = Path("/config/client.json")
        digest = "a" * 64
        with patch("os.execve", side_effect=RuntimeError("exec intercepted")) as execute:
            with self.assertRaises(RuntimeError):
                exec_local_source(source, config, config_sha256=digest)
        executable, argv, env = execute.call_args.args
        self.assertEqual(os.sys.executable, executable)
        self.assertEqual("-c", argv[1])
        self.assertIn("sys.path.insert(0,'/trusted/OpenKapsel')", argv[2])
        self.assertEqual(["--config", "/config/client.json"], argv[-2:])
        self.assertTrue(env["PYTHONPATH"].startswith("/trusted/OpenKapsel"))
        self.assertEqual(digest, env["OPENKAPSEL_CLIENT_CONFIG_SHA256"])


class ServerFirstHandshakeTests(unittest.TestCase):
    def start_server(self, *, timeout=None):
        try:
            import websocket  # noqa: F401
        except ImportError:
            self.skipTest("client extras required")
        sessions = []
        ready = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner_self):
                context = (
                    patch("openkapsel.mapping.mapping_transport.MAPPING_HELLO_TIMEOUT_SECONDS", timeout)
                    if timeout is not None else patch("time.time", wraps=time.time)
                )
                with context:
                    session = ProviderSession(inner_self)
                    sessions.append(session)
                    try:
                        session.run(ready.set)
                    except (OSError, ValueError, TimeoutError):
                        pass

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, sessions, ready

    def connect(self, server):
        import websocket
        return websocket.create_connection(
            f"ws://127.0.0.1:{server.server_port}/provider",
            timeout=3,
            http_no_proxy=["*"],
        )

    def test_server_sends_first_frame_and_ready_requires_valid_client_hello(self):
        server, thread, sessions, ready = self.start_server()
        ws = self.connect(server)
        try:
            hello = json.loads(ws.recv())
            self.assertEqual("server_hello", hello["type"])
            self.assertEqual(MAPPING_HANDSHAKE_VERSION, hello["handshake_version"])
            self.assertEqual(SERVER_SOURCE_FINGERPRINT, hello["server_fingerprint"])
            self.assertEqual(MINIMUM_MAPPING_CLIENT_VERSION, hello["minimum_client_version"])
            ws.send(json.dumps({
                "type": "client_hello",
                "handshake_version": MAPPING_HANDSHAKE_VERSION,
                "client_version": __version__,
                "client_fingerprint": source_fingerprint(project_root(), "client"),
                "capabilities": {"protocol": 1},
            }))
            self.assertEqual(
                {"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION},
                json.loads(ws.recv()),
            )
            self.assertTrue(ready.wait(2))
            self.assertTrue(sessions[0].ready)
            self.assertEqual(__version__, sessions[0].client_version)
        finally:
            ws.close()
            server.shutdown(); server.server_close(); thread.join(3)

    def test_legacy_client_hello_is_rejected(self):
        server, thread, sessions, ready = self.start_server()
        ws = self.connect(server)
        try:
            json.loads(ws.recv())
            ws.send(json.dumps({"type": "hello", "capabilities": {}}))
            with self.assertRaises(Exception):
                # websocket-client raises after the server closes the invalid session.
                while True:
                    if not ws.recv():
                        raise ConnectionError()
            self.assertFalse(ready.is_set())
            deadline = time.time() + 2
            while not sessions and time.time() < deadline:
                time.sleep(.01)
            self.assertFalse(sessions[0].ready)
        finally:
            ws.close()
            server.shutdown(); server.server_close(); thread.join(3)

    def test_server_rejects_client_below_minimum_version(self):
        server, thread, sessions, ready = self.start_server()
        ws = self.connect(server)
        try:
            json.loads(ws.recv())
            ws.send(json.dumps({
                "type": "client_hello",
                "handshake_version": MAPPING_HANDSHAKE_VERSION,
                "client_version": "1.61.0",
                "client_fingerprint": source_fingerprint(project_root(), "client"),
                "capabilities": {},
            }))
            closed = False
            try:
                closed = not bool(ws.recv())
            except Exception:
                closed = True
            self.assertTrue(closed)
            self.assertFalse(ready.is_set())
        finally:
            ws.close()
            server.shutdown(); server.server_close(); thread.join(3)

    def test_client_hello_deadline_closes_unready_session(self):
        server, thread, sessions, ready = self.start_server(timeout=1)
        ws = self.connect(server)
        try:
            hello = json.loads(ws.recv())
            self.assertEqual(1, hello["hello_timeout_seconds"])
            deadline = time.time() + 3
            closed = False
            while time.time() < deadline:
                try:
                    ws.ping("keepalive")
                    ws.settimeout(.25)
                    data = ws.recv()
                    if not data:
                        closed = True
                        break
                except Exception as exc:
                    if (
                        time.time() < deadline
                        and exc.__class__.__name__ == "WebSocketTimeoutException"
                    ):
                        continue
                    closed = True
                    break
            self.assertTrue(closed)
            self.assertFalse(ready.is_set())
        finally:
            ws.close()
            server.shutdown(); server.server_close(); thread.join(3)


if __name__ == "__main__":
    unittest.main()

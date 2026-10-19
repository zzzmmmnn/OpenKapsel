"""Real and simulated regressions for auto_git_pull and non-disruptive reload."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import (
    _create_resources, _periodic_reload_check, _reload_decision,
    ClientReloadRequired,
)
from openkapsel.client_runtime.client_reload import (
    GitPullGate, LocalSource, pull_trusted_source,
)
from openkapsel.mapping.mapping_transport import MAPPING_HANDSHAKE_VERSION, MINIMUM_MAPPING_CLIENT_VERSION
from openkapsel import __version__


class FakeRuntime:
    client_fingerprint = "A" * 44
    pending_reload = False
    active = False
    def has_active_tasks(self):
        return self.active


class FakeState:
    def __init__(self):
        self.last_server_fingerprint = "B" * 44
        self.last_source_check_at = time.time() - 86401
        self.source_checks = 0
    def mark_source_checked(self):
        self.last_source_check_at = time.time()
        self.source_checks += 1


class FakeGate:
    def __init__(self):
        self.thread = None
        self.ready = threading.Event()
        self.started = 0
        self.reset_count = 0
    def start(self):
        self.started += 1
        self.thread = object()
        return self.ready.is_set()
    def reset(self):
        self.thread = None
        self.ready.clear()
        self.reset_count += 1


class GitPullGateTests(unittest.TestCase):
    def test_config_requires_explicit_boolean_and_auto_reload(self):
        base = {"url": "ws://localhost/connection", "token": "t",
                "root": "/does/not/matter", "auto_reload": True}
        for value in ("true", 1, None, [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "auto_git_pull must be a boolean"):
                _create_resources(dict(base, auto_git_pull=value))
        with self.assertRaisesRegex(ValueError, "auto_git_pull requires auto_reload"):
            _create_resources(dict(base, auto_reload=False, auto_git_pull=True))

    def test_failure_waits_thirty_seconds_and_retries_without_setting_reload(self):
        gate = GitPullGate(Path.cwd())
        calls = []
        entered, release = threading.Event(), threading.Event()
        def attempt(_root):
            calls.append(1)
            if len(calls) == 1:
                entered.set()
                if not release.wait(3):
                    raise AssertionError("the first Git pull was never released")
                raise OSError("git offline")
        try:
            with (patch("openkapsel.client_runtime.client_reload.pull_trusted_source", side_effect=attempt),
                  patch.object(gate.stop, "wait", return_value=False) as wait):
                self.assertFalse(gate.start())
                self.assertTrue(entered.wait(3))
                self.assertFalse(gate.ready.is_set())
                release.set()
                self.assertTrue(gate.ready.wait(3))
            self.assertEqual(2, len(calls))
            wait.assert_called_once_with(30)
        finally:
            release.set()
            gate.close()

    def test_compatible_heartbeat_and_handshake_stay_ready_until_pull_succeeds(self):
        runtime = FakeRuntime()
        runtime.git_pull = FakeGate()
        state = FakeState()
        updated = LocalSource(Path("/trusted/repo"), __version__, "Z" * 44, MAPPING_HANDSHAKE_VERSION)
        config = {"auto_reload": True, "auto_git_pull": True}
        with patch("openkapsel.client.inspect_local_source", return_value=updated):
            # A changed compatible source no longer closes a socket on connect.
            _reload_decision(config, runtime, state, MAPPING_HANDSHAKE_VERSION,
                             "C" * 44, MINIMUM_MAPPING_CLIENT_VERSION)
            self.assertEqual(1, runtime.git_pull.started)
            self.assertFalse(runtime.pending_reload)
            # 30-second retry cycles have no effect on established sessions.
            for _ in range(4):
                self.assertFalse(_periodic_reload_check(config, runtime, state,
                                                        MINIMUM_MAPPING_CLIENT_VERSION))
                self.assertFalse(runtime.pending_reload)
            runtime.git_pull.ready.set()
            self.assertTrue(_periodic_reload_check(config, runtime, state,
                                                   MINIMUM_MAPPING_CLIENT_VERSION))
            self.assertTrue(runtime.pending_reload)

    def test_success_then_normal_reload_waits_for_active_jobs(self):
        runtime = FakeRuntime()
        runtime.git_pull = FakeGate()
        runtime.git_pull.ready.set()
        runtime.active = True
        state = FakeState()
        source = LocalSource(Path("/trusted/repo"), __version__, "Z" * 44, MAPPING_HANDSHAKE_VERSION)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            _reload_decision({"auto_reload": True}, runtime, state,
                             MAPPING_HANDSHAKE_VERSION, "C" * 44, MINIMUM_MAPPING_CLIENT_VERSION)
            self.assertTrue(runtime.pending_reload)
            runtime.active = False
            with self.assertRaises(ClientReloadRequired):
                _reload_decision({"auto_reload": True}, runtime, state,
                                 MAPPING_HANDSHAKE_VERSION, "C" * 44, MINIMUM_MAPPING_CLIENT_VERSION)

    def test_incompatible_server_stays_offline_until_git_succeeds(self):
        from openkapsel.client import ClientProtocolRequired
        runtime = FakeRuntime()
        runtime.git_pull = FakeGate()
        required_handshake = MAPPING_HANDSHAKE_VERSION + 1
        source = LocalSource(Path("/trusted/repo"), __version__, "Z" * 44,
                             required_handshake)
        with patch("openkapsel.client.inspect_local_source", return_value=source):
            with self.assertRaises(ClientProtocolRequired):
                _reload_decision({"auto_reload": True}, runtime, FakeState(),
                                 required_handshake, "S" * 44,
                                 MINIMUM_MAPPING_CLIENT_VERSION)
            self.assertEqual(1, runtime.git_pull.started)
            self.assertFalse(runtime.pending_reload)
            runtime.git_pull.ready.set()
            with self.assertRaises(ClientReloadRequired) as error:
                _reload_decision({"auto_reload": True}, runtime, FakeState(),
                                 required_handshake, "S" * 44,
                                 MINIMUM_MAPPING_CLIENT_VERSION)
            self.assertTrue(error.exception.required)

    def test_success_no_changed_source_does_not_restart(self):
        runtime = FakeRuntime()
        runtime.git_pull = FakeGate()
        runtime.git_pull.ready.set()
        state = FakeState()
        old = LocalSource(Path("/trusted/repo"), __version__, runtime.client_fingerprint, MAPPING_HANDSHAKE_VERSION)
        with patch("openkapsel.client.inspect_local_source", return_value=old):
            self.assertFalse(_periodic_reload_check({"auto_reload": True}, runtime,
                                                     state, MINIMUM_MAPPING_CLIENT_VERSION))
        self.assertEqual(1, runtime.git_pull.reset_count)
        self.assertFalse(runtime.pending_reload)

    def test_live_ready_connection_keeps_ping_while_git_is_blocked(self):
        import json
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        import openkapsel.client as client
        from openkapsel.mapping.mapping_transport import SERVER_SOURCE_FINGERPRINT
        from openkapsel.client import ClientRuntime, run_once
        entered, release, pinged = threading.Event(), threading.Event(), threading.Event()
        def stalled_pull(_root):
            entered.set()
            release.wait(5)
            raise OSError("upstream unavailable")

        class State(FakeState):
            last_server_fingerprint = SERVER_SOURCE_FINGERPRINT
            def mark_ready(self, _fingerprint):
                pass

        messages = iter([
            json.dumps({
                "type": "server_hello",
                "handshake_version": MAPPING_HANDSHAKE_VERSION,
                "server_version": __version__,
                "server_fingerprint": SERVER_SOURCE_FINGERPRINT,
                "minimum_client_version": MINIMUM_MAPPING_CLIENT_VERSION,
                "hello_timeout_seconds": 30,
            }),
            json.dumps({"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION}),
        ])
        sends = []
        class Socket:
            def recv(self):
                try:
                    return next(messages)
                except StopIteration:
                    self_assert = entered.wait(2)
                    if not self_assert:
                        raise AssertionError("Git job was not started")
                    if not pinged.wait(2):
                        raise AssertionError("heartbeat stopped while Git was blocked")
                    return ""
            def send(self, message):
                sends.append(json.loads(message))
            def ping(self, _value):
                pinged.set()
            def close(self):
                pass

        with tempfile.TemporaryDirectory() as td:
            config = {"url": "ws://127.0.0.1/provider", "token": "test", "root": td,
                      "auto_reload": True, "auto_git_pull": True, "sandbox": False}
            runtime = ClientRuntime(config)
            try:
                websocket = SimpleNamespace(
                    create_connection=lambda *_args, **_kwargs: Socket(),
                    WebSocketConnectionClosedException=type("Closed", (Exception,), {}),
                    WebSocketTimeoutException=type("TimedOut", (Exception,), {}),
                    WebSocketException=type("WebSocketError", (Exception,), {}),
                )
                with (patch.dict(sys.modules, {"websocket": websocket}),
                      patch("openkapsel.client.HEARTBEAT_SECONDS", 0.01),
                      patch("openkapsel.client_runtime.client_reload.pull_trusted_source", side_effect=stalled_pull)):
                    run_once(config, runtime=runtime, reload_state=State())
                self.assertTrue(pinged.is_set())
                self.assertFalse(runtime.pending_reload)
                self.assertTrue(any(item.get("type") == "client_hello" for item in sends))
            finally:
                release.set()
                runtime.close()

    @unittest.skipUnless(shutil.which("git"), "real Git is required")
    def test_fast_forward_real_git_and_reject_enclosing_checkout(self):
        def git(*args, cwd=None):
            result = subprocess.run(["git", *args], cwd=cwd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False)
            if result.returncode:
                self.fail(f"git {' '.join(args)} failed: {result.stderr!r}")
            return result.stdout.decode().strip()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bare, producer, consumer = root / "remote.git", root / "producer", root / "consumer"
            git("init", "--bare", str(bare))
            git("clone", str(bare), str(producer))
            git("config", "user.name", "Test", cwd=producer)
            git("config", "user.email", "test@example.invalid", cwd=producer)
            (producer / "version.txt").write_text("old")
            git("add", "version.txt", cwd=producer)
            git("commit", "-m", "initial", cwd=producer)
            git("push", "-u", "origin", "HEAD", cwd=producer)
            git("clone", str(bare), str(consumer))
            (producer / "version.txt").write_text("new")
            git("commit", "-am", "upgrade", cwd=producer)
            git("push", cwd=producer)
            pull_trusted_source(consumer)
            self.assertEqual("new", (consumer / "version.txt").read_text())
            child = consumer / "nested"
            child.mkdir()
            with self.assertRaisesRegex(OSError, "Git worktree root"):
                pull_trusted_source(child)


if __name__ == "__main__":
    unittest.main()

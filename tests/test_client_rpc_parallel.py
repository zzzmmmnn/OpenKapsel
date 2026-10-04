"""Concurrent RPC isolation over the real provider WebSocket transport."""
import errno
import json
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from openkapsel.client import ClientRuntime, run_once
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_rpc import ClientRpcSession
from openkapsel.mapping.mapping_transport import ProviderSession, MappingSessionDisconnected


class ClientRpcParallelTests(unittest.TestCase):
    def setUp(self):
        try:
            import websocket
        except ImportError:
            self.skipTest("client extras required")
        self.directory = tempfile.TemporaryDirectory()
        self.sessions = []
        self.threads = []
        self.errors = []
        self.connected = threading.Event()
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                session = ProviderSession(self)
                outer.sessions.append(session)
                session.run(outer.connected.set)
            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.config = {"url": f"ws://127.0.0.1:{self.server.server_port}/provider",
                       "token": "test", "root": self.directory.name, "writable": True}
        self.runtime = ClientRuntime(self.config)
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        for session in self.sessions:
            session.close()
        for thread in self.threads:
            thread.join(3)
        deadline = time.monotonic() + 3
        while self.runtime.rpc_active and time.monotonic() < deadline:
            time.sleep(.01)
        self.runtime.close()
        self.server.shutdown()
        self.server.server_close()
        self.directory.cleanup()

    def connect(self):
        self.connected.clear()
        def provider():
            try:
                run_once(self.config, runtime=self.runtime)
            except Exception as exc:
                self.errors.append(exc)
        thread = threading.Thread(target=provider, daemon=True)
        self.threads.append(thread)
        thread.start()
        self.assertTrue(self.connected.wait(3))
        return self.sessions[-1]

    @staticmethod
    def ssh(session):
        return session.call("rpc", {"family": "ssh", "operation": "stat",
                                   "args": {"path": "/remote", "profile": "test"}})

    def call_thread(self, func):
        results = queue.Queue()
        def call():
            try:
                results.put((True, func()))
            except Exception as exc:
                results.put((False, exc))
        threading.Thread(target=call, daemon=True).start()
        return results

    def test_blocked_ssh_does_not_block_files_or_task_polling(self):
        entered = threading.Event()
        def remote(*_):
            entered.set()
            self.release.wait(3)
            return {"remote": True}
        with patch.object(self.runtime.files.rpc_registry, "dispatch_sync", side_effect=remote):
            session = self.connect()
            result = self.call_thread(lambda: self.ssh(session))
            self.assertTrue(entered.wait(1))
            local = self.call_thread(lambda: session.call("stat", {"path": "."}))
            ok, value = local.get(timeout=1)
            self.assertTrue(ok, value)
            self.assertIn("st_mode", value)
            self.assertEqual([], session.call("task_list", {}))
            self.assertTrue(result.empty())
            self.release.set()
            self.assertEqual((True, {"remote": True}), result.get(timeout=1))
        self.assertFalse(self.errors)

    def test_two_independent_ssh_requests_execute_concurrently(self):
        both = threading.Barrier(3)
        def remote(*_):
            both.wait(2)
            self.release.wait(3)
            return "ok"
        with patch.object(self.runtime.files.rpc_registry, "dispatch_sync", side_effect=remote):
            session = self.connect()
            first = self.call_thread(lambda: self.ssh(session))
            second = self.call_thread(lambda: self.ssh(session))
            both.wait(2)
            self.release.set()
            self.assertEqual((True, "ok"), first.get(timeout=1))
            self.assertEqual((True, "ok"), second.get(timeout=1))

    def test_disconnect_reconnect_does_not_wait_for_ssh_or_send_late_reply(self):
        entered = threading.Event()
        def remote(*_):
            entered.set()
            self.release.wait(3)
            return "old-session-result"
        with patch.object(self.runtime.files.rpc_registry, "dispatch_sync", side_effect=remote):
            first = self.connect()
            result = self.call_thread(lambda: self.ssh(first))
            self.assertTrue(entered.wait(1))
            self.assertTrue(self.runtime.has_active_tasks())
            first.close()
            self.threads[-1].join(1)
            self.assertFalse(self.threads[-1].is_alive(), "disconnect waited for SSH")
            ok, error = result.get(timeout=1)
            self.assertFalse(ok)
            self.assertIsInstance(error, MappingSessionDisconnected)
            second = self.connect()
            self.assertIn("st_mode", second.call("stat", {"path": "."}))
            self.release.set()
            self.assertEqual([], second.call("task_list", {}))
        self.assertFalse(self.errors)

    def test_worker_limit_survives_reconnect_and_recovers_after_completion(self):
        self.runtime.rpc_slots = threading.BoundedSemaphore(1)
        entered = threading.Event()
        def remote(*_):
            entered.set()
            self.release.wait(3)
            return "ok"
        with patch.object(self.runtime.files.rpc_registry, "dispatch_sync", side_effect=remote):
            first = self.connect()
            self.call_thread(lambda: self.ssh(first))
            self.assertTrue(entered.wait(1))
            first.close()
            self.threads[-1].join(1)
            second = self.connect()
            with self.assertRaises(OSError) as error:
                second.call("stat", {"path": "."})
            self.assertEqual(errno.EBUSY, error.exception.errno)
            self.assertEqual(1, self.runtime.rpc_active)
            self.release.set()
            deadline = time.monotonic() + 1
            while self.runtime.rpc_active and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(0, self.runtime.rpc_active)
            self.assertIn("st_mode", second.call("stat", {"path": "."}))

    def test_worker_exception_is_returned_without_killing_transport(self):
        with patch.object(self.runtime.files.rpc_registry, "dispatch_sync", side_effect=RuntimeError("bad plugin")):
            session = self.connect()
            with self.assertRaises(OSError) as error:
                self.ssh(session)
            self.assertEqual(errno.EINVAL, error.exception.errno)
            self.assertIn("st_mode", session.call("stat", {"path": "."}))

    def test_local_mutation_waiting_for_lock_is_discarded_on_disconnect(self):
        session = self.connect()
        with self.runtime.files.lock:
            result = self.call_thread(lambda: session.call("create", {"path": "must-not-exist"}))
            deadline = time.monotonic() + 1
            while not self.runtime.rpc_active and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(1, self.runtime.rpc_active)
            session.close()
            self.threads[-1].join(1)
            self.assertFalse(self.threads[-1].is_alive())
        self.assertFalse(result.get(timeout=1)[0])
        deadline = time.monotonic() + 1
        while self.runtime.rpc_active and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertFalse((Path(self.directory.name) / "must-not-exist").exists())

    def test_file_handles_are_scoped_to_the_transport_session(self):
        class Socket:
            def __init__(self):
                self.replies = queue.Queue()
            def send(self, value):
                self.replies.put(json.loads(value))
        path = Path(self.directory.name) / "data.txt"
        path.write_text("data")
        first_socket, second_socket = Socket(), Socket()
        first = ClientRpcSession(self.runtime, first_socket, threading.Event())
        second = ClientRpcSession(self.runtime, second_socket, threading.Event())
        try:
            first.submit({"id": "open", "op": "open", "args": {"path": "data.txt"}})
            handle = first_socket.replies.get(timeout=1)["result"]
            second.submit({"id": "read", "op": "read", "args": {"handle": handle, "size": 4}})
            self.assertIn("error", second_socket.replies.get(timeout=1))
            first.close()
            self.assertFalse(first.files.handles)
        finally:
            first.close()
            second.close()

    def test_rpc_timeout_keeps_transport_heartbeat_and_other_requests_alive(self):
        entered = threading.Event()
        calls = []
        def remote(*args):
            calls.append(args)
            entered.set()
            self.release.wait(5)
            return "late-ssh-reply"
        with (
            patch.object(self.runtime.files.rpc_registry, "dispatch_sync", side_effect=remote),
            patch("openkapsel.client.HEARTBEAT_SECONDS", .05),
        ):
            session = self.connect()
            session.rpc_timeout_seconds = 1
            before = session.last_seen
            result = self.call_thread(lambda: self.ssh(session))
            self.assertTrue(entered.wait(1))
            self.assertIn("st_mode", session.call("stat", {"path": "."}))
            ok, error = result.get(timeout=2)
            self.assertFalse(ok)
            self.assertEqual(errno.ETIMEDOUT, error.errno)
            self.assertFalse(session.closed)
            self.assertGreater(session.last_seen, before, "heartbeat stopped during RPC")
            self.assertTrue(self.threads[-1].is_alive())
            self.assertFalse(session.pending)
            self.assertEqual([], session.call("task_list", {}))
            # The server frees only the timed-out request slot. Client work
            # remains active until it finishes, without retrying the operation.
            self.assertEqual(1, self.runtime.rpc_active)
            self.release.set()
            deadline = time.monotonic() + 1
            while self.runtime.rpc_active and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(0, self.runtime.rpc_active)
            self.assertIn("st_mode", session.call("stat", {"path": "."}))
            self.assertEqual(1, len(calls))
            self.assertFalse(session.closed)
            self.assertFalse(self.errors)

    def test_mutation_can_finish_after_timeout_without_replay_or_disconnect(self):
        entered = threading.Event()
        original = ClientFiles._dispatch
        calls = []
        def dispatch(files, op, args):
            if op == "create":
                calls.append(args)
                entered.set()
                self.release.wait(5)
            return original(files, op, args)
        with patch.object(ClientFiles, "_dispatch", dispatch):
            session = self.connect()
            session.rpc_timeout_seconds = 1
            result = self.call_thread(lambda: session.call("create", {"path": "once.txt"}))
            self.assertTrue(entered.wait(1))
            ok, error = result.get(timeout=2)
            self.assertFalse(ok)
            self.assertEqual(errno.ETIMEDOUT, error.errno)
            self.assertFalse(session.closed)
            self.assertEqual([], session.call("task_list", {}))
            self.release.set()
            deadline = time.monotonic() + 1
            while self.runtime.rpc_active and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue((Path(self.directory.name) / "once.txt").exists())
            self.assertEqual(1, len(calls))
            self.assertEqual(0, session.call("stat", {"path": "once.txt"})["st_size"])
            self.assertFalse(session.closed)

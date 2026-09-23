"""Real child processes survive replacement of the provider transport."""
import base64
import json
import sys
import tempfile
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest.mock import patch

from openkapsel.client import ClientRuntime, run_once
from openkapsel.mapping.mapping_transport import MAPPING_HANDSHAKE_VERSION, MINIMUM_MAPPING_CLIENT_VERSION, SERVER_SOURCE_FINGERPRINT


class ClientReconnectTests(unittest.TestCase):
    def setUp(self):
        try:
            import websocket
        except ImportError:
            self.skipTest("client extras required")
        self.directory = tempfile.TemporaryDirectory()
        self.config = {"url": "ws://127.0.0.1/provider", "token": "test",
                       "root": self.directory.name, "allow_exec": True,
                       "writable": True, "sandbox": False, "limits": {"max_tasks": 1}}
        self.runtime = ClientRuntime(self.config)

    def tearDown(self):
        if hasattr(self, "runtime"):
            self.runtime.close()
            for task in self.runtime.tasks.tasks.values():
                task["done"].wait(5)
            self.directory.cleanup()

    @staticmethod
    def server_hello():
        return json.dumps({
            "type": "server_hello",
            "handshake_version": MAPPING_HANDSHAKE_VERSION,
            "server_version": MINIMUM_MAPPING_CLIENT_VERSION,
            "server_fingerprint": SERVER_SOURCE_FINGERPRINT,
            "minimum_client_version": MINIMUM_MAPPING_CLIENT_VERSION,
            "hello_timeout_seconds": 30,
        })

    def connection(self, op, args):
        messages = iter([
            self.server_hello(),
            json.dumps({"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION}),
            json.dumps({"id": "rpc", "op": op, "args": args}),
            "",
        ])
        replies = []
        class Socket:
            def send(self, data): replies.append(json.loads(data))
            def recv(self): return next(messages)
            def close(self): pass
            def ping(self, *_): pass
        with patch("websocket.create_connection", return_value=Socket()):
            run_once(self.config, runtime=self.runtime)
        self.assertFalse(self.runtime.tasks.closed)
        return replies[-1]

    def start(self, tid, program):
        result = self.connection("task_start", {"task_id": tid, "argv": [sys.executable, "-u", "-c", program]})
        self.assertIn("result", result, result)
        return self.runtime.tasks.tasks[tid]

    def test_transport_timeout_is_configurable_and_bounded(self):
        config = dict(self.config, transport_timeout_seconds=75)
        runtime = ClientRuntime(config)
        messages = iter([
            self.server_hello(),
            json.dumps({"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION}),
            "",
        ])
        class Socket:
            def send(self, _data): pass
            def recv(self): return next(messages)
            def close(self): pass
            def ping(self, *_): pass
        try:
            with patch("websocket.create_connection", return_value=Socket()) as create:
                run_once(config, runtime=runtime)
            self.assertEqual(75.0, create.call_args.kwargs["timeout"])
        finally:
            runtime.close()
        with self.assertRaises(ValueError):
            ClientRuntime(dict(self.config, transport_timeout_seconds=5))

    def test_completed_offline_result_survives_long_disconnect(self):
        task = self.start("offline-result", "import time; time.sleep(.1); print('completed offline'); raise SystemExit(7)")
        self.assertTrue(task["done"].wait(5))
        with patch("openkapsel.client_runtime.client_tasks.time.time", return_value=time.time() + 7200):
            listed = self.connection("task_list", {})["result"]
            self.assertEqual("offline-result", listed[0]["task_id"])
            result = self.connection("task_get", {"task_id": "offline-result"})["result"]
        self.assertFalse(result["running"])
        self.assertEqual(7, result["exit_code"])
        self.assertIn(b"completed offline", base64.b64decode(result["output"]))

    def test_running_task_can_be_killed_after_reconnect(self):
        task = self.start("still-running", "import time; time.sleep(60)")
        pid = task["process"].pid
        result = self.connection("task_get", {"task_id": "still-running"})["result"]
        self.assertTrue(result["running"])
        self.assertEqual(pid, task["process"].pid)
        self.connection("task_kill", {"task_id": "still-running"})
        self.assertTrue(task["done"].wait(5))

    def test_uncollected_results_are_bounded_without_silent_eviction(self):
        for i in range(5):
            task = self.start("completed-" + str(i), "print('result')")
            self.assertTrue(task["done"].wait(5))
        denied = self.connection("task_start", {"task_id": "one-too-many", "argv": [sys.executable, "-V"]})
        self.assertIn("error", denied)
        self.assertEqual(5, len(self.connection("task_list", {})["result"]))
        self.connection("task_get", {"task_id": "completed-0"})
        task = self.start("replacement-task", "print('new result')")
        self.assertTrue(task["done"].wait(5))
        self.assertNotIn("completed-0", self.runtime.tasks.tasks)

    def test_transport_disconnect_closes_handles_but_keeps_rpc_registry(self):
        from pathlib import Path
        (Path(self.directory.name) / "handle.txt").write_text("data")
        registry = self.runtime.files.rpc_registry
        with patch.object(registry, "close", wraps=registry.close) as close:
            response = self.connection("open", {"path": "handle.txt", "mode": "r"})
            self.assertIn("result", response)
            self.assertFalse(self.runtime.files.handles)
            close.assert_not_called()
            self.runtime.close()
            close.assert_called_once_with()
        self.runtime = ClientRuntime(self.config)

    def test_offline_deadline_and_connection_failure_do_not_reset_runtime(self):
        response = self.connection("task_start", {"task_id": "offline-deadline", "timeout_seconds": .2,
            "argv": [sys.executable, "-u", "-c", "import time; time.sleep(60)"]})
        self.assertIn("result", response)
        with patch("websocket.create_connection", side_effect=OSError("offline")):
            with self.assertRaises(OSError):
                run_once(self.config, runtime=self.runtime)
        self.assertFalse(self.runtime.tasks.closed)
        task = self.runtime.tasks.tasks["offline-deadline"]
        self.assertTrue(task["done"].wait(5))
        self.assertFalse(self.connection("task_get", {"task_id": "offline-deadline"})["result"]["running"])

    def test_runtime_close_stops_tasks_and_config_cannot_switch(self):
        task = self.start("runtime-close", "import time; time.sleep(60)")
        with self.assertRaises(ValueError):
            run_once(dict(self.config, token="different"), runtime=self.runtime)
        self.runtime.close()
        self.assertTrue(task["done"].wait(5))

    def test_runtime_reports_loaded_rpc_extensions(self):
        self.runtime.close()
        with self.assertLogs("openkapsel.client", level="INFO") as logs:
            self.runtime = ClientRuntime(self.config)
        output = "\n".join(logs.output)
        self.assertIn("Loaded RPC extensions:", output)
        self.assertIn("archive v1", output)
        self.assertIn("git v2", output)

    def test_real_websocket_reconnect_reads_completed_result(self):
        from openkapsel.mapping.mapping_transport import ProviderSession
        connected = threading.Event()
        sessions, clients, failures = [], [], []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                session = ProviderSession(self)
                sessions.append(session)
                session.run(connected.set)
            def log_message(self, *_): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        self.runtime.close()
        self.config["url"] = f"ws://127.0.0.1:{server.server_port}/provider"
        self.runtime = ClientRuntime(self.config)
        def provider():
            try:
                run_once(self.config, runtime=self.runtime)
            except Exception as exc:
                failures.append(exc)
        def connect():
            connected.clear()
            thread = threading.Thread(target=provider, daemon=True)
            clients.append(thread)
            thread.start()
            self.assertTrue(connected.wait(5))
            return sessions[-1]
        try:
            first = connect()
            first.call("task_start", {"task_id": "websocket-task", "argv": [sys.executable, "-u", "-c",
                "import sys; print('ready'); sys.stdin.readline(); print('offline result')"]})
            first.close()
            clients[-1].join(5)
            self.assertFalse(clients[-1].is_alive())
            self.assertFalse(self.runtime.tasks.closed)
            task = self.runtime.tasks.tasks["websocket-task"]
            self.assertIsNone(task["process"].poll())
            # Finish with no server connection; then retrieve via a fresh socket.
            self.runtime.tasks.dispatch("task_stdin", {"task_id": "websocket-task", "data": "Cg=="})
            self.assertTrue(task["done"].wait(5))
            second = connect()
            result = second.call("task_get", {"task_id": "websocket-task"})
            self.assertFalse(result["running"])
            self.assertEqual(0, result["exit_code"])
            self.assertIn(b"offline result", base64.b64decode(result["output"]))
            self.assertFalse(failures, failures)
        finally:
            for session in sessions: session.close()
            for thread in clients: thread.join(5)
            server.shutdown()
            server.server_close()
            serving.join(5)

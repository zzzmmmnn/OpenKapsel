"""SSH RPC connection reuse, lifetime, host-key and SFTP tests."""

from __future__ import annotations

import base64
import errno
import io
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.rpc_plugins import load_client_rpc_registry
from openkapsel.rpc_plugins.registry import ClientRpcRegistry
from openkapsel.rpc_plugins.ssh import SshRpcPlugin, _parse_config


class Task:
    def __init__(self, cancelled=False):
        self.cancelled = cancelled
        self.output = bytearray()

    def check_cancelled(self):
        if self.cancelled:
            raise OSError(errno.ECANCELED, "cancelled")

    def write(self, value):
        if isinstance(value, str):
            value = value.encode()
        self.output.extend(value)


class FakeMissingHostKeyPolicy:
    pass


class FakeAuthenticationException(Exception):
    pass


class FakeBadHostKeyException(Exception):
    pass


class FakeSSHException(Exception):
    pass


class FakeKey:
    def __init__(self, value=b"fake-host-key"):
        self.value = value

    def asbytes(self):
        return self.value

    def get_name(self):
        return "ssh-ed25519"


class FakeHostKeys:
    def __init__(self):
        self.values = {}

    def add(self, hostname, kind, key):
        self.values[(hostname, kind)] = key


class FakeAttr:
    def __init__(self, filename=None, *, mode=stat.S_IFREG | 0o644, size=0):
        self.filename = filename
        self.st_mode = mode
        self.st_size = size
        self.st_uid = 1000
        self.st_gid = 1000
        self.st_atime = 1
        self.st_mtime = 2


class WriteHandle(io.BytesIO):
    def __init__(self, remote, path):
        super().__init__()
        self.remote = remote
        self.path = path

    def close(self):
        if not self.closed:
            self.remote.files[self.path] = self.getvalue()
        super().close()


class FakeSFTP:
    def __init__(self, remote):
        self.remote = remote

    def close(self):
        pass

    def _file(self, path):
        if path not in self.remote.files:
            raise OSError(errno.ENOENT, "missing")
        return self.remote.files[path]

    def lstat(self, path):
        if path in self.remote.dirs:
            return FakeAttr(mode=stat.S_IFDIR | 0o755)
        data = self._file(path)
        return FakeAttr(size=len(data))

    stat = lstat

    def listdir_attr(self, path):
        if path not in self.remote.dirs:
            raise OSError(errno.ENOENT, "missing")
        prefix = path.rstrip("/") + "/"
        names = {}
        for item in self.remote.dirs:
            if item == path or not item.startswith(prefix):
                continue
            rest = item[len(prefix):]
            if rest and "/" not in rest:
                names[rest] = FakeAttr(rest, mode=stat.S_IFDIR | 0o755)
        for item, data in self.remote.files.items():
            if not item.startswith(prefix):
                continue
            rest = item[len(prefix):]
            if rest and "/" not in rest:
                names[rest] = FakeAttr(rest, size=len(data))
        return list(names.values())

    def open(self, path, mode):
        if mode == "rb":
            return io.BytesIO(self._file(path))
        if mode == "wx":
            if path in self.remote.files:
                raise OSError(errno.EEXIST, "exists")
            return WriteHandle(self.remote, path)
        raise AssertionError(mode)

    def rename(self, source, destination):
        if destination in self.remote.files:
            raise OSError(errno.EEXIST, "exists")
        self.remote.files[destination] = self._file(source)
        del self.remote.files[source]

    def posix_rename(self, source, destination):
        self.remote.files[destination] = self._file(source)
        del self.remote.files[source]

    def remove(self, path):
        if path not in self.remote.files:
            raise OSError(errno.ENOENT, "missing")
        del self.remote.files[path]


class FakeChannel:
    def __init__(self, transport):
        self.transport = transport
        self.stdout = b""
        self.stderr = b""
        self.exit_code = 0
        self.command = None
        self.closed = False

    def get_pty(self):
        pass

    def exec_command(self, command):
        self.command = command
        if command == "drop-after-send":
            self.transport.active = False
            return
        self.stdout = ("ran:" + command + "\n").encode()
        if command.startswith("fail "):
            self.stderr = b"failure\n"
            self.exit_code = 7

    def recv_ready(self):
        return bool(self.stdout)

    def recv(self, size):
        data, self.stdout = self.stdout[:size], self.stdout[size:]
        return data

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv_stderr(self, size):
        data, self.stderr = self.stderr[:size], self.stderr[size:]
        return data

    def exit_status_ready(self):
        return self.transport.active and not self.stdout and not self.stderr

    def recv_exit_status(self):
        return self.exit_code

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self):
        self.active = True
        self.channels = []
        self.keepalive = None

    def is_active(self):
        return self.active

    def set_keepalive(self, seconds):
        self.keepalive = seconds

    def open_session(self, timeout=None):
        if not self.active:
            raise FakeSSHException("closed")
        channel = FakeChannel(self)
        self.channels.append(channel)
        return channel


class FakeRemote:
    def __init__(self):
        self.files = {"/remote/source.txt": b"from remote"}
        self.dirs = {"/", "/remote"}


class FakeSSHClient:
    def __init__(self, module):
        self.module = module
        self.transport = FakeTransport()
        self.remote = module.remote
        self.host_keys = FakeHostKeys()
        self.policy = None
        self.closed = False

    def load_system_host_keys(self):
        pass

    def load_host_keys(self, path):
        self.module.loaded_host_files.append(path)

    def get_host_keys(self):
        return self.host_keys

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.module.connect_calls.append(kwargs)
        if self.module.auth_fail:
            raise FakeAuthenticationException("bad auth")
        if self.policy is not None:
            self.policy.missing_host_key(self, kwargs["hostname"], FakeKey(self.module.host_key))

    def get_transport(self):
        return self.transport

    def open_sftp(self):
        if not self.transport.active:
            raise FakeSSHException("transport down")
        return FakeSFTP(self.remote)

    def close(self):
        self.closed = True
        self.transport.active = False


class FakeProxySocket:
    def __init__(self, response=b"HTTP/1.1 200 Connection established\r\n\r\n"):
        self.response = bytearray(response)
        self.sent = bytearray()
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        if not self.response:
            return b""
        data = bytes(self.response[:size])
        del self.response[:size]
        return data

    def close(self):
        self.closed = True


class FakeParamiko:
    MissingHostKeyPolicy = FakeMissingHostKeyPolicy
    AuthenticationException = FakeAuthenticationException
    BadHostKeyException = FakeBadHostKeyException
    SSHException = FakeSSHException

    def __init__(self):
        self.remote = FakeRemote()
        self.clients = []
        self.connect_calls = []
        self.loaded_host_files = []
        self.auth_fail = False
        self.host_key = b"fake-host-key"

    def SSHClient(self):
        client = FakeSSHClient(self)
        self.clients.append(client)
        return client


def config(*, policy="accept-new", idle=60):
    return {
        "ssh": {
            "idle_seconds": idle,
            "profiles": {
                "box": {
                    "host": "host.internal",
                    "port": 2222,
                    "username": "user",
                    "password": "secret",
                    "host_key_policy": policy,
                }
            },
        }
    }


class SshRpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.files = ClientFiles(self.root, writable=True)
        self.fake = FakeParamiko()
        self.plugin = SshRpcPlugin(config(), paramiko_module=self.fake)

    def tearDown(self):
        self.plugin.close()
        self.files.close()
        self.temp.cleanup()

    def call(self, operation, args, expected=200):
        value = self.plugin.dispatch(self.files, operation, args)
        self.assertEqual(expected, value["status"], value)
        return value.get("body", value.get("error"))

    def task(self, operation, args, expected=200):
        task = Task()
        value = self.plugin.dispatch_task(self.files, operation, args, task)
        self.assertEqual(expected, value["status"], value)
        return value.get("body", value.get("error")), bytes(task.output)

    def test_capability_states_and_metadata(self):
        empty = load_client_rpc_registry({}).capability_map({})
        self.assertEqual("unsupported", empty["ssh"]["state"])
        self.assertEqual("not_configured", empty["ssh"]["reason"])
        self.assertTrue(empty["ssh"]["operation_specs"]["read"]["write"])
        self.assertEqual("task", empty["ssh"]["operation_specs"]["exec"]["execution"])
        with patch("openkapsel.rpc_plugins.ssh._installed", return_value=False):
            plugin = SshRpcPlugin(config())
            try:
                state, reason, details = plugin.probe(config())
            finally:
                plugin.close()
        self.assertEqual("unsupported", state)
        self.assertEqual("dependency_missing", reason)
        self.assertNotIn("secret", repr(details))

    def test_profile_host_port_compact_syntax(self):
        base = {
            "username": "user",
            "password": "secret",
            "host_key_policy": "accept-new",
        }
        profiles, _ = _parse_config({"ssh": {"profiles": {
            "ipv4": {**base, "host": "192.0.2.1:12222"},
            "dns": {**base, "host": "host.example:2200"},
            "ipv6": {**base, "host": "[2001:db8::1]:2022"},
            "bare_ipv6": {**base, "host": "2001:db8::2"},
        }}})
        self.assertEqual(("192.0.2.1", 12222), (profiles["ipv4"].host, profiles["ipv4"].port))
        self.assertEqual(("host.example", 2200), (profiles["dns"].host, profiles["dns"].port))
        self.assertEqual(("2001:db8::1", 2022), (profiles["ipv6"].host, profiles["ipv6"].port))
        self.assertEqual(("2001:db8::2", 22), (profiles["bare_ipv6"].host, profiles["bare_ipv6"].port))

    def test_profile_rejects_duplicate_host_and_port(self):
        with self.assertRaisesRegex(ValueError, "must not set port"):
            _parse_config({"ssh": {"profiles": {"box": {
                "host": "host.example:12222",
                "port": 22,
                "username": "user",
                "password": "secret",
            }}}})

    def test_profiles_never_return_credentials(self):
        body = self.call("profiles", {})
        encoded = repr(body)
        self.assertEqual(1, body["total"])
        self.assertIn("password", body["profiles"][0]["authentication"])
        self.assertNotIn("secret", encoded)

    def test_proxy_types_aliases_defaults_and_validation(self):
        base = {"host": "target.internal", "username": "user", "password": "secret"}
        profiles, _ = _parse_config({"ssh": {"profiles": {
            "s4": {**base, "proxy": {"type": "s4", "host": "proxy4"}},
            "s5": {**base, "proxy": {"type": "s5", "host": "proxy5", "remote_dns": False}},
            "http": {**base, "proxy": {"type": "http", "host": "proxy-http"}},
            "https": {**base, "proxy": {"type": "https", "host": "proxy-tls"}},
        }}})
        self.assertEqual(("socks4", 1080, True),
                         (profiles["s4"].proxy.type, profiles["s4"].proxy.port,
                          profiles["s4"].proxy.remote_dns))
        self.assertEqual(("socks5", 1080, False),
                         (profiles["s5"].proxy.type, profiles["s5"].proxy.port,
                          profiles["s5"].proxy.remote_dns))
        self.assertEqual(("http", 8080),
                         (profiles["http"].proxy.type, profiles["http"].proxy.port))
        self.assertEqual(("https", 443, True),
                         (profiles["https"].proxy.type, profiles["https"].proxy.port,
                          profiles["https"].proxy.tls_verify))
        with self.assertRaisesRegex(ValueError, "password is not supported by SOCKS4"):
            _parse_config({"ssh": {"profiles": {"bad": {
                **base,
                "proxy": {"type": "socks4", "host": "proxy4",
                          "username": "ident", "password": "not-supported"},
            }}}})

    def test_proxy_credentials_never_return_from_profiles(self):
        proxy_config = config()
        proxy_config["ssh"]["profiles"]["box"]["proxy"] = {
            "type": "socks5", "host": "proxy.internal", "port": 1081,
            "username": "proxy-user", "password": "proxy-secret",
        }
        plugin = SshRpcPlugin(proxy_config, paramiko_module=self.fake)
        try:
            value = plugin.dispatch(self.files, "profiles", {})
        finally:
            plugin.close()
        self.assertEqual(200, value["status"], value)
        body = value["body"]
        self.assertEqual("socks5", body["profiles"][0]["proxy"]["type"])
        self.assertTrue(body["profiles"][0]["proxy"]["authenticated"])
        self.assertNotIn("proxy-user", repr(body))
        self.assertNotIn("proxy-secret", repr(body))

    def test_http_connect_proxy_passes_tunnel_socket_to_paramiko(self):
        proxy_config = config()
        proxy_config["ssh"]["profiles"]["box"]["proxy"] = {
            "type": "http", "host": "proxy.internal", "port": 3128,
            "username": "proxy-user", "password": "proxy-secret",
        }
        plugin = SshRpcPlugin(proxy_config, paramiko_module=self.fake)
        proxy_socket = FakeProxySocket()
        try:
            with patch("openkapsel.network.proxy.socket.create_connection",
                       return_value=proxy_socket) as connect:
                value = plugin.dispatch(self.files, "stat", {"profile": "box", "path": "/"})
        finally:
            plugin.close()
        self.assertEqual(200, value["status"], value)
        connect.assert_called_once_with(("proxy.internal", 3128), timeout=15)
        self.assertIs(self.fake.connect_calls[-1]["sock"], proxy_socket)
        request = bytes(proxy_socket.sent).decode("ascii")
        self.assertIn("CONNECT host.internal:2222 HTTP/1.1\r\n", request)
        expected = base64.b64encode(b"proxy-user:proxy-secret").decode("ascii")
        self.assertIn("Proxy-Authorization: Basic " + expected, request)

    def test_https_connect_proxy_wraps_tls_before_connect(self):
        proxy_config = config()
        proxy_config["ssh"]["profiles"]["box"]["proxy"] = {
            "type": "https", "host": "proxy.internal", "port": 8443,
            "ca_file": "/tmp/proxy-ca.pem", "tls_server_name": "proxy.example",
        }
        plugin = SshRpcPlugin(proxy_config, paramiko_module=self.fake)
        raw = FakeProxySocket()
        context = SimpleNamespace()
        wrapped = raw
        calls = []
        def wrap_socket(sock, server_hostname):
            calls.append((sock, server_hostname))
            return wrapped
        context.wrap_socket = wrap_socket
        try:
            with patch("openkapsel.network.proxy.socket.create_connection", return_value=raw), \
                 patch("openkapsel.network.proxy.ssl.create_default_context", return_value=context) as create_ctx:
                value = plugin.dispatch(self.files, "stat", {"profile": "box", "path": "/"})
        finally:
            plugin.close()
        self.assertEqual(200, value["status"], value)
        create_ctx.assert_called_once_with(cafile="/tmp/proxy-ca.pem")
        self.assertEqual([(raw, "proxy.example")], calls)
        self.assertIs(self.fake.connect_calls[-1]["sock"], wrapped)

    def test_socks4_and_socks5_use_python_socks_tunnel(self):
        for kind, expected_name in (("socks4", "SOCKS4"), ("socks5", "SOCKS5")):
            with self.subTest(kind=kind):
                fake = FakeParamiko()
                proxy_config = config()
                proxy_config["ssh"]["profiles"]["box"]["proxy"] = {
                    "type": kind, "host": "proxy.internal", "port": 1080,
                    "remote_dns": True,
                }
                plugin = SshRpcPlugin(proxy_config, paramiko_module=fake)
                proxy_socket = FakeProxySocket(response=b"")
                try:
                    with patch("python_socks.sync.Proxy") as proxy_cls:
                        proxy_cls.return_value.connect.return_value = proxy_socket
                        value = plugin.dispatch(
                            self.files, "stat", {"profile": "box", "path": "/"}
                        )
                    self.assertEqual(200, value["status"], value)
                    self.assertEqual(expected_name, proxy_cls.call_args.args[0].name)
                    self.assertEqual("proxy.internal", proxy_cls.call_args.args[1])
                    self.assertEqual(1080, proxy_cls.call_args.args[2])
                    self.assertTrue(proxy_cls.call_args.kwargs["rdns"])
                    proxy_cls.return_value.connect.assert_called_once_with(
                        "host.internal", 2222, timeout=15
                    )
                    self.assertIs(fake.connect_calls[-1]["sock"], proxy_socket)
                finally:
                    plugin.close()

    def test_http_proxy_auth_failure_is_specific_and_closes_socket(self):
        proxy_config = config()
        proxy_config["ssh"]["profiles"]["box"]["proxy"] = {
            "type": "http", "host": "proxy.internal",
            "username": "proxy-user", "password": "proxy-bad",
        }
        plugin = SshRpcPlugin(proxy_config, paramiko_module=self.fake)
        proxy_socket = FakeProxySocket(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
        )
        try:
            with patch("openkapsel.network.proxy.socket.create_connection",
                       return_value=proxy_socket):
                value = plugin.dispatch(
                    self.files, "stat", {"profile": "box", "path": "/"}
                )
        finally:
            plugin.close()
        self.assertEqual(502, value["status"], value)
        self.assertEqual("ssh_proxy_authentication_failed", value["error"]["code"])
        self.assertTrue(proxy_socket.closed)
        self.assertNotIn("proxy-bad", repr(value))

    def test_client_task_result_exposes_connection_id_for_reuse(self):
        registry = ClientRpcRegistry()
        registry.register(self.plugin, source="test:ssh")
        self.files.rpc_registry = registry
        self.files.rpc_capabilities = registry.capability_map(config())
        tasks = ClientTasks(self.files, enabled=False, max_tasks=2, max_seconds=30)
        try:
            started = tasks.dispatch("task_start", {
                "task_id": "ssh-exec-task-1",
                "rpc": {
                    "family": "ssh",
                    "operation": "exec",
                    "args": {"profile": "box", "command": "hostname"},
                },
            })
            self.assertEqual("rpc", started["kind"])
            self.assertTrue(started["write"])
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                completed = tasks.dispatch(
                    "task_get", {"task_id": "ssh-exec-task-1", "offset": 0}
                )
                if not completed["running"]:
                    break
                time.sleep(0.01)
            else:
                self.fail("SSH RPC task did not finish")
            self.assertEqual(0, completed["exit_code"], completed)
            connection_id = completed["result"]["connection_id"]
            output = base64.b64decode(completed["output"])
            self.assertEqual(b"ran:hostname\n", output)
            reused, _ = self.task(
                "exec", {"connection_id": connection_id, "command": "uptime"}
            )
            self.assertEqual(connection_id, reused["connection_id"])
            self.assertEqual(1, len(self.fake.connect_calls))
        finally:
            tasks.close()

    def test_first_exec_returns_id_and_second_reuses_one_transport(self):
        first, output1 = self.task("exec", {"profile": "box", "command": "hostname"})
        connection_id = first["connection_id"]
        self.assertTrue(connection_id.startswith("ssh_"))
        self.assertEqual(b"ran:hostname\n", output1)
        second, output2 = self.task(
            "exec", {"connection_id": connection_id, "command": "uptime"}
        )
        self.assertEqual(connection_id, second["connection_id"])
        self.assertEqual(b"ran:uptime\n", output2)
        self.assertEqual(1, len(self.fake.clients))
        self.assertEqual(1, len(self.fake.connect_calls))
        self.assertEqual(2, len(self.fake.clients[0].transport.channels))

    def test_status_close_and_closed_id_never_reconnect(self):
        first, _ = self.task("exec", {"profile": "box", "command": "true"})
        connection_id = first["connection_id"]
        status = self.call("status", {"connection_id": connection_id})
        self.assertEqual("alive", status["state"])
        self.assertEqual("box", status["profile"])
        closed = self.call("close", {"connection_id": connection_id})
        self.assertEqual("closed", closed["state"])
        error = self.call("status", {"connection_id": connection_id}, 409)
        self.assertEqual("ssh_connection_closed", error["code"])
        self.assertEqual(1, len(self.fake.connect_calls))

    def test_idle_reaper_waits_for_active_operation_then_expires(self):
        first, _ = self.task("exec", {"profile": "box", "command": "true"})
        connection_id = first["connection_id"]
        conn = self.plugin._pool._live[connection_id]
        with self.plugin._pool.lease(profile_name=None, connection_id=connection_id):
            conn.last_idle_mono = time.monotonic() - 1000
            self.plugin._pool._reap_once()
            self.assertIn(connection_id, self.plugin._pool._live)
        conn.last_idle_mono = time.monotonic() - self.plugin._pool.idle_seconds - 1
        self.plugin._pool._reap_once()
        self.assertNotIn(connection_id, self.plugin._pool._live)
        error = self.call("status", {"connection_id": connection_id}, 409)
        self.assertEqual("ssh_connection_expired", error["code"])
        self.assertEqual(1, len(self.fake.connect_calls))

    def test_lost_connection_is_distinct_and_not_recreated(self):
        first, _ = self.task("exec", {"profile": "box", "command": "true"})
        connection_id = first["connection_id"]
        self.fake.clients[0].transport.active = False
        error = self.call("status", {"connection_id": connection_id}, 409)
        self.assertEqual("ssh_connection_lost", error["code"])
        self.assertEqual(1, len(self.fake.connect_calls))

    def test_command_loss_after_dispatch_is_uncertain(self):
        error, _ = self.task(
            "exec", {"profile": "box", "command": "drop-after-send"}, 409
        )
        self.assertEqual("ssh_execution_uncertain", error["code"])
        self.assertTrue(error["details"]["command_may_have_completed"])

    def test_sftp_stat_list_read_upload_download_reuse(self):
        listing = self.call("listdir", {"profile": "box", "path": "/remote"})
        connection_id = listing["connection_id"]
        self.assertEqual(["source.txt"], [item["name"] for item in listing["entries"]])
        stat_body = self.call(
            "stat", {"connection_id": connection_id, "path": "/remote/source.txt"}
        )
        self.assertEqual("file", stat_body["type"])
        read_body = self.call(
            "read", {"connection_id": connection_id, "path": "/remote/source.txt"}
        )
        self.assertEqual("from remote", read_body["text"])

        (self.root / "local.txt").write_text("from local", encoding="utf-8")
        uploaded, _ = self.task(
            "upload",
            {
                "connection_id": connection_id,
                "local_path": "local.txt",
                "remote_path": "/remote/uploaded.txt",
            },
        )
        self.assertTrue(uploaded["published"])
        self.assertEqual(b"from local", self.fake.remote.files["/remote/uploaded.txt"])

        downloaded, _ = self.task(
            "download",
            {
                "connection_id": connection_id,
                "remote_path": "/remote/source.txt",
                "local_path": "downloaded.txt",
            },
        )
        self.assertTrue(downloaded["published"])
        self.assertEqual("from remote", (self.root / "downloaded.txt").read_text())
        self.assertEqual(1, len(self.fake.connect_calls))

    def test_accept_new_pins_first_key_for_client_process(self):
        first = self.call("stat", {"profile": "box", "path": "/"})
        self.call("close", {"connection_id": first["connection_id"]})
        self.fake.host_key = b"changed-host-key"
        value = self.plugin.dispatch(self.files, "stat", {"profile": "box", "path": "/"})
        self.assertEqual(409, value["status"], value)
        self.assertEqual("ssh_host_key_mismatch", value["error"]["code"])
        self.assertEqual(2, len(self.fake.connect_calls))

    def test_strict_unknown_host_returns_pin_without_secret(self):
        plugin = SshRpcPlugin(config(policy="strict"), paramiko_module=self.fake)
        try:
            value = plugin.dispatch(self.files, "stat", {"profile": "box", "path": "/"})
        finally:
            plugin.close()
        self.assertEqual(409, value["status"], value)
        error = value["error"]
        self.assertEqual("ssh_host_key_unknown", error["code"])
        self.assertTrue(error["details"]["host_key_sha256"].startswith("SHA256:"))
        self.assertNotIn("secret", repr(value))

    def test_readonly_mapping_denies_even_profile_listing(self):
        self.files.writable = False
        value = self.plugin.dispatch(self.files, "profiles", {})
        self.assertEqual(403, value["status"])
        self.assertEqual("mapping_read_only", value["error"]["code"])


if __name__ == "__main__":
    unittest.main()

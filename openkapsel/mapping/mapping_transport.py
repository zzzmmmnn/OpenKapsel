"""Bounded, synchronous WebSocket RPC broker and FUSE worker IPC."""

from __future__ import annotations

import base64
import binascii
import errno
import json
import queue
import secrets
import socket
import threading
import time

from openkapsel import __version__
from openkapsel.source_fingerprint import running_fingerprint, version_at_least


MAX_MESSAGE = 1024 * 1024
MAX_CAPABILITIES = 256 * 1024
CHUNK_SIZE = 128 * 1024
DEFAULT_RPC_TIMEOUT_SECONDS = 90.0
DEFAULT_PROVIDER_IDLE_TIMEOUT_SECONDS = 60.0
MAPPING_HANDSHAKE_VERSION = 2
MAPPING_HELLO_TIMEOUT_SECONDS = 30
MINIMUM_MAPPING_CLIENT_VERSION = "1.62.0"
SERVER_SOURCE_FINGERPRINT = running_fingerprint("server")
FILE_API_READ_OPERATIONS = frozenset({"fs_list", "fs_stat", "fs_read", "fs_read_many", "fs_read_large", "fs_tree", "fs_search", "fs_manifest"})
FILE_API_WRITE_OPERATIONS = frozenset({"fs_write", "fs_replace", "fs_replace_batch", "fs_replace_large", "fs_mutate", "fs_mkdir", "fs_move", "fs_delete", "fs_delete_batch"})
FILE_API_OPERATIONS = FILE_API_READ_OPERATIONS | FILE_API_WRITE_OPERATIONS
READ_OPERATIONS = frozenset({"fstat", "stat", "list", "read", "open", "close", "flush", "statfs", "recycle_list",
                             "task_get", "task_list", "git_status", "git_diff", "git_log", "git_show", "git_ls_files", "git_diff_stat"}) | frozenset("api_" + op for op in FILE_API_READ_OPERATIONS)


def encode(value):
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > MAX_MESSAGE:
        raise OSError(errno.E2BIG, "mapping message exceeds limit")
    return data


def recv_line(stream):
    data = stream.readline(MAX_MESSAGE + 2)
    if not data or len(data) > MAX_MESSAGE + 1 or not data.endswith(b"\n"):
        raise OSError(errno.EPROTO, "invalid mapping IPC message")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise OSError(errno.EPROTO, "mapping message must be an object")
    return value


class ProviderSession:
    def __init__(
        self,
        handler,
        *,
        rpc_timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS,
        idle_timeout_seconds: float = DEFAULT_PROVIDER_IDLE_TIMEOUT_SECONDS,
    ):
        from wsproto import WSConnection, ConnectionType
        from wsproto.events import AcceptConnection
        self.handler = handler
        self.socket = handler.connection
        self.ws = WSConnection(ConnectionType.SERVER)
        self.lock = threading.RLock()
        self.pending = {}
        self.slots = threading.BoundedSemaphore(32)
        self.closed = False
        self.generation = secrets.token_hex(12)
        self.capabilities = {}
        self.ready = False
        self.client_version = None
        self.client_fingerprint = None
        self.last_seen = time.monotonic()
        self.rpc_timeout_seconds = float(rpc_timeout_seconds)
        self.idle_timeout_seconds = float(idle_timeout_seconds)
        if not 1 <= self.rpc_timeout_seconds <= 600:
            raise ValueError("mapping RPC timeout must be between 1 and 600 seconds")
        if not 10 <= self.idle_timeout_seconds <= 600:
            raise ValueError("mapping provider idle timeout must be between 10 and 600 seconds")
        headers = [(key.lower().encode("ascii"), value.encode("latin1")) for key, value in handler.headers.items()]
        self.ws.initiate_upgrade_connection(headers, handler.path)
        list(self.ws.events())
        self.socket.sendall(self.ws.send(AcceptConnection()))
        handler.close_connection = True
        self.socket.settimeout(MAPPING_HELLO_TIMEOUT_SECONDS)
        self.send({
            "type": "server_hello",
            "handshake_version": MAPPING_HANDSHAKE_VERSION,
            "server_version": __version__,
            "server_fingerprint": SERVER_SOURCE_FINGERPRINT,
            "minimum_client_version": MINIMUM_MAPPING_CLIENT_VERSION,
            "hello_timeout_seconds": MAPPING_HELLO_TIMEOUT_SECONDS,
        })

    def send(self, value):
        from wsproto.events import TextMessage
        with self.lock:
            if self.closed:
                raise OSError(errno.EHOSTDOWN, "mapping client is offline")
            self.socket.sendall(self.ws.send(TextMessage(data=encode(value).decode())))

    def call(self, operation, arguments):
        if not self.ready:
            raise OSError(errno.EHOSTDOWN, "mapping client handshake is not ready")
        if not self.slots.acquire(timeout=2):
            raise OSError(errno.EBUSY, "mapping request limit reached")
        rid = secrets.token_hex(12)
        answer = queue.Queue(maxsize=1)
        try:
            with self.lock:
                if self.closed:
                    raise OSError(errno.EHOSTDOWN, "mapping client is offline")
                self.pending[rid] = answer
            self.send({"id": rid, "op": operation, "args": arguments})
            try:
                result = answer.get(timeout=self.rpc_timeout_seconds)
            except queue.Empty:
                # An ambiguous write is never replayed into another session.
                self.close()
                raise OSError(errno.ETIMEDOUT, "mapping request timed out; result may be unknown") from None
            if "error" in result:
                error = result["error"]
                message = error.get("message")
                if not isinstance(message, str) or not message or len(message) > 200:
                    message = "client operation failed"
                raise OSError(int(error.get("errno", errno.EIO)), message)
            return result.get("result")
        finally:
            with self.lock:
                self.pending.pop(rid, None)
            self.slots.release()

    def run(self, on_seen):
        from wsproto.events import TextMessage, BytesMessage, CloseConnection, Ping
        fragments, length = [], 0
        hello_deadline = time.monotonic() + MAPPING_HELLO_TIMEOUT_SECONDS
        try:
            while not self.closed:
                if not self.ready:
                    remaining = hello_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("mapping client hello timed out")
                    self.socket.settimeout(remaining)
                data = self.socket.recv(65536)
                if not data:
                    break
                with self.lock:
                    self.ws.receive_data(data)
                    events = list(self.ws.events())
                for event in events:
                    if isinstance(event, Ping):
                        with self.lock:
                            self.socket.sendall(self.ws.send(event.response()))
                        self.last_seen = time.monotonic()
                        if self.ready:
                            on_seen()
                    elif isinstance(event, TextMessage):
                        length += len(event.data)
                        if length > MAX_MESSAGE:
                            raise ValueError("mapping message too large")
                        fragments.append(event.data)
                        if event.message_finished:
                            value = json.loads("".join(fragments))
                            fragments, length = [], 0
                            if not isinstance(value, dict):
                                raise ValueError("invalid mapping message")
                            if not self.ready:
                                if value.get("type") != "client_hello":
                                    raise ValueError("client_hello required before mapping RPC")
                                if value.get("handshake_version") != MAPPING_HANDSHAKE_VERSION:
                                    raise ValueError("unsupported mapping handshake version")
                                version = value.get("client_version")
                                fingerprint = value.get("client_fingerprint")
                                if not isinstance(version, str) or not version_at_least(
                                    version, MINIMUM_MAPPING_CLIENT_VERSION
                                ):
                                    raise ValueError("mapping client version is below the server minimum")
                                if not isinstance(fingerprint, str) or len(fingerprint) != 44:
                                    raise ValueError("invalid mapping client fingerprint")
                                try:
                                    decoded = base64.b64decode(fingerprint, validate=True)
                                except (binascii.Error, ValueError):
                                    raise ValueError("invalid mapping client fingerprint") from None
                                if len(decoded) != 32:
                                    raise ValueError("invalid mapping client fingerprint")
                                caps = value.get("capabilities", {})
                                if not isinstance(caps, dict) or len(encode(caps)) > MAX_CAPABILITIES:
                                    raise ValueError("invalid capabilities")
                                self.client_version = version
                                self.client_fingerprint = fingerprint
                                self.capabilities = caps
                                self.ready = True
                                self.last_seen = time.monotonic()
                                self.socket.settimeout(self.idle_timeout_seconds)
                                on_seen()
                                self.send({"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION})
                            else:
                                if value.get("type") in {"hello", "client_hello"}:
                                    raise ValueError("duplicate provider hello")
                                if not isinstance(value.get("id"), str):
                                    raise ValueError("invalid reply id")
                                with self.lock:
                                    waiter = self.pending.get(value.get("id"))
                                    if waiter is not None and waiter.empty():
                                        waiter.put_nowait(value)
                    elif isinstance(event, (CloseConnection, BytesMessage)):
                        return
        finally:
            self.close()

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for waiter in self.pending.values():
                if waiter.empty():
                    waiter.put_nowait({"error": {"errno": errno.EHOSTDOWN}})
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

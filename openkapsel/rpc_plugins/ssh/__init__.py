"""Client-local SSH/SFTP RPC with bounded reusable Paramiko connections."""

from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import importlib
import importlib.util
import os
import posixpath
import re
import secrets
import socket
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openkapsel.errors import ApiError
from .._data import Snapshot, export_path, fail, object_schema, response, validate


DEFAULT_IDLE_SECONDS = 60
DEFAULT_CONNECT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_CONNECTIONS = 8
DEFAULT_MAX_CHANNELS = 8
MAX_PROFILES = 64
MAX_REMOTE_READ_BYTES = 128 * 1024
MAX_LIST_ENTRIES = 100_000
MAX_COMMAND_CHARS = 100_000
MAX_REMOTE_PATH_CHARS = 4096
_COPY_CHUNK = 256 * 1024
_PROFILE_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,128}\Z")
_CONNECTION_ID = re.compile(r"ssh_[A-Za-z0-9_-]{20,80}\Z")
_SHA256_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")


@dataclass(frozen=True)
class SshProfile:
    name: str
    host: str
    port: int
    username: str
    password: str | None = field(default=None, repr=False)
    key_filename: str | None = None
    passphrase: str | None = field(default=None, repr=False)
    allow_agent: bool = False
    look_for_keys: bool = False
    host_key_policy: str = "strict"
    host_key_sha256: str | None = None
    known_hosts: str | None = None


@dataclass
class _Connection:
    id: str
    profile: SshProfile
    client: Any
    created_at: float
    last_idle_mono: float
    active: int = 0


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def _bounded_number(value: Any, *, name: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise ValueError(f"ssh.{name} must be an integer")
    value = int(value)
    if not minimum <= value <= maximum:
        raise ValueError(f"ssh.{name} must be between {minimum} and {maximum}")
    return value


def _text(value: Any, *, label: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{label} must not be empty")
    return value


def _parse_config(config: dict[str, Any]) -> tuple[dict[str, SshProfile], dict[str, Any]]:
    raw = config.get("ssh", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("ssh must be an object")
    allowed = {
        "profiles", "idle_seconds", "connect_timeout_seconds", "max_connections",
        "max_channels_per_connection", "known_hosts",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError("unsupported ssh settings: " + ", ".join(sorted(unknown)))

    idle = _bounded_number(raw.get("idle_seconds"), name="idle_seconds",
                           default=DEFAULT_IDLE_SECONDS, minimum=10, maximum=3600)
    connect_timeout = _bounded_number(
        raw.get("connect_timeout_seconds"), name="connect_timeout_seconds",
        default=DEFAULT_CONNECT_TIMEOUT_SECONDS, minimum=1, maximum=120,
    )
    max_connections = _bounded_number(
        raw.get("max_connections"), name="max_connections",
        default=DEFAULT_MAX_CONNECTIONS, minimum=1, maximum=32,
    )
    max_channels = _bounded_number(
        raw.get("max_channels_per_connection"), name="max_channels_per_connection",
        default=DEFAULT_MAX_CHANNELS, minimum=1, maximum=64,
    )
    global_known_hosts = raw.get("known_hosts")
    if global_known_hosts is not None:
        global_known_hosts = _text(global_known_hosts, label="ssh.known_hosts", maximum=4096)

    raw_profiles = raw.get("profiles", {})
    if raw_profiles is None:
        raw_profiles = {}
    if not isinstance(raw_profiles, dict) or len(raw_profiles) > MAX_PROFILES:
        raise ValueError(f"ssh.profiles must be an object with at most {MAX_PROFILES} entries")

    profiles: dict[str, SshProfile] = {}
    for name, value in raw_profiles.items():
        if not isinstance(name, str) or not _PROFILE_NAME.fullmatch(name):
            raise ValueError("SSH profile names must use 1-128 ASCII letters, digits, . _ @ or -")
        if not isinstance(value, dict):
            raise ValueError(f"ssh.profiles.{name} must be an object")
        permitted = {
            "host", "port", "username", "password", "key_filename", "passphrase",
            "allow_agent", "look_for_keys", "host_key_policy", "host_key_sha256",
            "known_hosts",
        }
        extra = set(value) - permitted
        if extra:
            raise ValueError(f"unsupported settings in SSH profile {name}: " + ", ".join(sorted(extra)))
        host = _text(value.get("host"), label=f"ssh.profiles.{name}.host", maximum=1024)
        username = _text(value.get("username"), label=f"ssh.profiles.{name}.username", maximum=256)
        port = _bounded_number(value.get("port"), name=f"profiles.{name}.port",
                               default=22, minimum=1, maximum=65535)
        password = value.get("password")
        if password is not None:
            password = _text(password, label=f"ssh.profiles.{name}.password",
                             maximum=65536, allow_empty=True)
        key_filename = value.get("key_filename")
        if key_filename is not None:
            key_filename = _text(key_filename, label=f"ssh.profiles.{name}.key_filename",
                                 maximum=4096)
        passphrase = value.get("passphrase")
        if passphrase is not None:
            passphrase = _text(passphrase, label=f"ssh.profiles.{name}.passphrase",
                               maximum=65536, allow_empty=True)
        allow_agent = value.get("allow_agent", False)
        look_for_keys = value.get("look_for_keys", False)
        if not isinstance(allow_agent, bool) or not isinstance(look_for_keys, bool):
            raise ValueError(f"ssh.profiles.{name}.allow_agent/look_for_keys must be boolean")
        policy = value.get("host_key_policy", "strict")
        if policy not in {"strict", "accept-new"}:
            raise ValueError(f"ssh.profiles.{name}.host_key_policy must be strict or accept-new")
        fingerprint = value.get("host_key_sha256")
        if fingerprint is not None and (
            not isinstance(fingerprint, str) or not _SHA256_FINGERPRINT.fullmatch(fingerprint)
        ):
            raise ValueError(f"ssh.profiles.{name}.host_key_sha256 must be an OpenSSH SHA256 fingerprint")
        known_hosts = value.get("known_hosts", global_known_hosts)
        if known_hosts is not None:
            known_hosts = _text(known_hosts, label=f"ssh.profiles.{name}.known_hosts", maximum=4096)
        if password is None and key_filename is None and not allow_agent and not look_for_keys:
            raise ValueError(
                f"SSH profile {name} needs password, key_filename, allow_agent=true, or look_for_keys=true"
            )
        profiles[name] = SshProfile(
            name=name, host=host, port=port, username=username, password=password,
            key_filename=key_filename, passphrase=passphrase, allow_agent=allow_agent,
            look_for_keys=look_for_keys, host_key_policy=policy,
            host_key_sha256=fingerprint, known_hosts=known_hosts,
        )

    return profiles, {
        "idle_seconds": idle,
        "connect_timeout_seconds": connect_timeout,
        "max_connections": max_connections,
        "max_channels_per_connection": max_channels,
    }


def _fingerprint(key: Any) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _remote_path(value: Any, *, label: str = "path") -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > MAX_REMOTE_PATH_CHARS:
        fail("ssh_remote_path_invalid", f"{label} must be a non-empty bounded remote path")
    return value


def _connection_args(args: dict[str, Any]) -> tuple[str | None, str | None]:
    profile = args.get("profile")
    connection_id = args.get("connection_id")
    if profile is not None and (not isinstance(profile, str) or not _PROFILE_NAME.fullmatch(profile)):
        fail("ssh_profile_invalid", "profile has an invalid name")
    if connection_id is not None and (
        not isinstance(connection_id, str) or not _CONNECTION_ID.fullmatch(connection_id)
    ):
        fail("ssh_connection_id_invalid", "connection_id has an invalid format")
    if connection_id is None and profile is None:
        fail("ssh_target_required", "provide profile for a new connection or connection_id to reuse one")
    if connection_id is not None and profile is not None:
        fail("ssh_target_conflict", "provide profile or connection_id, not both")
    return profile, connection_id


def _attr_type(mode: int | None) -> str:
    if mode is None:
        return "unknown"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "link"
    return "special"


def _attr_view(attr: Any, *, name: str | None = None) -> dict[str, Any]:
    mode = getattr(attr, "st_mode", None)
    body = {
        "type": _attr_type(mode),
        "size": getattr(attr, "st_size", None),
        "mode": mode,
        "uid": getattr(attr, "st_uid", None),
        "gid": getattr(attr, "st_gid", None),
        "atime": getattr(attr, "st_atime", None),
        "mtime": getattr(attr, "st_mtime", None),
    }
    if name is not None:
        body["name"] = name
    return body


class _ConnectionPool:
    def __init__(self, profiles: dict[str, SshProfile], settings: dict[str, Any],
                 *, paramiko_module: Any | None = None):
        self.profiles = profiles
        self.idle_seconds = settings["idle_seconds"]
        self.connect_timeout = settings["connect_timeout_seconds"]
        self.max_connections = settings["max_connections"]
        self.max_channels = settings["max_channels_per_connection"]
        self._paramiko = paramiko_module
        self._lock = threading.RLock()
        self._live: dict[str, _Connection] = {}
        self._dead: dict[str, tuple[str, float]] = {}
        self._accepted_host_keys: dict[str, str] = {}
        self._connecting = 0
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None

    def _module(self):
        if self._paramiko is None:
            self._paramiko = importlib.import_module("paramiko")
        return self._paramiko

    def _new_id(self) -> str:
        return "ssh_" + secrets.token_urlsafe(24)

    @staticmethod
    def _transport(conn: _Connection):
        return conn.client.get_transport()

    @classmethod
    def _active_transport(cls, conn: _Connection) -> bool:
        transport = cls._transport(conn)
        return transport is not None and transport.is_active()

    def _start_reaper(self):
        with self._lock:
            if self._reaper is not None:
                return
            self._reaper = threading.Thread(
                target=self._reap_loop, name="openkapsel-ssh-reaper", daemon=True
            )
            self._reaper.start()

    def _remember_dead_locked(self, connection_id: str, reason: str):
        self._dead[connection_id] = (reason, time.monotonic())
        if len(self._dead) > 1024:
            oldest = min(self._dead.items(), key=lambda item: item[1][1])[0]
            self._dead.pop(oldest, None)

    def _retire_locked(self, connection_id: str, reason: str):
        conn = self._live.pop(connection_id, None)
        if conn is not None:
            self._remember_dead_locked(connection_id, reason)
        return conn

    @staticmethod
    def _close_client(client):
        with contextlib.suppress(Exception):
            client.close()

    def _reap_once(self, now: float | None = None):
        now = time.monotonic() if now is None else now
        close_clients = []
        with self._lock:
            for connection_id, conn in list(self._live.items()):
                if conn.active == 0 and now - conn.last_idle_mono >= self.idle_seconds:
                    retired = self._retire_locked(connection_id, "expired")
                    if retired is not None:
                        close_clients.append(retired.client)
            for connection_id, (_reason, when) in list(self._dead.items()):
                if now - when > max(3600, self.idle_seconds * 10):
                    self._dead.pop(connection_id, None)
        for client in close_clients:
            self._close_client(client)

    def _reap_loop(self):
        interval = max(1.0, min(5.0, self.idle_seconds / 4))
        while not self._stop.wait(interval):
            self._reap_once()

    def _policy(self, paramiko: Any, profile: SshProfile):
        policy_name = profile.host_key_policy

        class Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(_self, client, hostname, key):
                actual = _fingerprint(key)
                with self._lock:
                    accepted = self._accepted_host_keys.get(profile.name)
                expected = profile.host_key_sha256 or accepted
                if expected is not None:
                    if actual != expected:
                        raise ApiError(
                            409, "ssh_host_key_mismatch",
                            "SSH host key does not match the pinned or previously accepted fingerprint",
                            {"profile": profile.name, "host": profile.host, "port": profile.port,
                             "host_key_type": key.get_name(),
                             "expected_sha256": expected, "actual_sha256": actual},
                        )
                    client.get_host_keys().add(hostname, key.get_name(), key)
                    return
                if policy_name == "accept-new":
                    with self._lock:
                        previous = self._accepted_host_keys.setdefault(profile.name, actual)
                    if previous != actual:
                        raise ApiError(
                            409, "ssh_host_key_mismatch",
                            "SSH host key changed after first-use acceptance",
                            {"profile": profile.name, "host": profile.host, "port": profile.port,
                             "host_key_type": key.get_name(),
                             "expected_sha256": previous, "actual_sha256": actual},
                        )
                    client.get_host_keys().add(hostname, key.get_name(), key)
                    return
                raise ApiError(
                    409, "ssh_host_key_unknown",
                    "SSH host key is not trusted; pin the returned SHA256 fingerprint or add it to known_hosts",
                    {"profile": profile.name, "host": profile.host, "port": profile.port,
                     "host_key_type": key.get_name(), "host_key_sha256": actual},
                )

        return Policy()

    def _connect(self, profile: SshProfile) -> _Connection:
        paramiko = self._module()
        with self._lock:
            if len(self._live) + self._connecting >= self.max_connections:
                fail("ssh_connection_limit",
                     "SSH connection pool limit reached; close or let an idle connection expire",
                     429, {"max_connections": self.max_connections})
            self._connecting += 1
        try:
            client = paramiko.SSHClient()
            with contextlib.suppress(Exception):
                client.load_system_host_keys()
            if profile.known_hosts is not None:
                known_hosts = Path(profile.known_hosts).expanduser()
                if not known_hosts.is_file():
                    fail("ssh_known_hosts_missing",
                         "configured SSH known_hosts file does not exist", 400,
                         {"profile": profile.name})
                client.load_host_keys(str(known_hosts))
            client.set_missing_host_key_policy(self._policy(paramiko, profile))
            kwargs = {
                "hostname": profile.host,
                "port": profile.port,
                "username": profile.username,
                "password": profile.password,
                "key_filename": str(Path(profile.key_filename).expanduser()) if profile.key_filename else None,
                "passphrase": profile.passphrase,
                "allow_agent": profile.allow_agent,
                "look_for_keys": profile.look_for_keys,
                "timeout": self.connect_timeout,
                "auth_timeout": self.connect_timeout,
                "banner_timeout": self.connect_timeout,
            }
            try:
                client.connect(**kwargs)
            except ApiError:
                self._close_client(client)
                raise
            except paramiko.AuthenticationException as exc:
                self._close_client(client)
                raise ApiError(403, "ssh_authentication_failed", "SSH authentication failed",
                               {"profile": profile.name}) from exc
            except paramiko.BadHostKeyException as exc:
                self._close_client(client)
                raise ApiError(409, "ssh_host_key_mismatch",
                               "SSH host key changed or does not match known_hosts",
                               {"profile": profile.name}) from exc
            except (socket.timeout, OSError, EOFError, paramiko.SSHException) as exc:
                self._close_client(client)
                raise ApiError(502, "ssh_connect_failed",
                               "SSH connection could not be established",
                               {"profile": profile.name, "error_type": type(exc).__name__}) from exc
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                self._close_client(client)
                fail("ssh_connect_failed", "SSH transport was not established", 502,
                     {"profile": profile.name})
            keepalive = max(5, min(30, self.idle_seconds // 2))
            with contextlib.suppress(Exception):
                transport.set_keepalive(keepalive)
            now = time.monotonic()
            conn = _Connection(
                id=self._new_id(), profile=profile, client=client,
                created_at=time.time(), last_idle_mono=now, active=1,
            )
            with self._lock:
                self._live[conn.id] = conn
            self._start_reaper()
            return conn
        finally:
            with self._lock:
                self._connecting -= 1

    def _dead_error(self, connection_id: str):
        dead = self._dead.get(connection_id)
        if dead is None:
            fail("ssh_connection_not_found",
                 "SSH connection_id is unknown in this client process", 404,
                 {"connection_id": connection_id})
        reason = dead[0]
        code = {"expired": "ssh_connection_expired",
                "lost": "ssh_connection_lost",
                "closed": "ssh_connection_closed"}[reason]
        message = {"expired": "SSH connection expired after the idle timeout",
                   "lost": "SSH connection was lost",
                   "closed": "SSH connection was explicitly closed"}[reason]
        fail(code, message, 409, {"connection_id": connection_id})

    @contextmanager
    def lease(self, *, profile_name: str | None, connection_id: str | None):
        if connection_id is None:
            profile = self.profiles.get(profile_name or "")
            if profile is None:
                fail("ssh_profile_not_found", "SSH profile does not exist", 404,
                     {"profile": profile_name})
            conn = self._connect(profile)
        else:
            with self._lock:
                conn = self._live.get(connection_id)
                if conn is None:
                    self._dead_error(connection_id)
                assert conn is not None
                if not self._active_transport(conn):
                    retired = self._retire_locked(connection_id, "lost")
                    if retired is not None:
                        self._close_client(retired.client)
                    self._dead_error(connection_id)
                if conn.active >= self.max_channels:
                    fail("ssh_channel_limit", "SSH connection channel limit reached", 429,
                         {"connection_id": connection_id, "max_channels": self.max_channels})
                conn.active += 1
        try:
            yield conn
        finally:
            with self._lock:
                current = self._live.get(conn.id)
                if current is conn:
                    current.active = max(0, current.active - 1)
                    if current.active == 0:
                        current.last_idle_mono = time.monotonic()

    def mark_lost(self, conn: _Connection):
        retired = None
        with self._lock:
            if self._live.get(conn.id) is conn:
                retired = self._retire_locked(conn.id, "lost")
        if retired is not None:
            self._close_client(retired.client)

    def is_active(self, conn: _Connection) -> bool:
        with self._lock:
            return self._live.get(conn.id) is conn and self._active_transport(conn)

    def close_connection(self, connection_id: str) -> dict[str, Any]:
        retired = None
        with self._lock:
            conn = self._live.get(connection_id)
            if conn is None:
                self._dead_error(connection_id)
            assert conn is not None
            if conn.active:
                fail("ssh_connection_busy", "SSH connection still has active operations", 409,
                     {"connection_id": connection_id, "active_operations": conn.active})
            retired = self._retire_locked(connection_id, "closed")
        assert retired is not None
        self._close_client(retired.client)
        return {"connection_id": connection_id, "state": "closed"}

    def status(self, connection_id: str) -> dict[str, Any]:
        with self.lease(profile_name=None, connection_id=connection_id) as conn:
            with self._lock:
                active = conn.active
            return {
                "connection_id": conn.id, "profile": conn.profile.name, "state": "alive",
                "created_at": conn.created_at, "active_operations": max(0, active - 1),
                "idle_timeout_seconds": self.idle_seconds,
            }

    def close(self):
        self._stop.set()
        reaper = self._reaper
        if reaper is not None and reaper is not threading.current_thread():
            reaper.join(timeout=1)
        with self._lock:
            connections = list(self._live.values())
            self._live.clear()
            for conn in connections:
                self._remember_dead_locked(conn.id, "closed")
        for conn in connections:
            self._close_client(conn.client)


_TARGET = {
    "profile": {"type": "string", "minLength": 1, "maxLength": 128},
    "connection_id": {"type": "string", "minLength": 24, "maxLength": 84},
}
_REMOTE_PATH = {"type": "string", "minLength": 1, "maxLength": MAX_REMOTE_PATH_CHARS}
_LOCAL_PATH = {"type": "string", "minLength": 1, "maxLength": 4096}


class SshRpcPlugin:
    family = "ssh"
    version = 1
    description = (
        "Privileged client-local SSH/SFTP using reusable Paramiko transports. "
        "Credentials remain in the mapping client configuration; connection IDs are process-scoped."
    )
    operations = {
        "profiles": {
            "description": "List configured SSH profile names and non-secret connection metadata. Requires write/control authorization.",
            "write": True, "execution": "sync", "input_schema": object_schema({}),
        },
        "status": {
            "description": "Check and refresh one live reusable SSH connection. Expired/lost/closed IDs return distinct errors.",
            "write": True, "execution": "sync",
            "input_schema": object_schema({"connection_id": _TARGET["connection_id"]}, ("connection_id",)),
        },
        "close": {
            "description": "Explicitly close one idle reusable SSH connection. Busy connections are not interrupted.",
            "write": True, "execution": "sync",
            "input_schema": object_schema({"connection_id": _TARGET["connection_id"]}, ("connection_id",)),
        },
        "stat": {
            "description": "SFTP stat/lstat one remote path. Pass profile to create a connection or connection_id to reuse one.",
            "write": True, "execution": "sync",
            "input_schema": object_schema(
                {**_TARGET, "path": _REMOTE_PATH,
                 "follow_symlinks": {"type": "boolean", "default": False}}, ("path",)),
        },
        "listdir": {
            "description": "List a bounded SFTP directory page. Pass profile to create a connection or connection_id to reuse one.",
            "write": True, "execution": "sync",
            "input_schema": object_schema(
                {**_TARGET, "path": _REMOTE_PATH,
                 "offset": {"type": "integer", "minimum": 0, "default": 0},
                 "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100}},
                ("path",)),
        },
        "read": {
            "description": "Read up to 128 KiB from a remote SFTP file at a byte offset; returns Base64 and UTF-8 text when decodable.",
            "write": True, "execution": "sync",
            "input_schema": object_schema(
                {**_TARGET, "path": _REMOTE_PATH,
                 "offset": {"type": "integer", "minimum": 0, "default": 0},
                 "limit": {"type": "integer", "minimum": 1,
                           "maximum": MAX_REMOTE_READ_BYTES, "default": 65536}},
                ("path",)),
        },
        "exec": {
            "description": "Run one remote shell command as a cancellable task. First use profile; task result returns connection_id for reuse. Never auto-replayed.",
            "write": True, "execution": "task",
            "input_schema": object_schema(
                {**_TARGET,
                 "command": {"type": "string", "minLength": 1, "maxLength": MAX_COMMAND_CHARS},
                 "pty": {"type": "boolean", "default": False}}, ("command",)),
        },
        "upload": {
            "description": "Atomically upload one guarded local mapping file to a remote SFTP path as a task.",
            "write": True, "execution": "task",
            "input_schema": object_schema(
                {**_TARGET, "local_path": _LOCAL_PATH, "remote_path": _REMOTE_PATH,
                 "overwrite": {"type": "boolean", "default": False}},
                ("local_path", "remote_path")),
        },
        "download": {
            "description": "Download one remote SFTP file into the mapping using a local temporary file and atomic publish.",
            "write": True, "execution": "task",
            "input_schema": object_schema(
                {**_TARGET, "remote_path": _REMOTE_PATH, "local_path": _LOCAL_PATH,
                 "overwrite": {"type": "boolean", "default": False},
                 "create_parents": {"type": "boolean", "default": False}},
                ("remote_path", "local_path")),
        },
    }

    def __init__(self, config: dict[str, Any] | None = None, *, paramiko_module: Any | None = None):
        self._config = config or {}
        self._profiles, self._settings = _parse_config(self._config)
        self._pool = _ConnectionPool(self._profiles, self._settings, paramiko_module=paramiko_module)
        self._paramiko_override = paramiko_module

    def probe(self, _config):
        details = {
            "profile_count": len(self._profiles),
            "idle_seconds": self._settings["idle_seconds"],
            "max_connections": self._settings["max_connections"],
            "max_channels_per_connection": self._settings["max_channels_per_connection"],
            "credentials": "client_config_only",
            "connection_ids": "client_process_scoped",
        }
        if not self._profiles:
            return "unsupported", "not_configured", details
        if self._paramiko_override is None and not _installed("paramiko"):
            return "unsupported", "dependency_missing", details
        return "available", None, details

    @staticmethod
    def _require_writable(files):
        if not files.writable:
            fail("mapping_read_only", "SSH RPC requires a writable mapping and control authorization", 403)

    def _sftp_error(self, conn: _Connection, exc: BaseException):
        if not self._pool.is_active(conn):
            self._pool.mark_lost(conn)
            fail("ssh_connection_lost", "SSH connection was lost during SFTP operation", 409,
                 {"connection_id": conn.id})
        if isinstance(exc, OSError):
            if exc.errno == errno.ENOENT:
                fail("ssh_remote_not_found", "remote path does not exist", 404)
            if exc.errno in {errno.EACCES, errno.EPERM}:
                fail("ssh_remote_permission_denied", "remote permission denied", 403)
            if exc.errno == errno.EEXIST:
                fail("ssh_remote_exists", "remote destination already exists", 409)
        fail("ssh_remote_io_failed", "remote SFTP operation failed", 409,
             {"connection_id": conn.id, "error_type": type(exc).__name__})

    def _lease(self, args):
        profile, connection_id = _connection_args(args)
        return self._pool.lease(profile_name=profile, connection_id=connection_id)

    @staticmethod
    def _connection_meta(conn: _Connection) -> dict[str, Any]:
        return {"connection_id": conn.id, "profile": conn.profile.name}

    def dispatch(self, files, operation, args):
        def run():
            self._require_writable(files)
            if operation not in {"profiles", "status", "close", "stat", "listdir", "read"}:
                fail("ssh_operation", "operation requires task execution")
            validate(args, self.operations[operation]["input_schema"])
            if operation == "profiles":
                entries = []
                for profile in sorted(self._profiles.values(), key=lambda item: item.name):
                    auth = []
                    if profile.password is not None:
                        auth.append("password")
                    if profile.key_filename is not None:
                        auth.append("key")
                    if profile.allow_agent:
                        auth.append("agent")
                    if profile.look_for_keys:
                        auth.append("discover_keys")
                    entries.append({
                        "name": profile.name, "host": profile.host, "port": profile.port,
                        "username": profile.username, "authentication": auth,
                        "host_key_policy": profile.host_key_policy,
                        "host_key_pinned": profile.host_key_sha256 is not None,
                    })
                return {"profiles": entries, "total": len(entries)}
            if operation == "status":
                connection_id = args["connection_id"]
                if not _CONNECTION_ID.fullmatch(connection_id):
                    fail("ssh_connection_id_invalid", "connection_id has an invalid format")
                return self._pool.status(connection_id)
            if operation == "close":
                connection_id = args["connection_id"]
                if not _CONNECTION_ID.fullmatch(connection_id):
                    fail("ssh_connection_id_invalid", "connection_id has an invalid format")
                return self._pool.close_connection(connection_id)

            with self._lease(args) as conn:
                try:
                    sftp = conn.client.open_sftp()
                except Exception as exc:
                    self._sftp_error(conn, exc)
                try:
                    if operation == "stat":
                        path = _remote_path(args["path"])
                        attr = sftp.stat(path) if args.get("follow_symlinks", False) else sftp.lstat(path)
                        return {**self._connection_meta(conn), "path": path, **_attr_view(attr)}
                    if operation == "listdir":
                        path = _remote_path(args["path"])
                        offset = args.get("offset", 0)
                        limit = args.get("limit", 100)
                        attrs = sftp.listdir_attr(path)
                        if len(attrs) > MAX_LIST_ENTRIES:
                            fail("ssh_directory_limit", "remote directory contains too many entries", 413,
                                 {"max_entries": MAX_LIST_ENTRIES})
                        attrs.sort(key=lambda item: item.filename)
                        selected = attrs[offset:offset + limit]
                        return {
                            **self._connection_meta(conn), "path": path,
                            "entries": [_attr_view(item, name=item.filename) for item in selected],
                            "offset": offset, "limit": limit, "total": len(attrs),
                            "truncated": offset + limit < len(attrs),
                        }
                    path = _remote_path(args["path"])
                    offset = args.get("offset", 0)
                    limit = args.get("limit", 65536)
                    with sftp.open(path, "rb") as stream:
                        if offset:
                            stream.seek(offset)
                        data = stream.read(limit)
                    body = {
                        **self._connection_meta(conn), "path": path, "offset": offset,
                        "bytes_read": len(data),
                        "data_base64": base64.b64encode(data).decode("ascii"),
                        "eof": len(data) < limit,
                    }
                    try:
                        body["text"] = data.decode("utf-8")
                        body["encoding"] = "utf-8"
                    except UnicodeDecodeError:
                        body["text"] = None
                        body["encoding"] = None
                    return body
                except ApiError:
                    raise
                except Exception as exc:
                    self._sftp_error(conn, exc)
                finally:
                    with contextlib.suppress(Exception):
                        sftp.close()
            raise AssertionError("unreachable")

        return response(run)

    def _exec(self, args, task):
        command = args["command"]
        if "\x00" in command or not command.strip():
            fail("ssh_command_invalid", "command must be a non-empty string without NUL")
        with self._lease(args) as conn:
            transport = conn.client.get_transport()
            if transport is None or not transport.is_active():
                self._pool.mark_lost(conn)
                fail("ssh_connection_lost", "SSH connection was lost before command execution", 409,
                     {"connection_id": conn.id})
            channel = None
            command_sent = False
            stdout_bytes = stderr_bytes = 0
            try:
                task.check_cancelled()
                channel = transport.open_session(timeout=self._settings["connect_timeout_seconds"])
                if args.get("pty", False):
                    channel.get_pty()
                channel.exec_command(command)
                command_sent = True
                while True:
                    task.check_cancelled()
                    progressed = False
                    while channel.recv_ready():
                        data = channel.recv(65536)
                        if not data:
                            break
                        stdout_bytes += len(data)
                        task.write(data)
                        progressed = True
                    while channel.recv_stderr_ready():
                        data = channel.recv_stderr(65536)
                        if not data:
                            break
                        stderr_bytes += len(data)
                        task.write(data)
                        progressed = True
                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        return {**self._connection_meta(conn),
                                "remote_exit_code": channel.recv_exit_status(),
                                "stdout_bytes": stdout_bytes, "stderr_bytes": stderr_bytes}
                    if not transport.is_active():
                        self._pool.mark_lost(conn)
                        fail("ssh_execution_uncertain",
                             "SSH transport was lost after command dispatch; do not automatically replay the command",
                             409, {"connection_id": conn.id, "profile": conn.profile.name,
                                   "command_may_have_completed": command_sent})
                    if not progressed:
                        time.sleep(0.02)
            except ApiError:
                raise
            except OSError as exc:
                if exc.errno == errno.ECANCELED:
                    raise
                if not self._pool.is_active(conn):
                    self._pool.mark_lost(conn)
                    fail("ssh_execution_uncertain" if command_sent else "ssh_connection_lost",
                         "SSH transport failed during command execution", 409,
                         {"connection_id": conn.id, "profile": conn.profile.name,
                          "command_may_have_completed": command_sent})
                fail("ssh_exec_failed", "remote command could not be executed", 409,
                     {"connection_id": conn.id, "error_type": type(exc).__name__})
            except Exception as exc:
                if not self._pool.is_active(conn):
                    self._pool.mark_lost(conn)
                    fail("ssh_execution_uncertain" if command_sent else "ssh_connection_lost",
                         "SSH transport failed during command execution", 409,
                         {"connection_id": conn.id, "profile": conn.profile.name,
                          "command_may_have_completed": command_sent})
                fail("ssh_exec_failed", "remote command could not be executed", 409,
                     {"connection_id": conn.id, "error_type": type(exc).__name__})
            finally:
                if channel is not None:
                    with contextlib.suppress(Exception):
                        channel.close()

    def _upload(self, files, args, task):
        local_path = export_path(files, args["local_path"])
        remote_path = _remote_path(args["remote_path"], label="remote_path")
        overwrite = args.get("overwrite", False)
        with Snapshot(files, local_path) as snap:
            with self._lease(args) as conn:
                try:
                    sftp = conn.client.open_sftp()
                except Exception as exc:
                    self._sftp_error(conn, exc)
                remote_dir, remote_name = posixpath.split(remote_path)
                remote_temp = posixpath.join(
                    remote_dir or ".", f".{remote_name or 'upload'}.openkapsel-put-{secrets.token_hex(12)}")
                written = 0
                try:
                    task.check_cancelled()
                    if not overwrite:
                        try:
                            sftp.lstat(remote_path)
                        except OSError as exc:
                            if exc.errno != errno.ENOENT:
                                raise
                        else:
                            fail("ssh_remote_exists", "remote destination already exists", 409)
                    with sftp.open(remote_temp, "wx") as target:
                        while True:
                            task.check_cancelled()
                            chunk = snap.stream.read(_COPY_CHUNK)
                            if not chunk:
                                break
                            target.write(chunk)
                            written += len(chunk)
                    snap.verify()
                    task.check_cancelled()
                    if overwrite:
                        try:
                            sftp.posix_rename(remote_temp, remote_path)
                        except Exception:
                            if self._pool.is_active(conn):
                                fail("ssh_atomic_replace_unsupported",
                                     "remote server did not accept atomic POSIX rename for overwrite", 409,
                                     {"connection_id": conn.id})
                            self._pool.mark_lost(conn)
                            fail("ssh_transfer_uncertain",
                                 "SSH connection was lost while publishing the uploaded file", 409,
                                 {"connection_id": conn.id, "remote_temp": remote_temp})
                    else:
                        sftp.rename(remote_temp, remote_path)
                    return {**self._connection_meta(conn), "local_path": args["local_path"],
                            "remote_path": remote_path, "bytes_transferred": written,
                            "published": True}
                except ApiError:
                    raise
                except OSError as exc:
                    if exc.errno == errno.ECANCELED:
                        raise
                    if not self._pool.is_active(conn):
                        self._pool.mark_lost(conn)
                        fail("ssh_transfer_uncertain",
                             "SSH connection was lost during upload; final destination was not intentionally replayed",
                             409, {"connection_id": conn.id, "remote_temp": remote_temp})
                    self._sftp_error(conn, exc)
                except Exception as exc:
                    if not self._pool.is_active(conn):
                        self._pool.mark_lost(conn)
                        fail("ssh_transfer_uncertain",
                             "SSH connection was lost during upload; final destination was not intentionally replayed",
                             409, {"connection_id": conn.id, "remote_temp": remote_temp})
                    self._sftp_error(conn, exc)
                finally:
                    with contextlib.suppress(Exception):
                        sftp.remove(remote_temp)
                    with contextlib.suppress(Exception):
                        sftp.close()
        raise AssertionError("unreachable")

    def _download(self, files, args, task):
        remote_path = _remote_path(args["remote_path"], label="remote_path")
        local_path = export_path(files, args["local_path"])
        overwrite = args.get("overwrite", False)
        create_parents = args.get("create_parents", False)
        temp = local_path.with_name(f".{local_path.name}.openkapsel-ssh-{secrets.token_hex(12)}")
        fd = None
        published = False
        with self._lease(args) as conn:
            try:
                sftp = conn.client.open_sftp()
            except Exception as exc:
                self._sftp_error(conn, exc)
            try:
                task.check_cancelled()
                with files.lock:
                    if create_parents:
                        files.paths.mkdir(local_path.parent, parents=True, exist_ok=True)
                    fd = files.paths.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                total = 0
                with os.fdopen(fd, "wb", closefd=True) as target:
                    fd = None
                    with sftp.open(remote_path, "rb") as source:
                        while True:
                            task.check_cancelled()
                            chunk = source.read(_COPY_CHUNK)
                            if not chunk:
                                break
                            target.write(chunk)
                            total += len(chunk)
                    target.flush()
                    os.fsync(target.fileno())
                task.check_cancelled()
                with files.lock:
                    try:
                        files._dispatch("rename", {
                            "path": temp.relative_to(files.root).as_posix(),
                            "destination": local_path.relative_to(files.root).as_posix(),
                            "overwrite": overwrite,
                        })
                    except OSError as exc:
                        if exc.errno == errno.EEXIST:
                            fail("ssh_local_exists", "local destination already exists", 409)
                        raise
                published = True
                with Snapshot(files, local_path) as final:
                    return {**self._connection_meta(conn), "remote_path": remote_path,
                            "local_path": args["local_path"], "bytes_transferred": total,
                            "etag": final.etag, "published": True}
            except ApiError:
                raise
            except OSError as exc:
                if exc.errno == errno.ECANCELED:
                    raise
                if not self._pool.is_active(conn):
                    self._pool.mark_lost(conn)
                    fail("ssh_transfer_interrupted",
                         "SSH connection was lost during download; local destination was not published",
                         409, {"connection_id": conn.id})
                self._sftp_error(conn, exc)
            except Exception as exc:
                if not self._pool.is_active(conn):
                    self._pool.mark_lost(conn)
                    fail("ssh_transfer_interrupted",
                         "SSH connection was lost during download; local destination was not published",
                         409, {"connection_id": conn.id})
                self._sftp_error(conn, exc)
            finally:
                if fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(fd)
                with contextlib.suppress(Exception):
                    sftp.close()
                if not published:
                    with files.lock:
                        with contextlib.suppress(OSError):
                            files._dispatch("unlink", {"path": temp.relative_to(files.root).as_posix()})
        raise AssertionError("unreachable")

    def dispatch_task(self, files, operation, args, task):
        def run():
            self._require_writable(files)
            if operation not in {"exec", "upload", "download"}:
                fail("ssh_operation", "operation is not task-based")
            validate(args, self.operations[operation]["input_schema"])
            _connection_args(args)
            task.check_cancelled()
            if operation == "exec":
                return self._exec(args, task)
            if operation == "upload":
                return self._upload(files, args, task)
            return self._download(files, args, task)

        return response(run)

    def close(self):
        self._pool.close()


# Direct import compatibility; client registry creates a per-runtime instance.
plugin = SshRpcPlugin()

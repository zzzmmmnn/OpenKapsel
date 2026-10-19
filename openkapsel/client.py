"""Outbound mapping provider: python -m openkapsel.client --config client.json."""

from __future__ import annotations

import argparse
import hashlib
import errno
import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

from openkapsel.client_runtime.client_config import ClientConfigError, ClientConfigLock
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_rpc import ClientRpcSession
from openkapsel.execution.function_registry import FunctionRegistry
from openkapsel.execution.builtin_functions import register_client_shell
from openkapsel.network.proxy import (
    connect_proxy_tunnel,
    parse_proxy_url,
    wrap_tls_stream,
)
from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.rpc_plugins import load_client_rpc_registry
from openkapsel.mapping.mapping_transport import (
    MAPPING_HANDSHAKE_VERSION,
    MAX_MESSAGE,
    encode,
)
from openkapsel.source_fingerprint import running_fingerprint, version_at_least
from openkapsel.client_runtime.client_reload import (
    LOCAL_REFRESH_SECONDS,
    ClientReloadState,
    GitPullGate,
    exec_local_source,
    inspect_local_source,
    local_source_can_satisfy,
)

LOG = logging.getLogger("openkapsel.client")
HEARTBEAT_SECONDS = 10.0
RECONNECT_DELAYS = (1, 3, 5, 10, 20)


def _reconnect_delay(disconnect_count):
    if disconnect_count < 1:
        raise ValueError("disconnect_count must be >= 1")
    return RECONNECT_DELAYS[min(disconnect_count, len(RECONNECT_DELAYS)) - 1]


class ClientReloadRequired(RuntimeError):
    def __init__(self, source, *, required: bool):
        super().__init__("mapping client source reload required")
        self.source = source
        self.required = required


class ClientVersionRequired(RuntimeError):
    def __init__(self, minimum_version: str):
        super().__init__(f"mapping server requires client >= {minimum_version}")
        self.minimum_version = minimum_version


class ClientProtocolRequired(RuntimeError):
    def __init__(self, handshake_version: int):
        super().__init__(f"mapping server requires handshake version {handshake_version}")
        self.handshake_version = handshake_version


def proxy_options(url, *, target_url=None, timeout=60):
    proxy = parse_proxy_url(url)
    if proxy is None:
        return {"http_no_proxy": ["*"]}
    if target_url is None:
        raise ValueError("target_url is required when a proxy is configured")
    target = urlsplit(target_url)
    if target.scheme not in {"ws", "wss"} or not target.hostname:
        raise ValueError("target_url must be a ws/wss URL with a host")
    try:
        target_port = target.port
    except ValueError as exc:
        raise ValueError("target_url has an invalid port") from exc
    if target_port is None:
        target_port = 443 if target.scheme == "wss" else 80
    timeout = float(timeout)
    tunnel = connect_proxy_tunnel(
        proxy,
        target.hostname,
        target_port,
        timeout=timeout,
    )
    if target.scheme == "wss":
        tunnel = wrap_tls_stream(
            tunnel,
            server_hostname=target.hostname,
            timeout=timeout,
        )
    return {
        "socket": tunnel,
        "http_no_proxy": ["*"],
        # A target-specific preconnected proxy tunnel cannot be reused safely
        # for an arbitrary redirect target.
        "redirect_limit": 0,
    }


class ClientRuntime:
    """Own transport sessions while Manager-backed jobs outlive this process."""
    def __init__(self, config, *, protected_paths=()):
        from openkapsel.client_runtime.job_backend import JobBackend
        self.config = json.loads(json.dumps(config))
        self.files, self.tasks = _create_resources(
            self.config, protected_paths=protected_paths
        )
        self.tasks: JobBackend
        self.functions = FunctionRegistry()
        register_client_shell(self.functions, self.tasks)
        from openkapsel.client_runtime.file_approval import register_file_functions
        register_file_functions(self.functions, self.files)
        self.client_fingerprint = running_fingerprint("client")
        self.pending_reload = False
        self.git_pull = (
            GitPullGate(_source_root(self.config))
            if self.config.get("auto_git_pull") is True else None
        )
        self.rpc_slots = threading.BoundedSemaphore(32)
        self.rpc_lock = threading.Lock()
        self.rpc_active = 0
        self.files.full_approval_active = self.full_approval_active
        self.tasks.full_approval_active = self.full_approval_active
        if hasattr(self.tasks, "legacy"):
            self.tasks.legacy.full_approval_active = self.full_approval_active

    def set_full_approval(self, seconds):
        """Server-admin-granted, volatile scope; monotonic expiry."""
        if type(seconds) is not int or seconds not in {0, 1800, 7200, 28800, 86400}:
            raise ValueError("invalid approval duration")
        with self.rpc_lock:
            self._full_approval_deadline = (
                time.monotonic() + seconds if seconds else 0.0
            )
        return {"active": bool(seconds), "duration_seconds": seconds}

    def full_approval_active(self):
        with self.rpc_lock:
            return time.monotonic() < getattr(self, "_full_approval_deadline", 0.0)

    def has_active_tasks(self):
        with self.rpc_lock:
            if self.rpc_active:
                return True
        return self.tasks.has_active_jobs()

    def close(self):
        self.set_full_approval(0)
        if self.git_pull is not None:
            self.git_pull.close()
        try:
            self.tasks.close()
        finally:
            self.files.close()


def _create_resources(config, *, protected_paths=()):
    url = config["url"]
    parsed = urlsplit(url)
    if parsed.scheme not in {"wss", "ws"} or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("url must be the mapping WebSocket URL without credentials")
    if parsed.scheme == "ws" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("remote mapping connections require wss")
    if not isinstance(config.get("token"), str) or not config["token"] or any(c.isspace() for c in config["token"]):
        raise ValueError("a mapping token is required")
    for key in ("writable", "allow_exec", "sandbox", "network"):
        if key in config and not isinstance(config[key], bool):
            raise ValueError(f"{key} must be a boolean")
    ssh_config = config.get("ssh")
    rpc_config = config.get("rpc")
    if isinstance(rpc_config, dict):
        ssh_entry = rpc_config.get("ssh")
        if isinstance(ssh_entry, dict):
            ssh_config = ssh_entry.get("config", {}) if ssh_entry.get("enabled") is True else None
        elif ssh_entry is not True:
            ssh_config = None
    transport_timeout = config.get("transport_timeout_seconds", 60)
    if (
        isinstance(transport_timeout, bool)
        or not isinstance(transport_timeout, (int, float))
        or not 10 <= float(transport_timeout) <= 600
    ):
        raise ValueError("transport_timeout_seconds must be between 10 and 600 seconds")
    if "auto_reload" in config and not isinstance(config["auto_reload"], bool):
        raise ValueError("auto_reload must be a boolean")
    if "auto_git_pull" in config and not isinstance(config["auto_git_pull"], bool):
        raise ValueError("auto_git_pull must be a boolean")
    if config.get("auto_git_pull") and not config.get("auto_reload"):
        raise ValueError("auto_git_pull requires auto_reload=true")
    if "source_root" in config:
        if not isinstance(config["source_root"], str) or not config["source_root"].strip():
            raise ValueError("source_root must be a non-empty absolute path")
        source_root = Path(config["source_root"]).expanduser()
        if not source_root.is_absolute():
            raise ValueError("source_root must be an absolute path")
    export_root = Path(config["root"]).expanduser().resolve(strict=True)
    for protected in protected_paths:
        protected_path = Path(protected).expanduser().resolve(strict=False)
        try:
            protected_path.relative_to(export_root)
        except ValueError:
            continue
        raise ValueError(
            "active client configuration must be outside the exported mapping root"
        )
    rpc_registry = load_client_rpc_registry(config)
    rpc_capabilities = rpc_registry.capability_map(config)
    extensions = []
    for family in sorted(rpc_registry.families):
        capability = rpc_capabilities.get(family)
        if capability is None:
            continue
        extensions.append(
            f"{family} v{capability['version']} ({capability['state']})"
        )
    LOG.info("Loaded RPC extensions: %s", ", ".join(extensions) or "none")
    file_class = ClientFiles
    if os.name == "nt":
        from openkapsel.client_runtime.client_windows import WindowsClientFiles
        file_class = WindowsClientFiles
    files = file_class(
        config["root"],
        writable=config.get("writable", False),
        rpc_capabilities=rpc_capabilities,
        rpc_registry=rpc_registry,
        protected_paths=protected_paths,
    )
    if sys.platform.startswith("linux") or os.name == "nt":
        from openkapsel.files.filename_index import FilenameIndex
        from openkapsel.files.filename_index import watcher_available
        canonical_root = str(export_root).casefold() if os.name == "nt" else str(export_root)
        root_key = hashlib.sha256(canonical_root.encode("utf-8")).hexdigest()[:24]
        if protected_paths:
            state_dir = Path(protected_paths[0]).expanduser().resolve().parent / ".openkapsel-client-state"
        elif os.name == "nt":
            # An exported workspace must not contain its private search cache.
            state_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "OpenKapsel" / "state"
        else:
            state_dir = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "openkapsel"
        try:
            if watcher_available():
                files.filename_index = FilenameIndex(export_root, state_dir / f"files-{root_key}.sqlite3")
                files.filename_index.start()
        except (OSError, ValueError) as exc:
            LOG.warning("Local filename index unavailable; recursive search will be used: %s", exc)
            files.filename_index = None
    limits = config.get("limits", {})
    if not isinstance(limits, dict) or set(limits) - {"max_tasks", "max_seconds", "memory_mb", "processes", "cpus"}:
        raise ValueError("invalid client limits")
    from openkapsel.client_runtime.job_sandbox_config import make_job_sandbox
    job_sandbox = make_job_sandbox(config, files, protected_paths=protected_paths)
    if job_sandbox is not None:
        from types import SimpleNamespace
        files.sandbox_denied_paths = frozenset(
            Path(path) for path in job_sandbox["hidden_paths"]
        )
        files.sandbox_path_rules = tuple(SimpleNamespace(path=item["path"], access=item["access"])
            for item in (*job_sandbox["allowed_paths"], *job_sandbox["pattern_rules"]))
    is_mapping = urlsplit(config["url"]).path.rstrip("/").split("/")[-2:-1] == ["mapping-connect"]
    if job_sandbox is not None and not is_mapping:
        raise ValueError("job_sandbox requires a mapping-connect Client")
    # Interpret only literal, in-scope file commands without approval on Windows.
    # Every other Windows Shell invocation requires explicit approval.
    from types import SimpleNamespace
    powershell_rules = (
        tuple(SimpleNamespace(path=item["path"], access=item["access"])
              for item in (*job_sandbox["allowed_paths"], *job_sandbox["pattern_rules"]))
        + tuple(SimpleNamespace(path=path, access="deny")
                for path in job_sandbox["hidden_paths"])
        if os.name == "nt" and job_sandbox is not None else ()
    )
    tasks = ClientTasks(files, enabled=config.get("allow_exec", False),
                        sandbox=(config.get("sandbox", True)
                                 if job_sandbox is None and os.name != "nt" else False),
                        managed_sandbox=job_sandbox is not None or os.name == "nt",
                        approval_only=os.name == "nt",
                        powershell_rules=powershell_rules,
                        backend=config.get("backend", "podman"), image=config.get("image", "docker.io/library/python:3.14-slim-trixie"),
                        network=config.get("network", False),
                        git_network_mode=(job_sandbox["network_mode"] if job_sandbox else "full"),
                        git_allowed_domains=(job_sandbox["allowed_domains"] if job_sandbox else ()),
                        **limits)
    from openkapsel.client_runtime.shared_job_tasks import SharedClientTasks
    if is_mapping:
        tasks = SharedClientTasks(tasks, url=config["url"], job_sandbox=job_sandbox)
    if tasks.enabled and not tasks.sandbox and job_sandbox is None:
        if isinstance(ssh_config, dict) and ssh_config.get("profiles"):
            LOG.warning(
                "Sandbox explicitly disabled while SSH profiles are configured: "
                "remote tasks have this OS account's host permissions and may read "
                "client configuration or referenced SSH credentials"
            )
        else:
            LOG.warning(
                "Sandbox explicitly disabled: remote tasks have this OS account's host permissions"
            )
    return files, tasks


def _recv_message(sock):
    data = sock.recv()
    if not data:
        raise ConnectionError("mapping provider disconnected during handshake")
    if not isinstance(data, str) or len(data.encode("utf-8")) > MAX_MESSAGE:
        raise ValueError("invalid mapping handshake message")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("mapping handshake message must be an object")
    return value


def _server_hello(value):
    if value.get("type") != "server_hello":
        raise ValueError("mapping server_hello required")
    handshake_version = value.get("handshake_version")
    server_version = value.get("server_version")
    server_fingerprint = value.get("server_fingerprint")
    minimum = value.get("minimum_client_version")
    timeout = value.get("hello_timeout_seconds")
    if (
        isinstance(handshake_version, bool)
        or not isinstance(handshake_version, int)
        or not 1 <= handshake_version <= 65535
    ):
        raise ValueError("invalid mapping handshake version")
    if not isinstance(server_version, str) or not isinstance(minimum, str):
        raise ValueError("invalid mapping server version")
    # Parsing both also rejects malformed version strings.
    version_at_least(server_version, "0.0.0")
    version_at_least(minimum, "0.0.0")
    if not isinstance(server_fingerprint, str) or len(server_fingerprint) != 44:
        raise ValueError("invalid mapping server fingerprint")
    import base64, binascii
    try:
        digest = base64.b64decode(server_fingerprint, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("invalid mapping server fingerprint") from None
    if len(digest) != 32:
        raise ValueError("invalid mapping server fingerprint")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
        raise ValueError("invalid mapping hello timeout")
    return handshake_version, server_fingerprint, minimum


def _source_root(config):
    from openkapsel.source_fingerprint import project_root
    return (Path(config["source_root"]).expanduser().resolve()
            if config.get("source_root") else project_root())


def _pull_before_reload(runtime):
    gate = getattr(runtime, "git_pull", None)
    return gate is None or gate.start()


def _check_completed_pull(config, runtime, minimum_version):
    gate = getattr(runtime, "git_pull", None)
    if gate is None or not gate.ready.is_set():
        return False
    source = inspect_local_source(config)
    if (source is None or source.fingerprint == runtime.client_fingerprint
            or not local_source_can_satisfy(
                source, minimum_version, MAPPING_HANDSHAKE_VERSION)):
        gate.reset()
        return False
    runtime.pending_reload = True
    if runtime.has_active_tasks():
        LOG.info("Deferring Git-updated client reload until active tasks drain")
    else:
        LOG.info("Git-updated client source is ready for reload")
    return True


def _reload_decision(
    config,
    runtime,
    reload_state,
    server_handshake_version,
    server_fingerprint,
    minimum_version,
):
    protocol_mismatch = server_handshake_version != MAPPING_HANDSHAKE_VERSION
    below_minimum = not version_at_least(__version__, minimum_version)
    source = None
    if protocol_mismatch or below_minimum:
        # A required upgrade cannot become READY, but Git can already retry
        # while existing tasks are finishing in the old runtime.
        pull_ready = _pull_before_reload(runtime)
        # Preserve already-running client tasks until they drain.
        if runtime.has_active_tasks():
            if protocol_mismatch:
                raise ClientProtocolRequired(server_handshake_version)
            raise ClientVersionRequired(minimum_version)
        if pull_ready:
            source = inspect_local_source(config)
            if (
                local_source_can_satisfy(
                    source, minimum_version, server_handshake_version
                )
                and source.fingerprint != runtime.client_fingerprint
            ):
                raise ClientReloadRequired(source, required=True)
        if protocol_mismatch:
            raise ClientProtocolRequired(server_handshake_version)
        raise ClientVersionRequired(minimum_version)

    if reload_state is None:
        return

    server_changed = (
        reload_state.last_server_fingerprint is not None
        and reload_state.last_server_fingerprint != server_fingerprint
    )
    refresh_due = time.time() - reload_state.last_source_check_at >= LOCAL_REFRESH_SECONDS
    gate = getattr(runtime, "git_pull", None)
    inspect = (runtime.pending_reload or server_changed or refresh_due
               or (gate is not None and gate.ready.is_set()))
    if not inspect:
        return
    if gate is not None:
        if not gate.ready.is_set():
            gate.start()
            if server_changed or refresh_due:
                reload_state.mark_source_checked()
            # The handshake may still complete using compatible running code.
            return
        if not _check_completed_pull(config, runtime, minimum_version):
            return
    source = inspect_local_source(config)
    reload_state.mark_source_checked()
    if (
        source is None
        or source.fingerprint == runtime.client_fingerprint
        or not local_source_can_satisfy(
            source, minimum_version, MAPPING_HANDSHAKE_VERSION
        )
    ):
        runtime.pending_reload = False
        return
    if runtime.has_active_tasks():
        runtime.pending_reload = True
        LOG.info("Deferring optional client source reload until active tasks drain")
        return
    raise ClientReloadRequired(source, required=False)


def _periodic_reload_check(config, runtime, reload_state, minimum_version):
    if reload_state is None or runtime.pending_reload:
        return runtime.pending_reload
    gate = getattr(runtime, "git_pull", None)
    if gate is not None:
        if gate.ready.is_set():
            return _check_completed_pull(config, runtime, minimum_version)
        if gate.thread is not None:
            # Git retries are entirely background; keep sending heartbeats.
            return False
        if time.time() - reload_state.last_source_check_at < LOCAL_REFRESH_SECONDS:
            return False
        reload_state.mark_source_checked()
        gate.start()
        return False
    if time.time() - reload_state.last_source_check_at < LOCAL_REFRESH_SECONDS:
        return False
    source = inspect_local_source(config)
    reload_state.mark_source_checked()
    if (
        source is None
        or source.fingerprint == runtime.client_fingerprint
        or not local_source_can_satisfy(
            source, minimum_version, MAPPING_HANDSHAKE_VERSION
        )
    ):
        return False
    runtime.pending_reload = True
    if runtime.has_active_tasks():
        LOG.info("Deferring periodic client source reload until active tasks drain")
    else:
        LOG.info("Updated client source detected; reconnecting to reload")
    return True


def _capabilities(files, tasks, functions=None):
    capabilities = {
        "file_stream": {"version": 1, "descriptor_stat": True, "directory_details": True,
                        "search_prefix": True, "external_root_file_api": True,
                        "external_realpath": True},
        "protocol": 1,
        "temporary_full_approval": True,
        "writable": files.writable,
        "rpc": files.rpc_capabilities,
        "execution": tasks.capabilities(),
    }
    if functions is not None:
        capabilities["functions"] = functions.describe()
    return capabilities


def run_once(config, stop=None, *, runtime=None, reload_state=None, on_ready=None):
    import websocket
    stop = stop or threading.Event()
    owned = runtime is None
    runtime = runtime or ClientRuntime(config)
    if runtime.config != config:
        raise ValueError("runtime belongs to a different client configuration")
    files, tasks = runtime.files, runtime.tasks
    url = runtime.config["url"]
    sock = None
    stopped = threading.Event()
    session = None
    try:
        transport_timeout = float(config.get("transport_timeout_seconds", 60))
        sock = websocket.create_connection(
            url,
            header={"Authorization": "Bearer " + config["token"]},
            suppress_origin=True,
            timeout=transport_timeout,
            **proxy_options(
                config.get("proxy"), target_url=url, timeout=transport_timeout
            ),
        )
        server_handshake_version, server_fingerprint, minimum_version = _server_hello(
            _recv_message(sock)
        )
        _reload_decision(
            config,
            runtime,
            reload_state,
            server_handshake_version,
            server_fingerprint,
            minimum_version,
        )
        sock.send(encode({
            "type": "client_hello",
            "handshake_version": MAPPING_HANDSHAKE_VERSION,
            "client_version": __version__,
            "client_fingerprint": runtime.client_fingerprint,
            "capabilities": _capabilities(files, tasks, getattr(runtime, "functions", None)),
        }).decode())
        ready = _recv_message(sock)
        if ready != {"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION}:
            raise ValueError("mapping server did not confirm READY")
        if on_ready is not None:
            on_ready()
        runtime.pending_reload = False
        if reload_state is not None:
            reload_state.mark_ready(server_fingerprint)
        LOG.info("Mapping provider connected and READY")
        def heartbeat():
            try:
                while not stopped.wait(HEARTBEAT_SECONDS):
                    _periodic_reload_check(config, runtime, reload_state, minimum_version)
                    if runtime.pending_reload and not runtime.has_active_tasks():
                        break
                    sock.ping("keepalive")
            except websocket.WebSocketConnectionClosedException:
                if not stopped.is_set():
                    LOG.info("Mapping heartbeat detected closed connection")
            except Exception as exc:
                if not stopped.is_set():
                    LOG.warning("Mapping heartbeat failed (%s)", type(exc).__name__)
            finally:
                if not stopped.is_set():
                    # On Windows, closing a socket from another thread does not
                    # reliably wake a blocking recv(). websocket-client 1.9.x
                    # WebSocket.shutdown() only closes the raw socket, so abort
                    # both directions first to force the receive loop to return.
                    raw_sock = getattr(sock, "sock", None)
                    if raw_sock is not None:
                        try:
                            raw_sock.shutdown(socket.SHUT_RDWR)
                        except (OSError, AttributeError):
                            pass
                    try:
                        shutdown = getattr(sock, "shutdown", None)
                        if callable(shutdown):
                            shutdown()
                        else:
                            sock.close()
                    except (OSError, websocket.WebSocketException):
                        pass
        session = ClientRpcSession(runtime, sock, stopped)
        threading.Thread(target=heartbeat, daemon=True).start()
        while not stop.is_set():
            try:
                data = sock.recv()
            except websocket.WebSocketTimeoutException:
                LOG.info("Mapping provider receive timed out")
                break
            if not data:
                LOG.info("Mapping provider disconnected")
                break
            if len(data) > MAX_MESSAGE:
                raise ValueError("mapping request exceeds limit")
            request = json.loads(data)
            if not isinstance(request, dict) or not isinstance(request.get("id"), str):
                raise ValueError("invalid mapping request")
            session.submit(request)

    except websocket.WebSocketConnectionClosedException:
        LOG.info("Mapping provider disconnected")
    finally:
        stopped.set()
        if session is not None:
            session.close()
        # Never retain an administrative grant across transport generations.
        runtime.set_full_approval(0)
        if owned:
            runtime.close()
        if sock:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true", help="do not reconnect")
    parser.add_argument("--stop-manager", action="store_true",
                        help="stop the shared Job Manager if idle (requires exclusive config ownership)")
    parser.add_argument("--force", action="store_true",
                        help="with --stop-manager, kill every Manager job before exit")
    options = parser.parse_args()
    if options.force and not options.stop_manager:
        parser.error("--force requires --stop-manager")
    if options.once and options.stop_manager:
        parser.error("--once cannot be combined with --stop-manager")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    options.config = options.config.expanduser().resolve()
    try:
        config_lock = ClientConfigLock.acquire(options.config)
    except (ClientConfigError, OSError) as exc:
        parser.error(str(exc))
    config = config_lock.config
    try:
        if options.stop_manager:
            # The same config's normal Client process holds this exclusive
            # lock for its lifetime. Do not stop its shared Manager while a
            # competing instance still owns this configuration.
            from openkapsel.job_manager import shutdown, state_home
            try:
                result = shutdown(state_home(), force=options.force)
            except (OSError, ConnectionError, EOFError) as exc:
                parser.error(f"Job Manager is not available: {type(exc).__name__}: {exc}")
            print(json.dumps(result, ensure_ascii=False))
            if not result["stopping"]:
                raise SystemExit(2)
            return
        reload_state = ClientReloadState(options.config)
        # Every process start loads code afresh. It also initializes the periodic
        # trusted-source check used by healthy long-lived provider connections.
        os.environ.pop("OPENKAPSEL_CLIENT_RELOADED", None)
        reload_state.mark_process_reload()
        runtime = ClientRuntime(config, protected_paths=(options.config,))
        disconnect_count = 0

        def reset_disconnect_count():
            nonlocal disconnect_count
            disconnect_count = 0

        try:
            while True:
                try:
                    run_once(
                        config,
                        runtime=runtime,
                        reload_state=reload_state,
                        on_ready=reset_disconnect_count,
                    )
                except ClientReloadRequired as exc:
                    delay = reload_state.next_required_delay() if exc.required else 0
                    LOG.info(
                        "Reloading client source %s%s",
                        exc.source.root,
                        f" after {delay}s" if delay else "",
                    )
                    if options.once:
                        raise SystemExit(1) from None
                    if delay:
                        time.sleep(delay)
                    runtime.close()
                    config_fd = config_lock.exec_descriptor()
                    try:
                        exec_local_source(
                            exc.source,
                            options.config,
                            config_sha256=config_lock.sha256,
                            config_fd=config_fd,
                        )
                    finally:
                        config_lock.restore_noninheritable()
                except ClientVersionRequired as exc:
                    delay = reload_state.next_required_delay()
                    LOG.warning(
                        "Client %s is below required %s; rechecking in %ss",
                        __version__, exc.minimum_version, delay,
                    )
                    if options.once:
                        raise SystemExit(1) from None
                    if delay:
                        time.sleep(delay)
                    continue
                except ClientProtocolRequired as exc:
                    delay = reload_state.next_required_delay()
                    LOG.warning(
                        "Client mapping handshake %s is incompatible with required %s; "
                        "rechecking local source in %ss",
                        MAPPING_HANDSHAKE_VERSION,
                        exc.handshake_version,
                        delay,
                    )
                    if options.once:
                        raise SystemExit(1) from None
                    if delay:
                        time.sleep(delay)
                    continue
                except Exception as exc:
                    # Transport exceptions can contain URL/proxy credentials.
                    LOG.warning("Provider connection ended (%s)", type(exc).__name__)
                    if options.once:
                        raise SystemExit(1) from None
                if options.once:
                    return
                disconnect_count += 1
                delay = _reconnect_delay(disconnect_count)
                LOG.info("Reconnecting mapping provider in %ss", delay)
                time.sleep(delay)
        except KeyboardInterrupt:
            return
        finally:
            runtime.close()
    finally:
        config_lock.close()


if __name__ == "__main__":
    main()

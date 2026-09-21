"""Outbound mapping provider: python -m openkapsel.client --config client.json."""

from __future__ import annotations

import argparse
import errno
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import __version__

from .client_files import ClientFiles
from .client_tasks import ClientTasks
from .rpc_plugins import load_client_rpc_registry
from .mapping_transport import (
    MAPPING_HANDSHAKE_VERSION,
    MAX_MESSAGE,
    encode,
)
from .source_fingerprint import running_fingerprint, version_at_least
from .client_reload import (
    LOCAL_REFRESH_SECONDS,
    ClientReloadState,
    exec_local_source,
    inspect_local_source,
    local_source_can_satisfy,
)

LOG = logging.getLogger("openkapsel.client")


class ClientReloadRequired(RuntimeError):
    def __init__(self, source, *, required: bool):
        super().__init__("mapping client source reload required")
        self.source = source
        self.required = required


class ClientVersionRequired(RuntimeError):
    def __init__(self, minimum_version: str):
        super().__init__(f"mapping server requires client >= {minimum_version}")
        self.minimum_version = minimum_version


def proxy_options(url):
    if not url:
        return {"http_no_proxy": ["*"]}
    parsed = urlsplit(url)
    if parsed.scheme not in {"socks4", "socks4a", "socks5", "socks5h", "http"} or not parsed.hostname or not parsed.port:
        raise ValueError("proxy must be an http/socks4/socks5 URL with host and port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("proxy URL cannot include a path, query, or fragment")
    options = {"http_proxy_host": parsed.hostname, "http_proxy_port": parsed.port,
               "proxy_type": parsed.scheme, "http_no_proxy": ["never-bypass-proxy.invalid"]}
    if parsed.username is not None:
        options["http_proxy_auth"] = (unquote(parsed.username), unquote(parsed.password or ""))
    return options


class ClientRuntime:
    """Own tasks across transport sessions, bound to one immutable configuration."""
    def __init__(self, config):
        self.config = json.loads(json.dumps(config))
        self.files, self.tasks = _create_resources(self.config)
        self.client_fingerprint = running_fingerprint("client")
        self.pending_reload = False

    def has_active_tasks(self):
        with self.tasks.lock:
            return any(task["finished_at"] is None for task in self.tasks.tasks.values())

    def close(self):
        try:
            self.tasks.close()
        finally:
            self.files.close()


def _create_resources(config):
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
    transport_timeout = config.get("transport_timeout_seconds", 60)
    if (
        isinstance(transport_timeout, bool)
        or not isinstance(transport_timeout, (int, float))
        or not 10 <= float(transport_timeout) <= 600
    ):
        raise ValueError("transport_timeout_seconds must be between 10 and 600 seconds")
    if "auto_reload" in config and not isinstance(config["auto_reload"], bool):
        raise ValueError("auto_reload must be a boolean")
    if "source_root" in config:
        if not isinstance(config["source_root"], str) or not config["source_root"].strip():
            raise ValueError("source_root must be a non-empty absolute path")
        source_root = Path(config["source_root"]).expanduser()
        if not source_root.is_absolute():
            raise ValueError("source_root must be an absolute path")
    rpc_registry = load_client_rpc_registry(config)
    rpc_capabilities = rpc_registry.capability_map(config)
    extensions = []
    for family in sorted(rpc_registry.families):
        capability = rpc_capabilities[family]
        extensions.append(
            f"{family} v{capability['version']} ({capability['state']})"
        )
    LOG.info("Loaded RPC extensions: %s", ", ".join(extensions) or "none")
    file_class = ClientFiles
    if os.name == "nt":
        from .client_windows import WindowsClientFiles
        file_class = WindowsClientFiles
    files = file_class(
        config["root"],
        writable=config.get("writable", False),
        rpc_capabilities=rpc_capabilities,
        rpc_registry=rpc_registry,
    )
    limits = config.get("limits", {})
    if not isinstance(limits, dict) or set(limits) - {"max_tasks", "max_seconds", "memory_mb", "processes", "cpus"}:
        raise ValueError("invalid client limits")
    tasks = ClientTasks(files, enabled=config.get("allow_exec", False), sandbox=config.get("sandbox", True),
                        backend=config.get("backend", "podman"), image=config.get("image", "docker.io/library/python:3.14-slim-trixie"),
                        network=config.get("network", False), **limits)
    if tasks.enabled and not tasks.sandbox:
        LOG.warning("Sandbox explicitly disabled: remote tasks have this OS account's host permissions")
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
    if value.get("handshake_version") != MAPPING_HANDSHAKE_VERSION:
        raise ValueError("unsupported mapping handshake version")
    server_version = value.get("server_version")
    server_fingerprint = value.get("server_fingerprint")
    minimum = value.get("minimum_client_version")
    timeout = value.get("hello_timeout_seconds")
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
    return server_fingerprint, minimum


def _reload_decision(config, runtime, reload_state, server_fingerprint, minimum_version):
    below_minimum = not version_at_least(__version__, minimum_version)
    source = None
    if below_minimum:
        # A required upgrade never makes an incompatible runtime READY. Preserve
        # already-running client tasks by remaining offline until they drain.
        if runtime.has_active_tasks():
            raise ClientVersionRequired(minimum_version)
        source = inspect_local_source(config)
        if (
            local_source_can_satisfy(source, minimum_version)
            and source.fingerprint != runtime.client_fingerprint
        ):
            raise ClientReloadRequired(source, required=True)
        raise ClientVersionRequired(minimum_version)

    if reload_state is None:
        return

    server_changed = (
        reload_state.last_server_fingerprint is not None
        and reload_state.last_server_fingerprint != server_fingerprint
    )
    refresh_due = time.time() - reload_state.last_reload_at >= LOCAL_REFRESH_SECONDS
    inspect = runtime.pending_reload or server_changed or refresh_due
    if not inspect:
        return
    source = inspect_local_source(config)
    if (
        source is None
        or source.fingerprint == runtime.client_fingerprint
        or not local_source_can_satisfy(source, minimum_version)
    ):
        runtime.pending_reload = False
        return
    if runtime.has_active_tasks():
        runtime.pending_reload = True
        LOG.info("Deferring optional client source reload until active tasks drain")
        return
    raise ClientReloadRequired(source, required=False)


def _capabilities(files, tasks):
    capabilities = {
        "file_stream": {"version": 1, "descriptor_stat": True, "directory_details": True,
                        "search_prefix": True},
        "protocol": 1,
        "writable": files.writable,
        "rpc": files.rpc_capabilities,
        "execution": tasks.capabilities(),
    }
    capabilities["file_api"] = {
        "version": files.rpc_capabilities["file"]["version"],
        "operations": files.rpc_capabilities["file"]["operations"],
    }
    if files.rpc_capabilities["git"]["state"] == "available":
        capabilities["git_api"] = {
            "version": files.rpc_capabilities["git"]["version"],
            "read_only": True,
        }
    return capabilities


def run_once(config, stop=None, *, runtime=None, reload_state=None):
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
    try:
        sock = websocket.create_connection(
            url,
            header={"Authorization": "Bearer " + config["token"]},
            suppress_origin=True,
            timeout=float(config.get("transport_timeout_seconds", 60)),
            **proxy_options(config.get("proxy")),
        )
        server_fingerprint, minimum_version = _server_hello(_recv_message(sock))
        _reload_decision(
            config, runtime, reload_state, server_fingerprint, minimum_version
        )
        sock.send(encode({
            "type": "client_hello",
            "handshake_version": MAPPING_HANDSHAKE_VERSION,
            "client_version": __version__,
            "client_fingerprint": runtime.client_fingerprint,
            "capabilities": _capabilities(files, tasks),
        }).decode())
        ready = _recv_message(sock)
        if ready != {"type": "ready", "handshake_version": MAPPING_HANDSHAKE_VERSION}:
            raise ValueError("mapping server did not confirm READY")
        runtime.pending_reload = False
        if reload_state is not None:
            reload_state.mark_ready(server_fingerprint)
        LOG.info("Mapping provider connected and READY")
        def heartbeat():
            while not stopped.wait(10):
                if runtime.pending_reload and not runtime.has_active_tasks():
                    sock.close()
                    return
                try:
                    sock.ping("keepalive")
                except (OSError, websocket.WebSocketException):
                    return
        threading.Thread(target=heartbeat, daemon=True).start()
        while not stop.is_set():
            data = sock.recv()
            if not data:
                break
            if len(data) > MAX_MESSAGE:
                raise ValueError("mapping request exceeds limit")
            request = json.loads(data)
            if not isinstance(request, dict) or not isinstance(request.get("id"), str):
                raise ValueError("invalid mapping request")
            op, args = request.get("op"), request.get("args")
            try:
                if not isinstance(op, str) or not isinstance(args, dict):
                    raise OSError(errno.EINVAL, "invalid operation")
                result = tasks.dispatch(op, args) if op.startswith("task_") else files.dispatch(op, args)
                response = {"id": request["id"], "result": result}
                encode(response)
            except (OSError, ValueError, KeyError, TypeError, OverflowError) as exc:
                response = {"id": request["id"], "error": {"errno": getattr(exc, "errno", None) or errno.EINVAL}}
            sock.send(encode(response).decode())
    except websocket.WebSocketConnectionClosedException:
        LOG.info("Mapping provider disconnected")
    finally:
        stopped.set()
        if owned:
            tasks.close()
        files.close()
        if sock:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true", help="do not reconnect")
    options = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    options.config = options.config.expanduser().resolve()
    config = json.loads(options.config.read_text())
    if os.name != "nt" and options.config.stat().st_mode & 0o077:
        parser.error("client configuration contains credentials: chmod 600 it first")
    reload_state = ClientReloadState(options.config)
    # Every process start loads code afresh, whether caused by our exec, a
    # service restart, or an operator. Use that as the 24-hour refresh origin.
    os.environ.pop("OPENKAPSEL_CLIENT_RELOADED", None)
    reload_state.mark_process_reload()
    runtime = ClientRuntime(config)
    try:
        while True:
            try:
                run_once(config, runtime=runtime, reload_state=reload_state)
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
                exec_local_source(exc.source, options.config)
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
            except Exception as exc:
                # Transport exceptions can contain URL/proxy credentials.
                LOG.warning("Provider connection ended (%s)", type(exc).__name__)
                if options.once:
                    raise SystemExit(1) from None
            if options.once:
                return
            time.sleep(5)
    except KeyboardInterrupt:
        return
    finally:
        runtime.close()


if __name__ == "__main__":
    main()

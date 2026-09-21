"""Outbound mapping provider: python -m openkapsel.client --config client.json."""

from __future__ import annotations

import argparse
import errno
import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .client_files import ClientFiles
from .client_tasks import ClientTasks
from .rpc_plugins import load_client_rpc_registry
from .mapping_transport import MAX_MESSAGE, encode

LOG = logging.getLogger("openkapsel.client")


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


def run_once(config, stop=None, *, runtime=None):
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
        capabilities = {
            "file_stream": {"version": 1, "descriptor_stat": True, "directory_details": True,
                            "search_prefix": True},
            "protocol": 1,
            "writable": files.writable,
            "rpc": files.rpc_capabilities,
            "execution": tasks.capabilities(),
        }
        # Core file RPC is mandatory. Optional extensions are advertised only
        # when usable, including to rolling-upgrade servers.
        capabilities["file_api"] = {
            "version": files.rpc_capabilities["file"]["version"],
            "operations": files.rpc_capabilities["file"]["operations"],
        }
        if files.rpc_capabilities["git"]["state"] == "available":
            capabilities["git_api"] = {
                "version": files.rpc_capabilities["git"]["version"],
                "read_only": True,
            }
        sock.send(encode({"type": "hello", "capabilities": capabilities}).decode())
        LOG.info("Mapping provider connected")
        def heartbeat():
            while not stopped.wait(10):
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
    config = json.loads(options.config.read_text())
    if os.name != "nt" and options.config.stat().st_mode & 0o077:
        parser.error("client configuration contains credentials: chmod 600 it first")
    runtime = ClientRuntime(config)
    try:
        while True:
            try:
                run_once(config, runtime=runtime)
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

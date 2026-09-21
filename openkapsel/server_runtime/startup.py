"""Server construction and CLI lifecycle."""

from __future__ import annotations

import logging
import signal
from datetime import datetime, timezone
from urllib.parse import quote

from .config import ServerConfig, load_config, parse_args
from .http_server import WorkspaceHTTPServer

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_server(host: str, port: int, config: ServerConfig) -> WorkspaceHTTPServer:
    return WorkspaceHTTPServer((host, port), config)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        host_value, port_value, config = load_config(args)
    except ValueError as exc:
        raise SystemExit(f"configuration error: {exc}") from None
    server = create_server(host_value, port_value, config)
    host, port = server.server_address[:2]
    local_base = f"http://{host}:{port}{config.url_base_path}"
    print(f"OpenKapsel listening on {local_base}")
    if config.token:
        print(f"Bootstrap workspace URL: {local_base}/w/{quote(config.token, safe='')}/")
    if config.admin_enabled:
        print(f"Admin console: {local_base}/admin")
    print(f"Workspace root: {config.root}")
    def stop_service(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop_service)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

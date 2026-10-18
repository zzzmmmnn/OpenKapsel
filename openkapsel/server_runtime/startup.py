"""Server construction and CLI lifecycle."""

from __future__ import annotations

import ipaddress
import logging
import signal
from datetime import datetime, timezone
from urllib.parse import quote

from .config import ServerConfig, load_config, parse_args
from .http_server import WorkspaceHTTPServer


LOGGER = logging.getLogger(__name__)


def _is_loopback_bind(host: str) -> bool:
    """Only known loopback addresses are safe from remote HTTP connections."""
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Unknown hostnames and wildcard bindings are not proven local.
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def _warn_non_loopback_http(host: str, port: int) -> None:
    if not _is_loopback_bind(host):
        LOGGER.warning(
            "SECURITY: OpenKapsel HTTP is listening on non-loopback address %s:%s "
            "without TLS. Direct HTTP connections can expose administrator "
            "passwords, Bearer tokens and other credentials in plaintext. "
            "Bind to loopback and use an HTTPS reverse proxy, or strictly "
            "restrict direct access to this HTTP port. HTTPS at a reverse "
            "proxy does not protect direct HTTP connections to this listener.",
            host, port,
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_server(host: str, port: int, config: ServerConfig) -> WorkspaceHTTPServer:
    server = WorkspaceHTTPServer((host, port), config)
    # The bound address, not just the requested config, determines exposure.
    _warn_non_loopback_http(*server.server_address[:2])
    return server


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

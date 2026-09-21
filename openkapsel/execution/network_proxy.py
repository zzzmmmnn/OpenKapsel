"""Token-scoped HTTP/HTTPS egress proxy for restricted sandboxes."""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import socket
import socketserver
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


LOGGER = logging.getLogger("openkapsel.network")
NETWORK_MODES = {"none", "domain_allowlist", "full"}
DEFAULT_NETWORK_DOMAINS = (
    "github.com",
    ".githubusercontent.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "npm.pkg.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "nodejs.org",
    "gitlab.com",
    ".gitlab.com",
    "bitbucket.org",
    "api.bitbucket.org",
    "bbuseruploads.s3.amazonaws.com",
    "codeberg.org",
    "gitee.com",
    "git.sr.ht",
)
DEFAULT_NETWORK_PORTS = (80, 443)
PROXY_PORT = 18080
PROXY_MOUNT = "/run/openkapsel-proxy"
MAX_PROXY_HEADER_BYTES = 64 * 1024
DEFAULT_MAX_PROXY_CONNECTIONS = 64
DEFAULT_MAX_PROXY_CONNECTIONS_PER_INSTANCE = 16
DEFAULT_PROXY_HEADER_TIMEOUT_SECONDS = 15.0
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_PROXY_CONFIG_LOCK = threading.Lock()
_PROXY_GLOBAL_SLOTS = threading.BoundedSemaphore(DEFAULT_MAX_PROXY_CONNECTIONS)
_PROXY_PER_INSTANCE_LIMIT = DEFAULT_MAX_PROXY_CONNECTIONS_PER_INSTANCE
_PROXY_HEADER_TIMEOUT_SECONDS = DEFAULT_PROXY_HEADER_TIMEOUT_SECONDS


def configure_proxy_limits(
    max_connections: int,
    max_connections_per_instance: int,
    header_timeout_seconds: float,
) -> None:
    if min(max_connections, max_connections_per_instance, header_timeout_seconds) <= 0:
        raise ValueError("proxy connection limits and timeout must be positive")
    if max_connections_per_instance > max_connections:
        raise ValueError("per-instance proxy connection limit cannot exceed global limit")
    if header_timeout_seconds > 300:
        raise ValueError("proxy header timeout cannot exceed 300 seconds")
    global _PROXY_GLOBAL_SLOTS, _PROXY_PER_INSTANCE_LIMIT, _PROXY_HEADER_TIMEOUT_SECONDS
    with _PROXY_CONFIG_LOCK:
        _PROXY_GLOBAL_SLOTS = threading.BoundedSemaphore(max_connections)
        _PROXY_PER_INSTANCE_LIMIT = max_connections_per_instance
        _PROXY_HEADER_TIMEOUT_SECONDS = float(header_timeout_seconds)


def prepare_proxy_root(root: Path) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    for child in root.iterdir():
        if child.name.startswith("proxy-") and child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)


def normalize_domain_rule(value: str) -> str:
    """Normalize an exact domain or a leading-dot suffix rule."""
    raw = value.strip().lower().rstrip(".")
    suffix = raw.startswith(".")
    name = raw[1:] if suffix else raw
    if not name or len(name) > 253 or ":" in name or "/" in name:
        raise ValueError(f"invalid network domain: {value!r}")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"invalid network domain: {value!r}") from None
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in ascii_name.split(".")):
        raise ValueError(f"invalid network domain: {value!r}")
    return f".{ascii_name}" if suffix else ascii_name


def normalize_domain_rules(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        normalized = normalize_domain_rule(str(value))
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def domain_allowed(hostname: str, rules: tuple[str, ...]) -> bool:
    try:
        host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    for rule in rules:
        if rule.startswith("."):
            suffix = rule[1:]
            if host == suffix or host.endswith(rule):
                return True
        elif host == rule:
            return True
    return False


def public_destination(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _split_authority(authority: str, default_port: int) -> tuple[str, int]:
    parsed = urlsplit(f"//{authority}")
    if parsed.username is not None or parsed.password is not None or not parsed.hostname:
        raise ValueError("invalid proxy destination")
    try:
        port = parsed.port or default_port
    except ValueError:
        raise ValueError("invalid proxy destination port") from None
    return parsed.hostname, port


class ProxyPolicyError(ValueError):
    pass


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        proxy: DomainProxy = self.server.proxy  # type: ignore[attr-defined]
        client: socket.socket = self.request
        if not proxy._global_slots.acquire(blocking=False):
            self._error(429, "Too Many Requests")
            return
        local_acquired = proxy._slots.acquire(blocking=False)
        if not local_acquired:
            proxy._global_slots.release()
            self._error(429, "Too Many Requests")
            return
        upstream: socket.socket | None = None
        try:
            header, remainder = proxy.read_header(client)
            first, headers = proxy.parse_header(header)
            method, target, version = first
            content_length, had_content_length = proxy.request_content_length(headers)
            upgrade = proxy.request_upgrade(headers)
            if method == "CONNECT":
                host, port = _split_authority(target, 443)
                if port != 443:
                    raise ProxyPolicyError("CONNECT is allowed only for HTTPS port 443")
                proxy.validate_host_header(headers, host, port, 443)
                if content_length or proxy.header_values(headers, "transfer-encoding"):
                    raise ProxyPolicyError("CONNECT request bodies are not supported")
                upstream = proxy.connect(host, port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if remainder:
                    upstream.sendall(remainder)
                proxy.tunnel(client, upstream)
                return
            else:
                parsed = urlsplit(target)
                if (
                    parsed.scheme.lower() != "http"
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.fragment
                ):
                    raise ProxyPolicyError("only absolute HTTP URLs and HTTPS CONNECT are supported")
                host = parsed.hostname
                try:
                    port = parsed.port or 80
                except ValueError:
                    raise ProxyPolicyError("invalid proxy destination port") from None
                proxy.validate_host_header(headers, host, port, 80)
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                outgoing_header = proxy.origin_header(
                    method,
                    path,
                    version,
                    headers,
                    host,
                    port,
                    content_length,
                    had_content_length,
                    upgrade,
                )
                if upgrade is not None and (remainder or content_length):
                    raise ProxyPolicyError("WebSocket upgrade requests cannot have a body")
                if upgrade is None and len(remainder) > content_length:
                    raise ProxyPolicyError("HTTP pipelining is not supported")
            upstream = proxy.connect(host, port)
            upstream.sendall(outgoing_header)
            if upgrade is not None:
                proxy.upgrade_tunnel(client, upstream)
                return
            if remainder:
                upstream.sendall(remainder)
            proxy.forward_request_body(
                client,
                upstream,
                content_length - len(remainder),
            )
            try:
                upstream.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            proxy.relay_response(upstream, client)
        except ProxyPolicyError as exc:
            LOGGER.info("denied sandbox proxy request: %s", exc)
            self._error(403, "Forbidden")
        except (OSError, ValueError) as exc:
            LOGGER.info("sandbox proxy request failed: %s", exc)
            self._error(502, "Bad Gateway")
        finally:
            if upstream is not None:
                upstream.close()
            proxy._slots.release()
            proxy._global_slots.release()

    def _error(self, status: int, reason: str) -> None:
        try:
            body = f"{status} {reason}\n".encode("ascii")
            self.request.sendall(
                f"HTTP/1.1 {status} {reason}\r\nConnection: close\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\nContent-Length: {len(body)}\r\n\r\n".encode(
                    "ascii"
                )
                + body
            )
        except OSError:
            pass


@dataclass
class DomainProxy:
    """A private Unix-socket proxy instance carrying one token's policy."""

    directory: Path
    socket_path: Path
    domains: tuple[str, ...]
    ports: tuple[int, ...]
    _server: _ThreadingUnixServer
    _thread: threading.Thread
    _slots: threading.BoundedSemaphore
    _global_slots: threading.BoundedSemaphore
    _header_timeout_seconds: float

    @classmethod
    def start(
        cls,
        root: Path,
        domains: tuple[str, ...],
        ports: tuple[int, ...] = DEFAULT_NETWORK_PORTS,
    ) -> "DomainProxy":
        normalized = normalize_domain_rules(list(domains))
        if not normalized:
            raise ValueError("domain_allowlist network mode requires at least one domain")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        with _PROXY_CONFIG_LOCK:
            global_slots = _PROXY_GLOBAL_SLOTS
            per_instance_limit = _PROXY_PER_INSTANCE_LIMIT
            header_timeout_seconds = _PROXY_HEADER_TIMEOUT_SECONDS
        directory = Path(tempfile.mkdtemp(prefix="proxy-", dir=root))
        directory.chmod(0o700)
        socket_path = directory / "proxy.sock"
        server = _ThreadingUnixServer(str(socket_path), _ProxyHandler)
        os.chmod(socket_path, 0o600)
        proxy = cls(
            directory,
            socket_path,
            normalized,
            tuple(ports),
            server,
            None,  # type: ignore[arg-type]
            threading.BoundedSemaphore(per_instance_limit),
            global_slots,
            header_timeout_seconds,
        )
        server.proxy = proxy  # type: ignore[attr-defined]
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"domain-proxy-{directory.name}",
            daemon=True,
        )
        proxy._thread = thread
        thread.start()
        return proxy

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
        shutil.rmtree(self.directory, ignore_errors=True)

    def read_header(self, client: socket.socket) -> tuple[bytes, bytes]:
        client.settimeout(self._header_timeout_seconds)
        return self._read_header_bytes(client)

    @staticmethod
    def _read_header_bytes(stream: socket.socket) -> tuple[bytes, bytes]:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = stream.recv(16 * 1024)
            if not chunk:
                raise ValueError("incomplete proxy request")
            data.extend(chunk)
            if len(data) > MAX_PROXY_HEADER_BYTES:
                raise ProxyPolicyError("proxy request headers are too large")
        end = data.index(b"\r\n\r\n") + 4
        return bytes(data[:end]), bytes(data[end:])

    @staticmethod
    def parse_header(
        header: bytes,
    ) -> tuple[tuple[str, str, str], tuple[tuple[str, str], ...]]:
        try:
            lines = header.decode("iso-8859-1").split("\r\n")
        except UnicodeDecodeError:
            raise ProxyPolicyError("malformed proxy request") from None
        request_line = re.fullmatch(
            r"([A-Z!#$%&'*+.^_`|~-]+) ([^ ]+) (HTTP/1\.[01])",
            lines[0],
        )
        if request_line is None:
            raise ProxyPolicyError("malformed proxy request line")
        method, target, version = request_line.groups()
        if any(ord(char) < 33 or ord(char) == 127 for char in target):
            raise ProxyPolicyError("malformed proxy request target")
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line or line[:1].isspace():
                raise ProxyPolicyError("malformed proxy header")
            name, value = line.split(":", 1)
            if name != name.strip() or not _HEADER_NAME.fullmatch(name):
                raise ProxyPolicyError("malformed proxy header name")
            value = value.strip(" \t")
            if any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value):
                raise ProxyPolicyError("malformed proxy header value")
            headers.append((name.lower(), value))
        return (method, target, version), tuple(headers)

    @staticmethod
    def header_values(headers: tuple[tuple[str, str], ...], name: str) -> list[str]:
        normalized = name.lower()
        return [value for header_name, value in headers if header_name == normalized]

    @classmethod
    def request_content_length(
        cls,
        headers: tuple[tuple[str, str], ...],
    ) -> tuple[int, bool]:
        transfer_encoding = cls.header_values(headers, "transfer-encoding")
        content_lengths = cls.header_values(headers, "content-length")
        if transfer_encoding:
            raise ProxyPolicyError("Transfer-Encoding request bodies are not supported")
        if len(content_lengths) > 1:
            raise ProxyPolicyError("multiple Content-Length headers are not supported")
        if not content_lengths:
            return 0, False
        raw = content_lengths[0]
        if len(raw) > 20 or re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
            raise ProxyPolicyError("invalid Content-Length header")
        return int(raw), True

    @classmethod
    def request_upgrade(
        cls,
        headers: tuple[tuple[str, str], ...],
    ) -> str | None:
        upgrades = cls.header_values(headers, "upgrade")
        connection_tokens = cls.connection_tokens(headers)
        if not upgrades:
            return None
        if (
            len(upgrades) != 1
            or upgrades[0].lower() != "websocket"
            or "upgrade" not in connection_tokens
        ):
            raise ProxyPolicyError("only WebSocket HTTP upgrades are supported")
        return upgrades[0]

    @classmethod
    def connection_tokens(
        cls,
        headers: tuple[tuple[str, str], ...],
    ) -> set[str]:
        result: set[str] = set()
        for value in cls.header_values(headers, "connection"):
            for item in value.split(","):
                token = item.strip().lower()
                if not token or _HEADER_NAME.fullmatch(token) is None:
                    raise ProxyPolicyError("invalid Connection header")
                result.add(token)
        return result

    @classmethod
    def validate_host_header(
        cls,
        headers: tuple[tuple[str, str], ...],
        hostname: str,
        port: int,
        default_port: int,
    ) -> None:
        hosts = cls.header_values(headers, "host")
        if len(hosts) != 1:
            raise ProxyPolicyError("exactly one Host header is required")
        supplied_host, supplied_port = _split_authority(hosts[0], default_port)
        if (
            supplied_host.lower().rstrip(".") != hostname.lower().rstrip(".")
            or supplied_port != port
        ):
            raise ProxyPolicyError("Host header does not match the proxy target")

    @classmethod
    def origin_header(
        cls,
        method: str,
        path: str,
        version: str,
        headers: tuple[tuple[str, str], ...],
        hostname: str,
        port: int,
        content_length: int,
        had_content_length: bool,
        upgrade: str | None,
    ) -> bytes:
        result = [f"{method} {path} {version}"]
        connection_tokens = cls.connection_tokens(headers)
        blocked = {
            "host",
            "proxy-authorization",
            "proxy-connection",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "content-length",
            *connection_tokens,
        }
        if cls.header_values(headers, "expect"):
            raise ProxyPolicyError("Expect requests are not supported by the HTTP proxy")
        for name, value in headers:
            if name in blocked:
                continue
            result.append(f"{name}: {value}")
        result.append(f"Host: {hostname}" if port == 80 else f"Host: {hostname}:{port}")
        if had_content_length:
            result.append(f"Content-Length: {content_length}")
        if upgrade is not None:
            result.append(f"Upgrade: {upgrade}")
            result.append("Connection: Upgrade")
        else:
            result.append("Connection: close")
        return ("\r\n".join(result) + "\r\n\r\n").encode("iso-8859-1")

    def connect(self, hostname: str, port: int) -> socket.socket:
        if port not in self.ports:
            raise ProxyPolicyError(f"destination port {port} is not allowed")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ProxyPolicyError("IP-literal destinations are not allowed")
        if not domain_allowed(hostname, self.domains):
            raise ProxyPolicyError(f"destination domain {hostname!r} is not allowed")
        try:
            results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"cannot resolve destination domain {hostname!r}: {exc}") from None
        public = [item for item in results if public_destination(item[4][0])]
        if not public or len(public) != len(results):
            raise ProxyPolicyError("destination resolves to a non-public address")
        last_error: OSError | None = None
        for family, socktype, proto, _canonname, sockaddr in public:
            value = socket.socket(family, socktype, proto)
            value.settimeout(30)
            try:
                value.connect(sockaddr)
                value.settimeout(300)
                LOGGER.info("allowed sandbox proxy connection to %s:%d", hostname, port)
                return value
            except OSError as exc:
                last_error = exc
                value.close()
        raise ValueError(f"cannot connect to destination {hostname!r}: {last_error}")

    @staticmethod
    def forward_request_body(
        client: socket.socket,
        upstream: socket.socket,
        remaining: int,
    ) -> None:
        client.settimeout(300)
        while remaining:
            chunk = client.recv(min(64 * 1024, remaining))
            if not chunk:
                raise ValueError("request body ended before Content-Length")
            upstream.sendall(chunk)
            remaining -= len(chunk)

    @staticmethod
    def relay_response(upstream: socket.socket, client: socket.socket) -> None:
        upstream.settimeout(300)
        client.settimeout(300)
        try:
            while True:
                chunk = upstream.recv(64 * 1024)
                if not chunk:
                    return
                client.sendall(chunk)
        finally:
            upstream.close()

    @classmethod
    def upgrade_tunnel(
        cls,
        client: socket.socket,
        upstream: socket.socket,
    ) -> None:
        upstream.settimeout(30)
        header, remainder = cls._read_header_bytes(upstream)
        try:
            status_line = header.split(b"\r\n", 1)[0].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("malformed WebSocket upgrade response") from None
        match = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: .*)?", status_line)
        if match is None:
            raise ValueError("malformed WebSocket upgrade response")
        client.sendall(header)
        if remainder:
            client.sendall(remainder)
        if match.group(1) != "101":
            cls.relay_response(upstream, client)
            return
        cls.tunnel(client, upstream)

    @staticmethod
    def tunnel(client: socket.socket, upstream: socket.socket) -> None:
        client.settimeout(300)
        upstream.settimeout(300)

        def pump(source: socket.socket, destination: socket.socket) -> None:
            try:
                while True:
                    chunk = source.recv(64 * 1024)
                    if not chunk:
                        break
                    destination.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        upload = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        upload.start()
        try:
            pump(upstream, client)
        finally:
            upload.join(timeout=1)
            upstream.close()

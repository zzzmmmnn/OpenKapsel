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
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


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
        if not proxy._slots.acquire(blocking=False):
            self._error(429, "Too Many Requests")
            return
        try:
            header, remainder = proxy.read_header(client)
            first, headers = proxy.parse_header(header)
            method, target, version = first
            if method == "CONNECT":
                host, port = _split_authority(target, 443)
                outgoing_header = None
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
                supplied_host, supplied_port = _split_authority(
                    headers.get("host", "").strip(), 80
                )
                if (
                    supplied_host.lower().rstrip(".") != host.lower().rstrip(".")
                    or supplied_port != port
                ):
                    raise ProxyPolicyError("Host header does not match the proxy target")
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                outgoing_header = proxy.origin_header(
                    method,
                    path,
                    version,
                    header,
                    host,
                    port,
                )
            upstream = proxy.connect(host, port)
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                assert outgoing_header is not None
                upstream.sendall(outgoing_header)
            if remainder:
                upstream.sendall(remainder)
            proxy.tunnel(client, upstream)
        except ProxyPolicyError as exc:
            LOGGER.info("denied sandbox proxy request: %s", exc)
            self._error(403, "Forbidden")
        except (OSError, ValueError) as exc:
            LOGGER.info("sandbox proxy request failed: %s", exc)
            self._error(502, "Bad Gateway")
        finally:
            proxy._slots.release()

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
            threading.BoundedSemaphore(16),
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
        client.settimeout(300)
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = client.recv(16 * 1024)
            if not chunk:
                raise ValueError("incomplete proxy request")
            data.extend(chunk)
            if len(data) > MAX_PROXY_HEADER_BYTES:
                raise ProxyPolicyError("proxy request headers are too large")
        end = data.index(b"\r\n\r\n") + 4
        return bytes(data[:end]), bytes(data[end:])

    @staticmethod
    def parse_header(header: bytes) -> tuple[tuple[str, str, str], dict[str, str]]:
        try:
            lines = header.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            raise ProxyPolicyError("malformed proxy request") from None
        if not re.fullmatch(r"[A-Z!#$%&'*+.^_`|~-]+", method) or not version.startswith("HTTP/1."):
            raise ProxyPolicyError("malformed proxy request line")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line or line[:1].isspace():
                raise ProxyPolicyError("malformed proxy header")
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        return (method, target, version), headers

    @staticmethod
    def origin_header(
        method: str,
        path: str,
        version: str,
        header: bytes,
        hostname: str,
        port: int,
    ) -> bytes:
        lines = header.decode("iso-8859-1").split("\r\n")
        result = [f"{method} {path} {version}"]
        has_upgrade = any(
            line.lower().startswith("upgrade:")
            for line in lines[1:]
        )
        for line in lines[1:]:
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            if name in {"host", "proxy-authorization", "proxy-connection", "connection"}:
                continue
            result.append(line)
        result.append(f"Host: {hostname}" if port == 80 else f"Host: {hostname}:{port}")
        result.append("Connection: Upgrade" if has_upgrade else "Connection: close")
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

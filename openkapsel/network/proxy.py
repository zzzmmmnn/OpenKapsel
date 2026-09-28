"""Proxy tunnel transport shared by mapping and RPC clients."""

from __future__ import annotations

import base64
import contextlib
import errno
import functools
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit


SUPPORTED_PROXY_SCHEMES = {
    "http",
    "https",
    "socks4",
    "socks4a",
    "socks5",
    "socks5h",
}


@dataclass(frozen=True)
class ProxyConfig:
    """Normalized proxy settings for establishing a target TCP tunnel."""

    type: str
    host: str
    port: int
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    remote_dns: bool = True
    tls_verify: bool = True
    ca_file: str | None = None
    tls_server_name: str | None = None


class ProxyTunnelError(OSError):
    """A proxy tunnel failed before the upper-layer protocol started."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        proxy_type: str,
        status: int | None = None,
        status_line: str | None = None,
        error_type: str | None = None,
    ):
        errno_value = {
            "authentication_failed": errno.EACCES,
            "dependency_missing": errno.ENOSYS,
        }.get(reason, errno.ECONNREFUSED)
        super().__init__(errno_value, message)
        self.reason = reason
        self.proxy_type = proxy_type
        self.status = status
        self.status_line = status_line
        self.error_type = error_type

    def public_details(self) -> dict:
        details = {"proxy_type": self.proxy_type}
        if self.status is not None:
            details["proxy_status"] = self.status
        if self.status_line is not None:
            details["status_line"] = self.status_line
        if self.error_type is not None:
            details["error_type"] = self.error_type
        return details


def parse_proxy_url(url: str | None) -> ProxyConfig | None:
    """Parse a mapping-client proxy URL into normalized proxy settings."""

    if not url:
        return None
    if not isinstance(url, str):
        raise ValueError("proxy must be a URL string")
    parsed = urlsplit(url)
    if parsed.scheme not in SUPPORTED_PROXY_SCHEMES or not parsed.hostname:
        raise ValueError(
            "proxy must be an http/https/socks4/socks5 URL with host and port"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("proxy URL has an invalid port") from exc
    if port is None:
        raise ValueError(
            "proxy must be an http/https/socks4/socks5 URL with host and port"
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("proxy URL cannot include a path, query, or fragment")

    raw_type = parsed.scheme
    proxy_type = {
        "socks4a": "socks4",
        "socks5h": "socks5",
    }.get(raw_type, raw_type)
    remote_dns = raw_type in {"socks4a", "socks5h"}
    return ProxyConfig(
        type=proxy_type,
        host=parsed.hostname,
        port=port,
        username=unquote(parsed.username) if parsed.username is not None else None,
        password=unquote(parsed.password or "") if parsed.username is not None else None,
        remote_dns=remote_dns,
    )


def _authority(host: str, port: int) -> str:
    if "\r" in host or "\n" in host:
        raise ValueError("proxy destination host must not contain line breaks")
    display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{display}:{port}"


def _read_connect_response(sock) -> tuple[int, str]:
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        if len(data) >= 65536:
            raise OSError(errno.EPROTO, "proxy CONNECT response headers exceed 64 KiB")
        chunk = sock.recv(1)
        if not chunk:
            raise OSError(errno.ECONNRESET, "proxy closed during CONNECT response")
        data.extend(chunk)
    first = bytes(data).split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
    parts = first.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise OSError(errno.EPROTO, "proxy returned an invalid CONNECT response")
    return int(parts[1]), first[:200]


def _ssl_context(
    *,
    verify: bool,
    ca_file: str | None,
) -> ssl.SSLContext:
    cafile = str(Path(ca_file).expanduser()) if ca_file else None
    context = ssl.create_default_context(cafile=cafile)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def connect_proxy_tunnel(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    *,
    timeout: float,
):
    """Return a socket-like stream tunneled through *proxy* to the target."""

    if proxy.type not in {"socks4", "socks5", "http", "https"}:
        raise ValueError("unsupported proxy type")
    if not isinstance(target_host, str) or not target_host or "\r" in target_host or "\n" in target_host:
        raise ValueError("target_host must be a non-empty host without line breaks")
    if isinstance(target_port, bool) or not isinstance(target_port, int) or not 1 <= target_port <= 65535:
        raise ValueError("target_port must be between 1 and 65535")

    if proxy.type in {"socks4", "socks5"}:
        try:
            from python_socks import ProxyType
            from python_socks.sync import Proxy
        except ImportError as exc:
            raise ProxyTunnelError(
                "dependency_missing",
                "SOCKS proxy requires python-socks",
                proxy_type=proxy.type,
                error_type=type(exc).__name__,
            ) from exc
        proxy_type = ProxyType.SOCKS4 if proxy.type == "socks4" else ProxyType.SOCKS5
        try:
            sock = Proxy(
                proxy_type,
                proxy.host,
                proxy.port,
                username=proxy.username,
                password=proxy.password,
                rdns=proxy.remote_dns,
            ).connect(target_host, target_port, timeout=timeout)
            sock.settimeout(timeout)
            return sock
        except ProxyTunnelError:
            raise
        except Exception as exc:
            raise ProxyTunnelError(
                "connect_failed",
                "SOCKS proxy tunnel could not be established",
                proxy_type=proxy.type,
                error_type=type(exc).__name__,
            ) from exc

    raw = stream = None
    try:
        raw = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
        raw.settimeout(timeout)
        stream = raw
        if proxy.type == "https":
            context = _ssl_context(verify=proxy.tls_verify, ca_file=proxy.ca_file)
            stream = context.wrap_socket(
                raw,
                server_hostname=proxy.tls_server_name or proxy.host,
            )
            stream.settimeout(timeout)

        authority = _authority(target_host, target_port)
        headers = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
            "Proxy-Connection: Keep-Alive",
        ]
        if proxy.username is not None:
            token = base64.b64encode(
                f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
            ).decode("ascii")
            headers.append("Proxy-Authorization: Basic " + token)
        stream.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))

        status, status_line = _read_connect_response(stream)
        if status == 407:
            raise ProxyTunnelError(
                "authentication_failed",
                "proxy authentication failed",
                proxy_type=proxy.type,
                status=status,
                status_line=status_line,
            )
        if not 200 <= status < 300:
            raise ProxyTunnelError(
                "connect_failed",
                "proxy rejected CONNECT",
                proxy_type=proxy.type,
                status=status,
                status_line=status_line,
            )
        return stream
    except ProxyTunnelError:
        candidate = stream if stream is not None else raw
        if candidate is not None:
            with contextlib.suppress(Exception):
                candidate.close()
        raise
    except Exception as exc:
        candidate = stream if stream is not None else raw
        if candidate is not None:
            with contextlib.suppress(Exception):
                candidate.close()
        raise ProxyTunnelError(
            "connect_failed",
            "proxy tunnel could not be established",
            proxy_type=proxy.type,
            error_type=type(exc).__name__,
        ) from exc


class TLSOverTLSStream:
    """Blocking socket-like TLS stream layered over an existing TLS socket."""

    TLS_RECORD_SIZE = 16384

    def __init__(
        self,
        sock,
        ssl_context: ssl.SSLContext,
        server_hostname: str,
        timeout: float,
    ):
        self._sock = sock
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._sslobj = ssl_context.wrap_bio(
            incoming=self._incoming,
            outgoing=self._outgoing,
            server_hostname=server_hostname,
        )
        self.settimeout(timeout)
        self._perform_io(self._sslobj.do_handshake)

    def _flush(self):
        data = self._outgoing.read()
        if data:
            self._sock.sendall(data)

    def _perform_io(self, func):
        while True:
            want = None
            try:
                result = func()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError) as exc:
                want = exc.errno
                result = None
            self._flush()
            if want == ssl.SSL_ERROR_WANT_READ:
                data = self._sock.recv(self.TLS_RECORD_SIZE)
                if data:
                    self._incoming.write(data)
                else:
                    self._incoming.write_eof()
                continue
            if want == ssl.SSL_ERROR_WANT_WRITE:
                continue
            return result

    def recv(self, size: int, flags: int = 0) -> bytes:
        if flags:
            raise ValueError("TLS-over-TLS stream does not support recv flags")
        return self._perform_io(functools.partial(self._sslobj.read, size))

    def send(self, data, flags: int = 0) -> int:
        if flags:
            raise ValueError("TLS-over-TLS stream does not support send flags")
        return int(self._perform_io(functools.partial(self._sslobj.write, data)))

    def sendall(self, data, flags: int = 0):
        if flags:
            raise ValueError("TLS-over-TLS stream does not support sendall flags")
        view = memoryview(data)
        while view:
            sent = self.send(view)
            if sent <= 0:
                raise OSError(errno.EPIPE, "TLS-over-TLS stream could not write")
            view = view[sent:]

    def settimeout(self, value):
        self._sock.settimeout(value)

    def gettimeout(self):
        return self._sock.gettimeout()

    def fileno(self):
        return self._sock.fileno()

    def shutdown(self, how):
        return self._sock.shutdown(how)

    def close(self):
        return self._sock.close()

    def getpeername(self):
        return self._sock.getpeername()

    def getsockname(self):
        return self._sock.getsockname()


def wrap_tls_stream(
    sock,
    *,
    server_hostname: str,
    timeout: float,
    verify: bool = True,
    ca_file: str | None = None,
):
    """Wrap a target tunnel in TLS, including TLS-over-TLS when required."""

    context = _ssl_context(verify=verify, ca_file=ca_file)
    try:
        if isinstance(sock, ssl.SSLSocket):
            return TLSOverTLSStream(sock, context, server_hostname, timeout)
        wrapped = context.wrap_socket(sock, server_hostname=server_hostname)
        wrapped.settimeout(timeout)
        return wrapped
    except Exception:
        with contextlib.suppress(Exception):
            sock.close()
        raise

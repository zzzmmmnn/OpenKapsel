"""Client-side proxy transport helpers for mapping WebSocket connections."""

from __future__ import annotations

import base64
import contextlib
import errno
import functools
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit


SUPPORTED_PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}


@dataclass(frozen=True)
class ProxyUrl:
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = field(default=None, repr=False)


def parse_proxy_url(url: str | None) -> ProxyUrl | None:
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
    return ProxyUrl(
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=port,
        username=unquote(parsed.username) if parsed.username is not None else None,
        password=unquote(parsed.password or "") if parsed.username is not None else None,
    )


def websocket_proxy_options(proxy: ProxyUrl | None) -> dict:
    if proxy is None:
        return {"http_no_proxy": ["*"]}
    if proxy.scheme == "https":
        raise ValueError("HTTPS proxy requires a preconnected tunnel socket")
    options = {
        "http_proxy_host": proxy.host,
        "http_proxy_port": proxy.port,
        "proxy_type": proxy.scheme,
        "http_no_proxy": ["never-bypass-proxy.invalid"],
    }
    if proxy.username is not None:
        options["http_proxy_auth"] = (proxy.username, proxy.password or "")
    return options


def _authority(host: str, port: int) -> str:
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


def open_https_proxy_socket(
    proxy: ProxyUrl,
    target_url: str,
    *,
    timeout: float,
):
    if proxy.scheme != "https":
        raise ValueError("open_https_proxy_socket requires an https proxy")
    target = urlsplit(target_url)
    if target.scheme not in {"ws", "wss"} or not target.hostname:
        raise ValueError("target must be a ws/wss URL with a host")
    try:
        target_port = target.port
    except ValueError as exc:
        raise ValueError("target URL has an invalid port") from exc
    if target_port is None:
        target_port = 443 if target.scheme == "wss" else 80

    raw = outer = None
    try:
        raw = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
        raw.settimeout(timeout)
        proxy_context = ssl.create_default_context()
        outer = proxy_context.wrap_socket(raw, server_hostname=proxy.host)
        outer.settimeout(timeout)

        authority = _authority(target.hostname, target_port)
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
        outer.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))

        status, _status_line = _read_connect_response(outer)
        if status == 407:
            raise OSError(errno.EACCES, "HTTPS proxy authentication failed")
        if not 200 <= status < 300:
            raise OSError(errno.ECONNREFUSED, f"HTTPS proxy rejected CONNECT ({status})")

        if target.scheme == "ws":
            return outer

        target_context = ssl.create_default_context()
        return TLSOverTLSStream(
            outer,
            target_context,
            target.hostname,
            timeout,
        )
    except Exception:
        candidate = outer if outer is not None else raw
        if candidate is not None:
            with contextlib.suppress(Exception):
                candidate.close()
        raise

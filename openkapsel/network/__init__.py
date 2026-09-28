"""Shared outbound network transport helpers."""

from .proxy import (
    ProxyConfig,
    ProxyTunnelError,
    SUPPORTED_PROXY_SCHEMES,
    TLSOverTLSStream,
    connect_proxy_tunnel,
    parse_proxy_url,
    wrap_tls_stream,
)

__all__ = [
    "ProxyConfig",
    "ProxyTunnelError",
    "SUPPORTED_PROXY_SCHEMES",
    "TLSOverTLSStream",
    "connect_proxy_tunnel",
    "parse_proxy_url",
    "wrap_tls_stream",
]

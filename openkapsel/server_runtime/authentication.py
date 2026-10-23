"""Authentication layer data shared by every API entrance.

Each request is authenticated exactly once, in ``_authenticate_request``. The
result is a :class:`RequestPrincipal` whose ``control`` flag is the only
control authority that routing and endpoint handlers consult; handlers never
inspect credentials themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

PRINCIPAL_METHODS = frozenset({
    "url_token",       # read-only workspace URL token
    "bearer_control",  # workspace URL token plus matching Bearer control token
    "signed_get",      # HMAC-signed GET envelope at the workspace root
    "signed_native",   # HMAC-signed native method at the workspace root
    "oauth",           # OAuth MCP connection access token
    "static_mcp",      # Static MCP connection secret
    "preview",         # dedicated static preview token
})


@dataclass(frozen=True)
class RequestPrincipal:
    """Who is calling and whether the call carries control authority."""

    token_record: Any
    scope_root: Path
    control: bool
    method: str
    connection_id: str | None = None

    def __post_init__(self) -> None:
        if self.method not in PRINCIPAL_METHODS:
            raise ValueError(f"unknown authentication method: {self.method}")


@dataclass(frozen=True)
class AuthenticatedRequest:
    """Authentication-layer output handed to the routing layer."""

    entry_route: str
    route: str
    method: str
    query: dict[str, list[str]]
    query_routed: bool

"""Server-side mapping RPC capability negotiation and routing policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .git_operations import GIT_OPERATIONS
from .mapping_transport import FILE_API_OPERATIONS


RPC_STATES = frozenset({"available", "unsupported", "disabled", "offline"})
RPC_FAMILIES = {
    "file": {
        "version": 3,
        "legacy_key": "file_api",
        "operations": frozenset(FILE_API_OPERATIONS),
        "fallback": "fuse",
    },
    "git": {
        "version": 2,
        "legacy_key": "git_api",
        "operations": frozenset(GIT_OPERATIONS),
        "fallback": None,
    },
    "archive": {
        "version": 1,
        "legacy_key": None,
        "operations": frozenset({"list", "read"}),
        "fallback": None,
    },
}


@dataclass(frozen=True)
class MappingRpcCapability:
    family: str
    state: str
    reason: str | None = None
    version: int | None = None
    operations: tuple[str, ...] = ()
    fallback: str | None = None
    details: dict[str, Any] | None = None

    @property
    def available(self) -> bool:
        return self.state == "available"

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {"family": self.family, "state": self.state}
        if self.reason:
            result["reason"] = self.reason
        if self.version is not None:
            result["version"] = self.version
        if self.operations:
            result["operations"] = list(self.operations)
        if self.fallback:
            result["fallback"] = self.fallback
        if self.details:
            result["details"] = self.details
        return result


def legacy_rpc_capability(capabilities: dict[str, Any], family: str) -> dict[str, Any] | None:
    """Translate pre-rpc-map capability advertisements for rolling upgrades."""
    spec = RPC_FAMILIES.get(family)
    if spec is None:
        return None
    legacy_key = spec["legacy_key"]
    if not legacy_key:
        return None
    legacy = capabilities.get(legacy_key)
    if not isinstance(legacy, dict):
        return None
    result = dict(legacy, state="available")
    if family == "git":
        result.setdefault("operations", sorted(spec["operations"]))
    return result

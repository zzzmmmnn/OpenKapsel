"""Mapping RPC capability negotiation and routing state."""

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


def normalize_rpc_config(config: dict[str, Any]) -> dict[str, bool]:
    """Return per-family client preferences, preserving current defaults."""
    raw = config.get("rpc", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("rpc must be an object")
    unknown = set(raw) - set(RPC_FAMILIES)
    if unknown:
        raise ValueError("unsupported rpc categories: " + ", ".join(sorted(unknown)))
    result = {}
    for family in RPC_FAMILIES:
        value = raw.get(family, True)
        if not isinstance(value, bool):
            raise ValueError(f"rpc.{family} must be a boolean")
        result[family] = value
    return result


def client_rpc_capabilities(config: dict[str, Any], *, git_available: bool) -> dict[str, dict[str, Any]]:
    """Build the capability advertisement for one client process."""
    enabled = normalize_rpc_config(config)
    result: dict[str, dict[str, Any]] = {}
    for family, spec in RPC_FAMILIES.items():
        base: dict[str, Any] = {
            "version": spec["version"],
            "operations": sorted(spec["operations"]),
        }
        if family == "git":
            base["read_only"] = True
        if not enabled[family]:
            base.update(state="disabled", reason="client_config")
        elif family == "git" and not git_available:
            base.update(state="unsupported", reason="dependency_missing")
        else:
            base["state"] = "available"
        result[family] = base
    return result


def legacy_rpc_capability(capabilities: dict[str, Any], family: str) -> dict[str, Any] | None:
    """Translate pre-rpc-map capability advertisements for rolling upgrades."""
    spec = RPC_FAMILIES[family]
    legacy = capabilities.get(spec["legacy_key"])
    if not isinstance(legacy, dict):
        return None
    result = dict(legacy, state="available")
    if family == "git":
        result.setdefault("operations", sorted(spec["operations"]))
    return result

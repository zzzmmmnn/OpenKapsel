"""Explicit, bounded client RPC plugin loading and dispatch."""

from __future__ import annotations

import errno
import importlib
import re
from dataclasses import dataclass
from typing import Any, Protocol


_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")


class RpcPlugin(Protocol):
    family: str
    version: int
    operations: frozenset[str]
    read_only: bool

    def probe(self, config: dict[str, Any]) -> tuple[str, str | None, dict[str, Any] | None]:
        ...

    def dispatch(self, files: Any, operation: str, args: dict[str, Any]) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class RegisteredPlugin:
    family: str
    plugin: RpcPlugin
    source: str


def _plugin_object(value: Any) -> RpcPlugin:
    if isinstance(value, type):
        value = value()
    elif callable(value) and not hasattr(value, "family"):
        value = value()
    family = getattr(value, "family", None)
    version = getattr(value, "version", None)
    operations = getattr(value, "operations", None)
    read_only = getattr(value, "read_only", None)
    if not isinstance(family, str) or not _NAME.fullmatch(family):
        raise ValueError("RPC plugin family must match [a-z][a-z0-9_]{0,31}")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError(f"RPC plugin {family} has an invalid version")
    if not isinstance(operations, frozenset) or not operations or any(
        not isinstance(op, str) or not _NAME.fullmatch(op) for op in operations
    ):
        raise ValueError(f"RPC plugin {family} has invalid operations")
    if not isinstance(read_only, bool):
        raise ValueError(f"RPC plugin {family} must declare read_only")
    if not callable(getattr(value, "probe", None)) or not callable(getattr(value, "dispatch", None)):
        raise ValueError(f"RPC plugin {family} must implement probe and dispatch")
    return value


class ClientRpcRegistry:
    def __init__(self):
        self._plugins: dict[str, RegisteredPlugin] = {}

    @property
    def families(self) -> frozenset[str]:
        return frozenset(self._plugins)

    def register(self, plugin: RpcPlugin, *, source: str) -> None:
        plugin = _plugin_object(plugin)
        if plugin.family == "file":
            raise ValueError("file is a reserved core RPC family")
        if plugin.family in self._plugins:
            raise ValueError(f"duplicate RPC plugin family: {plugin.family}")
        self._plugins[plugin.family] = RegisteredPlugin(plugin.family, plugin, source)

    def load_import_spec(self, spec: str) -> None:
        if not isinstance(spec, str) or not spec or spec.count(":") != 1:
            raise ValueError("rpc_plugins entries must use module:object syntax")
        module_name, object_name = spec.split(":", 1)
        if not module_name or not object_name or object_name.startswith("_"):
            raise ValueError("invalid RPC plugin import spec")
        module = importlib.import_module(module_name)
        try:
            plugin = getattr(module, object_name)
        except AttributeError:
            raise ValueError(f"RPC plugin object not found: {spec}") from None
        self.register(plugin, source=spec)

    def capability_map(self, config: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw = config.get("rpc", {})
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ValueError("rpc must be an object")
        allowed = {"file"} | set(self._plugins)
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError("unsupported rpc categories: " + ", ".join(sorted(unknown)))

        file_enabled = raw.get("file", True)
        if not isinstance(file_enabled, bool):
            raise ValueError("rpc.file must be a boolean")
        from ..mapping_transport import FILE_API_OPERATIONS
        result: dict[str, dict[str, Any]] = {
            "file": {
                "state": "available" if file_enabled else "disabled",
                "version": 3,
                "operations": sorted(FILE_API_OPERATIONS),
            }
        }
        if not file_enabled:
            result["file"]["reason"] = "client_config"

        for family, registered in self._plugins.items():
            enabled = raw.get(family, True)
            if not isinstance(enabled, bool):
                raise ValueError(f"rpc.{family} must be a boolean")
            plugin = registered.plugin
            state, reason, details = plugin.probe(config)
            if state not in {"available", "unsupported"}:
                raise ValueError(f"RPC plugin {family} returned invalid probe state")
            if not enabled:
                state, reason, details = "disabled", "client_config", None
            capability: dict[str, Any] = {
                "state": state,
                "version": plugin.version,
                "operations": sorted(plugin.operations),
                "read_only": plugin.read_only,
                "plugin": registered.source,
            }
            if reason:
                capability["reason"] = reason
            if details:
                capability["details"] = details
            result[family] = capability
        return result

    def accepts(self, wire_operation: str) -> bool:
        return self._registered_for(wire_operation) is not None

    def read_only(self, wire_operation: str) -> bool:
        registered = self._registered_for(wire_operation)
        return bool(registered and registered.plugin.read_only)

    def _registered_for(self, wire_operation: str) -> RegisteredPlugin | None:
        if not isinstance(wire_operation, str):
            return None
        for family, registered in self._plugins.items():
            prefix = family + "_"
            if wire_operation.startswith(prefix) and wire_operation[len(prefix):] in registered.plugin.operations:
                return registered
        return None

    def dispatch(self, files: Any, wire_operation: str, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(wire_operation, str) or not isinstance(args, dict):
            raise ValueError("invalid RPC plugin request")
        for family, registered in self._plugins.items():
            prefix = family + "_"
            if not wire_operation.startswith(prefix):
                continue
            operation = wire_operation[len(prefix):]
            if operation not in registered.plugin.operations:
                raise OSError(errno.ENOSYS, "unsupported RPC plugin operation")
            capability = files.rpc_capabilities.get(family, {})
            if capability.get("state") != "available":
                raise OSError(errno.ENOSYS, "RPC plugin is not available")
            return registered.plugin.dispatch(files, operation, args)
        raise OSError(errno.ENOSYS, "unsupported RPC plugin family")


def load_client_rpc_registry(config: dict[str, Any]) -> ClientRpcRegistry:
    registry = ClientRpcRegistry()
    from .git import plugin as git_plugin
    from .archive import plugin as archive_plugin

    registry.register(git_plugin, source="openkapsel.rpc_plugins.git:plugin")
    registry.register(archive_plugin, source="openkapsel.rpc_plugins.archive:plugin")

    specs = config.get("rpc_plugins", [])
    if specs is None:
        specs = []
    if not isinstance(specs, list) or any(not isinstance(item, str) for item in specs):
        raise ValueError("rpc_plugins must be an array of module:object strings")
    if len(specs) > 32:
        raise ValueError("too many rpc_plugins")
    for spec in specs:
        registry.load_import_spec(spec)
    return registry

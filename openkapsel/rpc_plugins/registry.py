"""Explicit, bounded client RPC plugin loading and self-description."""

from __future__ import annotations

import errno
import importlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol


_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
MAX_DESCRIPTION_CHARS = 1000
MAX_OPERATIONS_PER_PLUGIN = 64
MAX_OPERATION_SCHEMA_BYTES = 32 * 1024


class RpcPlugin(Protocol):
    family: str
    version: int
    description: str
    operations: dict[str, dict[str, Any]]
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
    description: str
    operations: dict[str, dict[str, Any]]


def _description(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} description must be a string")
    value = value.strip()
    if not value or len(value) > MAX_DESCRIPTION_CHARS:
        raise ValueError(f"{label} description must contain 1-{MAX_DESCRIPTION_CHARS} characters")
    return value


def _operation_specs(value: Any, *, family: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not value or len(value) > MAX_OPERATIONS_PER_PLUGIN:
        raise ValueError(f"RPC plugin {family} must declare 1-{MAX_OPERATIONS_PER_PLUGIN} operations")
    result: dict[str, dict[str, Any]] = {}
    for operation, raw in value.items():
        if not isinstance(operation, str) or not _NAME.fullmatch(operation):
            raise ValueError(f"RPC plugin {family} has an invalid operation name")
        if not isinstance(raw, dict) or set(raw) != {"description", "input_schema"}:
            raise ValueError(
                f"RPC plugin {family}.{operation} must declare exactly description and input_schema"
            )
        description = _description(raw["description"], label=f"RPC plugin {family}.{operation}")
        schema = raw["input_schema"]
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise ValueError(f"RPC plugin {family}.{operation} input_schema must be an object schema")
        try:
            encoded = json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            raise ValueError(f"RPC plugin {family}.{operation} input_schema must be JSON serializable") from None
        if len(encoded) > MAX_OPERATION_SCHEMA_BYTES:
            raise ValueError(f"RPC plugin {family}.{operation} input_schema is too large")
        result[operation] = {
            "description": description,
            "input_schema": json.loads(encoded.decode("utf-8")),
        }
    return result


def _plugin_object(value: Any) -> tuple[RpcPlugin, str, dict[str, dict[str, Any]]]:
    if isinstance(value, type):
        value = value()
    elif callable(value) and not hasattr(value, "family"):
        value = value()
    family = getattr(value, "family", None)
    version = getattr(value, "version", None)
    read_only = getattr(value, "read_only", None)
    if not isinstance(family, str) or not _NAME.fullmatch(family):
        raise ValueError("RPC plugin family must match [a-z][a-z0-9_]{0,31}")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError(f"RPC plugin {family} has an invalid version")
    if not isinstance(read_only, bool):
        raise ValueError(f"RPC plugin {family} must declare read_only")
    description = _description(getattr(value, "description", None), label=f"RPC plugin {family}")
    operations = _operation_specs(getattr(value, "operations", None), family=family)
    if not callable(getattr(value, "probe", None)) or not callable(getattr(value, "dispatch", None)):
        raise ValueError(f"RPC plugin {family} must implement probe and dispatch")
    return value, description, operations


class ClientRpcRegistry:
    def __init__(self):
        self._plugins: dict[str, RegisteredPlugin] = {}

    @property
    def families(self) -> frozenset[str]:
        return frozenset(self._plugins)

    def register(self, plugin: RpcPlugin, *, source: str) -> None:
        plugin, description, operations = _plugin_object(plugin)
        if plugin.family == "file":
            raise ValueError("file is a reserved core RPC family")
        if plugin.family in self._plugins:
            raise ValueError(f"duplicate RPC plugin family: {plugin.family}")
        self._plugins[plugin.family] = RegisteredPlugin(
            plugin.family, plugin, source, description, operations
        )

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
                "description": registered.description,
                # Keep the compact list for compatibility with existing servers.
                "operations": sorted(registered.operations),
                # New clients self-describe every operation for dynamic callers.
                "operation_specs": registered.operations,
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
            if wire_operation.startswith(prefix) and wire_operation[len(prefix):] in registered.operations:
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
            if operation not in registered.operations:
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

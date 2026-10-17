"""Internal function contract shared by local and remote execution.

The public function name is independent of the internal method.  Only the
execute entrypoint is public.  Approval data is owned by the implementation:
the control server treats it as opaque JSON and supplies it out of band.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class FunctionImplementation:
    execute: Callable[[dict[str, Any], Any], Any]
    approval_grant: Callable[[Any, Any, int], Any] | None = None
    approval_prepare: Callable[[dict[str, Any]], Any] | None = None

    def __post_init__(self) -> None:
        if not callable(self.execute):
            raise TypeError("execute callback is required")
        if self.approval_grant is not None and not callable(self.approval_grant):
            raise TypeError("approval_grant must be callable")
        if self.approval_prepare is not None:
            if not callable(self.approval_prepare):
                raise TypeError("approval_prepare must be callable")
            if self.approval_grant is None:
                raise ValueError("approval_prepare requires approval_grant")


class FunctionRegistry:
    """Dispatch internal methods without reserving public name suffixes."""

    def __init__(self) -> None:
        self._functions: dict[str, FunctionImplementation] = {}

    def register(
        self,
        name: str,
        *,
        execute: Callable[[dict[str, Any], Any], Any],
        approval_grant: Callable[[Any, Any, int], Any] | None = None,
        approval_prepare: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        if not isinstance(name, str) or not name or name.startswith("."):
            raise ValueError("invalid function name")
        if name in self._functions:
            raise ValueError("duplicate function name")
        self._functions[name] = FunctionImplementation(
            execute=execute,
            approval_grant=approval_grant,
            approval_prepare=approval_prepare,
        )

    def get(self, name: str) -> FunctionImplementation:
        return self._functions[name]

    def approval_methods(self, name: str) -> tuple[str, ...]:
        """Advertise internal methods to the control server, not to AI."""
        implementation = self.get(name)
        if implementation.approval_grant is None:
            return ()
        if implementation.approval_prepare is None:
            return ("approval.grant",)
        return ("approval.prepare", "approval.grant")

    def execute(self, name: str, args: dict[str, Any], *, auth: Any = None) -> Any:
        """Auth is injected by the control layer, never merged into args."""
        if not isinstance(args, dict):
            raise TypeError("function arguments must be a JSON object")
        return self.get(name).execute(args, auth)

    def prepare(self, name: str, args: dict[str, Any]) -> Any | None:
        """When absent, the control server skips the prepare RPC altogether."""
        implementation = self.get(name)
        if implementation.approval_grant is None:
            raise ValueError("function does not support approval")
        if implementation.approval_prepare is None:
            return None
        if not isinstance(args, dict):
            raise TypeError("approval arguments must be a JSON object")
        return implementation.approval_prepare(args)

    def grant(self, name: str, *, old_auth: Any, request: Any, seconds: int) -> Any:
        implementation = self.get(name)
        if implementation.approval_grant is None:
            raise ValueError("function does not support approval")
        # The implementation decides how to merge old_auth and request.
        return implementation.approval_grant(old_auth, request, seconds)

    def describe(self) -> dict[str, dict[str, bool]]:
        """Internal capability metadata; not a public Discovery tool list."""
        return {
            name: {
                "approval": implementation.approval_grant is not None,
                "approval_prepare": implementation.approval_prepare is not None,
            }
            for name, implementation in self._functions.items()
        }

    def dispatch_internal(self, envelope: dict[str, Any]) -> Any:
        """Dispatch an internal request received from the trusted control layer.

        Method is not a suffix of function names.  Only the execute method
        consumes operation args and the injected auth; other methods are
        strictly internal and must never be exposed by the public router.
        """
        if not isinstance(envelope, dict):
            raise TypeError("function request must be an object")
        name = envelope.get("function")
        method = envelope.get("method")
        if not isinstance(name, str) or not isinstance(method, str):
            raise ValueError("function and method are required")
        if method == "execute":
            if set(envelope) - {"function", "method", "args", "internal"}:
                raise ValueError("invalid execute envelope")
            internal = envelope.get("internal", {})
            if not isinstance(internal, dict) or set(internal) - {"auth"}:
                raise ValueError("invalid internal authorization envelope")
            return self.execute(name, envelope.get("args", {}), auth=internal.get("auth"))
        if method == "approval.prepare":
            if set(envelope) != {"function", "method", "args"}:
                raise ValueError("invalid prepare envelope")
            return self.prepare(name, envelope["args"])
        if method == "approval.grant":
            if set(envelope) != {"function", "method", "old_auth", "request", "seconds"}:
                raise ValueError("invalid grant envelope")
            return self.grant(name, old_auth=envelope["old_auth"], request=envelope["request"], seconds=envelope["seconds"])
        raise ValueError("unknown internal function method")

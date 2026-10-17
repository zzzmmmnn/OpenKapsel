"""In-process Local Client for Server-hosted workspace execution.

This adapter deliberately has no transport or WebSocket lifecycle. It
executes through the same client-side RPC plugin registry and ClientFiles
provider that remote Mapping Clients use. Authentication/routing remain
the control server's responsibility.
"""
from __future__ import annotations

from typing import Any
import os

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.execution.function_registry import FunctionRegistry


class LocalRpcSession:
    def __init__(self, files: ClientFiles) -> None:
        self.files = files

    def dispatch_file(self, operation: str, arguments: dict[str, Any]) -> Any:
        """Invoke the same native File API used by Mapping Clients."""
        from openkapsel.mapping.mapping_transport import FILE_API_OPERATIONS
        if operation not in FILE_API_OPERATIONS:
            raise ValueError("unsupported Client File API operation")
        return self.files.dispatch("api_" + operation, arguments)

    def dispatch_sync(self, family: str, operation: str, args: dict[str, Any]) -> Any:
        return self.files.rpc_registry.dispatch_sync(
            self.files, family, operation, args
        )

    def dispatch_task(
        self,
        family: str,
        operation: str,
        args: dict[str, Any],
        task_context: Any,
    ) -> Any:
        return self.files.rpc_registry.dispatch_task(
            self.files, family, operation, args, task_context
        )


class LocalClient:
    """Server-local executor facade, separate from HTTP control logic."""

    def __init__(self, rpc_registry, rpc_capabilities, *, filename_index=None) -> None:
        self.rpc_registry = rpc_registry
        self.rpc_capabilities = rpc_capabilities
        self.filename_index = filename_index
        self.functions = FunctionRegistry()
        from openkapsel.execution.builtin_functions import shell_grant
        self.functions.register(
            "shell.exec", execute=self._execute_shell, approval_grant=shell_grant
        )
        from openkapsel.client_runtime.file_approval import register_file_functions
        register_file_functions(self.functions, native_execute=self._execute_approved_file)

    @staticmethod
    def _execute_approved_file(args, auth, *, access):
        from openkapsel.client_runtime.file_approval import FileApproval
        if args.get("operation") == "approval_status":
            return {"granted": FileApproval.status(args["arguments"], auth)}
        raise ValueError("File execution requires a request-scoped Local Client session")

    def execute_file(self, handler, method, *args, **kwargs):
        from openkapsel.files.file_handlers import FileExecutionMixin, FILE_APPROVAL_WRITE
        pending = getattr(handler, "_file_function_request", None)
        if pending is not None:
            from openkapsel.client_runtime.file_approval import FileApproval, register_file_functions
            operation, values, auth = pending
            # HTTP/stream objects belong to this in-process session, never to
            # the public operation JSON. Both transports execute the same
            # function contract with out-of-band opaque auth.
            def execute(arguments, injected_auth, *, access):
                FileApproval.authorize_native(handler, arguments["operation"], arguments["arguments"], injected_auth)
                return getattr(FileExecutionMixin, method)(handler, *args, **kwargs)
            functions = FunctionRegistry()
            register_file_functions(functions, native_execute=execute)
            return functions.execute("files.write" if operation in FILE_APPROVAL_WRITE else "files.read",
                {"operation": operation, "arguments": values}, auth=auth)
        return getattr(FileExecutionMixin, method)(handler, *args, **kwargs)

    @staticmethod
    def _execute_shell(args, auth):
        from openkapsel.execution.shell_execution import start_shell_task
        options = dict(args["options"])
        # Legacy routes still pass a server-validated unsandboxed flag.
        # A new function auth overrides that flag with client-owned policy.
        if auth is not None:
            if not isinstance(auth, dict):
                raise ValueError("invalid Shell authorization")
            options["unsandboxed"] = auth.get("unsandboxed") is True
        return start_shell_task(
            args["server"], args["record"], args["scope_root"], **options
        )

    def rpc_session(self, root, *, writable: bool) -> LocalRpcSession:
        index = self.filename_index
        if callable(index):
            index = index()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        files = factory(
            root,
            writable=writable,
            rpc_registry=self.rpc_registry,
            rpc_capabilities=self.rpc_capabilities,
            filename_index=index,
            index_owned=False,
        )
        return LocalRpcSession(files)

    def start_shell(self, server, record, scope_root, *, auth=None, **options):
        """Run Server workspace Shell through the local function registry."""
        return self.functions.execute(
            "shell.exec", {
                "server": server, "record": record,
                "scope_root": scope_root, "options": options,
            }, auth=auth,
        )

    def file_session(self, root, *, writable: bool) -> LocalRpcSession:
        return self.rpc_session(root, writable=writable)

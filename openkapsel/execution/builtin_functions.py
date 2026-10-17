"""Built-in Client function definitions.

The function owns both the merged auth format and its final interpretation.
An unsandboxed Shell grant is currently target-wide, mirroring the legacy
Shell approval; a future implementation can narrow this without server changes.
"""
from __future__ import annotations

import errno

from openkapsel.execution.function_registry import FunctionRegistry


def shell_grant(old_auth, request):
    """Function-owned merge. The Control Server must never interpret it."""
    if not isinstance(request, dict):
        raise ValueError("invalid Shell approval request")
    existing = dict(old_auth) if isinstance(old_auth, dict) else {}
    return dict(existing, unsandboxed=True)


def register_client_shell(functions: FunctionRegistry, tasks) -> None:
    def execute(args, auth):
        if "unsandboxed" in args:
            # This is strictly internal data, not a user/AI function argument.
            raise OSError(errno.EINVAL, "unsandboxed is not a function argument")
        if auth is not None and not isinstance(auth, dict):
            raise OSError(errno.EACCES, "invalid Shell authorization")
        elevated = isinstance(auth, dict) and auth.get("unsandboxed") is True
        return tasks.dispatch("task_start", dict(args, unsandboxed=elevated))

    functions.register(
        "shell.exec",
        execute=execute,
        approval_grant=shell_grant,
        # No preapproval callback: the server skips this optional method.
    )

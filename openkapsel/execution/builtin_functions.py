"""Built-in Client function definitions.

The function owns both the merged auth format and its final interpretation.
An unsandboxed Shell grant is currently target-wide, mirroring the legacy
Shell approval; a future implementation can narrow this without server changes.
"""
from __future__ import annotations

import errno
import math
import time

from openkapsel.execution.function_registry import FunctionRegistry


def _active_shell_grants(grants):
    """Only Client-clock-valid entries can authorize unsandboxed execution."""
    now = time.time()
    active = []
    for item in grants:
        if (not isinstance(item, dict)
                or type(item.get("expires_at")) not in (int, float)
                or not 0 <= item["expires_at"] <= 10**13
                or not math.isfinite(item["expires_at"])):
            raise OSError(errno.EACCES, "invalid Shell grant expiry")
        if item["expires_at"] > now:
            active.append(item)
    return active


def shell_grant(old_auth, request, seconds):
    """Renew only the Shell scope; leave unrelated Client grants untouched."""
    if not isinstance(request, dict) or type(seconds) is not int or seconds <= 0:
        raise ValueError("invalid Shell approval request")
    existing = dict(old_auth) if isinstance(old_auth, dict) else {}
    grants = [item for item in _active_shell_grants(existing.get("grants", []))
              if item.get("unsandboxed") is not True]
    return dict(existing, grants=[*grants,
                {"expires_at": time.time() + seconds, "unsandboxed": True}])


def shell_auth_unsandboxed(auth) -> bool:
    """Interpret current Client grants or pre-migration Server Shell auth.

    Legacy authorizations were already password-approved and injected
    privately by the control Server. Preserve them across a Client-first
    rollout; the new grants format remains authoritative when present.
    """
    if auth is None:
        return False
    if not isinstance(auth, dict):
        raise OSError(errno.EACCES, "invalid Shell authorization")
    if isinstance(auth.get("grants"), list):
        return any(item.get("unsandboxed") is True
                   for item in _active_shell_grants(auth["grants"]))
    if auth == {"unsandboxed": True}:
        return True
    raise OSError(errno.EACCES, "unrecognized Shell authorization")


def register_client_shell(functions: FunctionRegistry, tasks) -> None:
    def execute(args, auth):
        if "unsandboxed" in args:
            # This is strictly internal data, not a user/AI function argument.
            raise OSError(errno.EINVAL, "unsandboxed is not a function argument")
        return tasks.dispatch("task_start", dict(
            args, unsandboxed=shell_auth_unsandboxed(auth)))

    functions.register(
        "shell.exec",
        execute=execute,
        approval_grant=shell_grant,
        # No preapproval callback: the server skips this optional method.
    )

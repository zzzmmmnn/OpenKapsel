"""Read-only Git inspection RPC plugin."""

from __future__ import annotations

import shutil
from typing import Any

from ...errors import ApiError
from ...git_operations import GIT_OPERATIONS
from ...git_read import inspect_git


class GitRpcPlugin:
    family = "git"
    version = 2
    operations = frozenset(GIT_OPERATIONS)
    read_only = True

    def probe(self, config: dict[str, Any]):
        if shutil.which("git") is None:
            return "unsupported", "dependency_missing", {"dependency": "git"}
        return "available", None, None

    def dispatch(self, files, operation: str, args: dict[str, Any]):
        try:
            body = inspect_git(
                files.paths,
                files.path(args.get("cwd", ".")),
                operation,
                args.get("options", {}),
                args.get("timeout_seconds", 15),
            )
            return {"status": 200, "body": body}
        except ApiError as exc:
            return {
                "status": int(exc.status),
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                },
            }


plugin = GitRpcPlugin()

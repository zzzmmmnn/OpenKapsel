"""Read-only Git inspection RPC plugin."""

from __future__ import annotations

import shutil
from typing import Any

from ...errors import ApiError
from ...git_operations import GIT_OPERATIONS
from ...git_read import inspect_git


_DESCRIPTIONS = {
    "status": "Show bounded porcelain repository status.",
    "diff": "Show a bounded read-only Git diff for the working tree, index, or revisions.",
    "diff_stat": "Show a bounded summary of changed files and line counts.",
    "log": "Show bounded commit history.",
    "show": "Show one bounded revision without running repository helpers.",
    "ls_files": "List tracked repository files.",
}


def _schema(operation: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "cwd": {
            "type": "string",
            "default": ".",
            "description": "Client-export-relative repository root.",
        },
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 100,
            "description": "Optional literal repository-relative path filters.",
        },
        "timeout_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": 20,
            "default": 15,
        },
    }
    if operation in {"diff", "diff_stat", "log", "show"}:
        properties["revision"] = {"type": "string", "maxLength": 256}
    if operation in {"diff", "diff_stat"}:
        properties["to_revision"] = {"type": "string", "maxLength": 256}
        properties["staged"] = {"type": "boolean", "default": False}
    if operation == "log":
        properties["limit"] = {"type": "integer", "minimum": 1, "maximum": 200, "default": 20}
        properties["skip"] = {"type": "integer", "minimum": 0, "maximum": 100000, "default": 0}
    return {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }


class GitRpcPlugin:
    family = "git"
    version = 2
    description = (
        "Read-only bounded Git inspection against a sanitized local snapshot. "
        "Requires the host git executable and never falls back to server/FUSE for mappings."
    )
    operations = {
        operation: {
            "description": _DESCRIPTIONS[operation],
            "input_schema": _schema(operation),
        }
        for operation in GIT_OPERATIONS
    }

    def probe(self, config: dict[str, Any]):
        if shutil.which("git") is None:
            return "unsupported", "dependency_missing", {"dependency": "git"}
        return "available", None, None

    def dispatch(self, files, operation: str, args: dict[str, Any]):
        try:
            # Internal server Git routing still sends an explicit options object.
            # Generic RPC callers use the self-described flattened schema above.
            if "options" in args:
                options = args.get("options", {})
            else:
                options = {
                    key: value
                    for key, value in args.items()
                    if key not in {"cwd", "timeout_seconds"}
                }
            body = inspect_git(
                files.paths,
                files.path(args.get("cwd", ".")),
                operation,
                options,
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

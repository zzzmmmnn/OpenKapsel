"""Bounded, fixed Git operations shared by server and provider routing."""

from __future__ import annotations

import os

from openkapsel.errors import ApiError


GIT_READ_OPERATIONS = ("status", "diff", "log", "show", "ls_files", "diff_stat")
GIT_WRITE_OPERATIONS = ("add", "commit", "restore", "checkout")
GIT_NETWORK_OPERATIONS = ("fetch", "pull", "clone")
GIT_OPERATIONS = GIT_READ_OPERATIONS + GIT_WRITE_OPERATIONS + GIT_NETWORK_OPERATIONS


def git_arguments(operation, options):
    """Build the legacy/read REST argv for a sanitized Git snapshot."""
    if operation not in GIT_READ_OPERATIONS:
        raise ApiError(400, "invalid_git_operation", "unsupported Git inspection operation")
    if not isinstance(options, dict):
        raise ApiError(400, "invalid_request", "Git options must be an object")
    allowed = {"paths"}
    if operation in {"diff", "diff_stat"}:
        allowed |= {"revision", "to_revision", "staged"}
    if operation in {"log", "show"}:
        allowed.add("revision")
    if operation == "log":
        allowed |= {"limit", "skip"}
    if set(options) - allowed:
        raise ApiError(400, "invalid_request", "unsupported Git option")

    def revision(key, default=None):
        value = options.get(key, default)
        if value is not None and (
            not isinstance(value, str)
            or not value
            or len(value) > 256
            or value.startswith("-")
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
        ):
            raise ApiError(400, "invalid_request", f"{key} must be a bounded revision, not an option")
        return value

    paths = options.get("paths", [])
    if (
        not isinstance(paths, list)
        or len(paths) > 100
        or any(
            not isinstance(p, str)
            or not p
            or len(p) > 4096
            or "\x00" in p
            or any(0xD800 <= ord(c) <= 0xDFFF for c in p)
            or p.startswith(("/", "\\"))
            or "\\" in p
            or ":" in p
            or ".." in p.split("/")
            for p in paths
        )
        or sum(map(len, paths)) > 16000
    ):
        raise ApiError(400, "invalid_request", "paths must be bounded literal repository-relative paths")
    argv = [
        "git", "--no-pager", "--no-optional-locks", "--literal-pathspecs",
        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
        "-c", "color.ui=false", "-c", "core.quotePath=true",
        "-c", "submodule.recurse=false", "-c", "maintenance.auto=false",
        "-c", "gc.auto=0",
    ]
    if operation == "status":
        argv += ["status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=all"]
    elif operation == "ls_files":
        argv += ["ls-files", "--cached"]
    elif operation == "log":
        for key, default, maximum, minimum in (("limit", 20, 200, 1), ("skip", 0, 100000, 0)):
            value = options.get(key, default)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ApiError(400, "invalid_request", f"{key} is outside its allowed range")
        argv += [
            "log", "--no-show-signature", "--format=%H%x09%aI%x09%an%x09%s",
            f"--max-count={options.get('limit', 20)}", f"--skip={options.get('skip', 0)}",
            revision("revision", "HEAD"),
        ]
    elif operation == "show":
        argv += [
            "show", "--no-show-signature", "--no-ext-diff", "--no-textconv", "--no-renames",
            "--ignore-submodules=all", "--format=fuller", revision("revision", "HEAD"),
        ]
    else:
        staged = options.get("staged", False)
        if type(staged) is not bool:
            raise ApiError(400, "invalid_request", "staged must be boolean")
        first, second = revision("revision"), revision("to_revision")
        if second and (not first or staged):
            raise ApiError(400, "invalid_request", "to_revision requires revision and cannot combine with staged")
        argv += ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=all"]
        if operation == "diff_stat":
            argv += ["--stat=120"]
        if staged:
            argv += ["--cached"]
        argv += [value for value in (first, second) if value is not None]
    return argv + ["--", *paths]


def git_tool_properties(operation):
    if operation not in GIT_READ_OPERATIONS:
        raise ValueError("Git MCP read tool requires a read operation")
    properties = {
        "path": {"type": "string", "default": "."},
        "file": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 20, "default": 15},
    }
    if operation in {"diff", "diff_stat", "log", "show"}:
        properties["revision"] = {"type": "string", "maxLength": 256}
    if operation in {"diff", "diff_stat"}:
        properties.update(
            to_revision={"type": "string", "maxLength": 256},
            staged={"type": "boolean"},
        )
    if operation == "log":
        properties.update(
            limit={"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
            skip={"type": "integer", "minimum": 0, "maximum": 100000, "default": 0},
        )
    return properties


def git_discovery(base):
    result = {}
    for operation in GIT_READ_OPERATIONS:
        query = {"path": ".", "file": "optional repeated literal repository-relative path", "timeout_seconds": 15}
        if operation in {"diff", "diff_stat", "log", "show"}:
            query["revision"] = "optional revision (HEAD by default for log/show)"
        if operation in {"diff", "diff_stat"}:
            query.update(to_revision="optional second revision", staged=False)
        if operation == "log":
            query.update(limit=20, skip=0)
        result["git_" + operation] = {
            "method": "GET", "url": f"{base}/git/{operation}", "query": query,
            "authentication": "read permission; read URL is sufficient for REST; MCP uses its existing connection authentication",
            "notes": "Read-only bounded sanitized snapshot; no Shell/write/client allow_exec needed. Git RPC family version 2 for mapped reads; legacy git_api advertisements remain accepted during upgrades and unsupported operations fail closed. Synchronous result (no task/polling); 422 on Git failure, 504 timeout, 413 snapshot limit, 409 unsupported layout. Requires an ordinary SHA-1 repository root with .git directory, not linked worktrees or alternates. Symlinks/reparse points and special files in copied paths are rejected. Max 128 MiB and 100000 nodes; 4 concurrent queries per process. Timeout 15s default, maximum 20s. Output capped at 64 KiB per stream; narrow queries if truncated. Git is installed on the host, not in a Shell container. Config/hooks/filters/global config are excluded. Log/show/revision comparisons copy metadata only; status and working-tree diffs also copy working files. Private .openkapsel is excluded; the snapshot is not transactional.",
        }
    return result

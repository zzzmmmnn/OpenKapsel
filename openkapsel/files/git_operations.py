"""Bounded, fixed Git operations shared by server and provider routing."""

from __future__ import annotations

import os

from openkapsel.auth.path_access import has_private_component
from openkapsel.errors import ApiError


GIT_READ_OPERATIONS = ("status", "diff", "log", "show", "ls_files", "diff_stat",
                       "branch", "blame", "tag", "stash")
GIT_WRITE_OPERATIONS = ("add", "commit", "restore", "checkout",
                        "branch_create", "branch_delete", "tag_create", "tag_delete",
                        "stash_push", "stash_apply", "stash_pop", "stash_drop")
GIT_NETWORK_OPERATIONS = ("fetch", "pull", "push", "clone")
GIT_OPERATIONS = GIT_READ_OPERATIONS + GIT_WRITE_OPERATIONS + GIT_NETWORK_OPERATIONS


def git_arguments(operation, options):
    """Build fixed bounded Git read arguments for the real repository."""
    if operation not in GIT_READ_OPERATIONS:
        raise ApiError(400, "invalid_git_operation", "unsupported Git inspection operation")
    if not isinstance(options, dict):
        raise ApiError(400, "invalid_request", "Git options must be an object")
    allowed = {"paths"}
    if operation in {"diff", "diff_stat"}:
        allowed |= {"revision", "to_revision", "staged"}
    if operation in {"log", "show", "blame"}:
        allowed.add("revision")
    if operation == "blame":
        allowed.add("path")
    if operation == "branch":
        allowed.add("all")
    if operation == "log":
        allowed |= {"limit", "skip"}
    if operation in {"branch", "tag", "stash"}:
        allowed.discard("paths")
    if operation == "blame":
        allowed.discard("paths")
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
    if operation == "branch":
        all_branches = options.get("all", False)
        if type(all_branches) is not bool:
            raise ApiError(400, "invalid_request", "all must be boolean")
        return argv + ["branch", "--no-color", "--list", *(["--all"] if all_branches else [])]
    if operation == "tag":
        return argv + ["tag", "--list", "--sort=-creatordate"]
    if operation == "stash":
        return argv + ["stash", "list", "--format=%gd%x09%gs"]
    if operation == "blame":
        path = options.get("path")
        if not isinstance(path, str) or not path or len(path) > 4096 or path.startswith("/") or chr(92) in path or chr(0) in path or ":" in path or ".." in path.split("/") or has_private_component(path):
            raise ApiError(400, "invalid_request", "path must be a literal repository-relative file")
        return argv + ["blame", "--porcelain", "--no-textconv", revision("revision", "HEAD"), "--", path]
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
    if operation in {"diff", "diff_stat", "log", "show", "blame"}:
        properties["revision"] = {"type": "string", "maxLength": 256}
    if operation in {"diff", "diff_stat"}:
        properties.update(
            to_revision={"type": "string", "maxLength": 256},
            staged={"type": "boolean"},
        )
    if operation == "blame":
        properties["path"] = {"type": "string", "minLength": 1, "maxLength": 4096}
        properties.pop("file", None)
    if operation == "branch":
        properties["all"] = {"type": "boolean", "default": False}
    if operation == "log":
        properties.update(
            limit={"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
            skip={"type": "integer", "minimum": 0, "maximum": 100000, "default": 0},
        )
    return properties

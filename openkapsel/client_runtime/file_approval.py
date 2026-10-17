"""Client-owned File approval policy, shared by local and Mapping executors.

The control server stores the JSON returned here without interpreting scopes.
Preparing an approval performs lexical checks only. Filesystem resolution runs
only in the grant callback after the browser has verified the password.
"""
from __future__ import annotations

import errno
import os
import secrets
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from openkapsel.errors import ApiError
from openkapsel.auth.path_access import effective_path_access


def absolute_scope(value):
    if (not isinstance(value, str) or not value or len(value) > 4096
            or "\x00" in value or ".." in Path(value).parts
            or any(p == ".openkapsel" or p.startswith(".openkapsel-") for p in Path(value).parts)
            or os.name != "nt" and "\\" in value):
        raise ApiError(400, "invalid_path", "approval requires an absolute path without traversal")
    path = Path(value)
    if not path.is_absolute() or path == Path(path.anchor):
        raise ApiError(400, "invalid_path", "host roots cannot be approved")
    if os.name == "nt":
        from openkapsel.client_runtime.windows_filename_policy import check_windows_filename_parts
        try:
            check_windows_filename_parts(path.parts[1:])
        except OSError:
            raise ApiError(400, "invalid_path", "invalid Windows approval path") from None
    return path


class FileApproval:
    def __init__(self, files=None):
        self.files = files
        self.streams = {}

    def prepare(self, args):
        if set(args) - {"path", "scope_is_directory"}:
            raise ApiError(400, "invalid_request", "invalid File approval request")
        path = args.get("path", "")
        directory = args.get("scope_is_directory", True)
        if not isinstance(directory, bool) or not path and not directory:
            raise ApiError(400, "invalid_request", "invalid directory scope")
        if path:
            absolute_scope(path)
        return {"request": dict(args), "confirmation_required": bool(path),
                "display": {"requested_path": path or "Workspace", "scope_is_directory": directory}}

    def grant(self, old_auth, request, *, write=False):
        self.prepare(request)
        updated = {"workspace": bool((old_auth or {}).get("workspace")),
                   "paths": list((old_auth or {}).get("paths", []))}
        raw = request.get("path", "")
        if not raw:
            updated["workspace"] = True
            return updated
        directory = request.get("scope_is_directory", True)
        try:
            actual = absolute_scope(raw).resolve(strict=directory)
            scope = actual if directory else actual.parent
            if not scope.is_dir():
                raise ValueError("not a directory")
            absolute_scope(str(scope))
            if self.files is not None:
                self.files.ensure_accessible_path(actual)
        except (OSError, RuntimeError, ValueError):
            raise ApiError(400, "approval_path_unavailable", "approval path is unavailable") from None
        # Canonical scopes, not aliases. The execute path rechecks realpaths
        # on every operation and pins descriptors to these approved roots.
        roots = [Path(p) for p in updated["paths"]]
        if not any(scope == p or p in scope.parents for p in roots):
            roots = [p for p in roots if scope not in p.parents] + [scope]
        updated["paths"] = sorted(str(p) for p in roots)
        return updated

    @staticmethod
    def paths(auth):
        if (not isinstance(auth, dict) or set(auth) - {"workspace", "paths"}
                or not isinstance(auth.get("workspace"), bool)
                or not isinstance(auth.get("paths"), list)
                or any(not isinstance(p, str) for p in auth["paths"])):
            raise ApiError(403, "invalid_file_authorization", "invalid File authorization")
        return tuple(absolute_scope(p) for p in auth["paths"])

    @classmethod
    def check(cls, value, root, auth, *, write=False, rules=()):
        if (not isinstance(value, str) or "\x00" in value
                or ".." in Path(value).parts or os.name != "nt" and "\\" in value):
            raise ApiError(400, "invalid_path", "File approval rejects traversal and ambiguous paths")
        candidate = Path(value) if value else root
        if not candidate.is_absolute():
            if candidate.drive:
                raise ApiError(400, "invalid_path", "drive-relative File paths are ambiguous")
            candidate = root / candidate
        if os.name == "nt":
            from openkapsel.client_runtime.windows_filename_policy import check_windows_filename_parts
            try:
                check_windows_filename_parts(candidate.parts[1:])
            except OSError:
                raise ApiError(400, "invalid_path", "invalid Windows File path") from None
        candidate = Path(os.path.abspath(candidate))
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            raise ApiError(404, "path_unavailable", "path does not exist or access is denied") from None
        scopes = cls.paths(auth)
        internal = resolved == root or root in resolved.parents
        if not (internal and auth["workspace"] or
                any(resolved == p or p in resolved.parents for p in scopes)):
            raise ApiError(404, "path_unavailable", "path does not exist or access is denied")
        if any(p == ".openkapsel" or p.startswith(".openkapsel-") for p in resolved.parts):
            raise ApiError(403, "reserved_path", "internal paths cannot be approved")
        granted_rules = (*rules, *(SimpleNamespace(path=str(p), access="rw" if write else "ro") for p in scopes))
        for checked in (candidate, resolved):
            policy = effective_path_access(checked, root, write, granted_rules, resolve_symlinks=False)
            # An alias outside all scopes may name an authorized canonical
            # path. Explicit deny/ro entries still apply to that spelling.
            if policy == "deny" or write and policy == "ro":
                raise ApiError(403, "path_access_denied", "path is denied or read-only")
        if write:
            for rule in rules:
                protected = Path(rule.path)
                if rule.access in {"deny", "ro"} and (resolved == protected or resolved in protected.parents):
                    raise ApiError(403, "path_access_denied", "directory contains protected paths")
        return resolved

    @classmethod
    def authorize_native(cls, handler, operation, values, auth):
        """Apply client-owned policy to one native request, preserving limits."""
        from openkapsel.files.file_handlers import FILE_APPROVAL_WRITE
        write = operation in FILE_APPROVAL_WRITE
        handler._file_approval_active = True
        scopes = cls.paths(auth)
        rules = handler.token_record.allowed_paths
        if operation == "fs_read_files":
            paths = values.get("paths", [])
        elif operation in {"fs_manifest", "fs_mutate"} and isinstance(values.get("items"), list):
            paths = [item.get("path") for item in values["items"] if isinstance(item, dict)]
        elif operation == "fs_move":
            paths = [values.get("source"), values.get("destination")]
        else:
            paths = [values.get("path", ".")]
        denied = set()
        for raw in paths:
            try:
                real = cls.check(raw, handler.token_scope_root, auth, write=write, rules=rules)
                row = handler.server.mappings.at_path(real)
                if row is not None:
                    raise ApiError(403, "file_approval_target_mismatch", "file path does not match approved target")
            except ApiError as exc:
                if operation != "fs_read_files" or exc.code not in {"path_unavailable", "path_access_denied"}:
                    raise
                candidate = Path(raw)
                if not candidate.is_absolute():
                    candidate = handler.token_scope_root / candidate
                denied.add(str(candidate))
        from openkapsel.auth.tokens import PathGrant
        handler._file_approval_denied_paths = frozenset(denied)
        handler._file_function_policy = (auth, rules, write)
        handler._file_approval_active = True
        handler.token_record = replace(handler.token_record,
            allowed_paths=(*rules, *(PathGrant(str(p), access="rw" if write else "ro") for p in scopes)),
            **({"can_write": True} if write else {"can_read": True}))

    def execute(self, operation, arguments, auth, *, write):
        """Mapping execution: native path checks stay entirely on this Client."""
        from openkapsel.client_runtime.approved_file_api import ApprovedFileAPI
        if operation == "approval_status":
            return {"granted": self.status(arguments, auth)}
        if operation == "file_stream":
            with self.files.lock:
                return self.stream(arguments, auth, write=write)
        if write:
            with self.files.lock:
                return ApprovedFileAPI.dispatch_approved(self.files, operation, arguments, auth, write=write)
        return ApprovedFileAPI.dispatch_approved(self.files, operation, arguments, auth, write=write)

    def stream(self, arguments, auth, *, write):
        from openkapsel.client_runtime.approved_file_api import ApprovedFiles
        from openkapsel.client_runtime.client_files import ClientFiles
        if (not isinstance(arguments, dict) or set(arguments) != {"operation", "args", "rules"}
                or not isinstance(arguments["args"], dict)):
            raise OSError(errno.EINVAL, "invalid File stream")
        operation, args = arguments["operation"], dict(arguments["args"])
        allowed = {"stat", "open", "fstat", "read", "close"}
        if write and self.files.writable:
            allowed |= {"create", "write", "flush", "mkdir", "rename", "unlink", "truncate_handle"}
        if operation not in allowed or not write and operation == "open" and (
                args.get("mode", "r") != "r" or args.get("truncate")):
            raise OSError(errno.EACCES, "File stream access denied")
        rules = tuple(SimpleNamespace(path=str(Path(r["path"]) if Path(r["path"]).is_absolute()
            else self.files.root / r["path"]), access=r["access"]) for r in arguments["rules"])
        provider = ApprovedFiles(self.files, auth, write, rules)
        handle = args.get("handle")
        if handle is not None:
            record = self.streams.get(handle)
            if record is None or record[2] != write:
                raise OSError(errno.EBADF, "File stream is unavailable")
            if operation != "close":
                provider.path(record[1])
            args["handle"] = record[0]
        dispatch = ClientFiles._dispatch
        if os.name == "nt" and operation in {"stat", "unlink"}:
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            dispatch = WindowsClientFiles._dispatch
        result = dispatch(provider, operation, args)
        if operation in {"open", "create"}:
            token = secrets.token_urlsafe(24)
            self.streams[token] = (result, str(provider.path(args["path"])), write)
            return token
        if operation == "close":
            self.streams.pop(handle, None)
        return result

    @classmethod
    def status(cls, request, auth):
        FileApproval().prepare(request)
        paths = cls.paths(auth)
        if not request.get("path"):
            return auth["workspace"]
        try:
            actual = absolute_scope(request["path"]).resolve(strict=False)
            return any(actual == p or p in actual.parents for p in paths)
        except (OSError, RuntimeError):
            return False


def register_file_functions(functions, files=None, *, native_execute=None):
    policy = FileApproval(files)
    for access in ("read", "write"):
        def execute(args, auth, access=access):
            if native_execute is not None:
                return native_execute(args, auth, access=access)
            return policy.execute(args["operation"], args["arguments"], auth, write=access == "write")
        functions.register("files." + access, execute=execute,
                           approval_prepare=policy.prepare,
                           approval_grant=lambda old, request, access=access: policy.grant(old, request, write=access == "write"))

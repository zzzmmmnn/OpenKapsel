"""Client-owned File approval policy, shared by local and Mapping executors.

The control server stores the JSON returned here without interpreting scopes.
Preparing an approval performs lexical checks only. Filesystem resolution runs
only in the grant callback after the browser has verified the password.
"""
from __future__ import annotations

import errno
import math
import os
import secrets
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from openkapsel.errors import ApiError
from openkapsel.auth.path_access import effective_path_access, has_private_component


def absolute_scope(value):
    if (not isinstance(value, str) or not value or len(value) > 4096
            or "\x00" in value or ".." in Path(value).parts
            or any(part.casefold().startswith(".openkapsel-") for part in Path(value).parts)
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

    def grant(self, old_auth, request, seconds, *, write=False):
        self.prepare(request)
        if type(seconds) is not int or seconds <= 0:
            raise ValueError("invalid File approval duration")
        updated = dict(old_auth) if isinstance(old_auth, dict) else {}
        grants = self._active_grants(updated) if old_auth is not None else []
        raw = request.get("path", "")
        if not raw:
            new_item = {"expires_at": time.time() + seconds, "workspace": True}
            grants = [item for item in grants if item.get("workspace") is not True]
            updated["grants"] = [*grants, new_item]
            return updated
        directory = request.get("scope_is_directory", True)
        try:
            actual = absolute_scope(raw).resolve(strict=directory)
            scope = actual if directory else actual.parent
            if not scope.is_dir():
                raise ValueError("not a directory")
            absolute_scope(str(scope))
            if self.files is not None:
                # Either read or write Approval may target protect, even when
                # ordinary Client access cannot inspect the protected path.
                # Absolute deny and hard Client configuration never qualify.
                protected = (*self.files.global_protected_paths,
                             *self.files.sandbox_denied_paths)
                if any(actual == p or p in actual.parents for p in protected):
                    raise OSError(errno.EACCES, "protected Client path")
                for checked in (Path(raw), actual):
                    if effective_path_access(checked, self.files.root,
                            self.files.writable, self.files.sandbox_path_rules,
                            resolve_symlinks=False) == "deny":
                        raise OSError(errno.EACCES, "absolute deny cannot be approved")
        except (OSError, RuntimeError, ValueError):
            raise ApiError(400, "approval_path_unavailable", "approval path is unavailable") from None
        # Canonical scopes, not aliases. Keep independent child protect grants,
        # and renew only the specifically confirmed canonical directory.
        new_item = {"expires_at": time.time() + seconds, "path": str(scope)}
        grants = [item for item in grants if item.get("path") != str(scope)]
        updated["grants"] = [*grants, new_item]
        return updated

    @staticmethod
    def _active_grants(auth):
        """Client clock is authoritative; the Server's grace never grants access."""
        if not isinstance(auth, dict) or not isinstance(auth.get("grants"), list):
            raise ApiError(403, "invalid_file_authorization", "invalid File authorization")
        now = time.time()
        active = []
        for item in auth["grants"]:
            if (not isinstance(item, dict) or type(item.get("expires_at")) not in (int, float)
                    or not 0 <= item["expires_at"] <= 10**13
                    or not math.isfinite(item["expires_at"])
                    or not (item.get("workspace") is True or isinstance(item.get("path"), str))):
                raise ApiError(403, "invalid_file_authorization", "invalid File authorization")
            if item["expires_at"] > now:
                active.append(item)
        return active

    @classmethod
    def paths(cls, auth):
        return tuple(absolute_scope(item["path"]) for item in cls._active_grants(auth)
                     if "path" in item)

    @classmethod
    def workspace_granted(cls, auth):
        return any(item.get("workspace") is True for item in cls._active_grants(auth))

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
        if not (internal and cls.workspace_granted(auth) or
                any(resolved == p or p in resolved.parents for p in scopes)):
            raise ApiError(404, "path_unavailable", "path does not exist or access is denied")
        if any(part.casefold().startswith(".openkapsel-")
               for part in (*candidate.parts, *resolved.parts)):
            raise ApiError(403, "reserved_path", "internal transport paths cannot be approved")
        # For each spelling, absolute deny always wins. A configured
        # protect can only be unlocked by an independent approval whose
        # canonical scope is at or below the effective protected directory;
        # broad parent/workspace approval does not cross this boundary.
        for checked in (candidate, resolved):
            # Approval may designate an external Client directory. Its
            # canonical scope provides the fallback root for evaluating
            # default */name/ rules, but NEVER grants wider access: the
            # independent approval scope check above remains authoritative.
            matching_scopes = [
                scope for scope in scopes
                if checked == scope or scope in checked.parents
            ]
            evaluation_root = (max(matching_scopes, key=lambda p: len(p.parts))
                               if matching_scopes else root)
            policy = effective_path_access(checked, evaluation_root, False, rules,
                                           resolve_symlinks=False)
            if policy == "deny":
                raise ApiError(403, "path_access_denied", "path is denied")
            if policy == "protect":
                # Each independently configured protection boundary requires
                # its own approval (or a narrower approved scope below it).
                # An outer protection does not unlock a nested protection.
                # Do not treat inherited "protect" on every path component
                # as a new boundary: only anchors of actual rules count.
                from openkapsel.auth.path_access import (
                    DEFAULT_ACCESS_RULES, _matching_anchor,
                    normalized_explicit_rule,
                )
                candidates = (
                    *((raw, mode) for raw, mode in DEFAULT_ACCESS_RULES),
                    *((normalized_explicit_rule(rule), rule.access)
                      for rule in rules),
                )
                protect_anchors = set()
                for raw, mode in candidates:
                    if mode != "protect":
                        continue
                    match = _matching_anchor(checked, raw)
                    if match is None:
                        continue
                    anchor, _ = match
                    if effective_path_access(anchor, evaluation_root, False, rules,
                                             resolve_symlinks=False) == "protect":
                        protect_anchors.add(anchor)
                for boundary in protect_anchors:
                    if not any((scope == boundary or boundary in scope.parents)
                               and (resolved == scope or scope in resolved.parents)
                               for scope in scopes):
                        raise ApiError(403, "path_access_denied",
                                       "protected path needs its own File approval")
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
        raw_rules = arguments["rules"]
        if not isinstance(raw_rules, list) or any(
                not isinstance(r, dict) or set(r) != {"path", "access"}
                or not isinstance(r["path"], str)
                or r["access"] not in {"ro", "rw", "protect", "deny"}
                for r in raw_rules):
            raise OSError(errno.EINVAL, "invalid approved File stream rules")
        # Preserve */name/ patterns and typed trailing slash; Path(...) alone
        # would turn a suffix rule into an unrelated literal root/* path.
        from openkapsel.auth.path_access import _rule_parts
        rules = []
        for row in raw_rules:
            raw = row["path"]
            suffix, directory, _name = _rule_parts(
                raw if raw.startswith("*/") or Path(raw).is_absolute()
                else str(self.files.root / raw) + ("/" if raw.endswith("/") else ""))
            normalized = (raw if suffix else
                          str(Path(raw) if Path(raw).is_absolute()
                              else self.files.root / raw.rstrip("/")) +
                          ("/" if directory else ""))
            rules.append(SimpleNamespace(path=normalized, access=row["access"]))
        provider = ApprovedFiles(self.files, auth, write, tuple(rules))
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
            return cls.workspace_granted(auth)
        try:
            actual = absolute_scope(request["path"]).resolve(strict=False)
            # A broad ancestor may not cover an intervening protect rule.
            # Status checking must never skip an independent nested approval.
            # Exact grants are retained even when an ancestor was approved.
            return actual in paths
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
                           approval_grant=lambda old, request, seconds, access=access: policy.grant(old, request, seconds, write=access == "write"))

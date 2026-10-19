"""File API executor with client-owned opaque authorization and guarded roots."""
from __future__ import annotations

import errno
import os
from pathlib import Path
from types import SimpleNamespace

from openkapsel.client_runtime.client_file_api import ClientFileAPI
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.file_approval import FileApproval
from openkapsel.files.safe_paths import SafePathAccess
from openkapsel.mapping.mapping_transport import FILE_API_WRITE_OPERATIONS
from openkapsel.errors import ApiError


class ApprovedFiles:
    def __init__(self, base, auth, write, rules):
        self.base, self.auth, self.write = base, auth, write
        self.rules = (*rules, *base.sandbox_path_rules)
        self.root = base.root
        self.scopes = FileApproval.paths(auth)
        self.paths = SafePathAccess((self.root, *self.scopes))
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsPaths
            self.paths = WindowsPaths(self.root, roots=(self.root, *self.scopes))
        self.writable = base.writable and write

    def __getattr__(self, name):
        return getattr(self.base, name)

    @property
    def next_handle(self):
        return self.base.next_handle

    @next_handle.setter
    def next_handle(self, value):
        self.base.next_handle = value

    def path(self, value):
        path = FileApproval.check(value, self.root, self.auth, write=self.write, rules=self.rules)
        if self._protected(path):
            raise OSError(errno.ENOENT, "path does not exist")
        # FileApproval.check already enforced protect/deny and canonical
        # scoped authorization. Reapplying the normal Client restriction
        # would undo a confirmed files.read approval of protect.
        return path

    def _protected(self, path):
        # sandbox_denied_paths contains only auto-protected Client secrets
        # and internal metadata; user configured deny is a normal rule.
        protected = (*self.base.global_protected_paths, *self.base.sandbox_denied_paths)
        return any(path == p or p in path.parents for p in protected)

    def ensure_mutable_path(self, path):
        if path in (self.root, *self.scopes):
            raise OSError(errno.EACCES, "approved root is protected")
        FileApproval.check(str(path), self.root, self.auth, write=True, rules=self.rules)
        # A broad File approval cannot delete a parent of default protected
        # Git metadata without an independent approval for that child.
        if path.is_dir() and not path.is_symlink():
            from openkapsel.auth.path_access import existing_pattern_masks
            for mask in existing_pattern_masks(path, self.base.writable, self.rules):
                if mask.access == "deny":
                    raise OSError(errno.EACCES, "directory contains denied metadata")
                try:
                    FileApproval.check(mask.path, self.root, self.auth,
                                       write=True, rules=self.rules)
                except ApiError:
                    raise OSError(errno.EACCES, "directory contains protected paths") from None
        # An approved parent must not be removed when doing so would
        # destroy absolute denied or still-protected descendant content.
        for rule in self.rules:
            if rule.path.startswith("*/"):
                continue
            restricted = Path(rule.path.rstrip("/"))
            if path != restricted and path in restricted.parents:
                if rule.access == "deny":
                    raise OSError(errno.EACCES, "directory contains absolute deny")
                if rule.access == "protect":
                    try:
                        FileApproval.check(str(restricted), self.root, self.auth,
                                           write=True, rules=self.rules)
                    except ApiError:
                        raise OSError(errno.EACCES, "directory contains protected paths") from None
        if any(path == p or p in path.parents or path in p.parents
               for p in (*self.base.global_protected_paths, *self.base.sandbox_denied_paths)):
            raise OSError(errno.EACCES, "protected path")

    def is_protected_path(self, path):
        if self._protected(path):
            return True
        try:
            FileApproval.check(str(path), self.root, self.auth, write=self.write, rules=self.rules)
            return False
        except ApiError:
            return True

    def recycle(self, path, original=None):
        # Recycle against an authorized descriptor root. Never widen an
        # external grant to the host root or another approved directory.
        roots = [p for p in (self.root, *self.scopes) if p in path.parents]
        if not roots:
            raise ApiError(403, "root_protected", "approved root is protected")
        root = max(roots, key=lambda p: len(p.parts))
        files = type(self.base)(root, writable=self.writable,
            rpc_registry=self.base.rpc_registry, rpc_capabilities=self.base.rpc_capabilities,
            protected_paths=self.base.global_protected_paths, index_owned=False)
        # The approved write scope supersedes user-configured rules, but
        # retains the Client's automatic hard-deny private paths.
        files.sandbox_denied_paths = self.base.sandbox_denied_paths
        # Keep absolute deny on recycle; parent operations cannot bypass it.
        files.sandbox_path_rules = tuple(rule for rule in self.base.sandbox_path_rules
                                         if rule.access == "deny")
        args = {"path": path.relative_to(root).as_posix()}
        if original is not None:
            args["original_path"] = original.relative_to(root).as_posix()
        return files._dispatch("recycle", args)


class FullApprovalPaths:
    def __init__(self, files):
        self.files = files

    def __getattr__(self, name):
        def guarded(path, *args, **kwargs):
            actual = self.files.path(str(path))
            root = Path(actual.anchor)
            paths = SafePathAccess((root,))
            if os.name == "nt":
                from openkapsel.client_runtime.client_windows import WindowsPaths
                paths = WindowsPaths(root)
            if name == "rename":
                destination = self.files.path(str(args[0]))
                if Path(destination.anchor) != root:
                    raise OSError(errno.EXDEV, "cross-device rename")
                args = (destination, *args[1:])
            return getattr(paths, name)(actual, *args, **kwargs)
        return guarded


class FullApprovedFiles(ApprovedFiles):
    """Host-wide File API, enabled only by the live administrator grant.

    The marker arrives in the private authorization envelope. It is never a
    grant by itself: every path and stream use checks the Client deadline.
    """
    def __init__(self, base, auth, write, rules):
        if not base.full_approval_active():
            raise OSError(errno.EACCES, "temporary full Client approval is inactive")
        self.base, self.auth, self.write = base, auth, write
        self.rules = tuple(rules)  # Server Token rules, never Client rules.
        self.root = base.root
        self.scopes = ()
        # The normal index may omit paths hidden before this grant.
        self.filename_index = None
        self._recycle_roots = {}
        # Authorize the host root dynamically, including Windows drive/UNC
        # roots, after validating a requested path. Descriptor guards remain.
        self.paths = FullApprovalPaths(self)
        self.writable = base.writable and write

    def path(self, value):
        if not self.base.full_approval_active():
            raise OSError(errno.EACCES, "temporary full Client approval is inactive")
        if (not isinstance(value, str) or "\x00" in value
                or ".." in Path(value).parts
                or os.name != "nt" and "\\" in value):
            raise ApiError(400, "invalid_path", "invalid File path")
        path = Path(value) if value else self.root
        if not path.is_absolute():
            if path.drive:
                raise ApiError(400, "invalid_path", "ambiguous File path")
            path = self.root / path
        if os.name == "nt":
            from openkapsel.client_runtime.windows_filename_policy import check_windows_filename_parts
            check_windows_filename_parts(path.parts[1:])
        actual = path.resolve(strict=False)
        # Preserve explicit Server Token restrictions; the admin grant
        # removes only Client-configured policy.
        from openkapsel.auth.path_access import _matching_anchor, normalized_explicit_rule
        for checked in (path, actual):
            matches = []
            for rule in self.rules:
                match = _matching_anchor(checked, normalized_explicit_rule(rule))
                if match is not None:
                    if rule.access == "deny" and not match[1]:
                        raise OSError(errno.EACCES, "Server Token path restriction")
                    matches.append((len(match[0].parts), rule.access))
            if matches:
                depth = max(item[0] for item in matches)
                modes = {mode for n, mode in matches if n == depth}
                if modes & {"deny", "protect"} or self.write and "ro" in modes:
                    raise OSError(errno.EACCES, "Server Token path restriction")
        return actual

    def ensure_mutable_path(self, path):
        self.path(str(path))
        if path == self.root or path == Path(path.anchor):
            raise OSError(errno.EACCES, "root is protected")
        for rule in self.rules:
            if not rule.path.startswith("*/") and rule.access != "rw":
                restricted = Path(rule.path.rstrip("/"))
                if path in restricted.parents:
                    raise OSError(errno.EACCES, "directory contains Server Token restrictions")

    def _protected(self, path):
        return False

    def is_protected_path(self, path):
        try:
            self.path(str(path))
            return False
        except (OSError, ApiError):
            return True

    def recycle(self, path, original=None):
        self.ensure_mutable_path(path)
        # Use a directory on the same filesystem, not an OS-root recycle bin.
        root = path.parent
        files = type(self.base)(root, writable=self.writable,
            rpc_registry=self.base.rpc_registry, rpc_capabilities=self.base.rpc_capabilities,
            index_owned=False)
        files.full_approval_active = self.base.full_approval_active
        args = {"path": path.name}
        if original is not None:
            args["original_path"] = original.relative_to(root).as_posix()
        result = files._dispatch("recycle", args)
        self._recycle_roots[result["recycle_id"]] = files
        return dict(result, root=str(root))

    def restore_recycle(self, recycle_id):
        # Rollback uses only bins created by this very transaction, even if
        # the grant expires between publication and recovery.
        files = self._recycle_roots[recycle_id]
        return files._dispatch("recycle_restore", {"recycle_id": recycle_id})


def approved_provider(files, auth, write, rules):
    factory = FullApprovedFiles if auth == {"full_client_approval": True} else ApprovedFiles
    return factory(files, auth, write, rules)


class ApprovedFileAPI(ClientFileAPI):
    @classmethod
    def dispatch_approved(cls, files, operation, arguments, auth, *, write):
        if operation in FILE_API_WRITE_OPERATIONS and not write:
            raise OSError(errno.EACCES, "File read authorization cannot write")
        if not isinstance(arguments, dict) or set(arguments) - {"body", "query", "limits", "display_root", "rules"}:
            raise OSError(errno.EINVAL, "invalid approved File request")
        raw_rules = arguments.get("rules", [])
        if not isinstance(raw_rules, list) or any(
            not isinstance(r, dict) or set(r) != {"path", "access"}
            or not isinstance(r["path"], str) or r["access"] not in {"ro", "rw", "protect", "deny"}
            for r in raw_rules):
            raise OSError(errno.EINVAL, "invalid File policy")
        rules = tuple(SimpleNamespace(
            path=(r["path"] if r["path"].startswith("*/")
                  else str(Path(r["path"]) if Path(r["path"]).is_absolute()
                           else files.root / r["path"]) +
                  ("/" if r["path"].endswith("/") else "")),
            access=r["access"]) for r in raw_rules)
        provider = approved_provider(files, auth, write, rules)
        if operation == "fs_read_files":
            paths = arguments.get("body", {}).get("paths", [])
            allowed = False
            for value in paths if isinstance(paths, list) else []:
                try:
                    provider.path(value)
                    allowed = True
                except ApiError as exc:
                    if exc.code == "invalid_path":
                        raise
                except OSError:
                    pass
            if paths and not allowed:
                return {"status": 404, "error": {"code": "path_unavailable", "message": "path does not exist or access is denied"}}
        return cls.dispatch(provider, operation, arguments)

    def _resolve_path(self, value, *, write=False):
        path = self.files.path(value)
        if any(self._is_internal_transfer_name(p) for p in path.parts):
            raise ApiError(403, "reserved_path", "temporary transfer paths are not available")
        if write:
            if path in (self.files.root, *self.files.scopes):
                raise ApiError(403, "root_protected", "approved root is protected")
            self.files.ensure_mutable_path(path)
        return path

    def _try_indexed_find(self, **kwargs):
        path = self.files.path(kwargs["path"])
        if path != self.files.root and self.files.root not in path.parents:
            return None
        return super()._try_indexed_find(**kwargs)

    def _authorize_external_recycle(self, path):
        if not isinstance(self.files, FullApprovedFiles):
            return False
        self.files.ensure_mutable_path(path)
        return True

    def _recycle_path(self, path):
        return self.files.recycle(path)

    def _transaction_recycle(self, source, original):
        return self.files.recycle(source, original)

    def _transaction_restore_recycle(self, recycle_id, *, root=None):
        if isinstance(self.files, FullApprovedFiles):
            return self.files.restore_recycle(recycle_id)
        return super()._transaction_restore_recycle(recycle_id)

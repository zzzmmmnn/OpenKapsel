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
        if not self.write:
            self.base.ensure_accessible_path(path)
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
        # A scoped write grant replaces ordinary ro/deny sandbox rules;
        # only private Client configuration and metadata remain protected.
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
        files.sandbox_path_rules = ()
        args = {"path": path.relative_to(root).as_posix()}
        if original is not None:
            args["original_path"] = original.relative_to(root).as_posix()
        return files._dispatch("recycle", args)


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
            or not isinstance(r["path"], str) or r["access"] not in {"ro", "rw", "deny"}
            for r in raw_rules):
            raise OSError(errno.EINVAL, "invalid File policy")
        rules = tuple(SimpleNamespace(path=str(Path(r["path"]) if Path(r["path"]).is_absolute()
            else files.root / r["path"]), access=r["access"]) for r in raw_rules)
        provider = ApprovedFiles(files, auth, write, rules)
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

    def _recycle_path(self, path):
        return self.files.recycle(path)

    def _transaction_recycle(self, source, original):
        return self.files.recycle(source, original)

"""Local filesystem provider. Remote paths never select the exported root."""

from __future__ import annotations

import base64
import errno
import os
import stat
import threading
from contextvars import ContextVar
from pathlib import Path, PurePosixPath

from openkapsel.auth.path_access import (
    has_private_component, is_internal_transfer_stage, is_private_name,
)
from openkapsel.client_runtime.rpc_deadline import check_deadline, deadline_scope
from openkapsel.files.safe_paths import SafePathAccess
from openkapsel.mapping.mapping_transport import (
    CHUNK_SIZE, FILE_API_READ_OPERATIONS, READ_OPERATIONS,
)

COARSE_READ_OPERATIONS = frozenset("api_" + name for name in FILE_API_READ_OPERATIONS)


class ClientFiles:
    def __init__(
        self,
        root,
        *,
        writable=False,
        rpc_capabilities=None,
        rpc_registry=None,
        protected_paths=(),
        filename_index=None,
        index_owned=True,
    ):
        self.filename_index = filename_index
        self._index_owned = index_owned
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("export root must be a directory")
        # Retain *all* protected paths, even those outside the regular export:
        # an approved external File API root must not reveal client secrets.
        self.global_protected_paths = tuple(
            Path(raw).expanduser().resolve(strict=False) for raw in protected_paths
        )
        protected = set()
        for raw in self.global_protected_paths:
            candidate = Path(raw).expanduser().resolve(strict=False)
            try:
                candidate.relative_to(self.root)
            except ValueError:
                continue
            protected.add(candidate)
        self.protected_paths = frozenset(protected)
        # Populated once the Client's job_sandbox policy is validated.
        self.sandbox_denied_paths = frozenset()
        self.sandbox_path_rules = ()
        self.writable = writable
        if rpc_registry is None:
            from openkapsel.rpc_plugins import load_client_rpc_registry
            rpc_registry = load_client_rpc_registry({})
        self.rpc_registry = rpc_registry
        self.rpc_capabilities = rpc_capabilities or rpc_registry.capability_map({})
        self.paths = SafePathAccess((self.root,))
        self.lock = threading.RLock()
        self.handles = {}
        self.next_handle = 1
        # Internal Mapping transport may operate on tightly validated staging
        # paths. Context-local scope prevents File API and plugin RPC from
        # inheriting this exception, including during parallel reads.
        self._transport_stage = ContextVar("openkapsel_mapping_transport_stage", default=False)

    def _is_transport_stage(self, path):
        return self._transport_stage.get() and is_internal_transfer_stage(path, self.root)

    def path(self, value):
        if not isinstance(value, str) or "\x00" in value or "\\" in value or ":" in value:
            raise OSError(errno.EINVAL, "invalid relative path")
        parts = PurePosixPath(value).parts
        path = self.root.joinpath(*parts)
        if (value.startswith("/") or ".." in parts or
                any(is_private_name(p) for p in parts) and not self._is_transport_stage(path)):
            raise OSError(errno.EACCES, "path is outside exported files")
        self.ensure_accessible_path(path)
        return path

    def is_protected_path(self, path):
        path = Path(path)
        if has_private_component(path) and not self._is_transport_stage(path):
            return True
        if any(path == entry or entry in path.parents
               for entry in (*self.protected_paths, *self.sandbox_denied_paths)):
            return True
        if self.sandbox_path_rules:
            from openkapsel.auth.path_access import effective_path_access
            return any(effective_path_access(
                checked, self.root, self.writable, self.sandbox_path_rules,
                resolve_symlinks=False,
                internal_transfer=self._is_transport_stage(checked)) in {"protect", "deny"}
                for checked in (path, path.resolve(strict=False)))
        return False

    def ensure_accessible_path(self, path):
        if self.is_protected_path(path):
            # Denied content is hidden from both Shell and exported file APIs.
            raise OSError(errno.ENOENT, "path does not exist")

    def ensure_mutable_path(self, path):
        path = Path(path)
        if self.is_protected_path(path):
            raise OSError(errno.EACCES, "internal or protected path cannot be modified")
        from openkapsel.auth.path_access import effective_path_access
        if self.sandbox_path_rules and any(effective_path_access(
                checked, self.root, self.writable, self.sandbox_path_rules,
                resolve_symlinks=False,
                internal_transfer=self._is_transport_stage(checked)) in {"ro", "protect", "deny"}
                for checked in (path, path.resolve(strict=False))):
            raise OSError(errno.EACCES, "sandbox path is read-only or denied")
        # Do not allow deleting/renaming an ancestor of a restricted
        # subtree. This never interferes with writing inside nested rw.
        for rule in self.sandbox_path_rules:
            restricted = Path(rule.path)
            if rule.access in {"ro", "protect", "deny"} and path != restricted and path in restricted.parents:
                raise OSError(errno.EACCES, "directory contains restricted paths")
        for protected in (*self.protected_paths, *self.sandbox_denied_paths):
            if (path == protected or protected in path.parents or
                    path in protected.parents):
                raise OSError(errno.EACCES, "configuration or sandbox deny path is protected")

    @staticmethod
    def details(st):
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise OSError(errno.EACCES, "only regular files and directories are exported")
        return {key: getattr(st, key) for key in
                ("st_mode", "st_size", "st_atime", "st_mtime", "st_ctime", "st_nlink", "st_ino",
                 "st_dev", "st_atime_ns", "st_mtime_ns", "st_ctime_ns")}

    def dispatch(self, operation, args, *, cancelled=None):
        if not isinstance(args, dict):
            raise OSError(errno.EINVAL, "arguments must be an object")
        if operation == "rpc":
            family = args.get("family")
            rpc_operation = args.get("operation")
            rpc_args = args.get("args")
            if (
                not isinstance(family, str)
                or not isinstance(rpc_operation, str)
                or not isinstance(rpc_args, dict)
                or set(args) != {"family", "operation", "args"}
            ):
                raise OSError(errno.EINVAL, "invalid RPC request")
            spec = self.rpc_registry.operation_spec(family, rpc_operation)
            if spec is None:
                raise OSError(errno.ENOSYS, "RPC plugin capability is unavailable")
            if spec["execution"] != "sync":
                raise OSError(errno.EINVAL, "RPC plugin operation must run as a task")
            if spec["write"] and not self.writable:
                raise OSError(errno.EROFS, "client export is read-only")
            # SSH owns its connection/channel locks and does not access local
            # file handles. Remote I/O must not hold the local filesystem lock.
            if family == "ssh":
                with deadline_scope(75.0, cancelled):
                    return self.rpc_registry.dispatch_sync(self, family, rpc_operation, rpc_args)
            # Read-only RPC plugins have their own per-request state and never
            # touch the seek-based handle table. Do not let a long Git/archive
            # read block unrelated file requests or hold up local mutations.
            if not spec["write"]:
                if family in {"archive", "tabular"}:
                    with deadline_scope(75.0, cancelled):
                        return self.rpc_registry.dispatch_sync(self, family, rpc_operation, rpc_args)
                return self.rpc_registry.dispatch_sync(self, family, rpc_operation, rpc_args)
            with self.lock:
                return self.rpc_registry.dispatch_sync(self, family, rpc_operation, rpc_args)
        read_only = operation in READ_OPERATIONS
        if not read_only and not self.writable:
            raise OSError(errno.EROFS, "client export is read-only")
        # Coarse-grained read-only File APIs use per-request file descriptors,
        # never the session's mutable handle table. Their path guards still
        # protect against symlink/reparse races on both POSIX and Windows.
        if operation in COARSE_READ_OPERATIONS:
            if cancelled is not None:
                args = dict(args, _rpc_cancelled=cancelled)
            return self._dispatch_with_transport_scope(operation, args)
        # Ordinary handle seek/read/write and all mutations stay serialized.
        # FUSE's low-level directory enumeration may also walk 100k entries.
        # Constrain that one read without injecting a timeout into mutations.
        with self.lock:
            if operation.startswith("api_") and cancelled is not None:
                args = dict(args, _rpc_cancelled=cancelled)
            if operation == "list":
                with deadline_scope(60.0, cancelled):
                    return self._dispatch_with_transport_scope(operation, args)
            return self._dispatch_with_transport_scope(operation, args)

    def _dispatch_with_transport_scope(self, op, args):
        token = self._transport_stage.set(not op.startswith("api_") and op != "resolve_path")
        try:
            return self._dispatch(op, args)
        finally:
            self._transport_stage.reset(token)

    def _dispatch(self, op, args):
        if op == "resolve_path":
            # A private, read-only Mapping RPC for File approval. Resolve on
            # the CLIENT: the Server's filesystem cannot resolve these links.
            raw = args.get("path")
            directory = args.get("directory", False)
            if (not isinstance(raw, str) or not raw.startswith("/")
                or not isinstance(directory, bool) or len(raw) > 4096
                or "\\x00" in raw or "\\\\" in raw
                or any(part == ".." or is_private_name(part) for part in raw.split("/"))):
                raise OSError(errno.EACCES, "invalid client absolute path")
            try:
                resolved = Path(raw).resolve(strict=directory)
            except (OSError, RuntimeError):
                raise OSError(errno.EACCES, "client path could not be resolved") from None
            if (not resolved.is_absolute() or str(resolved) == "/"
                or has_private_component(resolved)):
                raise OSError(errno.EACCES, "client path cannot be approved")
            if directory and not resolved.is_dir():
                raise OSError(errno.ENOTDIR, "approval scope is not a directory")
            return str(resolved)
        if op.startswith("api_"):
            from openkapsel.client_runtime.client_file_api import ClientFileAPI
            external_root = args.get("external_root")
            if external_root is not None:
                # Only coarse File API RPC supports this special path scope.
                # FUSE, ordinary file RPC, and plugin RPC keep their export root.
                if (not isinstance(external_root, str) or not external_root.startswith("/")
                    or "\x00" in external_root or "\\" in external_root
                    or any(p == ".." or is_private_name(p) for p in external_root.split("/"))
                    or os.path.normpath(external_root) == "/"):
                    raise OSError(errno.EACCES, "invalid external File API root")
                candidate = Path(os.path.abspath(external_root))
                # A symlink in *any* ancestor, not only the last component,
                # permits retargeting an already approved lexical directory.
                # Require the canonical real pathname on the Client host.
                try:
                    canonical = candidate.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise OSError(errno.EACCES, "external root must exist") from None
                if canonical != candidate or not candidate.is_dir():
                    raise OSError(errno.EACCES,
                                  "external root must be a canonical real directory without symlinks")
                if has_private_component(canonical):
                    raise OSError(errno.EACCES, "client runtime directories cannot be exported")
                extra = ClientFiles(
                    candidate, writable=self.writable,
                    rpc_capabilities={key: val for key, val in self.rpc_capabilities.items()
                                      if key != "file_search"},
                    rpc_registry=self.rpc_registry,
                    protected_paths=self.global_protected_paths,
                    filename_index=None,
                    index_owned=False,
                )
                # Check again after constructing ClientFiles: the pathname
                # may have been swapped while its root was being resolved.
                if extra.root != canonical:
                    extra.close()
                    raise OSError(errno.EACCES, "external root changed during authorization")
                extra.sandbox_denied_paths = self.sandbox_denied_paths
                extra.sandbox_path_rules = self.sandbox_path_rules
                # The standard filename index is tied to the normal export.
                # Never let an external directory consult that stale index.
                extra.rpc_capabilities["file_search"] = {"state": "disabled"}
                # Reject a requested alias that changed since the Server
                # resolved it. Operations themselves use ONLY the canonical
                # paths relative to a descriptor-anchored real root.
                checks = args.get("external_checks", [])
                if not isinstance(checks, list) or len(checks) > 1000:
                    raise OSError(errno.EACCES, "invalid external path checks")
                for check in checks:
                    if not isinstance(check, dict) or set(check) != {"original", "resolved"}:
                        raise OSError(errno.EACCES, "invalid external path check")
                    original, expected = check["original"], check["resolved"]
                    if (not isinstance(original, str) or not isinstance(expected, str)
                        or not original.startswith("/") or len(original) > 4096
                        or "\x00" in original or "\\" in original
                        or ".." in original.split("/")
                        or has_private_component(original)
                        or has_private_component(expected)):
                        raise OSError(errno.EACCES, "invalid external path check")
                    if str(Path(original).resolve(strict=False)) != expected:
                        raise OSError(errno.EACCES, "external path changed after approval")
                return ClientFileAPI.dispatch(extra, op[4:], args)
            return ClientFileAPI.dispatch(self, op[4:], args)
        if op == "fstat":
            return self.details(os.fstat(self.handles[int(args["handle"])]))
        if op == "close":
            fd = self.handles.pop(int(args["handle"]), None)
            if fd is not None:
                os.close(fd)
            return None
        if op in {"read", "write", "flush", "truncate_handle"}:
            fd = self.handles[int(args["handle"])]
            if op == "flush":
                os.fsync(fd)
                return None
            if op == "truncate_handle":
                os.ftruncate(fd, self._number(args["size"]))
                return None
            os.lseek(fd, self._number(args.get("offset", 0)), os.SEEK_SET)
            if op == "read":
                data = os.read(fd, min(CHUNK_SIZE, self._number(args["size"])))
                return base64.b64encode(data).decode()
            data = base64.b64decode(args["data"], validate=True)
            if len(data) > CHUNK_SIZE:
                raise OSError(errno.E2BIG, "write exceeds chunk limit")
            return os.write(fd, data)
        if op == "statfs":
            st = os.statvfs(self.root)
            return {key: getattr(st, key) for key in
                    ("f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_favail", "f_namemax")}
        if op in {"recycle", "recycle_list", "recycle_restore", "recycle_purge"}:
            from openkapsel.files.recycle import RecycleBin, RecycleError
            try:
                recycle = RecycleBin(self.root)
                if op == "recycle":
                    source = self.path(args["path"])
                    self.ensure_mutable_path(source)
                    original = source
                    if "original_path" in args:
                        original = self.path(args["original_path"])
                        self.ensure_mutable_path(original)
                    return recycle.recycle(source, original_path=original)
                if op == "recycle_restore":
                    return recycle.restore(args["recycle_id"])
                if op == "recycle_purge":
                    return recycle.purge(args["recycle_id"])
                entries, total = recycle.list_items(self._number(args.get("offset", 0)),
                                                     min(1000, self._number(args.get("limit", 100))))
                return {"entries": entries, "total": total}
            except RecycleError as exc:
                raise OSError(errno.EIO, exc.code) from None
        path = self.path(args.get("path", "."))
        if op == "stat":
            fd = self.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                return self.details(os.fstat(fd))
            finally:
                os.close(fd)
        if op == "list":
            fd = self.paths.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                offset = self._number(args.get("offset", 0))
                # Explicit cap prevents an enormous directory from exhausting RPC memory.
                names = []
                with os.scandir(fd) as entries:
                    for item in entries:
                        check_deadline()
                        if (
                            not is_private_name(item.name)
                            and not self.is_protected_path(path / item.name)
                            and (item.is_file(follow_symlinks=False) or item.is_dir(follow_symlinks=False))
                        ):
                            names.append(item.name)
                        if len(names) > 100000:
                            raise OSError(errno.E2BIG, "directory exceeds provider listing limit")
                check_deadline()
                names.sort()
                selected = names[offset:offset + 500]
                result = {"names": selected, "total": len(names)}
                if args.get("include_details"):
                    result["entries"] = {name: self.details(os.stat(name, dir_fd=fd, follow_symlinks=False)) for name in selected}
                return result
            finally:
                os.close(fd)
        if op in {"open", "create"}:
            if len(self.handles) >= 256:
                raise OSError(errno.EMFILE, "provider handle limit reached")
            mode = args.get("mode", "r")
            if mode not in {"r", "w", "rw"}:
                raise OSError(errno.EINVAL, "invalid open mode")
            if (mode != "r" or op == "create") and not self.writable:
                raise OSError(errno.EROFS, "client export is read-only")
            if mode != "r" or op == "create" or args.get("truncate"):
                self.ensure_mutable_path(path)
            flags = {"r": os.O_RDONLY, "w": os.O_WRONLY, "rw": os.O_RDWR}[mode]
            if op == "create":
                flags |= os.O_CREAT | os.O_EXCL
            if args.get("truncate"):
                if mode == "r":
                    raise OSError(errno.EACCES, "read-only open cannot truncate")
                flags |= os.O_TRUNC
            fd = self.paths.open(path, flags | getattr(os, "O_NONBLOCK", 0), 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise OSError(errno.EACCES, "not a regular file")
            handle = self.next_handle
            self.next_handle += 1
            self.handles[handle] = fd
            return handle
        if path == self.root:
            raise OSError(errno.EBUSY, "export root is protected")
        if op == "mkdir":
            self.ensure_mutable_path(path)
            return self.paths.mkdir(path, parents=False, exist_ok=False)
        if op == "rename":
            destination = self.path(args["destination"])
            self.ensure_mutable_path(path)
            self.ensure_mutable_path(destination)
            if not args.get("overwrite", True) and os.name != "nt":
                from openkapsel.files.rename_exclusive import rename_exclusive
                with self.paths.parent(path) as src, self.paths.parent(destination) as dst:
                    rename_exclusive(src.name, dst.name, src.fd, dst.fd)
                return False
            return self.paths.rename(path, destination, overwrite=bool(args.get("overwrite", True)), create_parents=False)
        if op in {"unlink", "rmdir"}:
            self.ensure_mutable_path(path)
            with self.paths.parent(path) as parent:
                parent.unlink(directory=op == "rmdir")
            return None
        if op in {"truncate", "chmod", "utimens"}:
            self.ensure_mutable_path(path)
            flags = os.O_WRONLY if op == "truncate" else os.O_RDONLY
            fd = self.paths.open(path, flags | getattr(os, "O_NONBLOCK", 0))
            try:
                self.details(os.fstat(fd))
                if op == "truncate":
                    os.ftruncate(fd, self._number(args["size"]))
                elif op == "chmod":
                    os.fchmod(fd, int(args["mode"]) & 0o777)
                else:
                    os.utime(fd, times=args.get("times"))
                return None
            finally:
                os.close(fd)
        raise OSError(errno.ENOSYS, "unsupported filesystem operation")

    @staticmethod
    def _number(value):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
            raise OSError(errno.EINVAL, "invalid nonnegative integer")
        return value

    def close_handles(self):
        """Close transport-scoped file handles without closing process-scoped RPC plugins."""
        with self.lock:
            for fd in self.handles.values():
                os.close(fd)
            self.handles.clear()

    def close(self):
        try:
            if self._index_owned and self.filename_index is not None:
                self.filename_index.close()
        finally:
            try:
                self.rpc_registry.close()
            finally:
                self.close_handles()

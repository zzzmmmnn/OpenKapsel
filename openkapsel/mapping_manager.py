"""RPC-first mappings, session fencing, and leased native FUSE views."""

from __future__ import annotations

import errno
import logging
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

from .mapping_capabilities import MappingRpcCapability, RPC_FAMILIES, RPC_STATES, legacy_rpc_capability
from .mapping_store import MappingStore
from .mapping_transport import ProviderSession, READ_OPERATIONS, encode, recv_line

LOG = logging.getLogger("openkapsel.mappings")


class MappingManager:
    def __init__(
        self, root, state_dir, *, enabled=False, mount_helper=None,
        rpc_timeout_seconds=90.0, provider_idle_timeout_seconds=60.0,
        fuse_enabled=True, max_active_mounts=16, mount_idle_seconds=30.0,
    ):
        self.root = root
        self.store = MappingStore(state_dir / "mappings.sqlite3")
        self.run_dir = root.parent / "mapping-run"
        self.run_dir.mkdir(mode=0o700, exist_ok=True)
        self.enabled = enabled
        self.fuse_enabled = fuse_enabled
        self.max_active_mounts = max_active_mounts
        self.mount_idle_seconds = float(mount_idle_seconds)
        self.mount_helper = mount_helper
        self.rpc_timeout_seconds = float(rpc_timeout_seconds)
        self.provider_idle_timeout_seconds = float(provider_idle_timeout_seconds)
        self.host_mounts = set()
        self.workspace_available = lambda workspace: True
        self.sessions, self.workers = {}, {}
        self.lock = threading.RLock()
        self.ipc = None
        self.socket_path = self.run_dir / "broker.sock"
        self.slots = threading.BoundedSemaphore(64)
        self.mount_references = {}
        self.mount_idle_since = {}
        self._closing = threading.Event()
        self._mount_janitor = None
        if enabled:
            # Configuration and provider connections do not require Linux/FUSE.
            # Detach mounts belonging to an earlier server generation, then keep
            # an inaccessible reservation so missed native access fails closed.
            for row in self.store.list():
                try:
                    if os.path.ismount(self.mount_path(row)):
                        self.unmount(row)
                    self.prepare(row)
                except (OSError, ValueError, subprocess.SubprocessError):
                    LOG.error("Could not reserve mapping path %s", row["id"])

    def prepare(self, row):
        """Reserve a name without exposing a writable local backing directory."""
        with self.lock:
            path = self.mount_path(row)
            if os.path.ismount(path):
                return path
            if path.is_symlink():
                raise ValueError("mapping mountpoint cannot be a symlink")
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
            try:
                if next(path.iterdir(), None) is not None:
                    raise ValueError("mapping mountpoint must be empty")
            finally:
                path.chmod(0)
            return path

    def _start_broker(self):
        if self.ipc is not None:
            return
        manager = self
        class IPCHandler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(manager.rpc_timeout_seconds + 5)
                try:
                    request = recv_line(self.rfile)
                    result = manager.call(request["mapping_id"], request["op"], request["args"])
                    response = {"result": result}
                except (OSError, ValueError, KeyError) as exc:
                    response = {"error": getattr(exc, "errno", None) or errno.EIO}
                self.wfile.write(encode(response) + b"\n")
        class IPCServer(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True
            def process_request(self, request, address):
                if not manager.slots.acquire(blocking=False):
                    request.close()
                    return
                try:
                    super().process_request(request, address)
                except BaseException:
                    manager.slots.release()
                    raise
            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    manager.slots.release()
        self.socket_path.unlink(missing_ok=True)
        self.ipc = IPCServer(str(self.socket_path), IPCHandler)
        os.chmod(self.socket_path, 0o600)
        threading.Thread(target=self.ipc.serve_forever, daemon=True).start()

    def _is_mounted(self, row):
        worker = self.workers.get(row["id"])
        return bool(row["id"] in self.host_mounts or (worker and worker.poll() is None))

    def acquire(self, rows):
        """Pin native mounts for one server process, all-or-rollback."""
        from .mapping_leases import MountLease
        acquired = []
        with self.lock:
            if self._closing.is_set():
                raise OSError(errno.EBUSY, "mapping manager is shutting down")
            try:
                for mid in sorted({row["id"] for row in rows}):
                    row = self.store.get(mid)
                    self.check_path(self.mount_path(row))
                    if not self.workspace_available(row["workspace"]):
                        raise OSError(errno.EACCES, "workspace is unavailable")
                    self.mount(row)
                    self.mount_references[mid] = self.mount_references.get(mid, 0) + 1
                    self.mount_idle_since.pop(mid, None)
                    acquired.append(mid)
            except BaseException:
                self.release(acquired, immediate=True)
                raise
            if acquired and self._mount_janitor is None:
                self._mount_janitor = threading.Thread(target=self._reap_loop, daemon=True)
                self._mount_janitor.start()
        return MountLease(self, acquired)

    def execution_mappings(self, workspace, cwd, names=()):
        """Resolve declared dependencies; never guess paths in shell source."""
        if not isinstance(names, (list, tuple)) or len(names) > 256 or any(not isinstance(n, str) or not n for n in names):
            raise ValueError("mount_mappings must be an array of at most 256 mapping names or IDs")
        rows = self.store.list(workspace)
        selected = {}
        for name in names:
            row = next((r for r in rows if name in (r["name"], r["id"])), None)
            if row is None:
                raise ValueError("declared mapping does not belong to this workspace")
            selected[row["id"]] = row
        row = self.at_path(Path(os.path.abspath(cwd)))
        if row is not None:
            if row["workspace"] != workspace:
                raise ValueError("mapping does not belong to this workspace")
            selected[row["id"]] = row
        return list(selected.values())

    def release(self, ids, *, immediate=False):
        with self.lock:
            for mid in ids:
                count = self.mount_references.get(mid, 0)
                if count > 1:
                    self.mount_references[mid] = count - 1
                    continue
                self.mount_references.pop(mid, None)
                self.mount_idle_since[mid] = time.monotonic()
                if immediate or self.mount_idle_seconds == 0:
                    try:
                        self.unmount(self.store.get(mid))
                    except (KeyError, OSError, ValueError, subprocess.SubprocessError):
                        LOG.warning("Could not release mapping mount %s", mid)

    def require_idle(self, mid):
        if self.mount_references.get(mid, 0):
            raise OSError(errno.EBUSY, "mapping is used by a server task or API worker; stop it first")

    def reap_idle_mounts(self):
        with self.lock:
            now = time.monotonic()
            for mid, idle_since in list(self.mount_idle_since.items()):
                if self.mount_references.get(mid, 0) or now - idle_since < self.mount_idle_seconds:
                    continue
                try:
                    self.unmount(self.store.get(mid))
                except (KeyError, OSError, ValueError, subprocess.SubprocessError):
                    LOG.warning("Could not reap mapping mount %s", mid)

    def _reap_loop(self):
        while not self._closing.wait(5):
            self.reap_idle_mounts()

    def empty_view(self):
        """Read-only, inaccessible source for undeclared sandbox mappings."""
        with self.lock:
            path = self.run_dir / "unavailable"
            if path.is_symlink():
                raise ValueError("mapping mask cannot be a symlink")
            path.mkdir(mode=0, exist_ok=True)
            path.chmod(0)
            return path

    def mount_path(self, row):
        workspace = self.root / row["workspace"]
        if workspace.is_symlink() or not workspace.is_dir() or workspace.resolve().parent != self.root:
            raise ValueError("mapping workspace must be an existing direct child workspace")
        return workspace / row["name"]

    def mount(self, row):
        if not self.enabled or not self.fuse_enabled:
            raise OSError(errno.ENOTSUP, "native mapping mounts are disabled; use client execution or RPC")
        if sys.platform != "linux":
            raise OSError(errno.ENOTSUP, "native mapping mounts require Linux FUSE; RPC does not")
        with self.lock:
            if not self._is_mounted(row):
                self.reap_idle_mounts()
                active = len(self.host_mounts) + sum(p.poll() is None for p in self.workers.values())
                if active >= self.max_active_mounts:
                    raise OSError(errno.EBUSY, "active mapping mount limit reached")
            self._start_broker()
            if self.mount_helper is not None:
                self._host_mount(row)
                return
            old = self.workers.get(row["id"])
            if old and old.poll() is None:
                return
            path = self.mount_path(row)
            if os.path.ismount(path):
                # A stale mount from an earlier service process must be detached
                # before starting a new generation.
                subprocess.run([self._fusermount(), "-uz", str(path)], check=True, capture_output=True, timeout=10)
            if path.is_symlink():
                raise ValueError("mapping mountpoint cannot be a symlink")
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
            if next(path.iterdir(), None) is not None:
                raise ValueError("mapping mountpoint must be empty")
            # If the worker crashes or is unmounted, fail closed on the backing
            # directory. The normal service account cannot enumerate/write it.
            backing_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            process = subprocess.Popen([sys.executable, "-m", "openkapsel.mapping_fuse",
                                        "--socket", str(self.socket_path), f"--id={row['id']}", "--mount", str(path)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, close_fds=True)
            self.workers[row["id"]] = process
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if os.path.ismount(path):
                    os.fchmod(backing_fd, 0)
                    os.close(backing_fd)
                    return
                if process.poll() is not None:
                    break
                time.sleep(.05)
            process.terminate()
            process.wait(timeout=5)
            os.fchmod(backing_fd, 0)
            os.close(backing_fd)
            raise OSError(errno.EIO, "FUSE mount failed; check /dev/fuse, libfuse and fusermount permissions")

    def _host_mount(self, row):
        from .workspace_images import WorkspaceImageError
        path = self.mount_path(row)
        backing_fd = None
        if not os.path.ismount(path):
            if path.is_symlink():
                raise ValueError("mapping mountpoint cannot be a symlink")
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
            if next(path.iterdir(), None) is not None:
                raise ValueError("mapping mountpoint must be empty")
            backing_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.mount_helper._request("mapping_mount", id=row["id"], workspace=row["workspace"], name=row["name"])
            if not os.path.ismount(path):
                raise OSError(errno.EIO, "host mapping is not visible in service namespace")
            self.host_mounts.add(row["id"])
        except WorkspaceImageError as exc:
            raise OSError(errno.EIO, str(exc)) from None
        finally:
            if backing_fd is not None:
                os.fchmod(backing_fd, 0)
                os.close(backing_fd)

    @staticmethod
    def _fusermount():
        command = shutil.which("fusermount") or shutil.which("fusermount3")
        if command is None:
            raise ValueError("fusermount is not installed")
        return command

    def list(self, workspace=None):
        rows = self.store.list(workspace)
        with self.lock:
            for row in rows:
                session = self.sessions.get(row["id"])
                worker = self.workers.get(row["id"])
                ready = bool(session and not session.closed and getattr(session, "ready", False))
                row.update(
                           online=ready,
                           mounted=bool(row["id"] in self.host_mounts or (worker and worker.poll() is None)),
                           path=row["name"],
                           capabilities=session.capabilities if ready else {},
                           client_version=getattr(session, "client_version", None) if ready else None,
                           client_fingerprint=getattr(session, "client_fingerprint", None) if ready else None,
                           handshake_ready=ready,
                           mount_references=self.mount_references.get(row["id"], 0),
                           native_mounts_enabled=self.fuse_enabled)
        return rows

    def at_path(self, path):
        try:
            parts = path.relative_to(self.root).parts
        except ValueError:
            return None
        if len(parts) < 2:
            return None
        return next((row for row in self.store.list(parts[0]) if row["name"] == parts[1]), None)

    def check_path(self, path, *, write=False, protect_root=False):
        row = self.at_path(path)
        if row:
            if protect_root and path == self.mount_path(row):
                raise OSError(errno.EBUSY, "mapping root is protected")
            with self.lock:
                session = self.sessions.get(row["id"])
                if not row["enabled"]:
                    raise OSError(errno.EACCES, "mapping is disabled")
                if session is None or session.closed or not session.ready:
                    raise OSError(errno.EHOSTDOWN, "mapping client is offline")
            if write and not row["writable"]:
                raise OSError(errno.EROFS, "mapping is read-only")
        return row

    def call(self, mid, op, args, *, generation=None):
        row = self.store.get(mid)
        if not self.workspace_available(row["workspace"]):
            self.disconnect(mid)
            raise OSError(errno.EACCES, "workspace is unavailable")
        with self.lock:
            session = self.sessions.get(mid)
            if not row["enabled"]:
                raise OSError(errno.EACCES, "mapping is disabled")
            if session is None or session.closed or not session.ready:
                raise OSError(errno.EHOSTDOWN, "mapping client is offline")
        if generation is not None and session.generation != generation:
            raise OSError(errno.ESTALE, "mapping provider changed during the operation")
        if op.startswith("task_"):
            if op == "task_start" and isinstance(args.get("rpc"), dict):
                rpc_request = args["rpc"]
                family = rpc_request.get("family")
                operation = rpc_request.get("operation")
                capability = self.rpc_capability(mid, family, operation=operation)
                if not capability.available or capability.operation_spec is None:
                    raise OSError(errno.ENOSYS, "RPC task capability is unavailable")
                if capability.operation_spec.get("execution") != "task":
                    raise OSError(errno.EINVAL, "RPC operation is not task-based")
                if capability.operation_spec.get("write") and not row["writable"]:
                    raise OSError(errno.EROFS, "mapping is read-only")
            elif op in {"task_get", "task_list", "task_interrupt", "task_kill"}:
                # Query/control authorization is enforced by the caller-facing
                # task endpoint after inspecting task kind/metadata.
                pass
            elif not row["allow_exec"]:
                raise OSError(errno.EACCES, "mapping execution is disabled")
        else:
            plugin_read_only = False
            capabilities = getattr(session, "capabilities", {})
            rpc = capabilities.get("rpc") if isinstance(capabilities, dict) else None
            if isinstance(rpc, dict):
                for family, capability in rpc.items():
                    prefix = family + "_"
                    if not op.startswith(prefix) or not isinstance(capability, dict):
                        continue
                    operation = op[len(prefix):]
                    if capability.get("state", "available") == "available" and operation in capability.get("operations", []):
                        specs = capability.get("operation_specs")
                        spec = specs.get(operation) if isinstance(specs, dict) else None
                        if isinstance(spec, dict) and isinstance(spec.get("write", False), bool):
                            plugin_read_only = not spec.get("write", False)
                        elif capability.get("read_only") is True:
                            plugin_read_only = True
                    break
            read_operation = op in READ_OPERATIONS or plugin_read_only
            if op == "open" and (args.get("mode", "r") != "r" or args.get("truncate")):
                read_operation = False
            if not read_operation and not row["writable"]:
                raise OSError(errno.EROFS, "mapping is read-only")
        # Handle IDs are generation-bound, including file descriptors held open
        # by server tasks across a client reconnection.
        if "handle" in args:
            handle = args["handle"]
            if not isinstance(handle, str) or not handle.startswith(session.generation + ":"):
                raise OSError(errno.ESTALE, "mapping handle belongs to an old session")
            args = dict(args, handle=int(handle.split(":", 1)[1]))
        result = session.call(op, args)
        if op in {"open", "create"}:
            result = session.generation + ":" + str(result)
        return result

    def rpc_capability(self, mid, family, *, operation=None, min_version=1, max_version=None, required=None):
        if not isinstance(family, str) or not family:
            raise ValueError("invalid mapping RPC family")
        spec = RPC_FAMILIES.get(family, {"legacy_key": None, "fallback": None, "operations": frozenset()})
        row = self.store.get(mid)
        if not row["enabled"]:
            return MappingRpcCapability(family, "disabled", reason="mapping_disabled")
        with self.lock:
            session = self.sessions.get(mid)
            if session is None or session.closed or not session.ready:
                return MappingRpcCapability(family, "offline", reason="client_offline")
            capabilities = session.capabilities

        rpc = capabilities.get("rpc")
        advertised = rpc.get(family) if isinstance(rpc, dict) else None
        if advertised is None:
            advertised = legacy_rpc_capability(capabilities, family)
        if not isinstance(advertised, dict):
            return MappingRpcCapability(
                family,
                "unsupported",
                reason="not_advertised",
                fallback=spec["fallback"],
            )

        state = advertised.get("state", "available")
        if state not in RPC_STATES or state == "offline":
            return MappingRpcCapability(
                family,
                "unsupported",
                reason="invalid_capability",
                fallback=spec["fallback"],
            )
        version = advertised.get("version")
        operations = advertised.get("operations", ())
        if not isinstance(operations, list) or any(not isinstance(item, str) for item in operations):
            operations = ()
        operation_spec = None
        if operation is not None:
            advertised_specs = advertised.get("operation_specs")
            raw_spec = advertised_specs.get(operation) if isinstance(advertised_specs, dict) else None
            if isinstance(raw_spec, dict) and isinstance(raw_spec.get("write", False), bool):
                operation_spec = dict(raw_spec)
                operation_spec["write"] = raw_spec.get("write", False)
                execution = raw_spec.get("execution", "sync")
                if execution in {"sync", "task"}:
                    operation_spec["execution"] = execution
                else:
                    operation_spec = None
            elif isinstance(advertised.get("read_only"), bool):
                # Rolling-upgrade compatibility for pre-operation metadata.
                write = not advertised["read_only"]
                operation_spec = {
                    "write": write,
                    "execution": "sync",
                }
        details = {"advertised_reason": advertised.get("reason")} if advertised.get("reason") else None
        fallback = spec["fallback"] if state in {"unsupported", "disabled"} else None
        result = MappingRpcCapability(
            family,
            state,
            reason=advertised.get("reason"),
            version=version if type(version) is int else None,
            operations=tuple(operations),
            fallback=fallback,
            operation_spec=operation_spec,
            details=details,
        )
        if state != "available":
            return result
        if type(version) is not int or version < min_version or (max_version is not None and version > max_version):
            return MappingRpcCapability(
                family,
                "unsupported",
                reason="version_mismatch",
                version=version if type(version) is int else None,
                operations=tuple(operations),
                fallback=spec["fallback"],
            )
        if operation is not None and operation not in operations:
            return MappingRpcCapability(
                family,
                "unsupported",
                reason="operation_not_supported",
                version=version,
                operations=tuple(operations),
                fallback=spec["fallback"],
            )
        if required:
            for key, expected in required.items():
                if advertised.get(key) != expected:
                    return MappingRpcCapability(
                        family,
                        "unsupported",
                        reason="incompatible_capability",
                        version=version,
                        operations=tuple(operations),
                        fallback=spec["fallback"],
                        details={"field": key},
                    )
        return result

    def supports_git_api(self, mid):
        return self.rpc_capability(
            mid,
            "git",
            min_version=2,
            max_version=2,
        ).available

    def supports_file_api(self, mid, operation, *, min_version=1):
        return self.rpc_capability(
            mid,
            "file",
            operation=operation,
            min_version=min_version,
            max_version=3,
        ).available

    def accept(self, handler, row):
        with self.lock:
            # Authentication may precede a concurrent rename or rotation.
            row = self.store.authenticate(row["id"], handler.headers["Authorization"][7:])
            self.prepare(row)
            existing = self.sessions.get(row["id"])
            if existing and not existing.closed:
                raise ValueError("mapping already has an active provider")
            session = ProviderSession(
                handler,
                rpc_timeout_seconds=self.rpc_timeout_seconds,
                idle_timeout_seconds=self.provider_idle_timeout_seconds,
            )
            self.sessions[row["id"]] = session
        try:
            def seen():
                if not self.workspace_available(row["workspace"]):
                    session.close()
                else:
                    self.store.seen(row["id"])
            session.run(seen)
        except (OSError, ValueError):
            pass
        finally:
            session.close()
            with self.lock:
                if self.sessions.get(row["id"]) is session:
                    self.sessions.pop(row["id"], None)

    def disconnect(self, mid):
        with self.lock:
            session = self.sessions.pop(mid, None)
        if session:
            session.close()

    def rename(self, mid, name):
        """Rename an idle virtual root without mounting or changing identity."""
        self.store.validate_name(name)
        with self.lock:
            row = self.store.get(mid)
            if name == row["name"]:
                return row
            self.require_idle(mid)
            if any(r["name"] == name for r in self.store.list(row["workspace"])):
                raise ValueError("mapping name is already registered")
            old_path = self.mount_path(row)
            new_path = old_path.with_name(name)
            new_path.mkdir(mode=0)
            try:
                self.unmount(row)
                updated, _ = self.store.update(mid, name=name)
            except BaseException:
                new_path.rmdir()
                raise
            try:
                old_path.rmdir()
            except FileNotFoundError:
                pass
            return updated

    def unmount(self, row, *, force=False):
        """Release only the native view. Provider sessions and RPC stay alive."""
        with self.lock:
            if not force:
                self.require_idle(row["id"])
            path = self.mount_path(row)
            if self.mount_helper is not None:
                from .workspace_images import WorkspaceImageError
                try:
                    if row["id"] in self.host_mounts or os.path.ismount(path):
                        self.mount_helper._request("mapping_unmount", id=row["id"], workspace=row["workspace"], name=row["name"])
                    self.host_mounts.discard(row["id"])
                except WorkspaceImageError as exc:
                    raise OSError(errno.EIO, str(exc)) from None
            else:
                process = self.workers.get(row["id"])
                if os.path.ismount(path):
                    subprocess.run([self._fusermount(), "-uz", str(path)], check=True, capture_output=True, timeout=10)
                if process and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                self.workers.pop(row["id"], None)
            self.mount_idle_since.pop(row["id"], None)

    def close(self):
        self._closing.set()
        if self._mount_janitor is not None:
            self._mount_janitor.join(timeout=2)
        for row in self.store.list():
            self.disconnect(row["id"])
            try:
                self.unmount(row, force=True)
            except (OSError, ValueError, subprocess.SubprocessError):
                LOG.warning("Mapping unmount needs attention: %s", row["id"])
        if self.ipc:
            self.ipc.shutdown()
            self.ipc.server_close()
            self.socket_path.unlink(missing_ok=True)

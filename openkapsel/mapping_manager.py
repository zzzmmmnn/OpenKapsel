"""Mapping lifecycle, session fencing, and isolated per-mount FUSE workers."""

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

from .mapping_store import MappingStore
from .mapping_transport import ProviderSession, READ_OPERATIONS, encode, recv_line

LOG = logging.getLogger("openkapsel.mappings")


class MappingManager:
    def __init__(self, root, state_dir, *, enabled=False, mount_helper=None):
        self.root = root
        self.store = MappingStore(state_dir / "mappings.sqlite3")
        self.run_dir = root.parent / "mapping-run"
        self.run_dir.mkdir(mode=0o700, exist_ok=True)
        self.enabled = enabled
        self.mount_helper = mount_helper
        self.host_mounts = set()
        self.workspace_available = lambda workspace: True
        self.sessions, self.workers = {}, {}
        self.lock = threading.RLock()
        self.ipc = None
        self.socket_path = self.run_dir / "broker.sock"
        self.slots = threading.BoundedSemaphore(64)
        if enabled:
            if sys.platform != "linux":
                raise ValueError("server mappings require Linux FUSE")
            manager = self
            class IPCHandler(socketserver.StreamRequestHandler):
                def handle(self):
                    self.connection.settimeout(35)
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
            for row in self.store.list():
                try:
                    self.mount(row)
                except (OSError, ValueError):
                    LOG.error("Could not mount mapping %s; access remains unavailable", row["id"])

    def mount_path(self, row):
        workspace = self.root / row["workspace"]
        if workspace.is_symlink() or not workspace.is_dir() or workspace.resolve().parent != self.root:
            raise ValueError("mapping workspace must be an existing direct child workspace")
        return workspace / row["name"]

    def mount(self, row):
        if not self.enabled:
            raise ValueError("mappings_enabled must be enabled in server configuration")
        with self.lock:
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
                                        "--socket", str(self.socket_path), "--id", row["id"], "--mount", str(path)],
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
                row.update(online=bool(session and not session.closed and session.capabilities),
                           mounted=bool(row["id"] in self.host_mounts or (worker and worker.poll() is None)),
                           path=row["name"], capabilities=session.capabilities if session else {})
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
            if write and not row["writable"]:
                raise OSError(errno.EROFS, "mapping is read-only")
            with self.lock:
                session = self.sessions.get(row["id"])
                if not row["enabled"] or session is None or session.closed:
                    raise OSError(errno.EHOSTDOWN, "mapping client is offline")
        return row

    def call(self, mid, op, args):
        row = self.store.get(mid)
        if not self.workspace_available(row["workspace"]):
            self.disconnect(mid)
            raise OSError(errno.EACCES, "workspace is unavailable")
        with self.lock:
            session = self.sessions.get(mid)
            if not row["enabled"] or session is None or session.closed:
                raise OSError(errno.EHOSTDOWN, "mapping client is offline")
        if op.startswith("task_"):
            if not row["allow_exec"]:
                raise OSError(errno.EACCES, "mapping execution is disabled")
        elif (op not in READ_OPERATIONS or (op == "open" and (args.get("mode", "r") != "r" or args.get("truncate")))) and not row["writable"]:
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

    def accept(self, handler, row):
        self.mount(row)
        with self.lock:
            existing = self.sessions.get(row["id"])
            if existing and not existing.closed:
                raise ValueError("mapping already has an active provider")
            session = ProviderSession(handler)
            self.sessions[row["id"]] = session
        self.store.seen(row["id"])
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

    def unmount(self, row):
        self.disconnect(row["id"])
        if self.mount_helper is not None:
            from .workspace_images import WorkspaceImageError
            try:
                self.mount_helper._request("mapping_unmount", id=row["id"], workspace=row["workspace"], name=row["name"])
                self.host_mounts.discard(row["id"])
                return
            except WorkspaceImageError as exc:
                raise OSError(errno.EIO, str(exc)) from None
        with self.lock:
            process = self.workers.pop(row["id"], None)
            path = self.mount_path(row)
            if os.path.ismount(path):
                subprocess.run([self._fusermount(), "-uz", str(path)], check=True, capture_output=True, timeout=10)
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def close(self):
        for row in self.store.list():
            try:
                self.unmount(row)
            except (OSError, ValueError, subprocess.SubprocessError):
                LOG.warning("Mapping unmount needs attention: %s", row["id"])
        if self.ipc:
            self.ipc.shutdown()
            self.ipc.server_close()
            self.socket_path.unlink(missing_ok=True)

"""Lifecycle and Unix-socket transport for sandboxed Workspace FastAPI apps."""

from __future__ import annotations

import http.client
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .cgroups import (
    BUBBLEWRAP_PROCESS_OVERHEAD,
    SandboxLimits,
    TokenCgroupManager,
)
from .network_proxy import DomainProxy, PROXY_MOUNT, PROXY_PORT
from .tokens import TokenRecord


class ApiWorkerError(RuntimeError):
    pass


def apparmor_restricts_user_namespaces() -> bool:
    """Return whether Ubuntu's generic unprivileged-userns profile is active."""
    try:
        value = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text(
            encoding="ascii"
        )
    except OSError:
        return False
    return value.strip() == "1"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        value = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        value.settimeout(self.timeout)
        value.connect(str(self.socket_path))
        self.sock = value


@dataclass
class ApiWorker:
    app_id: str
    process: subprocess.Popen[bytes]
    socket_path: Path
    fingerprint: tuple[object, ...]
    last_used: float
    log_handle: object
    network_proxy: DomainProxy | None = None


class ApiWorkerManager:
    def __init__(
        self,
        *,
        worker_root: Path,
        bubblewrap_path: Path,
        rootlesskit_path: Path,
        cgroups: TokenCgroupManager,
        network_proxy_root: Path | None = None,
        idle_seconds: int = 600,
        start_timeout: float = 15,
    ):
        self.worker_root = worker_root
        self.bubblewrap_path = bubblewrap_path
        self.rootlesskit_path = rootlesskit_path
        self.cgroups = cgroups
        self.network_proxy_root = (
            network_proxy_root.resolve()
            if network_proxy_root is not None
            else (worker_root.parent / "network-proxies").resolve()
        )
        self.idle_seconds = idle_seconds
        self.start_timeout = start_timeout
        self._workers: dict[str, ApiWorker] = {}
        self._lock = threading.RLock()
        worker_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        worker_root.chmod(0o700)
        self._closing = threading.Event()
        self._janitor = threading.Thread(target=self._janitor_loop, daemon=True)
        self._janitor.start()

    def connection(
        self,
        record: TokenRecord,
        workspace: Path,
        root_path: str,
        worker_key: str,
    ) -> UnixHTTPConnection:
        worker = self._ensure(record, workspace, root_path, worker_key)
        worker.last_used = time.monotonic()
        return UnixHTTPConnection(worker.socket_path)

    def stop(self, app_id: str) -> None:
        with self._lock:
            keys = [
                key
                for key, worker in self._workers.items()
                if worker.app_id == app_id
            ]
            workers = [self._workers.pop(key) for key in keys]
        for worker in workers:
            self._terminate(worker)

    def close(self) -> None:
        self._closing.set()
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
        for worker in workers:
            self._terminate(worker)
        self._janitor.join(timeout=2)

    def _ensure(
        self,
        record: TokenRecord,
        workspace: Path,
        root_path: str,
        worker_key: str,
    ) -> ApiWorker:
        api_root = workspace / "api"
        entry = api_root / "app.py"
        if api_root.is_symlink() or not api_root.is_dir() or not entry.is_file() or entry.is_symlink():
            raise ApiWorkerError("Workspace api/app.py does not exist")
        fingerprint = self._fingerprint(record, workspace, root_path)
        with self._lock:
            current = self._workers.get(worker_key)
            if current is not None and (
                current.process.poll() is not None or current.fingerprint != fingerprint
            ):
                self._workers.pop(worker_key, None)
                self._terminate(current)
                current = None
            if current is not None:
                return current
            worker = self._start(
                record, workspace, root_path, worker_key, fingerprint
            )
            self._workers[worker_key] = worker
            return worker

    def _start(
        self,
        record: TokenRecord,
        workspace: Path,
        root_path: str,
        worker_key: str,
        fingerprint: tuple[object, ...],
    ) -> ApiWorker:
        if not self.bubblewrap_path.is_file() or not os.access(self.bubblewrap_path, os.X_OK):
            raise ApiWorkerError(f"Bubblewrap is unavailable at {self.bubblewrap_path}")
        worker_dir = self.worker_root / worker_key
        if worker_dir.exists():
            shutil.rmtree(worker_dir)
        worker_dir.mkdir(mode=0o700)
        socket_path = worker_dir / "app.sock"
        log_handle = (worker_dir / "worker.log").open("ab", buffering=0)
        network_proxy = None
        if record.network_mode == "domain_allowlist":
            network_proxy = DomainProxy.start(
                self.network_proxy_root,
                record.allowed_domains,
            )
        try:
            argv = self._sandbox_argv(
                record, workspace, worker_dir, socket_path, root_path,
                network_proxy=network_proxy,
            )
        except Exception:
            log_handle.close()
            if network_proxy is not None:
                network_proxy.close()
            raise
        if self.cgroups.available:
            limits = SandboxLimits(
                record.sandbox_max_processes,
                record.sandbox_memory_mb * 1024 * 1024,
                record.sandbox_cpu_percent,
                process_overhead=BUBBLEWRAP_PROCESS_OVERHEAD,
            )
            procs_file = self.cgroups.ensure_capacity(record.token, limits)
            argv = [
                sys.executable,
                "-m",
                "openkapsel.cgroup_exec",
                str(procs_file),
                *argv,
            ]
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=log_handle,
                start_new_session=True,
            )
        except OSError as exc:
            log_handle.close()
            if network_proxy is not None:
                network_proxy.close()
            raise ApiWorkerError(f"cannot start FastAPI worker: {exc}") from None
        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log_handle.close()
                if network_proxy is not None:
                    network_proxy.close()
                message = self._log_tail(worker_dir / "worker.log")
                raise ApiWorkerError(f"FastAPI worker exited during startup: {message}")
            if socket_path.exists():
                return ApiWorker(
                    record.app_id,
                    process,
                    socket_path,
                    fingerprint,
                    time.monotonic(),
                    log_handle,
                    network_proxy,
                )
            time.sleep(0.05)
        process.terminate()
        log_handle.close()
        if network_proxy is not None:
            network_proxy.close()
        raise ApiWorkerError("FastAPI worker did not create its Unix socket in time")

    def _sandbox_argv(
        self,
        record: TokenRecord,
        workspace: Path,
        worker_dir: Path,
        socket_path: Path,
        root_path: str,
        command: list[str] | None = None,
        network_proxy: DomainProxy | None = None,
    ) -> list[str]:
        executable = str(self.bubblewrap_path)
        workspace_text = str(workspace)
        sql_root = workspace / ".sql"
        if sql_root.is_symlink() or (sql_root.exists() and not sql_root.is_dir()):
            raise ApiWorkerError("Workspace .sql must be a real directory")
        sql_root.mkdir(mode=0o700, exist_ok=True)
        sql_root.chmod(0o700)
        mounts = [
            executable,
            "--die-with-parent", "--new-session", "--unshare-user", "--unshare-ipc",
            "--unshare-uts", "--unshare-pid", "--unshare-cgroup-try",
            "--cap-drop", "ALL",
        ]
        if record.network_mode != "full":
            mounts.append("--unshare-net")
        mounts.extend([
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/sbin", "/sbin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--dev", "/dev", "--dir", "/etc", "--dir", "/var", "--dir", "/opt",
            "--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--dir", "/run",
            "--proc", "/proc",
        ])
        self._append_parent_dirs(mounts, Path("/opt/openkapsel"))
        mounts.extend([
            "--ro-bind", "/opt/openkapsel/venv", "/opt/openkapsel/venv",
        ])
        for host_path in ("/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/hosts",
                          "/etc/resolv.conf", "/etc/ssl", "/etc/ca-certificates",
                          "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/fonts",
                          "/etc/localtime", "/etc/timezone"):
            path = Path(host_path)
            if path.exists():
                self._append_parent_dirs(mounts, path.parent)
                mounts.extend(["--ro-bind", host_path, host_path])
        self._append_parent_dirs(mounts, workspace.parent)
        scope_mode = "--bind" if record.can_write else "--ro-bind"
        mounts.extend([scope_mode, workspace_text, workspace_text])
        mounts.extend(["--bind", str(sql_root), str(sql_root)])
        recycle = workspace / ".recycle"
        if recycle.is_dir():
            mounts.extend(["--tmpfs", str(recycle)])
        context_root = workspace / ".context"
        if context_root.is_dir():
            mounts.extend(["--tmpfs", str(context_root)])
        self._append_parent_dirs(mounts, worker_dir.parent)
        mounts.extend(["--bind", str(worker_dir), str(worker_dir)])
        python = "/opt/openkapsel/venv/bin/python"
        runtime_command = command or [
            python, "-m", "uvicorn", "api.app:app",
            "--uds", str(socket_path), "--root-path", root_path,
            "--no-server-header", "--log-level", "warning",
        ]
        if record.network_mode == "domain_allowlist":
            if network_proxy is None:
                raise ApiWorkerError("domain allowlist API worker is missing its network proxy")
            relay = Path(__file__).with_name("proxy_relay.py").resolve()
            mounts.extend(["--ro-bind", str(network_proxy.directory), PROXY_MOUNT])
            mounts.extend(["--ro-bind", str(relay), "/run/openkapsel-proxy-relay.py"])
            proxy_url = f"http://127.0.0.1:{PROXY_PORT}"
            runtime_command = [
                python, "/run/openkapsel-proxy-relay.py",
                "--socket", f"{PROXY_MOUNT}/proxy.sock", "--port", str(PROXY_PORT),
                "--", *runtime_command,
            ]
        mounts.extend([
            "--clearenv",
            "--setenv", "PATH", "/opt/openkapsel/venv/bin:/usr/bin:/bin",
            "--setenv", "HOME", workspace_text,
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "OPENKAPSEL_WORKSPACE", workspace_text,
        ])
        if record.network_mode == "domain_allowlist":
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                mounts.extend(["--setenv", name, proxy_url])
            mounts.extend(["--setenv", "NO_PROXY", "", "--setenv", "no_proxy", ""])
        mounts.extend(["--chdir", workspace_text, "--", *runtime_command])
        use_rootlesskit = record.network_mode == "full" or apparmor_restricts_user_namespaces()
        if use_rootlesskit:
            if not self.rootlesskit_path.is_file():
                reason = "full-network" if record.network_mode == "full" else "AppArmor-compatible"
                raise ApiWorkerError(f"RootlessKit is unavailable for {reason} API worker")
            return [
                str(self.rootlesskit_path), "--copy-up=/etc", "--net=slirp4netns",
                "--disable-host-loopback", "--", *mounts,
            ]
        return mounts

    @staticmethod
    def _append_parent_dirs(argv: list[str], path: Path) -> None:
        current = Path("/")
        existing = {argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--dir"}
        for part in path.parts[1:]:
            current /= part
            value = str(current)
            if value not in existing:
                argv.extend(["--dir", value])
                existing.add(value)

    @staticmethod
    def _fingerprint(record: TokenRecord, workspace: Path, root_path: str) -> tuple[object, ...]:
        files = []
        for path in sorted((workspace / "api").rglob("*.py")):
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append((str(path.relative_to(workspace)), stat.st_mtime_ns, stat.st_size))
        return (
            tuple(files), root_path, record.network_mode, record.allowed_domains,
            record.can_write, record.sandbox_max_processes, record.sandbox_memory_mb,
            record.sandbox_cpu_percent,
        )

    def _janitor_loop(self) -> None:
        while not self._closing.wait(30):
            cutoff = time.monotonic() - self.idle_seconds
            with self._lock:
                stale = [key for key, worker in self._workers.items()
                         if worker.last_used < cutoff or worker.process.poll() is not None]
                workers = [self._workers.pop(key) for key in stale]
            for worker in workers:
                self._terminate(worker)

    @staticmethod
    def _terminate(worker: ApiWorker) -> None:
        if worker.process.poll() is None:
            worker.process.terminate()
            try:
                worker.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                worker.process.kill()
                worker.process.wait(timeout=2)
        worker.log_handle.close()
        if worker.network_proxy is not None:
            worker.network_proxy.close()

    @staticmethod
    def _log_tail(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[-2000:].strip()
        except OSError:
            return "no worker log"

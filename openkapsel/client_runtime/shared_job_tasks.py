"""Mapping Client task adapter: local RPC workers plus persistent shared Shell jobs."""
from __future__ import annotations

import base64
import errno
import os
import queue
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from openkapsel.job_manager import JOB_RE, new_job_id, request, state_home


class SharedClientTasks:
    def __init__(self, legacy, *, url, token, home=None, config=None):
        self.legacy = legacy
        self.files = legacy.files
        self.id = urlsplit(url).path.rsplit("/", 1)[-1]
        self.credential = token
        self.config = config or {}
        self.home = state_home() if home is None else Path(home)
        if len(self.id) != 24 or not all(c.isalnum() or c in "_-" for c in self.id):
            raise ValueError("mapping URL must end with a 24-character mapping ID")

    def __getattr__(self, name):
        return getattr(self.legacy, name)

    def capabilities(self):
        result = self.legacy.capabilities()
        result.update(
            max_tasks=4,
            manager_max_tasks=16,
            job_manager=True,
            reconnect_persistence=True,
            restart_persistence=True,
            result_storage="shared_manager_disk",
            uncollected_results="disk_spool_until_acknowledged_or_cleanup",
            max_seconds=None,
            default_seconds=600,
        )
        return result

    def close(self):
        # The legacy in-client workers still close; shared shell jobs are NOT
        # interrupted. Only explicit manager --stop or task_kill terminates.
        self.legacy.close()

    def dispatch(self, op, args):
        if op == "task_start" and isinstance(args.get("rpc"), dict):
            if JOB_RE.fullmatch(args.get("task_id", "")):
                return request(self.home, self.id, self.credential, op,
                               self._prepare_rpc(args))
            return self.legacy.dispatch(op, args)
        if op == "task_list":
            remote = request(self.home, self.id, self.credential, op)
            legacy = self.legacy.dispatch(op, args)
            return remote + legacy
        tid = args.get("task_id", "")
        if op == "task_start" and not JOB_RE.fullmatch(tid):
            # In-process legacy callers may still use old IDs for tests or
            # internal clients. Normal Server-generated Shell IDs are &xxxx&.
            return self.legacy.dispatch(op, args)
        if op != "task_start" and not JOB_RE.fullmatch(tid):
            return self.legacy.dispatch(op, args)
        if op == "task_start":
            if not self.legacy.enabled:
                raise OSError(errno.EACCES, "client execution is disabled")
            prepared = self._prepare(args)
            return request(self.home, self.id, self.credential, op, prepared)
        if op not in {"task_get", "task_stdin", "task_interrupt", "task_kill"}:
            raise OSError(errno.ENOSYS, "unknown task operation")
        return request(self.home, self.id, self.credential, op, args)

    def _prepare_rpc(self, args):
        rpc = args["rpc"]
        family = rpc.get("family")
        operation = rpc.get("operation")
        rpc_args = rpc.get("args", {})
        if (not isinstance(family, str) or not isinstance(operation, str)
                or not isinstance(rpc_args, dict)):
            raise OSError(errno.EINVAL, "invalid RPC task request")
        spec = self.files.rpc_registry.operation_spec(family, operation)
        if spec is None or spec.get("execution") != "task":
            raise OSError(errno.ENOSYS, "task-based RPC plugin is not available")
        if spec.get("write") and not self.files.writable:
            raise OSError(errno.EROFS, "mapping export is read-only")
        timeout = args.get("timeout_seconds", 600)
        if timeout is None:
            timeout = 600
        if type(timeout) not in (int, float) or not 0.1 <= timeout < float("inf"):
            raise OSError(errno.EINVAL, "invalid task timeout")
        return {
            "kind": "rpc", "task_id": args["task_id"],
            "cwd": str(self.files.root), "interactive": False,
            "timeout_seconds": float(timeout),
            "env": None, "worker_python": sys.executable,
            "rpc_write": bool(spec.get("write")),
            "rpc_payload": {
                "config": self.config,
                "root": str(self.files.root),
                "protected_paths": [str(p) for p in self.files.protected_paths],
                "rpc": rpc,
            },
        }

    def _prepare(self, args):
        """Apply Client execution policy before the Manager gets subprocess argv."""
        legacy = self.legacy
        command = args.get("command")
        argv = args.get("argv")
        if command is not None:
            if (argv is not None or not isinstance(command, str) or not command.strip()
                    or len(command) > 100000 or "\x00" in command):
                raise OSError(errno.EINVAL, "invalid command")
            argv = ([ "cmd.exe", "/d", "/s", "/c", command ]
                    if os.name == "nt" and not legacy.sandbox
                    else ["/bin/sh", "-c", command])
        if not isinstance(argv, list) or not argv or len(argv) > 256 or any(
            not isinstance(arg, str) or "\x00" in arg for arg in argv
        ) or sum(map(len, argv)) > 32768:
            raise OSError(errno.EINVAL, "invalid argv")
        interactive = args.get("interactive", command is None)
        if type(interactive) is not bool:
            raise OSError(errno.EINVAL, "invalid interactive flag")
        cwd = self.files.path(args.get("cwd", "."))
        if os.name == "nt":
            with self.files.paths.guard(cwd, include_final=True):
                if not cwd.is_dir():
                    raise OSError(errno.ENOTDIR, "cwd is not a directory")
        else:
            descriptor = self.files.paths.open(cwd, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            os.close(descriptor)
        timeout = args.get("timeout_seconds", 600)
        if timeout is None:
            timeout = 600
        if (type(timeout) not in (int, float) or
                not 0.1 <= timeout < float("inf")):
            raise OSError(errno.EINVAL, "invalid task timeout")
        env = {k: os.environ[k] for k in (
            "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "LANG"
        ) if k in os.environ}
        executable = None
        container = None
        if legacy.sandbox:
            container = "openkapsel-client-" + args["task_id"][1:-1].lower()
            mode = "rw" if self.files.writable else "ro"
            hidden = []
            for protected in sorted(self.files.protected_paths, key=str):
                relative = protected.relative_to(self.files.root).as_posix()
                hidden.extend(["--volume", f"{legacy.secret_mask_path}:/workspace/{relative}:ro"])
            argv = [
                "podman", "run", "--rm", "--name", container, "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--pids-limit", str(legacy.processes),
                "--memory", f"{legacy.memory_mb}m", "--cpus", str(legacy.cpus),
                "--network", "slirp4netns" if legacy.network else "none",
                "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "--volume", f"{self.files.root}:/workspace:{mode}", *hidden,
                "--workdir", "/workspace/" + cwd.relative_to(self.files.root).as_posix(),
                "--tmpfs", "/workspace/.openkapsel:rw,nosuid,nodev,noexec,size=1m",
                "--interactive", legacy.image, *argv,
            ]
        if command is not None and os.name == "nt" and not legacy.sandbox:
            executable = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
            argv = f'"{executable}" /d /s /c "{command}"'
        return {
            "task_id": args["task_id"], "argv": argv, "cwd": str(cwd),
            "interactive": interactive, "timeout_seconds": float(timeout),
            "env": env, "executable": executable, "container": container,
        }

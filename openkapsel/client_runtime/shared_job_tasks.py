"""Mapping Shell Job Manager adapter; RPC stays entirely inside ClientRuntime."""
from __future__ import annotations

import errno
import os
from pathlib import Path
from urllib.parse import urlsplit

from openkapsel.job_manager import JOB_RE, prepare_home, request, state_home


class SharedClientTasks:
    def __init__(self, legacy, *, url, home=None):
        self.legacy = legacy
        self.files = legacy.files
        self.id = urlsplit(url).path.rsplit("/", 1)[-1]
        self.home = (state_home() if home is None else Path(home)).expanduser().resolve()
        # The Manager stores SQLite metadata and task I/O:
        # never let the Manager's private state be exposed by the Mapping.
        try:
            self.home.relative_to(self.files.root)
        except ValueError:
            pass
        else:
            raise ValueError("shared Job Manager state must be outside Mapping exports")
        if len(self.id) != 24 or not all(c.isalnum() or c in "_-" for c in self.id):
            raise ValueError("mapping URL must end with a 24-character mapping ID")
        self.legacy.shell_mapping_key = self.id

    def __getattr__(self, name):
        return getattr(self.legacy, name)

    def capabilities(self):
        result = self.legacy.capabilities()
        result.update(
            manager_max_tasks=16,
            manager_max_per_mapping=4,
            job_manager=True,
            reconnect_persistence=True,
            restart_persistence=True,
            restart_persistence_timeout_gt=120,
            result_storage="client_memory_or_shared_manager_disk",
            uncollected_results="client_memory_or_disk_spool",
            manager_max_seconds=None,
            default_seconds=120,
        )
        return result

    def has_active_jobs(self):
        # External Manager-owned jobs must NEVER defer a Client source reload.
        # Existing async RPC jobs are still Client-owned and block reload.
        return self.legacy.has_active_jobs()

    def close(self):
        # The legacy in-client workers still close; shared shell jobs are NOT
        # interrupted. Only explicit manager --stop or task_kill terminates.
        self.legacy.close()

    def dispatch(self, op, args):
        # RPC (both sync and async) uses the original Client code path.
        if op == "task_start" and isinstance(args.get("rpc"), dict):
            return self.legacy.dispatch(op, args)
        if op == "task_list":
            remote = request(self.home, self.id, op)
            return remote + self.legacy.dispatch(op, args)
        tid = args.get("task_id", "")
        if op == "task_start":
            if not JOB_RE.fullmatch(tid):
                raise OSError(errno.EINVAL, "Shell Job ID must be & followed by 4 alphanumeric chars and &")
            if not self.legacy.enabled:
                raise OSError(errno.EACCES, "client execution is disabled")
            timeout = args.get("timeout_seconds")
            if timeout is None:
                timeout = 120
            if (type(timeout) not in (int, float) or
                    not 0.1 <= timeout < float("inf")):
                raise OSError(errno.EINVAL, "invalid Shell timeout")
            invocation = dict(args, timeout_seconds=timeout)
            if timeout <= 120:
                # Short-lived Shell stays with the Client, including stdin and
                # output. No Manager process or IPC is needed to start it.
                return self.legacy.dispatch(op, invocation)
            # Long Shell is owned by the independent shared Job Manager.
            return request(self.home, self.id, op, self._prepare(invocation))
        if not JOB_RE.fullmatch(tid):
            return self.legacy.dispatch(op, args)
        if op not in {"task_get", "task_stdin", "task_interrupt", "task_kill"}:
            raise OSError(errno.ENOSYS, "unknown task operation")
        # Short Shell jobs share the same public ID shape as long ones.
        # Choose the in-process record while it exists. No mapping key or
        # other Client configuration is requested from the API caller.
        with self.legacy.lock:
            if tid in self.legacy.tasks:
                return self.legacy.dispatch(op, args)
        return request(self.home, self.id, op, args)

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
        timeout = args.get("timeout_seconds", 120)
        if timeout is None:
            timeout = 120
        if (type(timeout) not in (int, float) or
                not 0.1 <= timeout < float("inf")):
            raise OSError(errno.EINVAL, "invalid task timeout")
        env = {k: os.environ[k] for k in (
            "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "LANG"
        ) if k in os.environ}
        executable = None
        container = None
        if legacy.sandbox:
            container = "openkapsel-client-" + self.id + "-" + args["task_id"][1:-1]
            mode = "rw" if self.files.writable else "ro"
            hidden = []
            if self.files.protected_paths:
                # The Manager must own the bind-mount source throughout the
                # running Job, even when ClientRuntime closes its temp files.
                home = prepare_home(self.home)
                masks = home / "masks"
                masks.mkdir(mode=0o700, exist_ok=True)
                mask = masks / (self.id + "." + args["task_id"])
                try:
                    fd = os.open(mask, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    if not mask.is_file() or mask.stat().st_size:
                        raise OSError(errno.EACCES, "unsafe persistent sandbox mask")
                else:
                    os.close(fd)
                for protected in sorted(self.files.protected_paths, key=str):
                    relative = protected.relative_to(self.files.root).as_posix()
                    hidden.extend(["--volume", f"{mask}:/workspace/{relative}:ro"])
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

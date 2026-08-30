"""Asynchronous shell task execution, buffering, limits, and persistence."""

from __future__ import annotations

import base64
import logging
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any

from .cgroups import SandboxLimits, TokenCgroupManager
from .errors import ApiError
from .task_history import ArchivedTask, TaskHistoryStore


LOGGER = logging.getLogger("openkapsel")
RESOLVER_FD_MARKER = "__OPENKAPSEL_RESOLVER_FD__"
_SANDBOX_STDERR_BUFFER_LIMIT = 256 * 1024
_SANDBOX_LAUNCHERS = (b"bwrap", b"rootlesskit", b"cgroup_exec.py")
_SANDBOX_LAUNCH_ARGUMENTS = (
    b"--ro-bind",
    b"--bind",
    b"--unshare-user",
    b"--unshare-pid",
    b"--cap-drop",
    b"--die-with-parent",
)
_SANDBOX_LAUNCH_REDACTION = b"[workspace] sandbox launcher error details redacted"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BoundedOutput:
    """Thread-safe tail buffer that never exceeds its configured byte limit."""

    def __init__(self, limit: int):
        self.limit = limit
        self._data = bytearray()
        self._dropped = 0
        self._lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        with self._lock:
            self._data.extend(chunk)
            overflow = len(self._data) - self.limit
            if overflow > 0:
                del self._data[:overflow]
                self._dropped += overflow

    def snapshot(self) -> tuple[str, int]:
        with self._lock:
            return self._data.decode("utf-8", errors="replace"), self._dropped

    def snapshot_bytes(self) -> tuple[bytes, int]:
        with self._lock:
            return bytes(self._data), self._dropped

    def read_from(self, offset: int, limit: int) -> dict[str, Any]:
        with self._lock:
            start = self._dropped
            end = start + len(self._data)
            gap = offset < start
            actual = min(max(offset, start), end)
            relative = actual - start
            chunk = bytes(self._data[relative : relative + limit])
            return {
                "data": chunk.decode("utf-8", errors="replace"),
                "data_base64": base64.b64encode(chunk).decode("ascii"),
                "encoding": "utf-8-replace",
                "offset": actual,
                "next_offset": actual + len(chunk),
                "available_end": end,
                "gap": gap,
            }


@dataclass
class ShellTask:
    id: str
    command: str
    cwd: str
    output_limit: int
    timeout_seconds: float | None
    owner_token: str = field(repr=False)
    argv: tuple[str, ...] | None = field(default=None, repr=False)
    stdin_data: bytes | None = field(default=None, repr=False)
    interactive: bool = False
    sandboxed: bool = False
    sandbox_backend: str | None = None
    network_access: bool = True
    resource_limited: bool = False
    cgroup_procs_file: Path | None = field(default=None, repr=False)
    sandbox_controller: Any | None = field(default=None, repr=False)
    status: str = "running"
    exit_code: int | None = None
    error: str | None = None
    started_at: str = field(default_factory=_utc_now)
    finished_at: str | None = None
    timed_out: bool = False
    interrupted: bool = False
    force_killed: bool = False
    process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    stdout: BoundedOutput = field(init=False, repr=False)
    stderr: BoundedOutput = field(init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.stdout = BoundedOutput(self.output_limit)
        self.stderr = BoundedOutput(self.output_limit)

    def serialize(self) -> dict[str, Any]:
        stdout, stdout_dropped = self.stdout.snapshot()
        stderr, stderr_dropped = self.stderr.snapshot()
        with self._lock:
            return {
                "task_id": self.id,
                "status": self.status,
                "command": self.command,
                "cwd": self.cwd,
                "exit_code": self.exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated_bytes": stdout_dropped,
                "stderr_truncated_bytes": stderr_dropped,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "timed_out": self.timed_out,
                "interrupted": self.interrupted,
                "force_killed": self.force_killed,
                "interactive": self.interactive,
                "stdin_open": bool(
                    self.interactive
                    and self.process is not None
                    and self.process.poll() is None
                    and self.process.stdin is not None
                    and not self.process.stdin.closed
                ),
                "error": self.error,
                "sandboxed": self.sandboxed,
                "sandbox_backend": self.sandbox_backend,
                "network_access": self.network_access,
                "resource_limited": self.resource_limited,
            }

    def summary(self) -> dict[str, Any]:
        payload = self.serialize()
        payload.pop("stdout", None)
        payload.pop("stderr", None)
        return payload


class TaskRegistry:
    def __init__(self, config: Any, cgroups: TokenCgroupManager):
        self.config = config
        self.cgroups = cgroups
        self._tasks: dict[str, ShellTask] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self._closing = False
        assert config.task_history_dir is not None
        self.history = TaskHistoryStore(
            config.task_history_dir,
            retention_seconds=config.finished_task_retention_seconds,
            max_per_token=config.max_finished_tasks_per_token,
        )

    def close(self) -> None:
        with self._lock:
            if self._closing:
                threads = list(self._threads.values())
                tasks: list[ShellTask] = []
            else:
                self._closing = True
                threads = list(self._threads.values())
                tasks = list(self._tasks.values())
        for task in tasks:
            with task._lock:
                task.interrupted = True
                process = task.process
            if process is not None and process.poll() is None:
                self._terminate_task(task, process)
        deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._lock:
            remaining = list(self._tasks.values())
            threads = list(self._threads.values())
        for task in remaining:
            with task._lock:
                task.force_killed = True
                process = task.process
            if process is not None:
                self._kill_task(task, process)
        deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        self.history.close()

    def start(
        self,
        command: str,
        cwd: Path,
        timeout_seconds: float | None,
        owner_token: str,
        argv: tuple[str, ...] | None = None,
        stdin_data: bytes | None = None,
        interactive: bool = False,
        sandboxed: bool = False,
        sandbox_backend: str | None = None,
        sandbox_controller: Any | None = None,
        network_access: bool = True,
        resource_limits: SandboxLimits | None = None,
    ) -> ShellTask:
        with self._lock:
            if self._closing:
                raise ApiError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "shell_registry_closing",
                    "the server is shutting down and cannot start another shell task",
                )
        cgroup_procs_file = None
        if resource_limits is not None:
            try:
                cgroup_procs_file = self.cgroups.ensure_capacity(owner_token, resource_limits)
            except ProcessLookupError as exc:
                raise ApiError(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "sandbox_process_limit_reached",
                    str(exc),
                    {"scope": "token_sandbox", "limit": resource_limits.max_processes},
                ) from None
            except (OSError, RuntimeError) as exc:
                raise ApiError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "sandbox_resources_unavailable",
                    f"token resource controls are unavailable: {exc}",
                ) from None
        task = ShellTask(
            id=f"task_{secrets.token_urlsafe(12)}",
            command=command,
            cwd=str(cwd),
            output_limit=self.config.max_task_output_bytes,
            timeout_seconds=timeout_seconds,
            owner_token=owner_token,
            argv=argv,
            stdin_data=stdin_data,
            interactive=interactive,
            sandboxed=sandboxed,
            sandbox_backend=sandbox_backend,
            sandbox_controller=sandbox_controller,
            network_access=network_access,
            resource_limited=cgroup_procs_file is not None,
            cgroup_procs_file=cgroup_procs_file,
        )
        with self._lock:
            if self._closing:
                raise ApiError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "shell_registry_closing",
                    "the server is shutting down and cannot start another shell task",
                )
            running = [item for item in self._tasks.values() if item.status == "running"]
            global_running = len(running)
            token_running = sum(item.owner_token == owner_token for item in running)
            if token_running >= self.config.max_concurrent_shell_tasks_per_token:
                raise ApiError(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "shell_task_token_limit_reached",
                    f"this token already has the maximum number of running shell tasks ({self.config.max_concurrent_shell_tasks_per_token})",
                    {
                        "scope": "token",
                        "limit": self.config.max_concurrent_shell_tasks_per_token,
                        "running": token_running,
                    },
                )
            if global_running >= self.config.max_concurrent_shell_tasks:
                raise ApiError(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "shell_task_global_limit_reached",
                    f"the server already has the maximum number of running shell tasks ({self.config.max_concurrent_shell_tasks})",
                    {
                        "scope": "global",
                        "limit": self.config.max_concurrent_shell_tasks,
                        "running": global_running,
                    },
                )
            self._tasks[task.id] = task
            thread = threading.Thread(
                target=self._run,
                args=(task,),
                name=f"shell-{task.id}",
                daemon=True,
            )
            self._threads[task.id] = thread
            thread.start()
        return task

    def get(self, task_id: str, owner_token: str) -> ShellTask | ArchivedTask:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is not None and secrets.compare_digest(task.owner_token, owner_token):
            return task
        archived = self.history.load(owner_token, task_id)
        if archived is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "task_not_found", "task does not exist")
        return archived

    def list(self, owner_token: str, offset: int, limit: int, status: str | None) -> tuple[list[dict[str, Any]], int]:
        with self._lock:
            live_tasks = [
                task
                for task in self._tasks.values()
                if secrets.compare_digest(task.owner_token, owner_token)
                and (status is None or task.status == status)
            ]
        records = {task.id: task.summary() for task in live_tasks}
        if status in {None, "finished"}:
            for archived in self.history.list(owner_token):
                records.setdefault(str(archived["task_id"]), archived)
        tasks = sorted(records.values(), key=lambda task: str(task["started_at"]), reverse=True)
        return tasks[offset : offset + limit], len(tasks)

    def process_roots(self, owner_token: str) -> dict[int, str]:
        with self._lock:
            tasks = list(self._tasks.values())
        roots: dict[int, str] = {}
        for task in tasks:
            if not secrets.compare_digest(task.owner_token, owner_token):
                continue
            with task._lock:
                process = task.process
                if process is not None and process.poll() is None:
                    roots[process.pid] = task.id
        return roots

    def interrupt(self, task_id: str, owner_token: str) -> ShellTask:
        task = self.get(task_id, owner_token)
        with task._lock:
            if task.status == "finished":
                return task
            task.interrupted = True
            process = task.process
        if process is not None:
            self._terminate_task(task, process)
        return task

    def kill(self, task_id: str, owner_token: str) -> ShellTask:
        task = self.get(task_id, owner_token)
        with task._lock:
            if task.status == "finished":
                return task
            task.interrupted = True
            task.force_killed = True
            process = task.process
        if process is not None:
            self._kill_task(task, process)
        return task

    def write_stdin(self, task_id: str, owner_token: str, data: bytes, close: bool) -> ShellTask:
        task = self.get(task_id, owner_token)
        with task._lock:
            if not task.interactive:
                raise ValueError("task is not interactive")
            process = task.process
            if task.status == "finished" or process is None or process.stdin is None or process.stdin.closed:
                raise BrokenPipeError("task stdin is closed")
            try:
                if data:
                    process.stdin.write(data)
                    process.stdin.flush()
                if close:
                    process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                raise BrokenPipeError("task stdin is closed") from None
        return task

    @staticmethod
    def _looks_like_sandbox_launch(line: bytes) -> bool:
        return any(item in line for item in _SANDBOX_LAUNCHERS) and sum(
            item in line for item in _SANDBOX_LAUNCH_ARGUMENTS
        ) >= 2

    @classmethod
    def _copy_stream(
        cls,
        stream: Any,
        target: BoundedOutput,
        redact_sandbox_launcher: bool = False,
    ) -> None:
        pending = bytearray()
        discarding_redacted_line = False

        def append_line(line: bytes) -> None:
            if redact_sandbox_launcher and cls._looks_like_sandbox_launch(line):
                suffix = b"\n" if line.endswith(b"\n") else b""
                target.append(_SANDBOX_LAUNCH_REDACTION + suffix)
            else:
                target.append(line)

        try:
            while True:
                try:
                    chunk = os.read(stream.fileno(), 16 * 1024)
                except OSError:
                    break
                if not chunk:
                    break
                if not redact_sandbox_launcher:
                    target.append(chunk)
                    continue
                pending.extend(chunk)
                while True:
                    newline = pending.find(b"\n")
                    if newline < 0:
                        break
                    line = bytes(pending[: newline + 1])
                    del pending[: newline + 1]
                    if discarding_redacted_line:
                        discarding_redacted_line = False
                    else:
                        append_line(line)
                if discarding_redacted_line and len(pending) > _SANDBOX_STDERR_BUFFER_LIMIT:
                    pending.clear()
                if len(pending) > _SANDBOX_STDERR_BUFFER_LIMIT:
                    if cls._looks_like_sandbox_launch(pending):
                        target.append(_SANDBOX_LAUNCH_REDACTION)
                        pending.clear()
                        discarding_redacted_line = True
                    else:
                        flush_size = len(pending) - (_SANDBOX_STDERR_BUFFER_LIMIT // 2)
                        target.append(bytes(pending[:flush_size]))
                        del pending[:flush_size]
        finally:
            if pending and not discarding_redacted_line:
                append_line(bytes(pending))
            stream.close()

    def _run(self, task: ShellTask) -> None:
        injected_file = None
        try:
            command: str | tuple[str, ...] = task.argv if task.argv is not None else task.command
            pass_fds: tuple[int, ...] = ()
            if task.stdin_data is not None:
                injected_file = tempfile.TemporaryFile()
                injected_file.write(task.stdin_data)
                injected_file.seek(0)
                descriptor = injected_file.fileno()
                if task.argv is None:
                    raise RuntimeError("injected files require an argv command")
                command = tuple(str(descriptor) if item == RESOLVER_FD_MARKER else item for item in task.argv)
                pass_fds = (descriptor,)
            use_shell = task.argv is None
            executable = "/bin/sh" if use_shell else None
            if task.cgroup_procs_file is not None:
                child_command = ("/bin/sh", "-c", str(command)) if use_shell else tuple(command)
                command = (
                    sys.executable,
                    str(Path(__file__).with_name("cgroup_exec.py")),
                    str(task.cgroup_procs_file),
                    *child_command,
                )
                use_shell = False
                executable = None
            process = subprocess.Popen(
                command,
                shell=use_shell,
                executable=executable,
                cwd=task.cwd,
                stdin=subprocess.PIPE if task.interactive else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=pass_fds,
            )
            if injected_file is not None:
                injected_file.close()
                injected_file = None
            with task._lock:
                task.process = process
                interrupted = task.interrupted
                force_killed = task.force_killed
            if force_killed:
                self._kill_task(task, process)
            elif interrupted:
                self._terminate_task(task, process)
            stdout_thread = threading.Thread(target=self._copy_stream, args=(process.stdout, task.stdout), daemon=True)
            stderr_thread = threading.Thread(
                target=self._copy_stream,
                args=(process.stderr, task.stderr, task.sandboxed),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            try:
                exit_code = process.wait(timeout=task.timeout_seconds)
            except subprocess.TimeoutExpired:
                task.timed_out = True
                task.stderr.append(b"\n[workspace] command timed out; terminating process group\n")
                self._terminate_task(task, process)
                exit_code = process.wait()
            stdout_thread.join()
            stderr_thread.join()
            with task._lock:
                task.exit_code = exit_code
        except Exception as exc:  # pragma: no cover - platform/process failures
            LOGGER.exception("shell task %s failed", task.id)
            with task._lock:
                task.error = f"{type(exc).__name__}: {exc}"
                task.exit_code = None
        finally:
            if task.sandbox_controller is not None:
                task.sandbox_controller.cleanup()
            if injected_file is not None:
                injected_file.close()
            if task.process is not None and task.process.stdin is not None and not task.process.stdin.closed:
                task.process.stdin.close()
            with task._lock:
                task.status = "finished"
                task.finished_at = _utc_now()
            stdout, stdout_dropped = task.stdout.snapshot_bytes()
            stderr, stderr_dropped = task.stderr.snapshot_bytes()
            metadata = task.summary()
            metadata["stdout_truncated_bytes"] = stdout_dropped
            metadata["stderr_truncated_bytes"] = stderr_dropped
            try:
                self.history.save(task.owner_token, metadata, stdout, stderr)
            except (OSError, ValueError):
                LOGGER.exception("could not archive completed shell task %s", task.id)
            finally:
                with self._lock:
                    if self._tasks.get(task.id) is task:
                        self._tasks.pop(task.id, None)
                    self._threads.pop(task.id, None)

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _terminate_task(self, task: ShellTask, process: subprocess.Popen[bytes]) -> None:
        if task.sandbox_controller is not None:
            task.sandbox_controller.terminate()
        self._terminate_process_group(process)

    def _kill_task(self, task: ShellTask, process: subprocess.Popen[bytes]) -> None:
        if task.sandbox_controller is not None:
            task.sandbox_controller.kill()
        self._kill_process_group(process)

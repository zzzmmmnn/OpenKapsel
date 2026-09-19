"""Client-owned execution policy and bounded asynchronous task lifetime."""

from __future__ import annotations

import base64
import errno
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


class ClientTasks:
    def __init__(self, files, *, enabled=False, sandbox=True, backend="podman",
                 image="docker.io/library/python:3.14-slim-trixie", network=False,
                 max_tasks=2, max_seconds=600, memory_mb=256, processes=64, cpus=1):
        self.files = files
        self.enabled, self.sandbox, self.backend = enabled, sandbox, backend
        self.image, self.network = image, network
        self.max_tasks, self.max_seconds = max_tasks, max_seconds
        self.memory_mb, self.processes, self.cpus = memory_mb, processes, cpus
        for name, value in {"max_tasks": max_tasks, "max_seconds": max_seconds, "memory_mb": memory_mb, "processes": processes}.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_tasks > 16 or max_seconds > 86400 or isinstance(cpus, bool) or not isinstance(cpus, (float, int)) or not 0 < cpus <= 1024:
            raise ValueError("invalid client execution limits")
        if enabled and not sandbox and not files.writable:
            raise ValueError("native unsandboxed execution requires explicit writable=true")
        if enabled and sandbox and (backend != "podman" or not shutil.which("podman")):
            raise ValueError("enabled sandbox requires Podman; install it or explicitly set sandbox=false")
        self.lock = threading.RLock()
        self.tasks = {}
        self.closed = False

    def capabilities(self):
        return {"enabled": self.enabled, "sandbox": self.sandbox,
                "backend": self.backend if self.sandbox else "native-unsandboxed",
                "platform": sys.platform, "max_tasks": self.max_tasks,
                "max_seconds": self.max_seconds, "network": self.network if self.sandbox else "host"}

    def git(self, operation, args):
        """One RPC for command launch and a short bounded wait; never bypass policy."""
        from .git_operations import git_arguments
        from .errors import ApiError
        if not self.enabled or not self.files.writable:
            raise OSError(errno.EACCES, "Git requires writable client execution")
        try:
            argv = git_arguments(operation, args.get("options", {}))
        except ApiError as exc:
            raise OSError(errno.EINVAL, exc.message) from None
        timeout = args.get("timeout_seconds", 30)
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise OSError(errno.EINVAL, "invalid Git timeout")
        tid = "git_" + secrets.token_urlsafe(18)
        self.dispatch("task_start", {"task_id": tid, "argv": argv, "cwd": args.get("cwd", "."),
                                     "timeout_seconds": min(timeout, self.max_seconds)})
        with self.lock:
            task = self.tasks[tid]
            task["input"].put_nowait(None)
        task["done"].wait(2)
        result = self._public(task)
        with task["output_lock"]:
            output = bytes(task["output"][:65536]).decode("utf-8", errors="replace")
            more = len(task["output"]) > 65536 or task["truncated"]
            offset = min(65536, len(task["output"]))
        return {**result, "output": output, "next_offset": offset, "output_truncated": more}

    def dispatch(self, op, args):
        if not self.enabled:
            raise OSError(errno.EACCES, "client execution is disabled")
        with self.lock:
            self._prune()
            if op == "task_list":
                return [self._public(task) for task in self.tasks.values()]
            tid = args.get("task_id", "")
            if not isinstance(tid, str) or not 8 <= len(tid) <= 64 or not tid.replace("-", "").replace("_", "").isalnum():
                raise OSError(errno.EINVAL, "invalid task id")
            if op == "task_start":
                if tid in self.tasks:
                    return self._public(self.tasks[tid])
                return self._start(tid, args)
            task = self.tasks.get(tid)
            if task is None:
                raise OSError(errno.ENOENT, "task does not exist in this client session")
            if op == "task_get":
                offset = self.files._number(args.get("offset", 0))
                result = self._public(task)
                with task["output_lock"]:
                    result.update(output=base64.b64encode(bytes(task["output"][offset:offset + 65536])).decode(),
                                  next_offset=min(offset + 65536, len(task["output"])))
                return result
            if op in {"task_interrupt", "task_kill"}:
                self._signal(task, force=op == "task_kill")
                return self._public(task)
            if op == "task_stdin":
                data = base64.b64decode(args.get("data", ""), validate=True)
                if len(data) > 16384:
                    raise OSError(errno.E2BIG, "stdin chunk too large")
                if task["process"].poll() is not None or task["process"].stdin.closed:
                    raise OSError(errno.EPIPE, "task stdin is closed")
                # A separate bounded queue avoids blocking the provider on a child
                # which does not consume stdin.
                try:
                    task["input"].put_nowait(data if not args.get("eof") else None)
                except __import__("queue").Full:
                    raise OSError(errno.EBUSY, "task stdin buffer is full") from None
                return {"accepted": len(data)}
            raise OSError(errno.ENOSYS, "unknown task operation")

    def _start(self, tid, args):
        import queue
        if self.closed or sum(t["finished_at"] is None for t in self.tasks.values()) >= self.max_tasks:
            raise OSError(errno.EBUSY, "client task limit reached")
        argv = args.get("argv")
        if not isinstance(argv, list) or not argv or len(argv) > 256 or any(not isinstance(a, str) or "\x00" in a for a in argv) or sum(map(len, argv)) > 32768:
            raise OSError(errno.EINVAL, "argv must be a bounded string array")
        cwd = self.files.path(args.get("cwd", "."))
        if os.name == "nt":
            with self.files.paths.guard(cwd, include_final=True):
                if not cwd.is_dir():
                    raise OSError(errno.ENOTDIR, "cwd must be a directory")
        else:
            descriptor = self.files.paths.open(cwd, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            os.close(descriptor)
        timeout = args.get("timeout_seconds", self.max_seconds)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= self.max_seconds:
            raise OSError(errno.EINVAL, "timeout exceeds local policy")
        container = None
        env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "LANG") if key in os.environ}
        if self.sandbox:
            container = "openkapsel-client-" + tid.lower()
            mode = "rw" if self.files.writable else "ro"
            argv = ["podman", "run", "--rm", "--name", container, "--cap-drop=ALL", "--security-opt=no-new-privileges",
                    "--pids-limit", str(self.processes), "--memory", f"{self.memory_mb}m", "--cpus", str(self.cpus),
                    "--network", "slirp4netns" if self.network else "none", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                    "--volume", f"{self.files.root}:/workspace:{mode}", "--workdir", "/workspace/" + cwd.relative_to(self.files.root).as_posix(),
                    "--tmpfs", "/workspace/.openkapsel:rw,nosuid,nodev,noexec,size=1m",
                    "--interactive", self.image, *argv]
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, close_fds=True,
                                   start_new_session=os.name != "nt",
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
        task = {"id": tid, "process": process, "started_at": time.time(), "finished_at": None,
                "output": bytearray(), "output_lock": threading.Lock(), "truncated": False,
                "input": queue.Queue(maxsize=8), "container": container, "timeout": timeout,
                "done": threading.Event()}
        self.tasks[tid] = task
        threading.Thread(target=self._collect, args=(task,), daemon=True).start()
        threading.Thread(target=self._input, args=(task,), daemon=True).start()
        threading.Thread(target=self._deadline, args=(task,), daemon=True).start()
        return self._public(task)

    def _collect(self, task):
        try:
            while data := task["process"].stdout.read1(8192):
                with task["output_lock"]:
                    room = max(0, 2 * 1024 * 1024 - len(task["output"]))
                    task["output"].extend(data[:room])
                    task["truncated"] |= len(data) > room
        finally:
            task["process"].stdout.close()
            task["process"].wait()
            task["finished_at"] = time.time()
            task["done"].set()

    @staticmethod
    def _input(task):
        import queue
        stream = task["process"].stdin
        try:
            while task["process"].poll() is None:
                try:
                    data = task["input"].get(timeout=1)
                except queue.Empty:
                    continue
                if data is None:
                    break
                stream.write(data)
                stream.flush()
        except OSError:
            pass
        finally:
            stream.close()

    def _deadline(self, task):
        # The leader may exit while descendants still hold the output pipe.
        # Keep enforcing the lifetime and task slot until collection finishes.
        if not task["done"].wait(task["timeout"]):
            self._signal(task, force=True)

    @staticmethod
    def _public(task):
        return {"task_id": task["id"], "location": "client", "started_at": task["started_at"],
                "finished_at": task["finished_at"], "exit_code": task["process"].poll(),
                "running": task["finished_at"] is None, "output_truncated": task["truncated"]}

    @staticmethod
    def _signal(task, *, force):
        process = task["process"]
        if task["finished_at"] is not None:
            return
        if task["container"]:
            subprocess.run(["podman", "kill", "--signal", "KILL" if force else "INT", task["container"]],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        try:
            if os.name == "nt":
                if force:
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                else:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGKILL if force else signal.SIGINT)
        except ProcessLookupError:
            pass

    def _prune(self):
        finished = sorted((t for t in self.tasks.values() if t["finished_at"]), key=lambda t: t["finished_at"], reverse=True)
        for index, task in enumerate(finished):
            if index >= 4 or time.time() - task["finished_at"] > 3600:
                self.tasks.pop(task["id"], None)

    def close(self):
        with self.lock:
            self.closed = True
            for task in self.tasks.values():
                if task["finished_at"] is None:
                    self._signal(task, force=True)

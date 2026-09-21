"""Shell, task, process, and SSE HTTP endpoints."""

from __future__ import annotations

import base64
import binascii
import json
import os
import time
from datetime import datetime
from http import HTTPStatus
from typing import Any

from openkapsel.errors import ApiError
from openkapsel.execution.cgroups import BUBBLEWRAP_PROCESS_OVERHEAD, SandboxLimits
from openkapsel.execution.shell_execution import start_shell_task
from openkapsel.execution.shell_routing import RemoteTask

class TaskHttpMixin:
    def _handle_shell_exec(self) -> None:
        body = self._read_json()
        command = self._required_string(body, "command")
        if self._start_client_shell(body):
            return
        cwd_value = body.get("cwd", "")
        timeout = body.get("timeout_seconds", self.server.config.default_command_timeout)
        interactive = self._optional_bool(body, "interactive", False)
        task = start_shell_task(
            self.server,
            self.token_record,
            self.token_scope_root,
            command=command,
            cwd_value=cwd_value,
            timeout_seconds=timeout,
            interactive=interactive,
            mount_mappings=body.get("mount_mappings", []),
        )
        self._send_json(
            HTTPStatus.ACCEPTED,
            {"task_id": task.id, "status": task.status, "location": "server", "status_url": f"{self._base_path()}/tasks/{task.id}"},
        )


    def _full_shell_process_environment(self) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ),
            "HOME": str(self.token_scope_root),
            "TMPDIR": "/tmp",
            "OPENKAPSEL_WORKSPACE": str(self.token_scope_root),
        }
        for name in ("LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM"):
            value = os.environ.get(name)
            if value and "\x00" not in value:
                environment[name] = value
        return environment


    def _handle_task(self, task_id: str) -> None:
        if not task_id or "/" in task_id:
            raise ApiError(HTTPStatus.NOT_FOUND, "task_not_found", "task does not exist")
        task = self._get_shell_task(task_id)
        self._authorize_task_access(task)
        self._send_json(
            HTTPStatus.OK,
            dict(task.serialize(), location="client" if task_id.startswith("client.") else "server"),
        )


    def _handle_task_list(self, query: dict[str, list[str]]) -> None:
        if (
            self.token_record.shell_mode == "none"
            and not self.token_record.can_read
            and not self.token_record.can_write
        ):
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "task permission is not granted")
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 100, minimum=1, maximum=1000)
        status = self._query_one(query, "status", "").strip() or None
        if status not in {None, "running", "finished"}:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_status", "status must be running or finished")
        target = self._query_one(query, "target", "auto")
        if target not in {"auto", "server", "client"}:
            raise ApiError(400, "invalid_target", "target must be auto, server, or client")
        tasks, unavailable = [], []
        if target != "client" and self.token_record.shell_mode != "none":
            tasks, _ = self.server.tasks.list(self.token_record.token, 0, 100000, status)
            tasks = [dict(task, location="server") for task in tasks]
        elif target == "server" and self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "Shell permission is required for server tasks")
        if target != "server":
            remote, unavailable = self._list_client_shell_tasks()
            tasks.extend(task for task in remote if status is None or task["status"] == status)
        # ISO server timestamps and epoch client timestamps cannot be compared.
        def started(task):
            value = task["started_at"]
            return float(value) if isinstance(value, (int, float)) else datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        tasks.sort(key=started, reverse=True)
        total = len(tasks)
        tasks = tasks[offset:offset + limit]
        self._send_json(
            HTTPStatus.OK,
            {
                "tasks": tasks,
                "offset": offset,
                "limit": limit,
                "total": total,
                "truncated": offset + len(tasks) < total,
                "unavailable_mappings": unavailable,
            },
        )


    def _handle_sandbox_processes(self, query: dict[str, list[str]]) -> None:
        if self.token_record.shell_mode != "restricted":
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "sandbox_not_enabled",
                "process inspection is available only for restricted Shell tokens",
            )
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 100, minimum=1, maximum=1000)
        configured_backend = self.token_record.sandbox_backend
        effective_backend = (
            self.server.config.sandbox_default_backend
            if configured_backend == "auto"
            else configured_backend
        )
        payload = self.server.cgroups.inspect(
            self.token_record.token,
            self._sandbox_limits(backend=effective_backend),
            task_roots=self.server.tasks.process_roots(self.token_record.token),
            offset=offset,
            limit=limit,
        )
        self._send_json(HTTPStatus.OK, payload)


    def _sandbox_limits(self, *, backend: str | None = None) -> SandboxLimits:
        return SandboxLimits(
            max_processes=self.token_record.sandbox_max_processes,
            memory_bytes=self.token_record.sandbox_memory_mb * 1024 * 1024,
            cpu_percent=self.token_record.sandbox_cpu_percent,
            process_overhead=(
                BUBBLEWRAP_PROCESS_OVERHEAD if backend == "bubblewrap" else 0
            ),
        )


    def _handle_task_interrupt(self, task_id: str) -> None:
        task = self._get_shell_task(task_id)
        self._authorize_task_access(task)
        if self._client_task_control(task_id, "interrupt"):
            return
        task = self.server.tasks.interrupt(task_id, self.token_record.token)
        self._send_json(HTTPStatus.OK, task.serialize())


    def _handle_task_kill(self, task_id: str) -> None:
        task = self._get_shell_task(task_id)
        self._authorize_task_access(task)
        if self._client_task_control(task_id, "kill"):
            return
        task = self.server.tasks.kill(task_id, self.token_record.token)
        self._send_json(HTTPStatus.OK, task.serialize())


    def _handle_task_stdin(self, task_id: str) -> None:
        task = self._get_shell_task(task_id)
        self._authorize_task_access(task)
        if isinstance(task, RemoteTask) and task.result.get("kind") == "rpc":
            raise ApiError(HTTPStatus.CONFLICT, "not_interactive", "RPC tasks do not accept stdin")
        body = self._read_json()
        text_data = body.get("data")
        base64_data = body.get("data_base64")
        if text_data is not None and base64_data is not None:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "provide data or data_base64, not both")
        if text_data is None and base64_data is None:
            data = b""
        elif text_data is not None:
            if not isinstance(text_data, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "data must be a string")
            data = text_data.encode("utf-8")
        else:
            if not isinstance(base64_data, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "data_base64 must be a string")
            try:
                data = base64.b64decode(base64_data, validate=True)
            except (binascii.Error, ValueError):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_base64", "data_base64 is not valid Base64") from None
        if len(data) > 256 * 1024:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "input_too_large", "task input is limited to 262144 bytes per request")
        close = self._optional_bool(body, "close", False)
        if self._client_task_parts(task_id) and len(data) > 16384:
            raise ApiError(413, "input_too_large", "client task input is limited to 16384 bytes per request")
        if self._client_task_control(task_id, "stdin", data=base64.b64encode(data).decode("ascii"), eof=close):
            return
        try:
            task = self.server.tasks.write_stdin(task_id, self.token_record.token, data, close)
        except ValueError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "not_interactive", str(exc)) from None
        except BrokenPipeError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "stdin_closed", str(exc)) from None
        self._send_json(
            HTTPStatus.OK,
            {"task_id": task.id, "bytes_written": len(data), "stdin_closed": close},
        )


    def _handle_task_output(self, task_id: str, query: dict[str, list[str]]) -> None:
        stdout_offset = self._query_int(query, "stdout_offset", 0, minimum=0)
        stderr_offset = self._query_int(query, "stderr_offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 65536, minimum=1, maximum=262144)
        wait_seconds = self._query_float(query, "wait_seconds", 0.0, minimum=0.0, maximum=30.0)
        deadline = time.monotonic() + wait_seconds
        task = self._get_shell_task(task_id)
        self._authorize_task_access(task)
        while True:
            stdout = task.stdout.read_from(stdout_offset, limit)
            stderr = task.stderr.read_from(stderr_offset, limit)
            if (
                stdout["data"]
                or stderr["data"]
                or stdout["gap"]
                or stderr["gap"]
                or task.status == "finished"
                or time.monotonic() >= deadline
            ):
                break
            time.sleep(0.05)
        payload = {
            "task_id": task.id,
            "status": task.status,
            "stdout": stdout,
            "stderr": stderr,
            "location": "client" if isinstance(task, RemoteTask) else "server",
            "output_combined": isinstance(task, RemoteTask),
            "finished": task.status == "finished",
            "exit_code": task.exit_code,
            "interrupted": task.interrupted,
            "force_killed": task.force_killed,
        }
        if isinstance(task, RemoteTask) and task.result.get("kind") == "rpc":
            summary = task.summary()
            for key in (
                "kind",
                "rpc_family",
                "rpc_operation",
                "write",
                "execution",
                "result",
                "error",
            ):
                if key in summary:
                    payload[key] = summary[key]
        self._send_json(HTTPStatus.OK, payload)


    def _handle_task_stream(self, task_id: str, query: dict[str, list[str]]) -> None:
        stdout_offset = self._query_int(query, "stdout_offset", 0, minimum=0)
        stderr_offset = self._query_int(query, "stderr_offset", 0, minimum=0)
        task = self._get_shell_task(task_id)
        self._authorize_task_access(task)
        limited_by = self.server.acquire_sse_stream(self.token_record.token)
        if limited_by is not None:
            raise ApiError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "too_many_streams",
                "the concurrent SSE stream limit has been reached",
                details={
                    "scope": limited_by,
                    "max_global": self.server.config.max_sse_streams,
                    "max_per_token": self.server.config.max_sse_streams_per_token,
                },
                headers={"Retry-After": "1"},
            )
        stream_started = False
        try:
            context_id = self._finalize_context_operation(
                HTTPStatus.OK,
                {"task_id": task.id, "status": task.status, "stream": True},
            )
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            if context_id is not None:
                self.send_header("OpenKapsel-Context-ID", str(context_id))
            self.end_headers()
            stream_started = True
            self.close_connection = True
            started_at = time.monotonic()
            last_heartbeat = started_at
            while True:
                stdout = task.stdout.read_from(stdout_offset, 65536)
                stderr = task.stderr.read_from(stderr_offset, 65536)
                if stdout["data"] or stderr["data"] or stdout["gap"] or stderr["gap"]:
                    stdout_offset = stdout["next_offset"]
                    stderr_offset = stderr["next_offset"]
                    self._send_sse(
                        "output",
                        {"task_id": task.id, "status": task.status, "stdout": stdout, "stderr": stderr},
                    )
                    last_heartbeat = time.monotonic()
                if task.status == "finished" and (not isinstance(task, RemoteTask) or stdout_offset >= stdout["available_end"]):
                    self._send_sse("done", task.summary())
                    return
                now = time.monotonic()
                if now - started_at >= self.server.config.max_sse_duration_seconds:
                    self._send_sse(
                        "reconnect",
                        {
                            "task_id": task.id,
                            "status": task.status,
                            "reason": "stream_duration_limit",
                            "stdout_offset": stdout_offset,
                            "stderr_offset": stderr_offset,
                        },
                    )
                    return
                if now - last_heartbeat >= 10:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    last_heartbeat = now
                time.sleep(0.05)
        except ApiError as exc:
            if not stream_started:
                raise
            # Headers have already been sent. End the stream with a structured
            # event rather than appending an HTTP/JSON response to SSE bytes.
            self._send_sse("error", {"task_id": task.id, "code": exc.code,
                                     "stdout_offset": stdout_offset, "stderr_offset": stderr_offset})
        finally:
            self.server.release_sse_stream(self.token_record.token)


    def _send_sse(self, event: str, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        self.wfile.write(f"event: {event}\ndata: {data}\n\n".encode("utf-8"))
        self.wfile.flush()

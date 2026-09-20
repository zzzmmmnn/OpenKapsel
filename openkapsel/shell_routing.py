"""Explicit Shell placement and stateless routing of client-owned tasks."""

import base64
import os
import re
import time
from pathlib import Path

from .errors import ApiError
from .random_ids import token_urlsafe_alnum


def client_task_id(mid, tid):
    return f"client.{mid}.{tid}"


def client_summary(mid, result):
    return dict(result, task_id=client_task_id(mid, result["task_id"]),
                mapping_id=mid, location="client", output_combined=True,
                status="running" if result["running"] else "finished")


class RemoteOutput:
    def __init__(self, task, empty=False):
        self.task, self.empty = task, empty

    def read_from(self, offset, limit):
        if self.empty:
            data, actual, end = b"", 0, 0
        else:
            result = self.task.fetch(offset)
            data = base64.b64decode(result["output"], validate=True)[:limit]
            end = result.get("output_size", result["next_offset"])
            actual = min(offset, end)
        return {"data": data.decode("utf-8", errors="replace"),
                "data_base64": base64.b64encode(data).decode("ascii"),
                "encoding": "utf-8-replace", "offset": actual,
                "next_offset": actual + len(data), "available_end": end, "gap": False}


class RemoteTask:
    """Request-local adapter; no task ownership or process state lives on server."""
    def __init__(self, handler, row, tid):
        self.handler, self.row, self.tid = handler, row, tid
        self.id = client_task_id(row["id"], tid)
        self.stdout, self.stderr = RemoteOutput(self), RemoteOutput(self, empty=True)
        self.result, self.cached_offset, self.fetched_at = None, None, 0
        self.fetch(0)

    def fetch(self, offset):
        if self.cached_offset != offset or time.monotonic() - self.fetched_at >= .25:
            self.result = self.handler._mapping_rpc(self.row, "task_get", {"task_id": self.tid, "offset": offset})
            self.cached_offset, self.fetched_at = offset, time.monotonic()
        return self.result

    @property
    def status(self):
        return "running" if self.result["running"] else "finished"

    @property
    def exit_code(self):
        return self.result["exit_code"]

    @property
    def interrupted(self):
        return self.result.get("interrupted", False)

    @property
    def force_killed(self):
        return self.result.get("force_killed", False)

    def summary(self):
        result = client_summary(self.row["id"], self.result)
        result.pop("output", None)
        result.pop("next_offset", None)
        return result

    def serialize(self):
        result = self.fetch(0)
        return dict(self.summary(), stdout=base64.b64decode(result["output"]).decode("utf-8", errors="replace"),
                    stderr="", stdout_next_offset=result["next_offset"])


class ShellRoutingMixin:
    def _client_task_parts(self, task_id):
        if not task_id.startswith("client."):
            return None
        match = re.fullmatch(r"client\.([A-Za-z0-9_-]{24})\.([A-Za-z0-9_-]{8,64})", task_id)
        if not match:
            raise ApiError(404, "task_not_found", "task does not exist")
        return self._mapping_for_caller(match[1]), match[2]

    def _get_shell_task(self, task_id):
        parts = self._client_task_parts(task_id)
        if parts:
            return RemoteTask(self, *parts)
        return self.server.tasks.get(task_id, self.token_record.token)

    def _authorize_task_access(self, task):
        if isinstance(task, RemoteTask) and task.result.get("kind") == "rpc":
            if task.result.get("write"):
                self._require_permission(self.token_record.can_write, "write permission is required for this RPC task")
            else:
                self._require_permission(self.token_record.can_read, "read permission is required for this RPC task")
            return
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required")

    def _start_client_shell(self, body):
        target = body.get("target", "auto")
        if target not in ("auto", "server", "client"):
            raise ApiError(400, "invalid_target", "target must be auto, server, or client")
        cwd = body.get("cwd", ".")
        if not isinstance(cwd, str) or "\x00" in cwd:
            raise ApiError(400, "invalid_path", "cwd must be a NUL-free string")
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required")
        if target == "server":
            return False
        candidate = Path(cwd).expanduser() if cwd else self.token_scope_root
        if not candidate.is_absolute():
            candidate = self.token_scope_root / candidate
        candidate = Path(os.path.abspath(candidate))
        row = self.server.mappings.at_path(candidate)
        if row is None:
            # Resolve ordinary aliases without depending on the availability of
            # a known mapping's FUSE mount.
            candidate = candidate.resolve(strict=False)
            row = self.server.mappings.at_path(candidate)
        if row is None:
            if target == "client":
                raise ApiError(400, "mapping_required", "client target requires cwd inside a mapping")
            return False
        row = self._mapping_for_caller(row["id"])
        if not row["writable"] or not self.token_record.can_write:
            raise ApiError(403, "client_execution_requires_write", "client execution requires a writable mapping and caller")
        with self.server.mappings.lock:
            session = self.server.mappings.sessions.get(row["id"])
            execution = session.capabilities.get("execution", {}) if session else {}
        if session is None or session.closed or not row["enabled"]:
            raise ApiError(503, "mapping_unavailable", "mapping client is offline")
        if not row["allow_exec"] or not execution.get("enabled"):
            raise ApiError(403, "client_execution_disabled", "mapping and client execution must both be enabled")
        if not execution.get("shell_command"):
            raise ApiError(409, "client_upgrade_required", "update and reconnect client for unified Shell execution")
        args = {"task_id": token_urlsafe_alnum(18), "command": body["command"],
                "cwd": candidate.relative_to(self.server.mappings.mount_path(row)).as_posix(),
                "interactive": self._optional_bool(body, "interactive", False)}
        if body.get("timeout_seconds") is not None:
            args["timeout_seconds"] = body["timeout_seconds"]
        result = client_summary(row["id"], self._mapping_rpc(row, "task_start", args))
        result["status_url"] = f"{self._base_path()}/tasks/{result['task_id']}"
        self._send_json(202, result)
        return True

    def _client_task_control(self, task_id, operation, **args):
        parts = self._client_task_parts(task_id)
        if parts is None:
            return False
        row, tid = parts
        result = self._mapping_rpc(row, "task_" + operation, dict(args, task_id=tid))
        if operation == "stdin":
            result = {"task_id": task_id, "bytes_written": result["accepted"], "stdin_closed": args.get("eof", False)}
        else:
            result = client_summary(row["id"], result)
        self._send_json(200, result)
        return True

    def _list_client_shell_tasks(self):
        tasks, unavailable = [], []
        for row in self.server.mappings.store.list(self.token_record.path_prefix):
            if (
                self.token_record.shell_mode == "none"
                and not self.token_record.can_read
                and not self.token_record.can_write
            ):
                continue
            try:
                results = self._mapping_rpc(row, "task_list", {})
            except ApiError as exc:
                unavailable.append({"mapping_id": row["id"], "code": exc.code})
                continue
            for result in results:
                kind = result.get("kind", "shell")
                if kind == "rpc":
                    visible = (
                        self.token_record.can_write
                        if result.get("write")
                        else self.token_record.can_read
                    )
                else:
                    visible = row["allow_exec"] and self.token_record.shell_mode != "none"
                if visible:
                    tasks.append(client_summary(row["id"], result))
        return tasks, unavailable

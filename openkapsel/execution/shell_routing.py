"""Explicit Shell placement and stateless routing of client-owned tasks."""

import base64
import os
import re
import time
from pathlib import Path

from openkapsel.errors import ApiError
from openkapsel.random_ids import token_urlsafe_alnum
from openkapsel.job_manager import new_job_id


def native_mapping_shell_ready(row, execution):
    """A modern Mapping already runs native Shell without a grant.

    Fail closed for old clients and for sandboxed/approval-only clients.
    A disabled Mapping or Client must still require explicit approval.
    """
    return (
        bool(row.get("writable")) and bool(row.get("allow_exec"))
        and execution.get("enabled") is True
        and execution.get("shell_command") is True
        and execution.get("sandbox") is False
        and execution.get("approval_required") is False
    )


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
            actual = max(result.get("output_base", 0), min(offset, end))
        return {"data": data.decode("utf-8", errors="replace"),
                "data_base64": base64.b64encode(data).decode("ascii"),
                "encoding": "utf-8-replace", "offset": actual,
                "next_offset": actual + len(data), "available_end": end,
                "gap": bool(result.get("gap", False)) if not self.empty else False}


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
            self.result = self.handler._mapping_rpc(
                self.row,
                "task_get",
                {"task_id": self.tid, "offset": offset},
                retry=False,
            )
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
        match = re.fullmatch(r"client\.([A-Za-z0-9_-]{24})\.(&[A-Za-z0-9]{4}&|[A-Za-z0-9_-]{8,64})", task_id)
        if not match:
            raise ApiError(404, "task_not_found", "task does not exist")
        return self._mapping_for_caller(match[1]), match[2]

    def _get_shell_task(self, task_id):
        parts = self._client_task_parts(task_id)
        if parts:
            return RemoteTask(self, *parts)
        return self.server.tasks.get(task_id, self.token_record.token)

    def _authorize_task_access(self, task):
        remote_rpc = isinstance(task, RemoteTask) and task.result.get("kind") == "rpc"
        local_rpc = not isinstance(task, RemoteTask) and getattr(task, "kind", "shell") == "rpc"
        if remote_rpc or local_rpc:
            write = task.result.get("write") if remote_rpc else bool(getattr(task, "write", False))
            if write:
                self._require_permission(self.token_record.can_write, "write permission is required for this RPC task")
            else:
                self._require_permission(self.token_record.can_read, "read permission is required for this RPC task")
            return
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required")

    def _start_client_shell(self, body):
        approved = self._optional_bool(body, "approved", False)
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
        if body.get("mount_mappings"):
            raise ApiError(400, "server_mapping_dependencies", "mount_mappings applies only to server execution")
        row = self._mapping_for_caller(row["id"])
        with self.server.mappings.lock:
            session = self.server.mappings.sessions.get(row["id"])
            execution = session.capabilities.get("execution", {}) if session else {}
        if session is None or session.closed or not row["enabled"]:
            raise ApiError(503, "mapping_unavailable", "mapping client is offline")
        if not execution.get("shell_command"):
            raise ApiError(409, "client_upgrade_required", "update and reconnect client for unified Shell execution")
        full = self.server.mappings.full_approval_status(row["id"])["active"]
        # approved=true must not demand a grant when the same native Shell
        # is already available without approval. Treat it as ordinary Shell;
        # do not elevate disabled or sandboxed clients.
        if native_mapping_shell_ready(row, execution):
            approved = False
        safe = None
        windows = execution.get("platform") == "win32"
        # Older Windows Clients always required approval. Only an explicit
        # false from a new Client enables ordinary native Shell.
        approval_required = windows and execution.get("approval_required", True) is not False
        if approval_required and execution.get("safe_powershell") and not approved and not full:
            if not self._optional_bool(body, "interactive", False):
                from openkapsel.client_runtime.windows_powershell_policy import parse_simple_powershell
                safe = parse_simple_powershell(body.get("command"))
        if safe is not None and not safe.write:
            self._require_permission(self.token_record.can_read, "File read permission is required")
        elif not row["writable"] or not self.token_record.can_write:
            raise ApiError(403, "client_execution_requires_write",
                           "client execution requires a writable mapping and caller")
        if not approved and (not row["allow_exec"] or not full and not execution.get("enabled")):
            raise ApiError(403, "client_execution_disabled",
                           "Mapping or Client execution is disabled. If temporary unsandboxed "
                           "execution is appropriate, use shell.request_approval with a reason "
                           "for this target, then retry with approved=true.",
                           {"request_operation": "shell.request_approval", "target": row["id"]})
        if full and not row["allow_exec"]:
            raise ApiError(403, "client_execution_disabled", "Mapping execution is disabled")
        if approval_required and not approved and not full and safe is None:
            raise ApiError(403, "capability_approval_required",
                           "Windows Shell requires temporary approval for unrecognized commands. "
                           "Call shell.request_approval with an explicit target and reason; "
                           "retry with approved=true after the user approves.",
                           {"capability": "shell.unsandboxed", "target": row["id"],
                            "request_operation": "shell.request_approval"})
        if approved and not full:
            if not execution.get("unsandboxed"):
                raise ApiError(409, "client_upgrade_required", "update and reconnect client for approved Shell execution")
            self._require_capability(body, row["id"], "shell.unsandboxed")
        args = {"task_id": new_job_id(), "command": body["command"],
                "cwd": candidate.relative_to(self.server.mappings.mount_path(row)).as_posix(),
                "interactive": self._optional_bool(body, "interactive", False)}
        if body.get("timeout_seconds") is not None:
            args["timeout_seconds"] = body["timeout_seconds"]
        function_auth = (
            self.server.function_grants.current(
                self.token_record.app_id, self._file_approval_conversation(body),
                row["id"], "shell.exec",
            ) if approved and not full else None
        )
        if function_auth is not None:
            # Auth is injected as a private RPC field. The Client, not the
            # Server, interprets it and decides whether to skip the sandbox.
            operation = "function"
            rpc_args = {
                "function": "shell.exec", "method": "execute",
                "args": args, "internal": {"auth": function_auth},
            }
        else:
            # Compatibility with approvals issued through the legacy flow.
            if approved and not full:
                args["unsandboxed"] = True
            operation, rpc_args = "task_start", args
        result = client_summary(
            row["id"], self._mapping_rpc(
                row, operation, rpc_args, retry=not approved
            )
        )
        result["status_url"] = f"{self._base_path()}/task/get/{result['task_id']}"
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
                results = self._mapping_rpc(row, "task_list", {}, retry=False)
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
                    visible = self.token_record.shell_mode != "none"
                if visible:
                    tasks.append(client_summary(row["id"], result))
        return tasks, unavailable

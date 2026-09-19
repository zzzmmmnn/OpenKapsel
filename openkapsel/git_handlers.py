"""Git inspection over the existing sandbox/task execution policy."""

import shlex
import re
from pathlib import Path

from .errors import ApiError
from .git_operations import git_arguments
from .shell_execution import start_shell_task


class GitHandlersMixin:
    def _handle_git(self, operation, query):
        self._require_permission(self.token_record.can_read and self.token_record.shell_mode != "none",
                                 "read and Shell permissions are required for Git inspection")
        if set(query) - {"path", "file", "timeout_seconds", "revision", "to_revision", "staged", "limit", "skip", "taskname", "message", "plan_id"}:
            raise ApiError(400, "invalid_request", "unsupported Git query parameter")
        options = {"paths": query.get("file", [])}
        for key in ("revision", "to_revision"):
            if key in query:
                options[key] = self._query_one(query, key, "")
        for key, default, maximum in (("limit", 20, 200), ("skip", 0, 100000)):
            if key in query:
                options[key] = self._query_int(query, key, default, minimum=0 if key == "skip" else 1, maximum=maximum)
        if "staged" in query:
            options["staged"] = self._query_bool(query, "staged", False)
        argv = git_arguments(operation, options)
        timeout = self._query_int(query, "timeout_seconds", 30, minimum=1, maximum=120)
        value = self._query_one(query, "path", ".")
        if not value or "\x00" in value or any(0xD800 <= ord(c) <= 0xDFFF for c in value) or ".." in Path(value).parts:
            raise ApiError(400, "invalid_path", "path must be a directory without parent traversal")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.token_scope_root / candidate
        self._assert_inside_root(candidate)
        row = self.server.mappings.at_path(candidate)
        if row:
            self._require_permission(self.token_record.can_write and row["writable"],
                                     "client execution requires a writable caller and mapping")
            relative = candidate.relative_to(self.server.mappings.mount_path(row))
            if ".openkapsel" in relative.parts:
                raise ApiError(403, "reserved_path", "workspace internal paths are not available")
            if not self.server.mappings.supports_git_api(row["id"]):
                raise ApiError(409, "git_client_upgrade_required", "reconnect an updated mapping client with execution enabled")
            result = self._mapping_rpc(row, "git_" + operation,
                                       {"options": options, "cwd": relative.as_posix(), "timeout_seconds": timeout})
            if (not isinstance(result, dict) or type(result.get("running")) is not bool or
                not isinstance(result.get("task_id"), str) or
                not re.fullmatch(r"git_[A-Za-z0-9_-]{8,60}", result["task_id"]) or
                not isinstance(result.get("output"), str) or
                (result.get("exit_code") is not None and type(result["exit_code"]) is not int)):
                raise ApiError(502, "invalid_mapping_response", "client returned an invalid Git task result")
            result["mapping_id"] = row["id"]
            result["status_url"] = f"{self._base_path()}/mappings/{row['id']}/tasks/{result['task_id']}"
        else:
            # Resolve again through the regular filesystem policy (including
            # private paths and symlinks) before handing off to Shell execution.
            cwd = self._resolve_path(value)
            task = start_shell_task(self.server, self.token_record, self.token_scope_root,
                                    command=shlex.join(argv), cwd_value=str(cwd), timeout_seconds=timeout)
            task._finished_event.wait(2)
            running = not task._finished_event.is_set()
            output = task.stdout.read_from(0, 65536)
            error = task.stderr.read_from(0, 65536)
            result = {"task_id": task.id, "location": "server", "running": running,
                      "exit_code": task.exit_code, "output": output["data"], "stderr": error["data"],
                      "next_offset": output["next_offset"], "stderr_next_offset": error["next_offset"],
                      "output_truncated": output["gap"] or output["next_offset"] < output["available_end"],
                      "stderr_truncated": error["gap"] or error["next_offset"] < error["available_end"],
                      "timed_out": task.timed_out, "error": task.error,
                      "status_url": f"{self._base_path()}/tasks/{task.id}"}
        result["operation"] = operation
        if getattr(self, "_capturing_mcp_tool", False):
            result.pop("status_url", None)
            result["poll_tool"] = "get_git_task"
            result["poll_arguments"] = {"task_id": result["task_id"]}
            if row:
                result["poll_arguments"]["mapping_id"] = row["id"]
        if not result["running"] and result["exit_code"] != 0:
            raise ApiError(422, "git_failed", "Git inspection failed; inspect task output and exit_code", result)
        self._send_json(202 if result["running"] else 200, result)

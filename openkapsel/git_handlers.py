"""Read-authorized Git inspection; never launches arbitrary Shell tasks."""
from pathlib import Path

from .errors import ApiError
from .git_operations import git_arguments
from .git_read import inspect_git


class GitHandlersMixin:
    def _handle_git(self, operation, query):
        self._require_permission(self.token_record.can_read, "read permission is required")
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
        git_arguments(operation, options)
        timeout = self._query_int(query, "timeout_seconds", 15, minimum=1, maximum=20)
        value = self._query_one(query, "path", ".")
        if not value or "\x00" in value or any(0xD800 <= ord(c) <= 0xDFFF for c in value) or ".." in Path(value).parts:
            raise ApiError(400, "invalid_path", "invalid repository root")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.token_scope_root / candidate
        self._assert_inside_root(candidate)
        row = self.server.mappings.at_path(candidate)
        if row:
            relative = candidate.relative_to(self.server.mappings.mount_path(row))
            if ".openkapsel" in relative.parts:
                raise ApiError(403, "reserved_path", "workspace internal paths are not available")
            capability = self.server.mappings.rpc_capability(
                row["id"],
                "git",
                operation=operation,
                min_version=2,
                max_version=2,
                required={"read_only": True},
            )
            if not capability.available:
                self._raise_mapping_rpc_unavailable(capability)
            response = self._mapping_rpc(row, "git_" + operation,
                                         {"options": options, "cwd": relative.as_posix(), "timeout_seconds": timeout})
            if not isinstance(response, dict) or type(response.get("status")) is not int:
                raise ApiError(502, "invalid_mapping_response", "invalid Git response")
            if "error" in response:
                error = response["error"]
                if not isinstance(error, dict) or not 400 <= response["status"] <= 599:
                    raise ApiError(502, "invalid_mapping_response", "invalid Git error")
                raise ApiError(response["status"], error.get("code", "git_failed"), error.get("message", "Git failed"), error.get("details"))
            result = response.get("body")
            if response["status"] != 200 or not isinstance(result, dict):
                raise ApiError(502, "invalid_mapping_response", "invalid Git result")
            result.update(location="client", mapping_id=row["id"])
        else:
            root = self._resolve_path(value)
            result = inspect_git(self._safe_path_access(), root, operation, options, timeout)
            result["location"] = "server"
        self._send_json(200, result)

"""Read-only archive browsing locally or through one mapped client RPC plugin."""

from __future__ import annotations

from pathlib import Path

from openkapsel.errors import ApiError
from openkapsel.rpc_plugins.archive import MAX_ARCHIVE_OFFSET, MAX_ARCHIVE_READ_BYTES, archive_list, archive_read


class ArchiveHandlersMixin:
    @staticmethod
    def _archive_rpc_body(response):
        if not isinstance(response, dict) or type(response.get("status")) is not int:
            raise ApiError(502, "invalid_mapping_response", "invalid Archive RPC response")
        if "error" in response:
            error = response["error"]
            if not isinstance(error, dict) or not 400 <= response["status"] <= 599:
                raise ApiError(502, "invalid_mapping_response", "invalid Archive RPC error")
            raise ApiError(
                response["status"],
                error.get("code", "archive_failed"),
                error.get("message", "Archive preview failed"),
                error.get("details"),
            )
        body = response.get("body")
        if response["status"] != 200 or not isinstance(body, dict):
            raise ApiError(502, "invalid_mapping_response", "invalid Archive RPC result")
        return body

    def _handle_archive(self, operation, query):
        self._require_permission(self.token_record.can_read, "read permission is required")
        if operation not in {"list", "read"}:
            raise ApiError(404, "not_found", "archive operation does not exist")
        allowed = {"path", "inner_path", "member", "offset", "limit", "encoding", "taskname", "message", "plan_id"}
        if set(query) - allowed:
            raise ApiError(400, "invalid_request", "unsupported Archive query parameter")

        value = self._query_one(query, "path", "")
        if not value or "\x00" in value or ".." in Path(value).parts:
            raise ApiError(400, "invalid_path", "invalid archive path")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.token_scope_root / candidate
        self._assert_inside_root(candidate)

        if operation == "list":
            args = {
                "inner_path": self._query_one(query, "inner_path", ""),
                "offset": self._query_int(query, "offset", 0, minimum=0, maximum=100_000),
                "limit": self._query_int(query, "limit", 200, minimum=1, maximum=1000),
            }
        else:
            args = {
                "member": self._query_one(query, "member", ""),
                "offset": self._query_int(query, "offset", 0, minimum=0, maximum=MAX_ARCHIVE_OFFSET),
                "limit": self._query_int(query, "limit", 65536, minimum=1, maximum=MAX_ARCHIVE_READ_BYTES),
                "encoding": self._query_one(query, "encoding", "utf-8"),
            }

        row = self.server.mappings.at_path(candidate)
        if row is None:
            candidate = self._resolve_path(value)
            row = self.server.mappings.at_path(candidate)
        if row:
            relative = candidate.relative_to(self.server.mappings.mount_path(row))
            if ".openkapsel" in relative.parts:
                raise ApiError(403, "reserved_path", "workspace internal paths are not available")
            capability = self.server.mappings.rpc_capability(
                row["id"],
                "archive",
                operation=operation,
                min_version=1,
                max_version=1,
            )
            if not capability.available:
                self._raise_mapping_rpc_unavailable(capability)
            if capability.operation_spec is None or capability.operation_spec.get("write") is not False:
                raise ApiError(409, "mapping_rpc_unsupported", "Archive preview operation is not advertised as read-only")
            body = self._archive_rpc_body(self._mapping_rpc(
                row,
                "archive_" + operation,
                dict(args, path=relative.as_posix()),
            ))
            body["location"] = "client"
            body["mapping_id"] = row["id"]
        else:
            path = self._resolve_path(value)
            if operation == "list":
                body = archive_list(self._safe_path_access(), path, **args)
            else:
                body = archive_read(self._safe_path_access(), path, **args)
            body["location"] = "server"

        body["path"] = value
        self._send_json(200, body)

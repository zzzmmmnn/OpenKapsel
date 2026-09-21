"""Context operation tracking and Context HTTP endpoints."""

from __future__ import annotations

import json
import logging
import sqlite3
from http import HTTPStatus
from typing import Any

from openkapsel.context.context_store import (
    MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
    MAX_CONTEXT_QUERY_LIMIT,
    MAX_CONTEXT_TASKNAME_CHARS,
)
from openkapsel.errors import ApiError
from openkapsel.routes import EndpointSpec

LOGGER = logging.getLogger("openkapsel")

class ContextHttpMixin:
    def _prepare_context_tracking(
        self,
        endpoint: EndpointSpec | None,
        query: dict[str, list[str]],
    ) -> None:
        """Require messages for mutations and optionally track named reads."""
        self._context_deferred_operation: str | None = None
        self._context_entry_id: int | None = None
        self._context_operation: str | None = None
        if endpoint is None or endpoint.context_mode == "none":
            return
        operation = endpoint.context_operation(self.command)
        if operation is None:
            raise RuntimeError(f"endpoint {endpoint.name} has no context operation")
        if endpoint.context_mode == "deferred":
            self._context_deferred_operation = operation
            return
        if endpoint.context_mode == "header":
            message = self._context_header_message() or ""
            taskname = self._context_header_taskname() or ""
            self._begin_context_operation(
                operation,
                taskname,
                message,
                self._context_header_plan_id(),
                self._context_request_details(query),
                plan_required=True,
            )
            return
        message_values = query.get("message", [])
        message = message_values[0].strip() if message_values else ""
        taskname_values = query.get("taskname", [])
        taskname = taskname_values[0].strip() if taskname_values else ""
        plan_id_values = query.get("plan_id", [])
        plan_id = plan_id_values[0].strip() if plan_id_values else None
        if message or taskname:
            self._require_control_token()
            self._begin_context_operation(
                operation,
                taskname,
                message,
                plan_id,
                self._context_request_details(query),
                plan_required=False,
            )


    def _begin_context_operation(
        self,
        operation: str,
        taskname: Any,
        message: Any,
        plan_id: Any,
        request: dict[str, Any] | None = None,
        *,
        plan_required: bool,
    ) -> int:
        if not isinstance(taskname, str) or not taskname.strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_taskname_required",
                "recorded operations require a non-empty taskname",
            )
        if not isinstance(message, str) or not message.strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_message_required",
                "recorded operations require a non-empty message",
            )
        if len(taskname.strip()) > MAX_CONTEXT_TASKNAME_CHARS:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_taskname_too_long",
                f"taskname cannot exceed {MAX_CONTEXT_TASKNAME_CHARS} characters",
            )
        if len(message.strip()) > MAX_CONTEXT_OPERATION_MESSAGE_CHARS:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_message_too_long",
                f"message cannot exceed {MAX_CONTEXT_OPERATION_MESSAGE_CHARS} characters",
            )
        parsed_plan_id = self._parse_operation_plan_id(
            plan_id,
            required=plan_required,
        )
        try:
            entry_id = self.server.context_for(self.token_scope_root).add(
                "operation",
                message,
                taskname=taskname,
                actor_id=self.token_record.actor_id,
                operation=operation,
                status="running",
                plan_id=parsed_plan_id,
                request=request,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_plan",
                str(exc),
            ) from None
        except (OSError, sqlite3.Error) as exc:
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "context_unavailable",
                f"cannot record operation context: {exc}",
            ) from None
        self._context_entry_id = entry_id
        self._context_operation = operation
        return entry_id


    def _begin_deferred_context_operation(self, body: dict[str, Any]) -> None:
        operation = getattr(self, "_context_deferred_operation", None)
        if operation is None or getattr(self, "_context_entry_id", None) is not None:
            return
        self._begin_context_operation(
            operation,
            body.get("taskname", self._context_header_taskname()),
            body.get("message", self._context_header_message()),
            body.get("plan_id", self._context_header_plan_id()),
            self._context_request_details(body),
            plan_required=True,
        )


    def _context_header_message(self) -> str | None:
        return self._context_header_value("OpenKapsel-Message")


    def _context_header_taskname(self) -> str | None:
        return self._context_header_value("OpenKapsel-Taskname")


    def _context_header_plan_id(self) -> str | None:
        return self._context_header_value("OpenKapsel-Plan-Id")


    @staticmethod
    def _parse_operation_plan_id(value: Any, *, required: bool) -> int | None:
        if value is None or value == "":
            if required:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "context_plan_id_required",
                    "modifying operations require a positive plan_id",
                )
            return None
        if isinstance(value, bool):
            parsed = 0
        elif isinstance(value, int):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = int(value.strip())
            except ValueError:
                parsed = 0
        else:
            parsed = 0
        if parsed < 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_plan_id",
                "plan_id must be a positive integer",
            )
        return parsed


    def _context_header_value(self, name: str) -> str | None:
        """Decode UTF-8 header bytes preserved by HTTP's latin-1 header mapping."""
        raw = self.headers.get(name)
        if raw is None:
            return None
        try:
            return raw.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return raw


    @classmethod
    def _context_request_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        blocked = {
            "message",
            "taskname",
            "plan_id",
            "content",
            "old",
            "new",
            "command",
            "data",
            "data_base64",
            "control_token",
            "token",
            "variables",
            "rc",
        }
        return {
            str(key): cls._context_safe_value(item)
            for key, item in value.items()
            if key not in blocked
        }


    @classmethod
    def _context_safe_value(cls, value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:2_000]
        if isinstance(value, list):
            return [cls._context_safe_value(item) for item in value[:50]]
        if isinstance(value, dict):
            return {
                str(key): cls._context_safe_value(item)
                for key, item in list(value.items())[:50]
                if str(key).lower() not in {
                    "content",
                    "data",
                    "data_base64",
                    "stdout",
                    "stderr",
                    "authorization",
                    "control_token",
                    "token",
                }
            }
        return str(value)[:2_000]


    def _finalize_context_operation(
        self,
        status: int,
        payload: dict[str, Any] | None,
    ) -> int | None:
        entry_id = getattr(self, "_context_entry_id", None)
        operation = getattr(self, "_context_operation", None)
        if entry_id is None or operation is None:
            return None
        self._context_entry_id = None
        self._context_operation = None
        succeeded = 200 <= int(status) < 400
        safe_payload = self._context_safe_value(payload or {})
        if succeeded:
            summary = f"{operation} succeeded with HTTP {int(status)}"
            target = None
            if isinstance(payload, dict):
                target = payload.get("path") or payload.get("destination")
                if target is None:
                    target = payload.get("task_id") or payload.get("upload_id")
            if target:
                summary += f": {str(target)[:2_000]}"
        else:
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            code = error.get("code") if isinstance(error, dict) else None
            summary = f"{operation} failed with HTTP {int(status)}"
            if code:
                summary += f": {code}"
        try:
            self.server.context_for(self.token_scope_root).finish_operation(
                entry_id,
                succeeded=succeeded,
                result_summary=summary,
                result=safe_payload if isinstance(safe_payload, dict) else None,
            )
        except (KeyError, OSError, sqlite3.Error, ValueError):
            LOGGER.exception("could not finalize context operation %s", entry_id)
        return entry_id


    def _handle_context_query(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        entry_id = (
            self._query_int(query, "id", 0, minimum=1)
            if "id" in query
            else None
        )
        before_id = (
            self._query_int(query, "before_id", 0, minimum=1)
            if "before_id" in query
            else None
        )
        limit = self._query_int(
            query,
            "limit",
            100,
            minimum=1,
            maximum=MAX_CONTEXT_QUERY_LIMIT,
        )
        entry_type = self._query_one(query, "type", "").strip() or None
        entry_status = self._query_one(query, "status", "").strip() or None
        taskname = self._query_one(query, "taskname", "").strip() or None
        actor_id = self._query_one(query, "actor_id", "").strip() or None
        path = self._query_one(query, "path", "").strip() or None
        plan_id = (
            self._query_int(query, "plan_id", 0, minimum=1)
            if "plan_id" in query
            else None
        )
        root_plans = self._query_bool(query, "root_plans", False)
        search = self._query_one(query, "query", "")
        try:
            entries, total = self.server.context_for(self.token_scope_root).query(
                entry_id=entry_id,
                query=search,
                entry_type=entry_type,
                entry_status=entry_status,
                taskname=taskname,
                actor_id=actor_id,
                path=path,
                plan_id=plan_id,
                root_plans=root_plans,
                before_id=before_id,
                limit=limit,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_query",
                str(exc),
            ) from None
        self._send_json(
            HTTPStatus.OK,
            {
                "entries": entries,
                "limit": limit,
                "total": total,
                "truncated": len(entries) < total,
                "next_before_id": entries[-1]["id"] if len(entries) < total else None,
            },
        )


    def _handle_context_add(self) -> None:
        entry = self._create_context_entry(self._read_json())
        self._send_json(HTTPStatus.OK if entry.get("replayed") else HTTPStatus.CREATED, entry)


    @staticmethod
    def _parse_context_entry_id(value: str) -> int:
        try:
            entry_id = int(value)
        except ValueError:
            entry_id = 0
        if entry_id < 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_id",
                "context id must be a positive integer",
            )
        return entry_id


    def _handle_context_plan_update(self, value: str) -> None:
        entry_id = self._parse_context_entry_id(value)
        body = self._read_json()
        taskname = self._required_string(body, "taskname")
        content = (
            self._required_string(body, "content")
            if "content" in body
            else None
        )
        plan_status = body.get("status")
        if plan_status is not None and not isinstance(plan_status, str):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                "status must be a string",
            )
        try:
            changes: dict[str, Any] = {
                "taskname": taskname,
                "content": content,
                "plan_status": plan_status,
            }
            completed_debrief: dict[str, Any] | None = None
            if plan_status == "completed":
                existing_entries, _ = self.server.context_for(self.token_scope_root).query(
                    entry_id=entry_id,
                )
                if not existing_entries or existing_entries[0]["type"] != "plan":
                    raise KeyError("context entry does not exist")
                if existing_entries[0]["status"] == "completed":
                    raise ValueError("plan is already completed")
                completed_debrief = self._apply_memory_debrief(
                    entry_id,
                    taskname,
                    body.get("debrief"),
                )
                changes["debrief"] = completed_debrief
                changes["actor_id"] = self.token_record.actor_id
            elif "debrief" in body:
                raise ValueError("plan debrief is only valid when status is completed")
            if "plan_id" in body:
                changes["plan_id"] = (
                    None
                    if body["plan_id"] is None
                    else self._parse_operation_plan_id(
                        body["plan_id"],
                        required=True,
                    )
                )
            entry = self.server.context_for(self.token_scope_root).update_plan(
                entry_id,
                **changes,
            )
            if completed_debrief is not None:
                entry["debrief"] = completed_debrief
        except KeyError as exc:
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "context_not_found",
                str(exc.args[0]),
            ) from None
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                str(exc),
            ) from None
        self._send_json(HTTPStatus.OK, entry)


    def _handle_context_note_replace(self, value: str) -> None:
        entry_id = self._parse_context_entry_id(value)
        body = self._read_json()
        taskname = self._required_string(body, "taskname")
        content = self._required_string(body, "content")
        plan_id = self._parse_operation_plan_id(
            body.get("plan_id"),
            required=True,
        )
        try:
            entry = self.server.context_for(self.token_scope_root).replace_note(
                entry_id,
                taskname=taskname,
                content=content,
                actor_id=self.token_record.actor_id,
                plan_id=plan_id,
            )
        except KeyError as exc:
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "context_not_found",
                str(exc.args[0]),
            ) from None
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                str(exc),
            ) from None
        self._send_json(HTTPStatus.CREATED, entry)


    def _handle_context_plan_tree(
        self,
        value: str,
        query: dict[str, list[str]],
    ) -> None:
        plan_id = self._parse_context_entry_id(value.rstrip("/"))
        max_depth = self._query_int(
            query,
            "max_depth",
            8,
            minimum=0,
            maximum=32,
        )
        limit = self._query_int(
            query,
            "limit",
            200,
            minimum=1,
            maximum=MAX_CONTEXT_QUERY_LIMIT,
        )
        try:
            payload = self.server.context_for(self.token_scope_root).plan_tree(
                plan_id,
                max_depth=max_depth,
                limit=limit,
            )
        except ValueError as exc:
            message = str(exc)
            status = (
                HTTPStatus.NOT_FOUND
                if message == "plan_id does not exist"
                else HTTPStatus.BAD_REQUEST
            )
            raise ApiError(
                status,
                "context_plan_not_found" if status == HTTPStatus.NOT_FOUND else "invalid_context_plan",
                message,
            ) from None
        self._send_json(HTTPStatus.OK, payload)

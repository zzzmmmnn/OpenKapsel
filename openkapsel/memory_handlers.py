"""REST handlers for revisioned project memory."""

from __future__ import annotations

import re
from http import HTTPStatus
from typing import Any

from .errors import ApiError
from .memory_store import MAX_MEMORY_QUERY_LIMIT


class MemoryHandlersMixin:
    """Memory-domain methods mixed into the main request handler."""

    def _memory_actor_id(self) -> str:
        return self.token_record.actor_id

    def _require_existing_plan(self, value: Any) -> int:
        try:
            plan_id = self._parse_operation_plan_id(value, required=True)
            entries, _ = self.server.context_for(self.token_scope_root).query(entry_id=plan_id)
            if not entries or entries[0]["type"] != "plan":
                raise ValueError("plan_id must reference a plan in this workspace")
            return plan_id
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_memory_plan",
                str(exc),
            ) from None

    @staticmethod
    def _memory_etag(entry: dict[str, Any]) -> str:
        return f'"memory-{entry["memory_id"]}-r{entry["revision"]}"'

    def _memory_expected_revision(self, memory_id: str, body: dict[str, Any]) -> int:
        candidate = body.get("expected_revision")
        header = self.headers.get("If-Match")
        if header:
            match = re.fullmatch(
                rf'(?:W/)?"?memory-{re.escape(memory_id)}-r([1-9][0-9]*)"?',
                header.strip(),
            )
            if match is None:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_memory_if_match",
                    "If-Match must use the ETag returned by the memory endpoint",
                )
            header_revision = int(match.group(1))
            if candidate is not None and candidate != header_revision:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "memory_revision_mismatch",
                    "expected_revision does not match If-Match",
                )
            candidate = header_revision
        if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 1:
            raise ApiError(
                HTTPStatus.PRECONDITION_REQUIRED,
                "memory_revision_required",
                "send If-Match with the current memory ETag or expected_revision",
            )
        return candidate

    def _memory_change_metadata(self, body: dict[str, Any]) -> tuple[int, str, str]:
        plan_id = self._require_existing_plan(body.get("plan_id"))
        taskname = self._required_string(body, "taskname")
        if len(taskname) > 32:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_memory_taskname",
                "taskname exceeds 32 characters",
            )
        message = self._required_string(body, "message")
        return plan_id, taskname, message

    def _related_memories(
        self,
        content: str,
        scope_paths: Any = None,
        memory_tags: Any = None,
    ) -> list[dict[str, Any]]:
        if scope_paths is not None and not isinstance(scope_paths, list):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_scope_paths",
                "scope_paths must be an array of workspace-relative paths",
            )
        if memory_tags is not None and not isinstance(memory_tags, list):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_memory_tags",
                "memory_tags must be an array of exact Memory tags",
            )
        try:
            return self.server.memory_for(self.token_scope_root).related(
                content,
                scope_paths,
                memory_tags,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_scope_paths",
                str(exc),
            ) from None

    def _apply_memory_debrief(
        self,
        plan_id: int,
        taskname: str,
        value: Any,
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "plan_completion_requires_debrief",
                "completing a plan requires a debrief object",
            )
        summary = value.get("summary")
        outcome = value.get("outcome")
        actions = value.get("memory_actions")
        if not isinstance(summary, str) or not summary.strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.summary must be a non-empty string",
            )
        if outcome not in {"succeeded", "partial", "no_change"}:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.outcome must be succeeded, partial, or no_change",
            )
        if not isinstance(actions, list):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_actions must be an array; use an empty array when nothing should be retained",
            )
        if len(actions) > 20:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_actions cannot contain more than 20 actions",
            )
        store = self.server.memory_for(self.token_scope_root)
        actor_id = self._memory_actor_id()
        results: list[dict[str, Any]] = []
        for index, action_value in enumerate(actions):
            if not isinstance(action_value, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory action {index} must be an object",
                )
            action = action_value.get("action")
            try:
                if action == "create":
                    entry = store.create(
                        category=action_value.get("category"),
                        key=action_value.get("key"),
                        title=action_value.get("title"),
                        content=action_value.get("content"),
                        status=action_value.get("status"),
                        severity=action_value.get("severity"),
                        tags=action_value.get("tags"),
                        paths=action_value.get("paths"),
                        plan_id=plan_id,
                        actor_id=actor_id,
                        message=f"Plan {plan_id} completion: {summary.strip()}",
                    )
                elif action in {"update", "resolve"}:
                    memory_id = action_value.get("memory_id")
                    if not isinstance(memory_id, str) or not memory_id:
                        raise ValueError("memory_id is required for update or resolve")
                    ignored = {"action", "memory_id", "expected_revision"}
                    changes = {
                        key: item
                        for key, item in action_value.items()
                        if key not in ignored
                    }
                    if action == "resolve":
                        changes["status"] = "resolved"
                    entry = store.update(
                        memory_id,
                        changes=changes,
                        expected_revision=action_value.get("expected_revision"),
                        plan_id=plan_id,
                        actor_id=actor_id,
                        message=f"Plan {plan_id} completion: {summary.strip()}",
                    )
                elif action == "archive":
                    memory_id = action_value.get("memory_id")
                    if not isinstance(memory_id, str) or not memory_id:
                        raise ValueError("memory_id is required for archive")
                    entry = store.archive(
                        memory_id,
                        expected_revision=action_value.get("expected_revision"),
                        plan_id=plan_id,
                        actor_id=actor_id,
                        message=f"Plan {plan_id} completion: {summary.strip()}",
                    )
                else:
                    raise ValueError("memory action must be create, update, resolve, or archive")
            except (KeyError, ValueError, RuntimeError) as exc:
                error = self._memory_error(exc)
                error.details = {"action_index": index}
                raise error from None
            results.append(
                {
                    "action": action,
                    "memory_id": entry["memory_id"],
                    "revision": entry["revision"],
                }
            )
        return {
            "summary": summary.strip(),
            "outcome": outcome,
            "memory_refs": results,
        }

    @staticmethod
    def _memory_error(exc: Exception) -> ApiError:
        if isinstance(exc, KeyError):
            return ApiError(HTTPStatus.NOT_FOUND, "memory_not_found", str(exc.args[0]))
        if isinstance(exc, RuntimeError):
            return ApiError(HTTPStatus.PRECONDITION_FAILED, "memory_revision_conflict", str(exc))
        return ApiError(HTTPStatus.BAD_REQUEST, "invalid_memory", str(exc))

    def _handle_memory_query(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        limit = self._query_int(
            query,
            "limit",
            100,
            minimum=1,
            maximum=MAX_MEMORY_QUERY_LIMIT,
        )
        try:
            entries, total = self.server.memory_for(self.token_scope_root).query(
                query=self._query_one(query, "query", ""),
                category=self._query_one(query, "category", "").strip() or None,
                status=self._query_one(query, "status", "").strip() or None,
                severity=self._query_one(query, "severity", "").strip() or None,
                tag=self._query_one(query, "tag", "").strip() or None,
                path=self._query_one(query, "path", "").strip() or None,
                include_archived=self._query_bool(query, "include_archived", False),
                limit=limit,
            )
        except ValueError as exc:
            raise self._memory_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            {
                "memories": entries,
                "limit": limit,
                "total": total,
                "truncated": len(entries) < total,
            },
        )

    def _handle_memory_project(self) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        self._send_json(
            HTTPStatus.OK,
            self.server.memory_for(self.token_scope_root).project(),
        )

    def _handle_memory_add(self) -> None:
        body = self._read_json()
        plan_id, _taskname, message = self._memory_change_metadata(body)
        try:
            entry = self.server.memory_for(self.token_scope_root).create(
                category=body.get("category"),
                key=body.get("key"),
                title=body.get("title"),
                content=body.get("content"),
                status=body.get("status"),
                severity=body.get("severity"),
                tags=body.get("tags"),
                paths=body.get("paths"),
                plan_id=plan_id,
                actor_id=self._memory_actor_id(),
                message=message,
            )
        except (ValueError, RuntimeError) as exc:
            raise self._memory_error(exc) from None
        self._send_json(
            HTTPStatus.CREATED,
            entry,
            headers={"ETag": self._memory_etag(entry)},
        )

    def _handle_memory_item(self, memory_id: str) -> None:
        store = self.server.memory_for(self.token_scope_root)
        if self.command == "GET":
            self._require_permission(self.token_record.can_read, "read permission is not granted")
            try:
                entry = store.get(memory_id)
            except KeyError as exc:
                raise self._memory_error(exc) from None
            self._send_json(
                HTTPStatus.OK,
                entry,
                headers={"ETag": self._memory_etag(entry)},
            )
            return

        body = self._read_json()
        plan_id, _taskname, message = self._memory_change_metadata(body)
        expected_revision = self._memory_expected_revision(memory_id, body)
        try:
            if self.command == "PATCH":
                ignored = {"plan_id", "taskname", "message", "expected_revision"}
                changes = {key: value for key, value in body.items() if key not in ignored}
                entry = store.update(
                    memory_id,
                    changes=changes,
                    expected_revision=expected_revision,
                    plan_id=plan_id,
                    actor_id=self._memory_actor_id(),
                    message=message,
                )
            elif self.command == "DELETE":
                entry = store.archive(
                    memory_id,
                    expected_revision=expected_revision,
                    plan_id=plan_id,
                    actor_id=self._memory_actor_id(),
                    message=message,
                )
            else:
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", "method is not allowed")
        except (KeyError, ValueError, RuntimeError) as exc:
            raise self._memory_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            entry,
            headers={"ETag": self._memory_etag(entry)},
        )

    def _handle_memory_revisions(
        self,
        memory_id: str,
        query: dict[str, list[str]],
    ) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        limit = self._query_int(
            query,
            "limit",
            100,
            minimum=1,
            maximum=MAX_MEMORY_QUERY_LIMIT,
        )
        try:
            revisions = self.server.memory_for(self.token_scope_root).revisions(
                memory_id,
                limit=limit,
            )
        except (KeyError, ValueError) as exc:
            raise self._memory_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            {"memory_id": memory_id, "revisions": revisions, "limit": limit},
        )

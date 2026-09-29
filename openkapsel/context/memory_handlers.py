"""REST handlers for revisioned project memory."""

from __future__ import annotations

import ntpath
import os
import posixpath
import re
from http import HTTPStatus
from pathlib import Path
from typing import Any

from openkapsel.errors import ApiError
from openkapsel.context.context_store import MAX_CONTEXT_QUERY_LIMIT
from openkapsel.context.memory_store import (
    MAX_MEMORY_QUERY_LIMIT,
    MAX_MEMORY_REVISION_LIMIT,
    MemoryStore,
)


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

    @staticmethod
    def _common_memory_scope(scopes: list[str]) -> str:
        return MemoryStore._common_path(scopes)

    @staticmethod
    def _extract_operation_paths(value: Any) -> list[tuple[str, bool]]:
        """Return (path, is_directory) candidates from a sanitized Context payload."""
        found: list[tuple[str, bool]] = []
        if isinstance(value, dict):
            item_operation = value.get("operation")
            for key, item in value.items():
                if key in {"path", "source", "destination", "cwd"} and isinstance(item, str):
                    is_directory = key == "cwd" or (key == "path" and item_operation == "mkdir")
                    found.append((item, is_directory))
                elif isinstance(item, (dict, list)):
                    found.extend(MemoryHandlersMixin._extract_operation_paths(item))
        elif isinstance(value, list):
            for item in value:
                found.extend(MemoryHandlersMixin._extract_operation_paths(item))
        return found

    @staticmethod
    def _mapping_scope(mapping_id: str, raw: str, *, directory: bool) -> str:
        normalized = raw.replace("\\", "/") or "."
        if not directory and normalized != ".":
            if re.match(r"^[A-Za-z]:/", normalized):
                parent = ntpath.dirname(normalized.replace("/", "\\")).replace("\\", "/")
            else:
                parent = posixpath.dirname(normalized)
            normalized = parent or "."
        normalized = posixpath.normpath(normalized).replace("\\", "/")
        return f"mapping:{mapping_id}:{normalized or '.'}"

    def _virtual_memory_scope(self, raw: str, *, directory: bool) -> str:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.token_scope_root / candidate
        candidate = Path(os.path.abspath(candidate))

        mapping = self.server.mappings.at_path(candidate)
        if mapping is None:
            resolved = candidate.resolve(strict=False)
            mapping = self.server.mappings.at_path(resolved)
            if mapping is not None:
                candidate = resolved
        if mapping is not None:
            root = self.server.mappings.mount_path(mapping)
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError:
                return "server:."
            if not directory:
                relative = posixpath.dirname(relative) or "."
            return f"mapping:{mapping['id']}:{relative or '.'}"

        storage = getattr(self.server, "storage_providers", None)
        storage_mapping = storage.mapping_at_path(candidate) if storage is not None else None
        if storage_mapping is not None:
            root = storage.mapping_path(storage_mapping)
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError:
                return "server:."
            if not directory:
                relative = posixpath.dirname(relative) or "."
            return f"storage:{storage_mapping['provider_id']}:{relative or '.'}"

        try:
            relative = candidate.relative_to(self.token_scope_root).as_posix()
        except ValueError:
            return "server:."
        if not directory:
            relative = posixpath.dirname(relative) or "."
        return f"server:{relative or '.'}"

    def _plan_memory_path(self, plan_id: int) -> str:
        write_operations = {
            "fs.copy", "fs.content.put", "fs.mutate", "fs.large.replace", "fs.mkdir",
            "fs.move", "fs.transfer.control", "recycle.restore", "upload.commit",
            "shell.exec", "schedule.execute", "server.rpc", "mapping.rpc",
        }
        context = self.server.context_for(self.token_scope_root)
        scopes: list[str] = []
        before_id: int | None = None
        while True:
            entries, _ = context.query(
                entry_type="operation",
                entry_status="succeeded",
                plan_id=plan_id,
                before_id=before_id,
                limit=MAX_CONTEXT_QUERY_LIMIT,
            )
            for entry in entries:
                operation = entry.get("operation")
                if operation not in write_operations:
                    continue
                request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
                result = entry.get("result") if isinstance(entry.get("result"), dict) else {}

                if operation == "shell.exec":
                    raw_cwd = request.get("cwd", ".")
                    candidates = [(raw_cwd if isinstance(raw_cwd, str) else ".", True)]
                else:
                    candidates = self._extract_operation_paths(request)
                    candidates.extend(self._extract_operation_paths(result))

                if operation == "mapping.rpc":
                    mapping_id = request.get("mapping_id")
                    if not isinstance(mapping_id, str) or not mapping_id:
                        scopes.append("server:.")
                        continue
                    if not candidates:
                        scopes.append(f"mapping:{mapping_id}:.")
                        continue
                    scopes.extend(
                        self._mapping_scope(mapping_id, raw, directory=directory)
                        for raw, directory in candidates
                    )
                    continue

                if operation == "server.rpc" and not candidates:
                    scopes.append("server:.")
                    continue

                if operation == "shell.exec" and not candidates:
                    candidates = [(".", True)]
                for raw, directory in candidates:
                    scopes.append(self._virtual_memory_scope(raw, directory=directory))

            if len(entries) < MAX_CONTEXT_QUERY_LIMIT:
                break
            before_id = int(entries[-1]["id"])

        return self._common_memory_scope(scopes)

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
        items = value.get("items")
        outcome = value.get("outcome")
        actions = value.get("memory_actions")
        feedback = value.get("memory_feedback")
        conflicts = value.get("memory_conflicts")
        if not isinstance(items, list):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.items must be an array",
            )
        if len(items) > 20:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.items cannot contain more than 20 items",
            )
        normalized_items: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"debrief item {index} must be an object",
                )
            content = item.get("content")
            tags = item.get("tags")
            if not isinstance(content, str) or not content.strip() or len(content.strip()) > 256:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"debrief item {index} content must be 1-256 characters",
                )
            if not isinstance(tags, list) or not tags or len(tags) > 32:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"debrief item {index} tags must contain 1-32 tags; prefer 4-16",
                )
            normalized_tags: list[str] = []
            for tag in tags:
                if not isinstance(tag, str) or not tag.strip() or len(tag.strip()) > 64:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_plan_debrief",
                        f"debrief item {index} tags must be non-empty strings up to 64 characters",
                    )
                normalized_tag = tag.strip()
                if normalized_tag in normalized_tags:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_plan_debrief",
                        f"debrief item {index} tags must be unique",
                    )
                normalized_tags.append(normalized_tag)
            normalized_items.append({"content": content.strip(), "tags": normalized_tags})
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
                "debrief.memory_actions must be an array; use an empty array when no existing Memory needs mutation",
            )
        if len(actions) > 20:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_actions cannot contain more than 20 actions",
            )
        if not isinstance(feedback, list):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_feedback must be an array; list only Memory that actually helped",
            )
        if len(feedback) > 20:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_feedback cannot contain more than 20 items",
            )
        if not isinstance(conflicts, list):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_conflicts must be an array",
            )
        if len(conflicts) > 20:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "debrief.memory_conflicts cannot contain more than 20 items",
            )

        store = self.server.memory_for(self.token_scope_root)
        actor_id = self._memory_actor_id()
        completion_message = f"Plan {plan_id} completion"
        try:
            normalized_feedback = store.validate_helpful_feedback(feedback)
        except (KeyError, ValueError, RuntimeError) as exc:
            raise self._memory_error(exc) from None

        normalized_conflicts: list[dict[str, Any]] = []
        conflict_ids: set[str] = set()
        for index, item in enumerate(conflicts):
            if not isinstance(item, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory conflict {index} must be an object",
                )
            memory_id = item.get("memory_id")
            revision = item.get("revision")
            reason = item.get("reason")
            if not isinstance(memory_id, str) or not memory_id:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory conflict {index} requires memory_id",
                )
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory conflict {index} requires a positive revision",
                )
            if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 1000:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory conflict {index} requires a non-empty reason up to 1000 characters",
                )
            if memory_id in conflict_ids:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory_conflicts duplicates {memory_id}",
                )
            conflict_ids.add(memory_id)
            normalized_conflicts.append(
                {"memory_id": memory_id, "revision": revision, "reason": reason.strip()}
            )

        feedback_ids = {item["memory_id"] for item in normalized_feedback}
        overlap = feedback_ids & conflict_ids
        if overlap:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_plan_debrief",
                "the same Memory cannot be both helpful and conflicting: "
                + ", ".join(sorted(overlap)),
            )

        conflict_handlers: dict[tuple[str, int], dict[str, Any]] = {}
        for action_value in actions:
            if not isinstance(action_value, dict):
                continue
            action = action_value.get("action")
            memory_id = action_value.get("memory_id")
            revision = action_value.get("expected_revision")
            if (
                action in {"update", "archive"}
                and isinstance(memory_id, str)
                and isinstance(revision, int)
                and not isinstance(revision, bool)
            ):
                conflict_handlers[(memory_id, revision)] = action_value

        for conflict in normalized_conflicts:
            handler = conflict_handlers.get((conflict["memory_id"], conflict["revision"]))
            if handler is None or (
                handler.get("action") == "update" and "content" not in handler
            ):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "unresolved_memory_conflict",
                    f"conflicting Memory {conflict['memory_id']} revision "
                    f"{conflict['revision']} must have its content updated or be archived",
                )

        try:
            store.preflight_actions(actions)
        except (KeyError, ValueError, RuntimeError) as exc:
            raise self._memory_error(exc) from None

        debrief_path = self._plan_memory_path(plan_id)
        results: list[dict[str, Any]] = []
        for index, item in enumerate(normalized_items):
            try:
                entry = store.create(
                    content=item["content"],
                    tags=item["tags"],
                    path=debrief_path,
                    plan_id=plan_id,
                    actor_id=actor_id,
                    message=f"Plan {plan_id} debrief memory",
                )
            except (KeyError, ValueError, RuntimeError) as exc:
                error = self._memory_error(exc)
                error.details = {"debrief_item_index": index}
                raise error from None
            results.append(
                {
                    "action": "create",
                    "memory_id": entry["memory_id"],
                    "revision": entry["revision"],
                }
            )

        for index, action_value in enumerate(actions):
            if not isinstance(action_value, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_plan_debrief",
                    f"memory action {index} must be an object",
                )
            action = action_value.get("action")
            try:
                if action == "update":
                    memory_id = action_value.get("memory_id")
                    if not isinstance(memory_id, str) or not memory_id:
                        raise ValueError("memory_id is required for update")
                    ignored = {"action", "memory_id", "expected_revision"}
                    changes = {
                        key: item
                        for key, item in action_value.items()
                        if key not in ignored
                    }
                    entry = store.update(
                        memory_id,
                        changes=changes,
                        expected_revision=action_value.get("expected_revision"),
                        plan_id=plan_id,
                        actor_id=actor_id,
                        message=completion_message,
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
                        message=completion_message,
                    )
                else:
                    raise ValueError("memory action must be update or archive")
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
        try:
            recorded_feedback = store.record_helpful_feedback(
                plan_id=plan_id,
                feedback=normalized_feedback,
                actor_id=actor_id,
            )
        except (KeyError, ValueError, RuntimeError) as exc:
            raise self._memory_error(exc) from None
        return {
            "items": normalized_items,
            "outcome": outcome,
            "memory_refs": results,
            "memory_feedback": recorded_feedback,
            "memory_conflicts": normalized_conflicts,
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
                content=body.get("content"),
                tags=body.get("tags"),
                path=body.get("path"),
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
            maximum=MAX_MEMORY_REVISION_LIMIT,
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

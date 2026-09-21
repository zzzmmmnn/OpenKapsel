"""Shared REST/MCP Context creation; keep both surfaces on one contract."""
from __future__ import annotations

from http import HTTPStatus
from typing import Any

from openkapsel.context.context_plans import PlanRequestConflict, normalize_plan_request
from openkapsel.errors import ApiError


class ContextCreationMixin:
    def _create_context_entry(self, body: dict[str, Any]) -> dict[str, Any]:
        entry_type = self._required_string(body, "type")
        if entry_type not in {"plan", "note"}:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_context_type", "manually added context type must be plan or note")
        content = self._required_string(body, "content")
        taskname = self._required_string(body, "taskname")
        store = self.server.context_for(self.token_scope_root)
        try:
            if entry_type == "plan":
                spec = normalize_plan_request(body)
                # Validate all Memory inputs and obtain a single deduplicated set
                # before creating any plan. A validation error cannot leave an
                # orphan root or only part of the requested children.
                related = self._related_memories(spec["hint_content"], spec["hint_paths"], spec["hint_tags"])
                entry = store.create_plans(body, actor_id=self.token_record.actor_id)
            else:
                if "subplans" in body or "request_id" in body:
                    raise ValueError("subplans and request_id are supported only for type=plan")
                if body.get("plan_id") is None:
                    raise ValueError("notes must reference a plan_id")
                plan_id = self._parse_operation_plan_id(body["plan_id"], required=True)
                if body.get("status") is not None:
                    raise ValueError("note context cannot have a plan status")
                entry_id = store.add("note", content, taskname=taskname, actor_id=self.token_record.actor_id, plan_id=plan_id)
                entries, _ = store.query(entry_id=entry_id)
                entry = entries[0]
        except PlanRequestConflict as exc:
            raise ApiError(HTTPStatus.CONFLICT, exc.code, str(exc)) from None
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_context_entry", str(exc)) from None
        if entry_type == "plan":
            entry["related_memory"] = related
            # Hints are live advisory data, not part of the persisted creation
            # receipt. Return them once, excluding this root and all subplans.
            unfinished = store.unfinished_root_plan_hints(exclude_plan_id=entry["id"])
            entry["unfinished_root_plans"] = unfinished["plans"]
            entry["unfinished_root_plans_total"] = unfinished["total"]
            entry["unfinished_root_plans_truncated"] = unfinished["truncated"]
        return entry

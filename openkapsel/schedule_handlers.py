"""Authenticated REST handlers for persistent scheduled Shell tasks."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from .errors import ApiError
from .scheduler_store import ScheduleError, validate_timing


class ScheduleHandlersMixin:
    def _schedule_plan_id(self, value: Any) -> int:
        plan_id = self._parse_operation_plan_id(value, required=True)
        assert plan_id is not None
        try:
            self.server.context_for(self.token_scope_root).plan_tree(
                plan_id, max_depth=0, limit=1
            )
        except ValueError as exc:
            raise ScheduleError(str(exc)) from None
        return plan_id

    def _require_schedule_permission(self) -> None:
        if not self.token_record.can_schedule:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "schedule_permission_denied",
                "scheduled task permission is not granted",
            )
        if self.token_record.shell_mode == "none":
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "permission_denied",
                "Shell permission is required for scheduled tasks",
            )

    @staticmethod
    def _schedule_api_error(exc: Exception) -> ApiError:
        if isinstance(exc, KeyError):
            return ApiError(HTTPStatus.NOT_FOUND, "schedule_not_found", str(exc))
        message = str(exc)
        if "revision" in message:
            return ApiError(HTTPStatus.CONFLICT, "schedule_revision_conflict", message)
        if "running" in message or "only a" in message:
            return ApiError(HTTPStatus.CONFLICT, "schedule_state_conflict", message)
        return ApiError(HTTPStatus.BAD_REQUEST, "invalid_schedule", message)

    def _schedule_store(self):
        self._require_schedule_permission()
        return self.server.schedules_for(self.token_scope_root)

    def _handle_schedule_list(self, query: dict[str, list[str]]) -> None:
        del query
        schedules = self._schedule_store().list(self.token_record.app_id)
        self._send_json(
            HTTPStatus.OK,
            {"schedules": [item.public() for item in schedules], "total": len(schedules)},
        )

    def _handle_schedule_create(self) -> None:
        store = self._schedule_store()
        body = self._read_json()
        try:
            timing = validate_timing(body.get("schedule"))
            run_context = body.get("run_context")
            if run_context is None:
                run_context = {
                    "plan_id": body.get("plan_id", self._context_header_plan_id()),
                    "taskname": body.get("taskname", self._context_header_taskname()),
                    "message": body.get("message", self._context_header_message()),
                }
            if not isinstance(run_context, dict):
                raise ScheduleError("run_context must be a JSON object")
            timeout = body.get("timeout_seconds", self.server.config.default_command_timeout)
            if timeout is not None:
                if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                    raise ScheduleError("timeout_seconds must be null or a number")
                timeout = float(timeout)
            record = store.create(
                self.token_record.app_id,
                name=self._required_string(body, "name"),
                timing=timing,
                command=self._required_string(body, "command"),
                cwd=body.get("cwd", ""),
                timeout_seconds=timeout,
                overlap_policy=body.get("overlap_policy", "skip"),
                misfire_policy=body.get("misfire_policy", "skip"),
                plan_id=self._schedule_plan_id(run_context.get("plan_id")),
                taskname=run_context.get("taskname", ""),
                message=run_context.get("message", ""),
            )
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self.server.scheduler.changed()
        self._send_json(HTTPStatus.CREATED, record.public())

    def _handle_schedule_get(self, schedule_id: str) -> None:
        try:
            record = self._schedule_store().get(self.token_record.app_id, schedule_id)
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self._send_json(HTTPStatus.OK, record.public())

    def _handle_schedule_update(self, schedule_id: str) -> None:
        store = self._schedule_store()
        body = self._read_json()
        expected_revision = body.get("expected_revision")
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_schedule",
                "expected_revision must be a positive integer",
            )
        changes: dict[str, Any] = {"expected_revision": expected_revision}
        for name in (
            "name",
            "command",
            "cwd",
            "overlap_policy",
            "misfire_policy",
        ):
            if name in body:
                changes[name] = body[name]
        if "timeout_seconds" in body:
            changes["timeout_seconds"] = body["timeout_seconds"]
        if "run_context" in body:
            run_context = body["run_context"]
            if not isinstance(run_context, dict):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_schedule",
                    "run_context must be a JSON object",
                )
            changes["plan_id"] = self._schedule_plan_id(run_context.get("plan_id"))
            changes["taskname"] = run_context.get("taskname")
            changes["message"] = run_context.get("message")
        if "schedule" in body:
            try:
                changes["timing"] = validate_timing(body["schedule"])
            except ScheduleError as exc:
                raise self._schedule_api_error(exc) from None
        if len(changes) == 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_schedule",
                "schedule update does not contain any changes",
            )
        try:
            record = store.update(self.token_record.app_id, schedule_id, **changes)
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self.server.scheduler.changed()
        self._send_json(HTTPStatus.OK, record.public())

    def _handle_schedule_delete(self, schedule_id: str) -> None:
        self._read_json()
        try:
            self._schedule_store().delete(self.token_record.app_id, schedule_id)
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self.server.scheduler.changed()
        self._send_json(HTTPStatus.OK, {"schedule_id": schedule_id, "deleted": True})

    def _handle_schedule_pause(self, schedule_id: str) -> None:
        self._read_json()
        try:
            record = self._schedule_store().pause(self.token_record.app_id, schedule_id)
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self.server.scheduler.changed()
        self._send_json(HTTPStatus.OK, record.public())

    def _handle_schedule_resume(self, schedule_id: str) -> None:
        self._read_json()
        try:
            record = self._schedule_store().resume(self.token_record.app_id, schedule_id)
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self.server.scheduler.changed()
        self._send_json(HTTPStatus.OK, record.public())

    def _handle_schedule_run(self, schedule_id: str) -> None:
        self._schedule_store()
        self._read_json()
        try:
            claim = self.server.scheduler.run_now(
                self.token_scope_root,
                self.token_record.app_id,
                schedule_id,
            )
            run = self.server.schedules_for(self.token_scope_root).get_run(
                self.token_record.app_id, claim.run.run_id
            )
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self._send_json(HTTPStatus.ACCEPTED, run.public())

    def _handle_schedule_runs(
        self, schedule_id: str, query: dict[str, list[str]]
    ) -> None:
        limit = self._query_int(query, "limit", 50, minimum=1, maximum=200)
        try:
            runs = self._schedule_store().list_runs(
                self.token_record.app_id, schedule_id, limit=limit
            )
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            {"runs": [run.public() for run in runs], "count": len(runs)},
        )

    def _handle_schedule_run_get(self, run_id: str) -> None:
        try:
            run = self._schedule_store().get_run(self.token_record.app_id, run_id)
        except (ScheduleError, KeyError) as exc:
            raise self._schedule_api_error(exc) from None
        self._send_json(HTTPStatus.OK, run.public())

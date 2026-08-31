"""Low-overhead daemon scheduler for per-workspace persistent schedules."""

from __future__ import annotations

import heapq
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import ApiError
from .scheduler_store import ScheduleClaim, ScheduleStore, parse_datetime, utc_now
from .shell_execution import start_shell_task


LOGGER = logging.getLogger("openkapsel")


class SchedulerManager:
    """One sleeping thread dispatches all registered workspace schedules."""

    def __init__(self, server: Any):
        self.server = server
        self._condition = threading.Condition()
        self._stores: dict[Path, ScheduleStore] = {}
        self._heap: list[tuple[datetime, str, Path]] = []
        self._dirty = True
        self._closing = False
        for record in server.tokens.list():
            try:
                self.store_for(server.tokens.scope_root(record))
            except (OSError, ValueError):
                LOGGER.exception("could not register scheduler workspace for %s", record.app_id)
        self._thread = threading.Thread(
            target=self._run,
            name="openkapsel-scheduler",
            daemon=True,
        )
        self._thread.start()

    def store_for(self, scope_root: Path) -> ScheduleStore:
        scope = Path(scope_root).resolve(strict=True)
        with self._condition:
            store = self._stores.get(scope)
            if store is None:
                store = ScheduleStore(scope)
                abandoned = store.abandon_running()
                if abandoned:
                    LOGGER.warning(
                        "marked %d interrupted schedule runs abandoned in %s",
                        abandoned,
                        scope,
                    )
                self._stores[scope] = store
                self._dirty = True
                self._condition.notify_all()
            return store

    def changed(self) -> None:
        with self._condition:
            self._dirty = True
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            self._closing = True
            self._condition.notify_all()
        self._thread.join(timeout=5)

    def delete_app(self, scope_root: Path, app_id: str) -> int:
        count = self.store_for(scope_root).delete_app(app_id)
        self.changed()
        return count

    def pause_app(self, scope_root: Path, app_id: str) -> int:
        count = self.store_for(scope_root).pause_app(app_id)
        self.changed()
        return count

    def _rebuild_heap_locked(self) -> None:
        heap: list[tuple[datetime, str, Path]] = []
        for scope, store in self._stores.items():
            due = store.next_due()
            if due is None:
                continue
            next_run_at, schedule_id = due
            try:
                when = parse_datetime(next_run_at, "next_run_at")
            except ValueError:
                LOGGER.exception("invalid next_run_at for schedule %s", schedule_id)
                continue
            heap.append((when, schedule_id, scope))
        heapq.heapify(heap)
        self._heap = heap
        self._dirty = False

    def _run(self) -> None:
        while True:
            target: tuple[datetime, str, Path] | None = None
            with self._condition:
                while target is None:
                    if self._closing:
                        return
                    if self._dirty:
                        self._rebuild_heap_locked()
                    if not self._heap:
                        self._condition.wait()
                        continue
                    target = self._heap[0]
                    delay = (target[0] - utc_now()).total_seconds()
                    if delay > 0:
                        self._condition.wait(timeout=delay)
                        target = None
                        continue
                    heapq.heappop(self._heap)
            assert target is not None
            _when, schedule_id, scope = target
            try:
                claim = self._stores[scope].claim_due(
                    schedule_id,
                    misfire_grace_seconds=self.server.config.schedule_misfire_grace_seconds,
                )
                if claim is not None and claim.execute:
                    self._execute(scope, self._stores[scope], claim)
            except Exception:
                LOGGER.exception("scheduled dispatch failed for %s", schedule_id)
            finally:
                self.changed()

    def run_now(self, scope_root: Path, app_id: str, schedule_id: str) -> ScheduleClaim:
        store = self.store_for(scope_root)
        claim = store.claim_due(schedule_id, force=True, app_id=app_id)
        assert claim is not None
        if claim.execute:
            self._execute(Path(scope_root), store, claim)
        self.changed()
        return claim

    def _execute(self, scope: Path, store: ScheduleStore, claim: ScheduleClaim) -> None:
        record = self.server.tokens.get_by_app_id(claim.schedule.app_id)
        if (
            record is None
            or not record.valid
            or not record.can_schedule
            or record.shell_mode == "none"
        ):
            store.finish_run(
                claim.run.run_id,
                status="skipped_permission",
                error="schedule permission, Shell permission, or workspace validity was revoked",
            )
            if record is not None:
                store.pause_app(record.app_id)
            return
        context_id: int | None = None
        try:
            context_id = self.server.context_for(scope).add(
                "operation",
                claim.schedule.message,
                taskname=claim.schedule.taskname,
                actor_id=record.actor_id,
                operation="schedule.run",
                status="running",
                plan_id=claim.schedule.plan_id,
                request={
                    "schedule_id": claim.schedule.schedule_id,
                    "run_id": claim.run.run_id,
                    "cwd": claim.schedule.cwd,
                },
            )
        except Exception:
            LOGGER.exception("could not create Context entry for schedule %s", claim.schedule.schedule_id)
            store.finish_run(
                claim.run.run_id,
                status="failed",
                error="Context operation could not be created",
            )
            return
        try:
            task = start_shell_task(
                self.server,
                record,
                scope,
                command=claim.schedule.command,
                cwd_value=claim.schedule.cwd,
                timeout_seconds=claim.schedule.timeout_seconds,
                interactive=False,
            )
        except ApiError as exc:
            status = (
                "skipped_capacity"
                if exc.code in {
                    "shell_task_token_limit_reached",
                    "shell_task_global_limit_reached",
                    "sandbox_process_limit_reached",
                }
                else "failed"
            )
            store.finish_run(claim.run.run_id, status=status, error=exc.message)
            self._finish_context(
                scope,
                context_id,
                False,
                exc.message,
                {"schedule_id": claim.schedule.schedule_id, "error": exc.code},
            )
            return
        except Exception as exc:
            store.finish_run(
                claim.run.run_id,
                status="failed",
                error=f"{type(exc).__name__}: {exc}",
            )
            self._finish_context(
                scope,
                context_id,
                False,
                "scheduled task could not be started",
                {"schedule_id": claim.schedule.schedule_id},
            )
            LOGGER.exception("could not start schedule %s", claim.schedule.schedule_id)
            return
        try:
            store.bind_task(claim.run.run_id, task.id)
        except Exception as exc:
            self.server.tasks.kill(task.id, record.token)
            try:
                store.finish_run(
                    claim.run.run_id,
                    status="failed",
                    error=f"schedule run could not be bound to task: {exc}",
                )
            except Exception:
                LOGGER.exception("could not recover unbound schedule run %s", claim.run.run_id)
            self._finish_context(
                scope,
                context_id,
                False,
                "scheduled task bookkeeping failed",
                {"schedule_id": claim.schedule.schedule_id, "task_id": task.id},
            )
            return
        watcher = threading.Thread(
            target=self._watch_task,
            args=(scope, store, claim, task, context_id),
            name=f"schedule-{claim.run.run_id}",
            daemon=True,
        )
        watcher.start()

    def _watch_task(
        self,
        scope: Path,
        store: ScheduleStore,
        claim: ScheduleClaim,
        task: Any,
        context_id: int | None,
    ) -> None:
        task._finished_event.wait()
        succeeded = task.exit_code == 0 and task.error is None
        status = "succeeded" if succeeded else "failed"
        error = task.error
        if error is None and not succeeded:
            error = f"command exited with status {task.exit_code}"
        try:
            store.finish_run(
                claim.run.run_id,
                status=status,
                exit_code=task.exit_code,
                error=error,
            )
            self._finish_context(
                scope,
                context_id,
                succeeded,
                "scheduled command completed" if succeeded else (error or "scheduled command failed"),
                {
                    "schedule_id": claim.schedule.schedule_id,
                    "run_id": claim.run.run_id,
                    "task_id": task.id,
                    "exit_code": task.exit_code,
                },
            )
        except Exception:
            LOGGER.exception("could not finalize schedule run %s", claim.run.run_id)
        finally:
            self.changed()

    def _finish_context(
        self,
        scope: Path,
        context_id: int | None,
        succeeded: bool,
        summary: str,
        result: dict[str, Any],
    ) -> None:
        if context_id is None:
            return
        try:
            self.server.context_for(scope).finish_operation(
                context_id,
                succeeded=succeeded,
                result_summary=summary,
                result=result,
            )
        except Exception:
            LOGGER.exception("could not finalize schedule Context entry %s", context_id)

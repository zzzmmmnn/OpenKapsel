from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openkapsel.scheduler_store import (
    MAX_ACTIVE_SCHEDULES_PER_APP,
    MAX_SCHEDULE_RUNS_PER_SCHEDULE,
    CronExpression,
    ScheduleError,
    ScheduleStore,
    validate_timing,
)


class SchedulerStoreTests(unittest.TestCase):
    def test_six_field_cron_requires_one_second_and_three_minute_spacing(self) -> None:
        parsed = CronExpression.parse("30 */3 * * * *")
        self.assertEqual(30, parsed.second)
        for invalid in (
            "*/3 * * * *",
            "* */3 * * * *",
            "0 * * * * *",
            "0 0,1 * * * *",
            "0 59,0 * * * *",
            "0 */2 * * * *",
            "0 0 0 * JAN *",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ScheduleError):
                CronExpression.parse(invalid)

    def test_cron_next_time_obeys_timezone_and_dst(self) -> None:
        now = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        timing = validate_timing(
            {
                "type": "cron",
                "expression": "15 30 9 * * *",
                "timezone": "Asia/Shanghai",
            },
            now=now,
        )
        self.assertEqual("2026-01-01T01:30:15+00:00", timing.next_run_at)

    def test_interval_and_once_enforce_three_minutes(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ScheduleError, "at least 3"):
            validate_timing({"type": "interval", "minutes": 2}, now=now)
        with self.assertRaisesRegex(ScheduleError, "at least 3"):
            validate_timing(
                {"type": "once", "run_at": (now + timedelta(seconds=179)).isoformat()},
                now=now,
            )
        interval = validate_timing({"type": "interval", "minutes": 3}, now=now)
        self.assertEqual("2026-01-01T00:03:00+00:00", interval.next_run_at)

    def test_store_is_private_per_app_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            store = ScheduleStore(workspace)
            timing = validate_timing(
                {"type": "interval", "minutes": 3},
                now=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            created = store.create(
                "0123456789abcdef",
                name="build",
                timing=timing,
                command="make",
                cwd=".",
                timeout_seconds=60,
                overlap_policy="skip",
                misfire_policy="skip",
                plan_id=1,
                taskname="scheduled-build",
                message="Run scheduled build",
            )
            self.assertEqual(created, store.get("0123456789abcdef", created.schedule_id))
            with self.assertRaises(KeyError):
                store.get("fedcba9876543210", created.schedule_id)
            self.assertEqual(0o600, store.path.stat().st_mode & 0o777)
            for index in range(1, MAX_ACTIVE_SCHEDULES_PER_APP):
                store.create(
                    "0123456789abcdef",
                    name=f"job-{index}",
                    timing=timing,
                    command="true",
                    cwd=".",
                    timeout_seconds=None,
                    overlap_policy="skip",
                    misfire_policy="coalesce",
                    plan_id=1,
                    taskname="scheduled-build",
                    message="Run scheduled build",
                )
            with self.assertRaisesRegex(ScheduleError, "more than 32"):
                store.create(
                    "0123456789abcdef",
                    name="too-many",
                    timing=timing,
                    command="true",
                    cwd=".",
                    timeout_seconds=None,
                    overlap_policy="skip",
                    misfire_policy="skip",
                    plan_id=1,
                    taskname="scheduled-build",
                    message="Run scheduled build",
                )

    def test_once_is_completed_when_claimed_and_cannot_be_claimed_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            store = ScheduleStore(workspace)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            timing = validate_timing(
                {"type": "once", "run_at": (now + timedelta(minutes=3)).isoformat()},
                now=now,
            )
            created = store.create(
                "0123456789abcdef",
                name="once",
                timing=timing,
                command="true",
                cwd=".",
                timeout_seconds=None,
                overlap_policy="skip",
                misfire_policy="coalesce",
                plan_id=1,
                taskname="once-test",
                message="Run once",
            )
            claim = store.claim_due(created.schedule_id, now=now + timedelta(minutes=3))
            self.assertIsNotNone(claim)
            assert claim is not None
            self.assertTrue(claim.execute)
            self.assertEqual("completed", claim.schedule.status)
            self.assertIsNone(claim.schedule.next_run_at)
            self.assertIsNone(
                store.claim_due(created.schedule_id, now=now + timedelta(minutes=6))
            )
            store.finish_run(claim.run.run_id, status="failed", error="launch failed")
            with self.assertRaisesRegex(ScheduleError, "cannot run again"):
                store.claim_due(
                    created.schedule_id,
                    now=now + timedelta(minutes=6),
                    force=True,
                    app_id=created.app_id,
                )

    def test_pause_resume_and_revision_checked_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ScheduleStore(Path(directory))
            timing = validate_timing({"type": "interval", "minutes": 3})
            created = store.create(
                "0123456789abcdef",
                name="build",
                timing=timing,
                command="make",
                cwd=".",
                timeout_seconds=60,
                overlap_policy="skip",
                misfire_policy="skip",
                plan_id=1,
                taskname="build",
                message="Build project",
            )
            paused = store.pause(created.app_id, created.schedule_id)
            self.assertEqual("paused", paused.status)
            self.assertIsNone(paused.next_run_at)
            resumed = store.resume(created.app_id, created.schedule_id)
            self.assertEqual("active", resumed.status)
            self.assertIsNotNone(resumed.next_run_at)
            updated = store.update(
                created.app_id,
                created.schedule_id,
                expected_revision=resumed.revision,
                name="renamed",
            )
            self.assertEqual("renamed", updated.name)
            with self.assertRaisesRegex(ScheduleError, "revision"):
                store.update(
                    created.app_id,
                    created.schedule_id,
                    expected_revision=resumed.revision,
                    name="stale",
                )

    def test_terminal_run_history_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ScheduleStore(Path(directory))
            created = store.create(
                "0123456789abcdef",
                name="bounded",
                timing=validate_timing({"type": "interval", "minutes": 3}),
                command="true",
                cwd=".",
                timeout_seconds=None,
                overlap_policy="skip",
                misfire_policy="skip",
                plan_id=1,
                taskname="history",
                message="Bound run history",
            )
            for _index in range(MAX_SCHEDULE_RUNS_PER_SCHEDULE + 3):
                claim = store.claim_due(
                    created.schedule_id,
                    force=True,
                    app_id=created.app_id,
                )
                assert claim is not None
                store.finish_run(claim.run.run_id, status="succeeded", exit_code=0)
            self.assertEqual(
                MAX_SCHEDULE_RUNS_PER_SCHEDULE,
                len(
                    store.list_runs(
                        created.app_id,
                        created.schedule_id,
                        limit=MAX_SCHEDULE_RUNS_PER_SCHEDULE + 10,
                    )
                ),
            )


if __name__ == "__main__":
    unittest.main()

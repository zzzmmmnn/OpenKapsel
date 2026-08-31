"""Persistent per-workspace schedules and strict time-expression validation."""

from __future__ import annotations

import calendar
import re
import secrets
import sqlite3
import threading
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .workspace_layout import SCHEDULER_DIRECTORY, ensure_workspace_directory


MIN_SCHEDULE_INTERVAL_MINUTES = 3
MIN_SCHEDULE_INTERVAL_SECONDS = MIN_SCHEDULE_INTERVAL_MINUTES * 60
MAX_ACTIVE_SCHEDULES_PER_APP = 32
MAX_SCHEDULE_NAME_CHARS = 128
MAX_SCHEDULE_COMMAND_CHARS = 100_000
MAX_SCHEDULE_CWD_CHARS = 4096
MAX_SCHEDULE_TASKNAME_CHARS = 32
MAX_SCHEDULE_MESSAGE_CHARS = 200
MAX_SCHEDULE_RUNS_PER_SCHEDULE = 50
SCHEDULE_RUN_RETENTION_DAYS = 30
MAX_SCHEDULE_LOOKAHEAD_DAYS = 366 * 8
SCHEDULE_TYPES = {"cron", "interval", "once"}
SCHEDULE_STATUSES = {"active", "paused", "completed"}
OVERLAP_POLICIES = {"skip"}
MISFIRE_POLICIES = {"skip", "coalesce"}
RUN_STATUSES = {
    "claimed",
    "running",
    "succeeded",
    "failed",
    "skipped_overlap",
    "skipped_capacity",
    "skipped_permission",
    "missed",
    "abandoned",
}
_BASIC_CRON_FIELD = re.compile(r"[0-9*/,-]+\Z")


class ScheduleError(ValueError):
    """A schedule request or stored schedule is invalid."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ScheduleError("scheduled datetimes must include a timezone")
    return value.astimezone(timezone.utc).isoformat()


def parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ScheduleError(f"{field} must be a non-empty ISO 8601 datetime")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ScheduleError(f"{field} must be a valid ISO 8601 datetime") from None
    if parsed.tzinfo is None:
        raise ScheduleError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_timezone(value: Any) -> ZoneInfo:
    if not isinstance(value, str) or not value.strip():
        raise ScheduleError("timezone must be a non-empty IANA timezone name")
    try:
        return ZoneInfo(value.strip())
    except ZoneInfoNotFoundError:
        raise ScheduleError("timezone must be a valid IANA timezone name") from None


def _expand_cron_field(
    value: str,
    minimum: int,
    maximum: int,
    name: str,
    *,
    normalize_sunday: bool = False,
) -> tuple[frozenset[int], bool]:
    if not value or not _BASIC_CRON_FIELD.fullmatch(value):
        raise ScheduleError(
            f"cron {name} supports only numbers, *, ranges, lists, and steps"
        )
    result: set[int] = set()
    for item in value.split(","):
        if not item:
            raise ScheduleError(f"cron {name} contains an empty list item")
        base, separator, step_text = item.partition("/")
        if separator:
            if not step_text.isdigit() or int(step_text) < 1:
                raise ScheduleError(f"cron {name} step must be a positive integer")
            step = int(step_text)
        else:
            step = 1
        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            start_text, range_separator, end_text = base.partition("-")
            if not range_separator or not start_text.isdigit() or not end_text.isdigit():
                raise ScheduleError(f"cron {name} range is invalid")
            start, end = int(start_text), int(end_text)
        elif base.isdigit():
            start = end = int(base)
            if separator:
                end = maximum
        else:
            raise ScheduleError(f"cron {name} item is invalid")
        if start < minimum or end > maximum or start > end:
            raise ScheduleError(
                f"cron {name} values must be between {minimum} and {maximum}"
            )
        result.update(range(start, end + 1, step))
    if normalize_sunday and 7 in result:
        result.discard(7)
        result.add(0)
    full = set(range(minimum, maximum + 1))
    if normalize_sunday:
        full = set(range(0, 7))
    return frozenset(result), result == full


@dataclass(frozen=True)
class CronExpression:
    expression: str
    second: int
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    days_unrestricted: bool
    weekdays_unrestricted: bool
    daily_seconds: tuple[int, ...]

    @classmethod
    def parse(cls, expression: Any) -> "CronExpression":
        if not isinstance(expression, str):
            raise ScheduleError("cron expression must be a string")
        fields = expression.split()
        if len(fields) != 6:
            raise ScheduleError(
                "cron expression must contain exactly six fields: second minute hour day month weekday"
            )
        second_text, minute_text, hour_text, day_text, month_text, weekday_text = fields
        if not second_text.isdigit() or not 0 <= int(second_text) <= 59:
            raise ScheduleError("cron second must be one explicit integer between 0 and 59")
        second = int(second_text)
        minutes, _ = _expand_cron_field(minute_text, 0, 59, "minute")
        hours, _ = _expand_cron_field(hour_text, 0, 23, "hour")
        days, days_unrestricted = _expand_cron_field(day_text, 1, 31, "day")
        months, _ = _expand_cron_field(month_text, 1, 12, "month")
        weekdays, weekdays_unrestricted = _expand_cron_field(
            weekday_text,
            0,
            7,
            "weekday",
            normalize_sunday=True,
        )
        daily_seconds = tuple(
            hour * 3600 + minute * 60 + second
            for hour in sorted(hours)
            for minute in sorted(minutes)
        )
        circular = (*daily_seconds, daily_seconds[0] + 24 * 60 * 60)
        minimum_gap = min(
            right - left for left, right in zip(circular, circular[1:])
        )
        if minimum_gap < MIN_SCHEDULE_INTERVAL_SECONDS:
            raise ScheduleError(
                f"cron occurrences must be at least {MIN_SCHEDULE_INTERVAL_MINUTES} minutes apart"
            )
        return cls(
            expression=" ".join(fields),
            second=second,
            minutes=minutes,
            hours=hours,
            days=days,
            months=months,
            weekdays=weekdays,
            days_unrestricted=days_unrestricted,
            weekdays_unrestricted=weekdays_unrestricted,
            daily_seconds=daily_seconds,
        )

    def _date_matches(self, candidate: date) -> bool:
        if candidate.month not in self.months:
            return False
        day_matches = candidate.day in self.days
        cron_weekday = (candidate.weekday() + 1) % 7
        weekday_matches = cron_weekday in self.weekdays
        if self.days_unrestricted and self.weekdays_unrestricted:
            return True
        if self.days_unrestricted:
            return weekday_matches
        if self.weekdays_unrestricted:
            return day_matches
        return day_matches or weekday_matches

    @staticmethod
    def _valid_utc_candidates(local_naive: datetime, zone: ZoneInfo) -> Iterable[datetime]:
        seen: set[datetime] = set()
        for fold in (0, 1):
            aware = local_naive.replace(tzinfo=zone, fold=fold)
            utc_value = aware.astimezone(timezone.utc)
            if utc_value in seen:
                continue
            round_trip = utc_value.astimezone(zone).replace(tzinfo=None)
            if round_trip == local_naive:
                seen.add(utc_value)
                yield utc_value

    def next_after(self, after: datetime, zone: ZoneInfo) -> datetime:
        after_utc = after.astimezone(timezone.utc)
        local_start = after_utc.astimezone(zone)
        for offset in range(MAX_SCHEDULE_LOOKAHEAD_DAYS + 1):
            candidate_date = local_start.date() + timedelta(days=offset)
            if not self._date_matches(candidate_date):
                continue
            best: datetime | None = None
            for seconds in self.daily_seconds:
                hour, remainder = divmod(seconds, 3600)
                minute, second = divmod(remainder, 60)
                local_naive = datetime.combine(
                    candidate_date,
                    datetime_time(hour, minute, second),
                )
                for candidate in self._valid_utc_candidates(local_naive, zone):
                    if candidate > after_utc and (best is None or candidate < best):
                        best = candidate
            if best is not None:
                return best
        raise ScheduleError("cron expression has no occurrence within eight years")


@dataclass(frozen=True)
class ScheduleTiming:
    type: str
    expression: str | None
    interval_minutes: int | None
    run_at: str | None
    timezone: str
    next_run_at: str


def validate_timing(value: Any, *, now: datetime | None = None) -> ScheduleTiming:
    if not isinstance(value, dict):
        raise ScheduleError("schedule must be a JSON object")
    now = (now or utc_now()).astimezone(timezone.utc)
    kind = value.get("type")
    if kind not in SCHEDULE_TYPES:
        raise ScheduleError("schedule type must be cron, interval, or once")
    timezone_name = value.get("timezone", "UTC")
    zone = parse_timezone(timezone_name)
    timezone_name = timezone_name.strip()
    if kind == "cron":
        cron = CronExpression.parse(value.get("expression"))
        next_run = cron.next_after(now, zone)
        return ScheduleTiming(kind, cron.expression, None, None, timezone_name, iso_utc(next_run))
    if kind == "interval":
        minutes = value.get("minutes")
        if isinstance(minutes, bool) or not isinstance(minutes, int):
            raise ScheduleError("interval minutes must be an integer")
        if minutes < MIN_SCHEDULE_INTERVAL_MINUTES:
            raise ScheduleError(
                f"interval minutes must be at least {MIN_SCHEDULE_INTERVAL_MINUTES}"
            )
        next_run = now + timedelta(minutes=minutes)
        return ScheduleTiming(kind, None, minutes, None, timezone_name, iso_utc(next_run))
    run_at = parse_datetime(value.get("run_at"), "once run_at")
    if run_at < now + timedelta(seconds=MIN_SCHEDULE_INTERVAL_SECONDS):
        raise ScheduleError(
            f"once run_at must be at least {MIN_SCHEDULE_INTERVAL_MINUTES} minutes in the future"
        )
    return ScheduleTiming(kind, None, None, iso_utc(run_at), timezone_name, iso_utc(run_at))


@dataclass(frozen=True)
class ScheduleRecord:
    schedule_id: str
    app_id: str
    name: str
    type: str
    expression: str | None
    interval_minutes: int | None
    run_at: str | None
    timezone: str
    command: str
    cwd: str
    timeout_seconds: float | None
    overlap_policy: str
    misfire_policy: str
    plan_id: int
    taskname: str
    message: str
    status: str
    next_run_at: str | None
    running_task_id: str | None
    created_at: str
    updated_at: str
    revision: int

    def public(self) -> dict[str, Any]:
        result = asdict(self)
        result["schedule"] = {
            "type": self.type,
            "timezone": self.timezone,
        }
        if self.type == "cron":
            result["schedule"]["expression"] = self.expression
        elif self.type == "interval":
            result["schedule"]["minutes"] = self.interval_minutes
        else:
            result["schedule"]["run_at"] = self.run_at
        for key in ("type", "expression", "interval_minutes", "run_at", "timezone", "app_id"):
            result.pop(key, None)
        return result


@dataclass(frozen=True)
class ScheduleRunRecord:
    run_id: str
    schedule_id: str
    app_id: str
    scheduled_at: str
    started_at: str | None
    finished_at: str | None
    status: str
    task_id: str | None
    exit_code: int | None
    error: str | None

    def public(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("app_id", None)
        return result


@dataclass(frozen=True)
class ScheduleClaim:
    schedule: ScheduleRecord
    run: ScheduleRunRecord
    execute: bool


class ScheduleStore:
    """SQLite schedule state scoped by stable app IDs inside one workspace."""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace).resolve(strict=True)
        directory = ensure_workspace_directory(self.workspace, SCHEDULER_DIRECTORY)
        self.path = directory / "scheduler.sqlite3"
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._lock, closing(self._connect()) as connection:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS schedules (
                        schedule_id TEXT PRIMARY KEY,
                        app_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL,
                        expression TEXT,
                        interval_minutes INTEGER,
                        run_at TEXT,
                        timezone TEXT NOT NULL,
                        command TEXT NOT NULL,
                        cwd TEXT NOT NULL,
                        timeout_seconds REAL,
                        overlap_policy TEXT NOT NULL,
                        misfire_policy TEXT NOT NULL,
                        plan_id INTEGER NOT NULL,
                        taskname TEXT NOT NULL,
                        message TEXT NOT NULL,
                        status TEXT NOT NULL,
                        next_run_at TEXT,
                        running_task_id TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        revision INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS schedules_app_status
                        ON schedules(app_id, status, next_run_at);
                    CREATE TABLE IF NOT EXISTS schedule_runs (
                        run_id TEXT PRIMARY KEY,
                        schedule_id TEXT NOT NULL,
                        app_id TEXT NOT NULL,
                        scheduled_at TEXT NOT NULL,
                        started_at TEXT,
                        finished_at TEXT,
                        status TEXT NOT NULL,
                        task_id TEXT,
                        exit_code INTEGER,
                        error TEXT,
                        FOREIGN KEY(schedule_id) REFERENCES schedules(schedule_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS schedule_runs_schedule
                        ON schedule_runs(schedule_id, scheduled_at DESC);
                    """
                )
        self.path.chmod(0o600)

    @staticmethod
    def _serialize(row: sqlite3.Row) -> ScheduleRecord:
        return ScheduleRecord(**{key: row[key] for key in ScheduleRecord.__dataclass_fields__})

    @staticmethod
    def _serialize_run(row: sqlite3.Row) -> ScheduleRunRecord:
        return ScheduleRunRecord(
            **{key: row[key] for key in ScheduleRunRecord.__dataclass_fields__}
        )

    @staticmethod
    def _timing_for(record: ScheduleRecord, now: datetime) -> ScheduleTiming:
        payload: dict[str, Any] = {
            "type": record.type,
            "timezone": record.timezone,
        }
        if record.type == "cron":
            payload["expression"] = record.expression
        elif record.type == "interval":
            payload["minutes"] = record.interval_minutes
        else:
            payload["run_at"] = record.run_at
        return validate_timing(payload, now=now)

    @staticmethod
    def _next_after_claim(record: ScheduleRecord, now: datetime) -> str | None:
        if record.type == "once":
            return None
        if record.type == "interval":
            assert record.interval_minutes is not None
            return iso_utc(now + timedelta(minutes=record.interval_minutes))
        assert record.expression is not None
        cron = CronExpression.parse(record.expression)
        return iso_utc(cron.next_after(now, parse_timezone(record.timezone)))

    @staticmethod
    def _validate_text(value: Any, field: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise ScheduleError(f"{field} must be a string")
        normalized = value.strip()
        if not normalized or len(normalized) > maximum:
            raise ScheduleError(f"{field} must contain 1 to {maximum} characters")
        return normalized

    def create(
        self,
        app_id: str,
        *,
        name: str,
        timing: ScheduleTiming,
        command: str,
        cwd: str,
        timeout_seconds: float | None,
        overlap_policy: str,
        misfire_policy: str,
        plan_id: int,
        taskname: str,
        message: str,
    ) -> ScheduleRecord:
        name = self._validate_text(name, "name", MAX_SCHEDULE_NAME_CHARS)
        command = self._validate_text(command, "command", MAX_SCHEDULE_COMMAND_CHARS)
        if not isinstance(cwd, str) or len(cwd) > MAX_SCHEDULE_CWD_CHARS:
            raise ScheduleError(f"cwd cannot exceed {MAX_SCHEDULE_CWD_CHARS} characters")
        if timeout_seconds is not None and not 0.1 <= timeout_seconds <= 86_400:
            raise ScheduleError("timeout_seconds must be null or between 0.1 and 86400")
        if overlap_policy not in OVERLAP_POLICIES:
            raise ScheduleError("overlap_policy must be skip")
        if misfire_policy not in MISFIRE_POLICIES:
            raise ScheduleError("misfire_policy must be skip or coalesce")
        if isinstance(plan_id, bool) or not isinstance(plan_id, int) or plan_id < 1:
            raise ScheduleError("plan_id must be a positive integer")
        taskname = self._validate_text(
            taskname, "taskname", MAX_SCHEDULE_TASKNAME_CHARS
        )
        message = self._validate_text(
            message, "message", MAX_SCHEDULE_MESSAGE_CHARS
        )
        now = iso_utc(utc_now())
        schedule_id = f"schedule_{secrets.token_urlsafe(12)}"
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            active_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM schedules WHERE app_id = ? AND status IN ('active', 'paused')",
                    (app_id,),
                ).fetchone()[0]
            )
            if active_count >= MAX_ACTIVE_SCHEDULES_PER_APP:
                connection.rollback()
                raise ScheduleError(
                    f"an app identity cannot have more than {MAX_ACTIVE_SCHEDULES_PER_APP} active or paused schedules"
                )
            connection.execute(
                """
                INSERT INTO schedules (
                    schedule_id, app_id, name, type, expression, interval_minutes,
                    run_at, timezone, command, cwd, timeout_seconds, overlap_policy,
                    misfire_policy, plan_id, taskname, message, status, next_run_at,
                    running_task_id, created_at, updated_at, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL, ?, ?, 1)
                """,
                (
                    schedule_id,
                    app_id,
                    name,
                    timing.type,
                    timing.expression,
                    timing.interval_minutes,
                    timing.run_at,
                    timing.timezone,
                    command,
                    cwd,
                    timeout_seconds,
                    overlap_policy,
                    misfire_policy,
                    plan_id,
                    taskname,
                    message,
                    timing.next_run_at,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
            connection.commit()
        assert row is not None
        return self._serialize(row)

    def get(self, app_id: str, schedule_id: str) -> ScheduleRecord:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM schedules WHERE app_id = ? AND schedule_id = ?",
                (app_id, schedule_id),
            ).fetchone()
        if row is None:
            raise KeyError("schedule does not exist")
        return self._serialize(row)

    def list(self, app_id: str) -> list[ScheduleRecord]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM schedules WHERE app_id = ? ORDER BY created_at DESC",
                (app_id,),
            ).fetchall()
        return [self._serialize(row) for row in rows]

    def update(
        self,
        app_id: str,
        schedule_id: str,
        *,
        expected_revision: int,
        name: str | None = None,
        timing: ScheduleTiming | None = None,
        command: str | None = None,
        cwd: str | None = None,
        timeout_seconds: float | None | object = ...,
        overlap_policy: str | None = None,
        misfire_policy: str | None = None,
        plan_id: int | None = None,
        taskname: str | None = None,
        message: str | None = None,
    ) -> ScheduleRecord:
        if isinstance(expected_revision, bool) or expected_revision < 1:
            raise ScheduleError("expected_revision must be a positive integer")
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM schedules WHERE app_id = ? AND schedule_id = ?",
                (app_id, schedule_id),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("schedule does not exist")
            current = self._serialize(row)
            if current.status == "completed":
                connection.rollback()
                raise ScheduleError(
                    "a completed once schedule cannot be updated; create a new schedule"
                )
            if current.revision != expected_revision:
                connection.rollback()
                raise ScheduleError("schedule revision does not match expected_revision")
            if current.running_task_id is not None:
                connection.rollback()
                raise ScheduleError("a running schedule cannot be updated")
            values: dict[str, Any] = {
                "name": current.name,
                "type": current.type,
                "expression": current.expression,
                "interval_minutes": current.interval_minutes,
                "run_at": current.run_at,
                "timezone": current.timezone,
                "command": current.command,
                "cwd": current.cwd,
                "timeout_seconds": current.timeout_seconds,
                "overlap_policy": current.overlap_policy,
                "misfire_policy": current.misfire_policy,
                "plan_id": current.plan_id,
                "taskname": current.taskname,
                "message": current.message,
                "next_run_at": current.next_run_at,
                "status": current.status,
            }
            if name is not None:
                values["name"] = self._validate_text(name, "name", MAX_SCHEDULE_NAME_CHARS)
            if command is not None:
                values["command"] = self._validate_text(
                    command, "command", MAX_SCHEDULE_COMMAND_CHARS
                )
            if cwd is not None:
                if not isinstance(cwd, str) or len(cwd) > MAX_SCHEDULE_CWD_CHARS:
                    raise ScheduleError(f"cwd cannot exceed {MAX_SCHEDULE_CWD_CHARS} characters")
                values["cwd"] = cwd
            if timeout_seconds is not ...:
                if timeout_seconds is not None and (
                    isinstance(timeout_seconds, bool)
                    or not isinstance(timeout_seconds, (int, float))
                    or not 0.1 <= float(timeout_seconds) <= 86_400
                ):
                    raise ScheduleError("timeout_seconds must be null or between 0.1 and 86400")
                values["timeout_seconds"] = (
                    None if timeout_seconds is None else float(timeout_seconds)
                )
            if overlap_policy is not None:
                if overlap_policy not in OVERLAP_POLICIES:
                    raise ScheduleError("overlap_policy must be skip")
                values["overlap_policy"] = overlap_policy
            if misfire_policy is not None:
                if misfire_policy not in MISFIRE_POLICIES:
                    raise ScheduleError("misfire_policy must be skip or coalesce")
                values["misfire_policy"] = misfire_policy
            if plan_id is not None:
                if isinstance(plan_id, bool) or not isinstance(plan_id, int) or plan_id < 1:
                    raise ScheduleError("plan_id must be a positive integer")
                values["plan_id"] = plan_id
            if taskname is not None:
                values["taskname"] = self._validate_text(
                    taskname, "taskname", MAX_SCHEDULE_TASKNAME_CHARS
                )
            if message is not None:
                values["message"] = self._validate_text(
                    message, "message", MAX_SCHEDULE_MESSAGE_CHARS
                )
            if timing is not None:
                values.update(
                    type=timing.type,
                    expression=timing.expression,
                    interval_minutes=timing.interval_minutes,
                    run_at=timing.run_at,
                    timezone=timing.timezone,
                    next_run_at=timing.next_run_at if current.status == "active" else None,
                )
                if current.status == "completed":
                    values["status"] = "active"
                    values["next_run_at"] = timing.next_run_at
            updated_at = iso_utc(utc_now())
            connection.execute(
                """
                UPDATE schedules SET name = ?, type = ?, expression = ?, interval_minutes = ?,
                    run_at = ?, timezone = ?, command = ?, cwd = ?, timeout_seconds = ?,
                    overlap_policy = ?, misfire_policy = ?, plan_id = ?, taskname = ?,
                    message = ?, status = ?, next_run_at = ?, updated_at = ?, revision = revision + 1
                WHERE app_id = ? AND schedule_id = ?
                """,
                (
                    values["name"], values["type"], values["expression"],
                    values["interval_minutes"], values["run_at"], values["timezone"],
                    values["command"], values["cwd"], values["timeout_seconds"],
                    values["overlap_policy"], values["misfire_policy"], values["plan_id"],
                    values["taskname"], values["message"], values["status"],
                    values["next_run_at"], updated_at, app_id, schedule_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
            ).fetchone()
            connection.commit()
        assert updated is not None
        return self._serialize(updated)

    def pause(self, app_id: str, schedule_id: str) -> ScheduleRecord:
        return self._set_status(app_id, schedule_id, "paused")

    def resume(self, app_id: str, schedule_id: str) -> ScheduleRecord:
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM schedules WHERE app_id = ? AND schedule_id = ?",
                (app_id, schedule_id),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("schedule does not exist")
            record = self._serialize(row)
            if record.status != "paused":
                connection.rollback()
                raise ScheduleError("only a paused schedule can be resumed")
            timing = self._timing_for(record, utc_now())
            now = iso_utc(utc_now())
            connection.execute(
                """UPDATE schedules SET status = 'active', next_run_at = ?, updated_at = ?,
                       revision = revision + 1 WHERE schedule_id = ?""",
                (timing.next_run_at, now, schedule_id),
            )
            updated = connection.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
            ).fetchone()
            connection.commit()
        assert updated is not None
        return self._serialize(updated)

    def _set_status(self, app_id: str, schedule_id: str, status: str) -> ScheduleRecord:
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM schedules WHERE app_id = ? AND schedule_id = ?",
                (app_id, schedule_id),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("schedule does not exist")
            current = self._serialize(row)
            if status == "paused" and current.status != "active":
                connection.rollback()
                raise ScheduleError("only an active schedule can be paused")
            now = iso_utc(utc_now())
            connection.execute(
                """UPDATE schedules SET status = ?, next_run_at = NULL, updated_at = ?,
                       revision = revision + 1 WHERE schedule_id = ?""",
                (status, now, schedule_id),
            )
            updated = connection.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
            ).fetchone()
            connection.commit()
        assert updated is not None
        return self._serialize(updated)

    def pause_app(self, app_id: str) -> int:
        with self._lock, closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """UPDATE schedules SET status = 'paused', next_run_at = NULL,
                           updated_at = ?, revision = revision + 1
                       WHERE app_id = ? AND status = 'active'""",
                    (iso_utc(utc_now()), app_id),
                )
                return cursor.rowcount

    def next_due(self) -> tuple[str, str] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT schedule_id, next_run_at FROM schedules
                   WHERE status = 'active' AND next_run_at IS NOT NULL
                   ORDER BY next_run_at ASC LIMIT 1"""
            ).fetchone()
        return None if row is None else (str(row["next_run_at"]), str(row["schedule_id"]))

    def claim_due(
        self,
        schedule_id: str,
        *,
        now: datetime | None = None,
        misfire_grace_seconds: int = 300,
        force: bool = False,
        app_id: str | None = None,
    ) -> ScheduleClaim | None:
        now_value = (now or utc_now()).astimezone(timezone.utc)
        now_text = iso_utc(now_value)
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            query = "SELECT * FROM schedules WHERE schedule_id = ?"
            parameters: tuple[Any, ...] = (schedule_id,)
            if app_id is not None:
                query += " AND app_id = ?"
                parameters += (app_id,)
            row = connection.execute(query, parameters).fetchone()
            if row is None:
                connection.rollback()
                if app_id is not None:
                    raise KeyError("schedule does not exist")
                return None
            record = self._serialize(row)
            if force:
                if record.status == "completed":
                    connection.rollback()
                    raise ScheduleError(
                        "a completed once schedule cannot run again; create a new schedule"
                    )
                if record.running_task_id is not None:
                    connection.rollback()
                    raise ScheduleError("the schedule already has a running task")
                scheduled_at = now_text
            else:
                if record.status != "active" or record.next_run_at is None:
                    connection.rollback()
                    return None
                due = parse_datetime(record.next_run_at, "next_run_at")
                if due > now_value:
                    connection.rollback()
                    return None
                scheduled_at = record.next_run_at
            run_id = f"run_{secrets.token_urlsafe(12)}"
            execute = True
            run_status = "claimed"
            error = None
            if record.running_task_id is not None:
                execute = False
                run_status = "skipped_overlap"
                error = "the previous scheduled task is still running"
            elif not force:
                due = parse_datetime(scheduled_at, "scheduled_at")
                if (
                    record.misfire_policy == "skip"
                    and (now_value - due).total_seconds() > misfire_grace_seconds
                ):
                    execute = False
                    run_status = "missed"
                    error = "the scheduled occurrence exceeded the misfire grace period"
            next_run = record.next_run_at
            status = record.status
            running_marker = record.running_task_id
            if not force:
                next_run = self._next_after_claim(record, now_value)
                if record.type == "once":
                    status = "completed"
            if execute:
                running_marker = f"claim:{run_id}"
            finished_at = None if execute else now_text
            connection.execute(
                """INSERT INTO schedule_runs (
                       run_id, schedule_id, app_id, scheduled_at, started_at, finished_at,
                       status, task_id, exit_code, error
                   ) VALUES (?, ?, ?, ?, NULL, ?, ?, NULL, NULL, ?)""",
                (
                    run_id, record.schedule_id, record.app_id, scheduled_at,
                    finished_at, run_status, error,
                ),
            )
            self._prune_runs(connection, record.schedule_id, now_value)
            connection.execute(
                """UPDATE schedules SET status = ?, next_run_at = ?, running_task_id = ?,
                       updated_at = ?, revision = revision + 1 WHERE schedule_id = ?""",
                (status, next_run, running_marker, now_text, schedule_id),
            )
            schedule_row = connection.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
            ).fetchone()
            run_row = connection.execute(
                "SELECT * FROM schedule_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            connection.commit()
        assert schedule_row is not None and run_row is not None
        return ScheduleClaim(
            schedule=self._serialize(schedule_row),
            run=self._serialize_run(run_row),
            execute=execute,
        )

    @staticmethod
    def _prune_runs(
        connection: sqlite3.Connection,
        schedule_id: str,
        now: datetime,
        keep_run_id: str | None = None,
    ) -> None:
        cutoff = iso_utc(now - timedelta(days=SCHEDULE_RUN_RETENTION_DAYS))
        connection.execute(
            """DELETE FROM schedule_runs
               WHERE schedule_id = ? AND scheduled_at < ?
                 AND (? IS NULL OR run_id != ?)
                 AND status NOT IN ('claimed', 'running')""",
            (schedule_id, cutoff, keep_run_id, keep_run_id),
        )
        connection.execute(
            """DELETE FROM schedule_runs
               WHERE run_id IN (
                   SELECT run_id FROM schedule_runs
                   WHERE schedule_id = ? AND status NOT IN ('claimed', 'running')
                     AND (? IS NULL OR run_id != ?)
                   ORDER BY scheduled_at DESC
                   LIMIT -1 OFFSET ?
               )""",
            (
                schedule_id,
                keep_run_id,
                keep_run_id,
                MAX_SCHEDULE_RUNS_PER_SCHEDULE - (1 if keep_run_id else 0),
            ),
        )

    def bind_task(self, run_id: str, task_id: str) -> ScheduleRunRecord:
        now = iso_utc(utc_now())
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM schedule_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None or row["status"] != "claimed":
                connection.rollback()
                raise ScheduleError("schedule run is not awaiting a task")
            connection.execute(
                """UPDATE schedule_runs SET status = 'running', task_id = ?, started_at = ?
                   WHERE run_id = ?""",
                (task_id, now, run_id),
            )
            connection.execute(
                "UPDATE schedules SET running_task_id = ? WHERE schedule_id = ? AND running_task_id = ?",
                (task_id, row["schedule_id"], f"claim:{run_id}"),
            )
            updated = connection.execute(
                "SELECT * FROM schedule_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            connection.commit()
        assert updated is not None
        return self._serialize_run(updated)

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        exit_code: int | None = None,
        error: str | None = None,
    ) -> ScheduleRunRecord:
        if status not in RUN_STATUSES - {"claimed", "running"}:
            raise ScheduleError("invalid terminal schedule run status")
        now = iso_utc(utc_now())
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM schedule_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError("schedule run does not exist")
            connection.execute(
                """UPDATE schedule_runs SET status = ?, finished_at = ?, exit_code = ?, error = ?
                   WHERE run_id = ?""",
                (status, now, exit_code, error, run_id),
            )
            marker = row["task_id"] or f"claim:{run_id}"
            connection.execute(
                """UPDATE schedules SET running_task_id = NULL, updated_at = ?
                   WHERE schedule_id = ? AND running_task_id = ?""",
                (now, row["schedule_id"], marker),
            )
            self._prune_runs(
                connection,
                str(row["schedule_id"]),
                utc_now(),
                keep_run_id=run_id,
            )
            updated = connection.execute(
                "SELECT * FROM schedule_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            connection.commit()
        assert updated is not None
        return self._serialize_run(updated)

    def list_runs(
        self, app_id: str, schedule_id: str, *, limit: int = 50
    ) -> list[ScheduleRunRecord]:
        if not 1 <= limit <= 200:
            raise ScheduleError("run history limit must be between 1 and 200")
        self.get(app_id, schedule_id)
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT * FROM schedule_runs WHERE app_id = ? AND schedule_id = ?
                   ORDER BY scheduled_at DESC LIMIT ?""",
                (app_id, schedule_id, limit),
            ).fetchall()
        return [self._serialize_run(row) for row in rows]

    def get_run(self, app_id: str, run_id: str) -> ScheduleRunRecord:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM schedule_runs WHERE app_id = ? AND run_id = ?",
                (app_id, run_id),
            ).fetchone()
        if row is None:
            raise KeyError("schedule run does not exist")
        return self._serialize_run(row)

    def abandon_running(self) -> int:
        now = iso_utc(utc_now())
        with self._lock, closing(self._connect()) as connection:
            with connection:
                runs = connection.execute(
                    "SELECT run_id FROM schedule_runs WHERE status IN ('claimed', 'running')"
                ).fetchall()
                connection.execute(
                    """UPDATE schedule_runs SET status = 'abandoned', finished_at = ?,
                           error = 'server restarted before the task completed'
                       WHERE status IN ('claimed', 'running')""",
                    (now,),
                )
                connection.execute(
                    "UPDATE schedules SET running_task_id = NULL WHERE running_task_id IS NOT NULL"
                )
                return len(runs)

    def delete(self, app_id: str, schedule_id: str) -> None:
        with self._lock, closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """DELETE FROM schedules WHERE app_id = ? AND schedule_id = ?
                       AND running_task_id IS NULL""",
                    (app_id, schedule_id),
                )
                if cursor.rowcount != 1:
                    existing = connection.execute(
                        "SELECT running_task_id FROM schedules WHERE app_id = ? AND schedule_id = ?",
                        (app_id, schedule_id),
                    ).fetchone()
                    if existing is None:
                        raise KeyError("schedule does not exist")
                    raise ScheduleError("a running schedule cannot be deleted")

    def delete_app(self, app_id: str) -> int:
        with self._lock, closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute("DELETE FROM schedules WHERE app_id = ?", (app_id,))
                return cursor.rowcount

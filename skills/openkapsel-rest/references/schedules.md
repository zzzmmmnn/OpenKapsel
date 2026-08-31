# Persistent Shell schedules

Read `GET /discovery/schedules` before use. Schedule endpoints require the Bearer control token, Shell permission, and the separate `schedules` permission. Read/control credential rotation and short credential expiry do not remove schedules; token disablement, workspace expiry, token deletion, Shell revocation, or schedule-permission revocation prevents future dispatch.

Schedules use the same Shell sandbox, environment, network, task concurrency, timeout, output-retention, and resource limits as `POST /shell/exec`. OpenKapsel does not inject read or control credentials into scheduled commands.

## Create

`POST /schedules` accepts:

```json
{
  "name": "nightly tests",
  "schedule": {
    "type": "cron",
    "expression": "0 0 2 * * *",
    "timezone": "UTC"
  },
  "command": "python3 -m unittest",
  "cwd": ".",
  "timeout_seconds": 3600,
  "overlap_policy": "skip",
  "misfire_policy": "skip",
  "plan_id": 42,
  "taskname": "scheduler",
  "message": "Create nightly test schedule"
}
```

The top-level `plan_id`, `taskname`, and `message` attribute the create operation and, by default, every later run. To use different run attribution, add a complete `run_context` object containing its own `plan_id`, `taskname`, and `message`.

Timing variants are:

- `{"type":"interval","minutes":3,"timezone":"UTC"}` with an integer of at least 3 minutes.
- `{"type":"once","run_at":"<timezone-aware ISO 8601>","timezone":"UTC"}` at least 3 minutes in the future.
- `{"type":"cron","expression":"<second minute hour day month weekday>","timezone":"<IANA name>"}` with exactly six fields. The second is one explicit integer. Numeric lists, ranges, steps, and `*` are supported in the remaining fields; names and Quartz extensions are not. The expression is rejected if any adjacent occurrences can be less than 3 minutes apart.

Use `POST /schedules/<id>/run` for an explicit immediate execution. It still observes task capacity and overlap limits, and it does not move the schedule's next ordinary occurrence.

## Manage and inspect

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/schedules` | List schedules |
| `GET` | `/schedules/<id>` | Read one schedule and its revision |
| `PATCH` | `/schedules/<id>` | Update with `expected_revision`; use `run_context` only to replace future-run attribution |
| `DELETE` | `/schedules/<id>` | Delete when it has no running task |
| `POST` | `/schedules/<id>/pause` | Stop future dispatch without killing a running task |
| `POST` | `/schedules/<id>/resume` | Recompute the next occurrence from now |
| `POST` | `/schedules/<id>/run` | Dispatch explicitly now |
| `GET` | `/schedules/<id>/runs?limit=50` | List dispatch history |
| `GET` | `/schedule-runs/<run_id>` | Read one dispatch and its linked `task_id` |

All modifying requests carry ordinary mutation Context fields. A schedule update is optimistic: fetch its revision first and send `expected_revision`. Pause before changing intent when another actor may edit it.

An interval or cron occurrence does not queue behind resource pressure: overlap, token/global task capacity, or sandbox PID capacity produces a skipped run record and advances to the next occurrence. `misfire_policy: skip` drops an occurrence that exceeds the published grace period; `coalesce` executes at most one catch-up run. The only overlap policy is `skip`.

A `once` schedule is atomically claimed and marked completed before its Shell command starts. Its own command cannot reactivate the same ID. It can create a different schedule only through an explicitly supplied control credential, and the new schedule still obeys the three-minute minimum.

After a scheduled command starts, use the ordinary task endpoints from [shell.md](shell.md) with the returned `task_id` to inspect retained output or interrupt it. Discovery publishes schedule-run metadata retention separately from the shorter ordinary task-output retention.

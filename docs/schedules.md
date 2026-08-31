# Scheduled Shell tasks

[Back to README](../README.md)

Schedules persist background Shell intent inside the workspace's private `.openkapsel` state. They use the same stable application identity as Context and Shell environment configuration, so rotating short-lived read/control credentials does not lose them.

## Permission and execution boundary

A token needs both a non-`none` Shell mode and the separate scheduled-task permission. Schedule HTTP and MCP operations also require the matching Bearer control token. Existing token records default to schedules disabled until an administrator enables them.

Each dispatched command uses the token's current Shell mode, sandbox backend and image, environment configuration, network policy, additional path grants, cgroup limits, timeout, and ordinary global/per-token task limits. Credentials are never injected into the scheduled process.

Disabling or deleting the token, allowing its workspace lifetime to expire, revoking Shell or schedules permission, or deleting the schedule prevents future dispatch. Expiration or rotation of the short-lived read/control credentials does not stop an otherwise valid schedule.

## Timing contracts

Schedules support:

- `interval`: integer minutes, minimum 3.
- `once`: a timezone-aware ISO 8601 timestamp at least three minutes in the future.
- `cron`: exactly six fields in `second minute hour day month weekday` order plus an IANA timezone.

Cron's second field is one explicit integer from 0 through 59. The other fields accept numeric values, lists, ranges, steps, and `*`; names and Quartz extensions are rejected. OpenKapsel validates the complete daily occurrence spacing and rejects expressions that can run less than three minutes apart. Day-of-month and weekday use standard cron OR semantics when both are restricted. DST skipped local times do not run, while repeated local times may produce both real instants when they still satisfy the interval rule.

The only overlap policy is `skip`. Misfire policy may be `skip` or `coalesce`: skip records an occurrence as missed after `schedule_misfire_grace_seconds`; coalesce starts at most one catch-up execution. Capacity failures do not queue and are recorded as skipped.

## API lifecycle

The focused Discovery document at `GET discovery/schedules` is authoritative. REST routes are:

- `GET|POST schedules`
- `GET|PATCH|DELETE schedules/<schedule_id>`
- `POST schedules/<schedule_id>/{run,pause,resume}`
- `GET schedules/<schedule_id>/runs`
- `GET schedule-runs/<run_id>`

Creation and every modifying action requires ordinary `plan_id`, `taskname`, and `message` Context. The creation values also become each run's automatic Context unless a complete `run_context` is supplied. Updates require `expected_revision`; a supplied `run_context` replaces future-run attribution as one unit.

`run` is the explicit immediate-execution path and does not move the next ordinary occurrence. It still observes overlap and task/sandbox capacity. Pause stops future dispatch but does not terminate an already running task. Delete and update are refused while a run is active.

The scheduler atomically claims an occurrence in its workspace database before starting Shell. A `once` schedule is marked completed in the same transaction, so the command cannot reactivate or rerun that ID; a later execution requires a new schedule and therefore obeys the three-minute minimum again.

Run history contains dispatch status, timestamps, exit status, errors, and the ordinary Shell `task_id`. The newest 50 terminal runs per schedule are retained for at most 30 days. Use task endpoints for retained stdout/stderr, streaming, interruption, and force-kill; ordinary task-output retention is shorter and independent.

## Server cost model

The service uses one daemon scheduler thread for all workspaces. Registered stores contribute only their nearest `next_run_at` to an in-memory minimum heap. A condition variable sleeps until that instant and schedule mutations wake it to rebuild. There is no per-token timer and no periodic database polling while idle.

SQLite transactions provide atomic claiming and restart recovery. A server restart marks previously claimed/running schedule records abandoned; the ordinary Shell task registry is process-local and is shut down by the service lifecycle. OpenKapsel is designed for one service process per Workspace Root.

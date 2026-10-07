# Scheduled Shell tasks

[Back to README](../README.md)

Schedules persist background Shell intent inside the workspace's private `.openkapsel` state. They use the same stable application identity as Context and Shell environment configuration, so rotating short-lived read/control credentials does not lose them.

## Permission and execution boundary

A token needs both a non-`none` Shell mode and the separate scheduled-task permission. Schedule REST operations require the matching Bearer control token; MCP operations use their connection's credential and inherit the linked configuration's permissions. Existing token records default to schedules disabled until an administrator enables them.

Each dispatched command uses the token's current Shell mode, sandbox backend and image, environment configuration, network policy, additional path grants, cgroup limits, timeout, and ordinary global/per-token task limits. Credentials are never injected into the scheduled process.

Disabling or deleting the token, allowing its workspace lifetime to expire, or revoking Shell or schedules permission prevents future dispatch. Expiration or rotation of the short-lived read/control credentials does not stop an otherwise valid schedule. Recurring schedules are ended non-destructively instead of being individually hard-deleted.

## Timing contracts

Schedules support:

- `interval`: integer minutes, minimum 3.
- `once`: a timezone-aware ISO 8601 timestamp at least three minutes in the future.
- `cron`: exactly six fields in `second minute hour day month weekday` order plus an IANA timezone.

Cron's second field is one explicit integer from 0 through 59. The other fields accept numeric values, lists, ranges, steps, and `*`; names and Quartz extensions are rejected. OpenKapsel validates the complete daily occurrence spacing and rejects expressions that can run less than three minutes apart. Day-of-month and weekday use standard cron OR semantics when both are restricted. DST skipped local times do not run, while repeated local times may produce both real instants when they still satisfy the interval rule.

The only overlap policy is `skip`. Misfire policy may be `skip` or `coalesce`: skip records an occurrence as missed after `schedule_misfire_grace_seconds`; coalesce starts at most one catch-up execution. Capacity failures do not queue and are recorded as skipped.

## API lifecycle

The focused Discovery document at `GET /discovery/schedules` is authoritative. REST routes are:

- `GET|POST /schedule`
- `GET|PATCH /schedule/<schedule_id>`
- `POST /schedule/{execute,pause,resume,end}/<schedule_id>`
- `GET /schedule/run/list/<schedule_id>`
- `GET /schedule/run/<run_id>`

MCP exposes the same lifecycle through `capability_call` with `family=schedule`. Operations are `list`, `get`, `run_list`, `run_get`, `create`, `update`, `end`, `execute`, `pause`, and `resume`. Load `discovery/mcp` on demand for the current operation schemas; they are intentionally omitted from the initial `tools/list` payload.

Creation and every modifying action requires `plan_id`, `taskname`, and `message` Context. Ordinary creation/update/control uses an `in_progress` Plan. `resume` and `end` are lifecycle exceptions: their Context may reference an existing completed or cancelled Plan, which allows long-lived recurring schedules to outlive the Plan that created them. The creation values also become each run's automatic Context unless a complete `run_context` is supplied. Automatic recurring dispatch keeps recording `schedule.run` under that configured historical `plan_id` even after the Plan closes. Updates require `expected_revision`; a supplied `run_context` replaces future-run attribution as one unit.

`execute` is the explicit immediate-execution action and does not move the next ordinary occurrence. It still observes overlap and task/sandbox capacity. `pause` is temporary. `end` is available only for cron/interval schedules and accepts `status=stopped|completed` (default `stopped`): `stopped` has no next occurrence but may later be resumed, while `completed` is terminal. Neither form removes schedule metadata or retained run history. Ending a schedule does not interrupt an already-running task; use ordinary task control for that.

The scheduler atomically claims an occurrence in its workspace database before starting Shell. A `once` schedule is marked `completed` in the same transaction, so the command cannot reactivate or rerun that ID; a later execution requires a new schedule and therefore obeys the three-minute minimum again. For recurring schedules, `stopped` is restartable through `resume`; `completed` is terminal. There is no public single-schedule hard-delete operation.

Run history contains dispatch status, timestamps, exit status, errors, and the ordinary Shell `task_id`. The newest 50 terminal runs per schedule are retained for at most 30 days. Use task endpoints for retained stdout/stderr, streaming, interruption, and force-kill; ordinary task-output retention is shorter and independent.

## Server cost model

The service uses one daemon scheduler thread for all workspaces. Registered stores contribute only their nearest `next_run_at` to an in-memory minimum heap. A condition variable sleeps until that instant and schedule mutations wake it to rebuild. There is no per-token timer and no periodic database polling while idle.

SQLite transactions provide atomic claiming and restart recovery. A server restart marks previously claimed/running schedule records abandoned; the ordinary Shell task registry is process-local and is shut down by the service lifecycle. OpenKapsel is designed for one service process per Workspace Root.

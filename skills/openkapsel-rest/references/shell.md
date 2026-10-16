# Shell tasks, streaming I/O, and process inspection

Read `GET /discovery/shell` before use. It states whether Shell is `none`, `restricted`, or `full`, the active sandbox backend, task limits, timeout limits, and cgroup availability. Load `GET /discovery/network` only when network policy matters, and `GET /discovery/rpc` only when using generic RPC or client mappings.

Restricted Shell and full Shell have different boundaries. Restricted Shell is confined by its configured backend, mounts, network setting, and available cgroup limits. Full Shell runs as the OpenKapsel service user and is not constrained by token path grants or the network flag.

## Git inspection and mutations

Git is a dedicated RPC family, not Shell execution. For the server use
`POST /rpc/git/<operation>`; for a Mapping use
`POST /mapping/<mapping_name>/rpc/git/<operation>`. MCP uses the generic
`rpc_call` family `git`. Shell permission is not needed. Read calls also
work with disabled client Shell execution or a read-only Mapping.

Supported synchronous reads: `status`, `diff`, `diff_stat`, `log`,
`show`, `ls_files`, `branch`, `blame`, `tag`, `stash`.
Use `args` for operation-specific parameters. The selected `cwd` identifies
a repository with an ordinary SHA-1 `.git` directory; common read options
include `paths` (bounded literal repository-relative names), `revision`,
`to_revision`, `staged`, `limit`, `skip`, `all`, and `path` for
`blame`, only when supported by that operation. Invalid options are rejected;
inspect runtime Discovery or Mapping `operation_specs` for the exact schema.

Reads execute fixed Git commands directly in the original repository; **no
working-tree or object-database snapshot is copied**. AI-controlled repository
Git metadata is validated, and commands run without a Shell, network access,
hooks, maintenance or external filter execution. Trusted operator system/user
configuration (including global ignore and attributes) remains effective.
Repository-local safe settings and ordinary symlinks are supported; executable
repository filters are disabled for the read subprocess. Alternate object
stores, linked Git dirs and redirecting/executable repository config are
rejected. There is no arbitrary Git argv.

Reads are synchronous, with a default 15-second deadline (maximum 20 seconds),
four simultaneous inspections per process and 64 KiB bounded stdout/stderr.
Responses include `operation`, `running: false`, `exit_code`, `output`,
`stderr`, `output_truncated`, `stderr_truncated`. There is no read task ID,
polling or `snapshot_bytes` field. Truncated results require narrower queries.
Log is TSV; other operations return Git text. Git failure returns 422 with
details; invalid/unsafe metadata or layout can return 409, deadlines 504.
Server Git RPC cannot cross a Mapping boundary; select that Mapping instead.

Supported asynchronous write/task operations include `add`, `commit`,
`restore`, `checkout`, `branch_create`, `branch_delete`, `tag_create`,
`tag_delete`, `stash_push`, `stash_apply`, `stash_pop`, `stash_drop`,
`fetch`, `pull`, `push`, and `clone`. They use the ordinary `/task/*`
lifecycle, require write permission and an in-progress Plan Context, and
mapped writes additionally require a writable Mapping. Network Git operations
require token network/domain permission and validated HTTPS destinations.
Git hooks and unsafe repository-provided execution settings are blocked.
Check runtime Discovery for supported operations, current restrictions and
version compatibility; never replay an uncertain write task start.

## Persistent Shell environment

The control-authenticated `/env` endpoint stores Shell configuration for the stable app identity behind the current token record. It is distinct from the local `.openkapsel.env` file used by this Skill to find a server and credentials. Two token records may share one Workspace while retaining different Shell environments; rotating either record's read/control credentials preserves its configuration.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/env` | Return the complete variables and POSIX rc content; treat the response as secret and do not log it |
| `PUT` | `/env` | Completely replace variables and rc; include `plan_id`, `taskname`, and `message` |
| `DELETE` | `/env` | Clear the configuration; include mutation Context |

Example replacement:

```json
{
  "variables": {
    "API_KEY": "secret",
    "BUILD_MODE": "release"
  },
  "rc": "umask 077\nalias ll='ls -la'",
  "plan_id": 42,
  "taskname": "shell-config",
  "message": "Configure build environment"
}
```

Variables and rc are injected into later full, Bubblewrap, and Podman Shell tasks. The rc contract is POSIX `/bin/sh`, not Bash-only syntax. OpenKapsel-owned launcher, path, proxy, loader, and `OPENKAPSEL_*` names are reserved; inspect Discovery for the exact list and size limits. Service-process environment variables are not inherited wholesale, and configured values are not placed in sandbox launcher arguments. The rc is executable Shell code with the same authority as that token's Shell mode, so do not treat it as a safer permission boundary.

## Start and inspect tasks

Use `target: "auto"` (default), `"server"`, or `"client"`. Auto selects client
RPC for a mapped `cwd` such as `laptop/project`, otherwise server execution.
Client requires a mapped cwd and uses RPC without a server mount. Server
execution acquires native mapping dependencies only when needed (see below).
Never infer location from `cd` inside the command. Inspect mapping capabilities
first: client execution requires caller Shell/write, writable mapping `allow_exec`,
client opt-in, and `execution.shell_command` (client 1.60.0+). Errors never cause
fallback. Client sandbox/limits apply and server `/env` is not injected. Native
Windows commands use cmd.exe; POSIX/Podman use `/bin/sh -c`. Omitted or null Shell timeout defaults to 120 seconds on both Server and Mapping Client; an explicit positive finite timeout has no maximum (e.g. 1e9).

All returned IDs work with ordinary `/task/*` APIs. Client output is combined in
stdout (`output_combined: true`), with empty stderr. Status returns the first
64 KiB plus `stdout_next_offset`; use incremental output for the rest. Client
stdin accepts at most 16 KiB/request. Task listing `target=auto` includes server
token tasks and workspace client tasks; `target=server|client` filters it.
Inspect `unavailable_mappings` rather than assuming missing tasks stopped.
Mapping Shell with timeout ≤120 seconds runs inside the Client, using memory output and Client lifetime. Explicit timeouts >120 seconds run in a separate per-user Job Manager and survive Client restarts; Manager jobs use disk-backed stdin/stdout with 16-global/4-per-Mapping limits. Their `client.<mapping_id>.&a1B2&` IDs remain queryable. `task/output` with increasing offset acknowledges consumed bytes so the Manager can delete them. Manager exit does not preserve anonymous pipes. Neither synchronous nor asynchronous RPC uses Job Manager. Never automatically retry a start whose response was lost; list by Mapping before retrying. Schedules remain
server-side; client execution uses unified `/shell/exec` and `/task/*` routes,
with no mapping-specific public task or argv REST endpoints.

`POST /shell/exec` returns `202` with `task_id`:

```json
{
  "command": "python3 -m unittest",
  "target": "auto",
  "cwd": ".",
  "timeout_seconds": 3600,
  "interactive": false,
  "plan_id": 42,
  "taskname": "tests",
  "message": "Run the test suite"
}
```

The command runs asynchronously. Omitted or null `timeout_seconds` uses 120 seconds; explicitly supplied positive finite values have no maximum. `interactive: true` keeps stdin available.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/task/list?offset=0&limit=100&status=running` | List this token's running/finished tasks; omit `status` for all |
| `GET` | `/task/get/<task_id>` | Current state and exit metadata |
| `GET` | `/task/output/<task_id>` | Incremental stdout/stderr by byte cursor |
| `GET` | `/task/stream/<task_id>` | Bounded SSE output until `done` or `reconnect` |
| `POST` | `/task/stdin/<task_id>` | Send UTF-8/Base64 input or close stdin |
| `POST` | `/task/interrupt/<task_id>` | Server: SIGTERM then SIGKILL; client: SIGINT or Windows CTRL_BREAK |
| `DELETE` | `/task/<task_id>` | Server/POSIX client: SIGKILL; native Windows client: taskkill `/T /F` |
| `GET` | `/sandbox/processes` | Token cgroup process/resource view for restricted Shell |

## Native mapping dependencies

On RPC-first servers (1.61.0+), a server task automatically leases the mapping
containing its cwd. For paths outside cwd, send `mount_mappings` explicitly:

```json
{
  "command": "python laptop/project/main.py",
  "target": "server",
  "cwd": ".",
  "mount_mappings": ["laptop"],
  "plan_id": 42,
  "taskname": "build",
  "message": "Run the mapped project using the server runtime"
}
```

The optional array accepts up to 256 non-empty names or IDs from this workspace.
Omitting it preserves existing cwd-based placement; it never implicitly selects
server execution. Non-empty dependencies are rejected for client execution.
The server resolves dependencies before cwd validation and sandbox creation;
it does not inspect shell source, scripts or environment variables to guess them.
Missing/disabled native support fails explicitly; do not mount all mappings or
switch execution location automatically. File/RPC tools and client tasks need
no FUSE. `online=true, mounted=false` is a healthy RPC-only state.

Leases follow the managed task/process group. Run consumers in the foreground;
deliberately detached processes are outside this lifetime guarantee. Restricted
sandboxes mask undeclared mappings, while full Shell is intentionally unsandboxed
and cannot promise per-task namespace masking. Schedules use the same server
launch path for their cwd mapping, but schedule records do not yet accept extra
`mount_mappings` declarations.

The HTTP client's request wait is separate from the task's `timeout_seconds`.
A slow native setup can delay the initial 202 response. A request timeout,
cancellation, or lost response does not prove the task was never started or has
stopped. Inspect `/task/list` and use an existing task ID; never automatically replay
a Shell start or an uncertain write.

## Output polling

Call:

```text
GET /task/output/<id>?stdout_offset=0&stderr_offset=0&limit=65536&wait_seconds=20
```

Advance each cursor to its returned `next_offset`. A `gap` means older bytes fell outside the bounded stream and the response tells where retained output begins. `wait_seconds` supports long polling up to the published maximum.

SSE uses `text/event-stream` with `output`, `done`, and `reconnect` events:

```text
GET /task/stream/<id>?stdout_offset=<n>&stderr_offset=<n>
```

`reconnect` means the maximum stream duration was reached while the task is still running. Reconnect using its exact `stdout_offset` and `stderr_offset`. Concurrent streams are limited globally and per token; `429 too_many_streams` includes `Retry-After` and the published limits.

A client failure during streaming produces an `error` event with byte cursors.
Wait for the client to reconnect, then resume from those cursors; do not restart
the command.

The generic helper writes SSE directly rather than buffering it:

```bash
python3 scripts/openkapsel_http.py GET tasks/<id>/stream --stream
```

## Interactive input and termination

`POST /task/stdin/<id>` JSON accepts exactly one of `data` (UTF-8) or `data_base64`, plus optional `close`. Include JSON Context fields. The task must have been created with `interactive: true`. Client tasks accept at most 16 KiB per call; server tasks accept at most 256 KiB. The final chunk and `close: true` can be sent together.

Interrupt and kill have no JSON body, so send all three `OpenKapsel-*` Context headers. Prefer interrupt; use force-kill when graceful termination is inappropriate or failed.

`GET /sandbox/processes?offset=0&limit=100` is available only for restricted Shell when server cgroup support is enabled. It reports aggregate memory/CPU/PID/OOM counters and process rows. A task limit, PID limit, memory limit, or CPU limit is independent; consult Discovery rather than assuming defaults.


For temporary unsandboxed execution, first request permission with
`POST /shell/approval/request`, JSON `{"target":"server","writer_nonce":"@xxxx@","reason":"specific reason"}`
(or use the exact Mapping ID as `target`). Include the owning in-progress Plan
Context headers. Only this explicit request creates an `approval_url`; an ordinary
Shell error never creates a URL. Display the returned URL and obtain Workspace
Password approval **before** executing the command. After approval, call
`POST /shell/exec` with `approved: true` and the same Conversation's
`writer_nonce`, plus normal Plan Context. The approval page never runs a command.
URLs last thirty minutes and grants default to ten minutes (maximum 24 hours),
independently for Server and each Mapping. An approved Mapping execution may
bypass disabled client Shell execution, but a writable Mapping and remaining
permissions are still required. Grants expire on revocation, password reset,
or Server restart. Expiry does not terminate an already started job.
OAuth sign-in does not grant unsandboxed Shell access.

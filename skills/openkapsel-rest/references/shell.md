# Shell tasks, streaming I/O, and process inspection

Read `GET /discovery/shell` before use. It states whether Shell is `none`, `restricted`, or `full`, the active sandbox backend, network access, task limits, timeout limits, and cgroup availability.

Restricted Shell and full Shell have different boundaries. Restricted Shell is confined by its configured backend, mounts, network setting, and available cgroup limits. Full Shell runs as the OpenKapsel service user and is not constrained by token path grants or the network flag.

## Git inspection

Git inspection is a read-only file capability, not Shell execution. REST needs
only the workspace read URL; MCP uses its existing connection authentication.
It works with Shell disabled, client `allow_exec=false`, and read-only mappings.

| GET endpoint | Parameters besides `path` and repeated literal `file` |
|---|---|
| `/git/status` | Porcelain v1 status |
| `/git/diff`, `/git/diff_stat` | `staged`, `revision`, `to_revision` |
| `/git/log` | `revision=HEAD`, `limit=20` (max 200), `skip=0` |
| `/git/show` | `revision=HEAD`, including `HEAD:relative/file` |
| `/git/ls_files` | Tracked files |

`path` must identify a repository root with an ordinary SHA-1 `.git` directory.
Git runs on a private sanitized temporary snapshot: source config, includes,
hooks, filter definitions, global config, and private `.openkapsel` storage
are not loaded. No original workspace path is passed to the Git process.
There is no arbitrary argv, no Shell task, and no execution-permission fallback.
Git must be installed on the host. A mapped path uses the read-only `git` RPC plugin version 2
RPC; old clients must update/reconnect and fail closed until then.

Limits: 128 MiB copied data, 100000 nodes, 4 simultaneous inspections per
process, 15-second default timeout (maximum 20), and 64 KiB output per stream.
Metadata-only queries (log/show/ls-files/staged or two-revision diffs) do not
copy working files; status and working-tree diffs do. This uses local temporary
disk and adds copying overhead; it does not transfer the snapshot to the server.
Linked worktrees, external object alternates, and symlinks/reparse points or
special files encountered in copied paths are rejected. Repository-local
configuration (including custom filters, ignore settings and autocrlf) is not
applied; output may therefore differ from normal developer Git commands.
Snapshots are not transactional across files. A server Git snapshot cannot cross
a virtual mapping root (`git_mapping_boundary`); inspect a repository entirely
in one backend or use its client Git RPC. Do not substitute an unapproved Shell
command for a read-authorized inspection.

Responses are synchronous: 200 with `output`, `stderr`, `exit_code`,
`output_truncated`, `stderr_truncated`, and `snapshot_bytes`; there is no
task ID or polling. Narrow queries when output is truncated. Errors use 413 for
snapshot limits, 409 for unsupported layouts, 504 for deadline expiry, and
422 for Git errors. Log is TSV; other outputs are Git text, not parsed rows.
Read Context is optional. Mutating RPCs still need write permission, and
arbitrary Shell/client tasks still require their execution permissions.

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
Windows commands use cmd.exe; POSIX/Podman use `/bin/sh -c`. Null/omitted timeout
uses the client maximum; an explicit timeout must fit its policy.

All returned IDs work with ordinary `/tasks` APIs. Client output is combined in
stdout (`output_combined: true`), with empty stderr. Status returns the first
64 KiB plus `stdout_next_offset`; use incremental output for the rest. Client
stdin accepts at most 16 KiB/request. Task listing `target=auto` includes server
token tasks and workspace client tasks; `target=server|client` filters it.
Inspect `unavailable_mappings` rather than assuming missing tasks stopped.
Reconnect preserves client tasks while the client process remains alive;
never automatically retry a start whose response was lost. Schedules remain
server-side; mapping-specific argv task APIs remain available.

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

The command runs asynchronously. `timeout_seconds` may be `null` or within the published bounds. `interactive: true` keeps stdin available.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/tasks?offset=0&limit=100&status=running` | List this token's running/finished tasks; omit `status` for all |
| `GET` | `/tasks/<task_id>` | Current state and exit metadata |
| `GET` | `/tasks/<task_id>/output` | Incremental stdout/stderr by byte cursor |
| `GET` | `/tasks/<task_id>/stream` | Bounded SSE output until `done` or `reconnect` |
| `POST` | `/tasks/<task_id>/stdin` | Send UTF-8/Base64 input or close stdin |
| `POST` | `/tasks/<task_id>/interrupt` | Server: SIGTERM then SIGKILL; client: SIGINT or Windows CTRL_BREAK |
| `POST` | `/tasks/<task_id>/kill` | Server/POSIX client: SIGKILL; native Windows client: taskkill `/T /F` |
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
stopped. Inspect `/tasks` and use an existing task ID; never automatically replay
a Shell start or an uncertain write.

## Output polling

Call:

```text
GET /tasks/<id>/output?stdout_offset=0&stderr_offset=0&limit=65536&wait_seconds=20
```

Advance each cursor to its returned `next_offset`. A `gap` means older bytes fell outside the bounded stream and the response tells where retained output begins. `wait_seconds` supports long polling up to the published maximum.

SSE uses `text/event-stream` with `output`, `done`, and `reconnect` events:

```text
GET /tasks/<id>/stream?stdout_offset=<n>&stderr_offset=<n>
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

`POST /tasks/<id>/stdin` JSON accepts exactly one of `data` (UTF-8) or `data_base64`, plus optional `close`. Include JSON Context fields. The task must have been created with `interactive: true`. Client tasks accept at most 16 KiB per call; server tasks accept at most 256 KiB. The final chunk and `close: true` can be sent together.

Interrupt and kill have no JSON body, so send all three `OpenKapsel-*` Context headers. Prefer interrupt; use force-kill when graceful termination is inappropriate or failed.

`GET /sandbox/processes?offset=0&limit=100` is available only for restricted Shell when server cgroup support is enabled. It reports aggregate memory/CPU/PID/OOM counters and process rows. A task limit, PID limit, memory limit, or CPU limit is independent; consult Discovery rather than assuming defaults.

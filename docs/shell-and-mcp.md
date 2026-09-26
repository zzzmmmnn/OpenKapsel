# Shell tasks and MCP

[Back to README](../README.md)

## Shell task lifecycle

### Execution placement

`POST /shell/exec` and MCP `run_shell` accept `target: "auto"` (default),
`"server"`, or `"client"`. Auto routes a `cwd` inside a mapping to that client
through RPC; other working directories run on the server. Use workspace-relative
paths such as `laptop/project`. Client requires a mapped cwd; explicit server
keeps execution on the server, using FUSE to access mapped files. Commands are
never inspected for `cd` or rewritten to translate embedded absolute paths.

Client execution requires caller Shell/write permissions, a writable mapping
with `allow_exec`, and client execution opt-in. Client 1.60.0+ advertises
`execution.shell_command`; older/offline/denied clients fail without fallback.
Client-local sandbox, timeout, and resource policy apply; server `/env` and
server sandbox/network settings are not copied to the client. Omitted or null
timeout uses the client's `max_seconds`; a supplied value cannot exceed it.
Native Windows uses `cmd.exe /d /s /c`; POSIX and client Podman use `/bin/sh -c`.
Choose commands for the advertised platform. The client argv limit (32768 total
characters, including the interpreter) still applies.

Responses include `location` and a unified `task_id`. Use this ID with ordinary
`/tasks/<id>` status/output/SSE/stdin/interrupt/kill APIs (or MCP task tools).
Client stdout and stderr are combined in `stdout`, marked `output_combined`;
status includes up to 64 KiB and `stdout_next_offset`. Continue with output
cursors for more data. SSE drains all retained bytes before `done`; a client
failure after headers produces an `error` event with resumable byte cursors.
Reconnect the client before resuming; this does not restart the task. Client stdin
chunks are at most 16 KiB; `interactive: true` is required. Client interrupt sends
SIGINT on POSIX/Podman or CTRL_BREAK on native Windows; force-kill terminates the
process group/tree. Server interruption retains its existing behavior.

`GET /tasks?target=auto` and MCP `list_tasks` list both the current token's server
tasks and the workspace's accessible client tasks. `target=server|client`
filters location; normal status/pagination still apply. `unavailable_mappings`
reports clients whose tasks could not be listed, not that their tasks stopped.
Client task IDs remain routable after reconnect/server restart. Retention and
client process-exit limitations are described in [client mappings](client-mappings.md).
Never replay an uncertain start automatically: reconnect and list tasks first.
The existing mapping-specific argv APIs remain available; schedules still
execute on the server.

### Git inspection

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
Git must be installed on the selected execution host. A mapped path uses the
`git` RPC family version 2; old clients must update/reconnect and fail closed
until the requested operation is advertised.

Limits: 128 MiB copied data, 100000 nodes, 4 simultaneous inspections per
process, 15-second default timeout (maximum 20), and 64 KiB output per stream.
Metadata-only queries (log/show/ls-files/staged or two-revision diffs) do not
copy working files; status and working-tree diffs do. This uses local temporary
disk and adds copying overhead; it does not transfer the snapshot to the server.
Linked worktrees, external object alternates, and symlinks/reparse points or
special files encountered in copied paths are rejected. Repository-local
configuration (including custom filters, ignore settings and autocrlf) is not
applied; output may therefore differ from normal developer Git commands.
Snapshots are not transactional across files.

Responses are synchronous: 200 with `output`, `stderr`, `exit_code`,
`output_truncated`, `stderr_truncated`, and `snapshot_bytes`; there is no
task ID or polling. Narrow queries when output is truncated. Errors use 413 for
snapshot limits, 409 for unsupported layouts, 504 for deadline expiry, and
422 for Git errors. Log is TSV; other outputs are Git text, not parsed rows.
MCP keeps the six `git_*` read tools. Git mutations use the generic `rpc` tool
with `family=git`: provide `mapping_id` for a mapped repository or omit it for
the server workspace. `add`, `commit`, `restore`, `checkout`, `fetch`, `pull`,
and `clone` run as RPC tasks and use the normal task APIs; they do not require
Shell permission. Mutations require write permission and Plan Context, mapped
writes also require a writable mapping, and fetch/pull/clone additionally obey
the caller's network/domain policy. Complex arbitrary Git commands still require
an explicitly authorized Shell command.

### Persistent environment

Each token record has a stable internal `app_id`. It is not a credential: read/control token rotation keeps it unchanged, and `actor_id` is a one-way SHA-256 pseudonym derived from it. OpenKapsel uses the stable ID to keep Shell environment configuration separate when multiple token records point at the same Workspace.

The control-authenticated environment API is:

- `GET /env`: return all configured variables and POSIX rc content with `Cache-Control: no-store`
- `PUT /env`: completely replace variables and rc
- `DELETE /env`: clear them

`PUT` and `DELETE` are mutations and require `plan_id`, `taskname`, and `message`. `GET` returns secret values, so clients should avoid logging its response. Configuration is stored in private `.openkapsel/env` state, deleted with its token record, and injected into later full, Bubblewrap, and Podman Shell tasks. Values are passed through a mode-0600 file rather than sandbox-launcher arguments.

The rc language is POSIX `/bin/sh`; Bash-only startup syntax is not portable across backends. It runs with the same authority as the selected Shell mode. OpenKapsel blocks names that could replace its workspace, path, proxy, loader, or startup controls, including `HOME`, `PATH`, proxy variables, loader variables, and the `OPENKAPSEL_` prefix. Discovery publishes the exact reserved names and configured size limits.

Full Shell receives a deliberately small base environment instead of inheriting the complete service environment. Restricted backends also establish their own base environment before sourcing the generated file. Every backend exposes `OPENKAPSEL_WORKSPACE` as the task's workspace path.

`POST /shell/exec` creates an asynchronous task and returns `task_id`. Defaults are eight concurrent tasks per token and sixteen globally. Each task has a maximum runtime, one hour by default. These values are service configuration, while process, memory, and CPU limits belong to the token.

Interactive tasks accept stdin. Output can be consumed by:

- task state and bounded retained output
- byte-cursor incremental reads
- waits of up to thirty seconds
- SSE `output`, `done`, and `reconnect` events

The default HTTP and SSE limits are:

- 128 accepted OpenKapsel HTTP connections
- 16 Shell SSE streams globally
- 4 SSE streams per token
- one hour per SSE connection
- 30 seconds for a stalled backend socket I/O operation

Exceeding the HTTP connection limit returns `503`. Exceeding an SSE limit returns `429 too_many_streams`. The one-hour stream rotation emits exact stdout and stderr byte offsets in `reconnect`; a client opens another stream from those cursors without losing task output.

These limits do not turn Caddy's Keep-Alive `idle` setting into a task deadline. See [Installation and reverse proxy](installation.md#recommended-caddy-connection-limits).

For server tasks, `interrupt` sends SIGTERM to the process group and escalates
after its grace period; `kill` sends SIGKILL immediately. Client task behavior
depends on its platform as described in [Execution placement](#execution-placement).

Finished output is persisted to files instead of remaining indefinitely in memory. Each token retains a bounded number of completed records, four by default, with configurable retention. Active task output remains available by cursor.

The restricted-sandbox process endpoint lists cgroup PIDs, commands, aggregate memory and CPU accounting, and OOM counters.

## MCP transport

Create a [static MCP connection](static-mcp-connections.md) or [OAuth connection](oauth-connections.md) for a workspace. A static connection uses:

```text
https://ws.example.com/kapsel/mcp-connect/<CONNECTION_ID>/mcp
```

It is stateless JSON-RPC. Every call requires the connection's Bearer credential; MCP has no anonymous read-only mode and no required session ID. Use `POST /mcp`; `GET /mcp` returns `405`.

The negotiated protocol is `2025-11-25`, with compatibility for `2025-03-26` and `2025-06-18`. Requests containing `Origin` are checked against the configured public origin to mitigate DNS rebinding.

Tool families include:

- Discovery: `workspace_info`
- Context: query, create, Plan tree, Plan update, and Note replacement
- Memory: query, get project Memory, add, revise, and archive
- files: listing, reading, metadata, search, tree, writes, replacements, directories, move, recycle, and restore
- transfer: prepared downloads and resumable upload create, chunk, status, commit, and abort
- preview: independent browser preview URL
- Shell: run, list, status, output, stdin, interrupt, kill, and process listing
- sharing: create, inspect, import, and delete

MCP binary chunks are bounded and Base64-encoded. Large transfers return complete authenticated `/transfer/...` URLs containing no read, control, or preview token. The client reuses its Bearer header. Downloads support GET, HEAD, ETag, and one Range; uploads support offset inspection, raw PATCH, commit, and cancel.

`workspace_info` defaults to compact Discovery and accepts `main`, `files`, `context`, `memory`, `shell`, `web`, `sharing`, or `full`. `tools/list` is authoritative for current MCP schemas.

The Shell tools in `tools/list` use the same unified task IDs as REST:
`run_shell` and `list_tasks` accept `target=auto|server|client`; `get_task` and
`read_task_output` report combined stdout and empty stderr for client tasks;
`send_task_input` accepts at most 16 KiB per client call and 256 KiB per server
call. `interrupt_task` and `kill_task` dispatch to the task's actual location.
Client execution requires a writable mapping with `allow_exec` and a connected
client advertising `execution.shell_command`.

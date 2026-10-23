# Shell tasks and MCP

[Back to README](../README.md)

## Shell task lifecycle

### Execution placement

`POST /shell/exec` and MCP `capability_call` with `family=shell, operation=exec` accept `target: "auto"` (default),
`"server"`, or `"client"`. Auto routes a `cwd` inside a mapping to that client
through RPC; other working directories run on the server. Use workspace-relative
paths such as `laptop/project`. Client requires a mapped cwd; explicit server
keeps execution on the server, using FUSE to access mapped files. Commands are
never inspected for `cd` or rewritten to translate embedded absolute paths.

Ordinary Client execution requires caller Shell/write permissions, a writable
mapping with `allow_exec`, and client execution opt-in. Temporary approval can
override disabled execution after user approval; see the approval workflow below. Client 1.60.0+ advertises
`execution.shell_command`; older/offline/denied clients fail without fallback.
Client-local sandbox and resource policy apply; server `/env` and
server sandbox/network settings are not copied to the client. Both Server and
Mapping Shell default to a **120-second timeout** when omitted or null.
An explicit positive finite `timeout_seconds` has no maximum (for example, `1e9`);
Mapping Shell at most 120 seconds runs in Client; longer Mapping Shell runs in Manager. With Linux/macOS `job_sandbox` configured, every Mapping Shell job runs in Manager. Both ignore Client `limits.max_seconds`, which applies only to asynchronous RPC tasks.
Native Windows uses `cmd.exe /d /s /c`; POSIX and client Podman use `/bin/sh -c`.
Choose commands for the advertised platform. The client argv limit (32768 total
characters, including the interpreter) still applies.

Responses include `location` and a unified `task_id`. Job IDs are `&a1B2&`
(four case-sensitive alphanumeric characters between ampersands) for Server
jobs, or `client.<mapping_id>.&a1B2&` for Mapping jobs. The ID format changes,
but the existing task APIs, paths, and request parameter names remain unchanged.
Pass the returned ID directly to the ordinary
`/task/get/<id>` status/output/SSE/stdin/interrupt/kill APIs (or MCP task tools).
Client stdout and stderr are combined in `stdout`, marked `output_combined`;
status includes up to 64 KiB and `stdout_next_offset`. Continue with output
cursors for more data. SSE drains all retained bytes before `done`; a client
failure after headers produces an `error` event with resumable byte cursors.
Reconnect the client before resuming; this does not restart the task. Client stdin
chunks are at most 16 KiB; `interactive: true` is required. Client interrupt sends
SIGINT on POSIX/Podman or CTRL_BREAK on native Windows; force-kill terminates the
process group/tree. Server interruption retains its existing behavior.

`GET /task/list?target=auto` and MCP `task_list` list both the current token's server
tasks and the workspace's accessible client tasks. `target=server|client`
filters location; normal status/pagination still apply. `unavailable_mappings`
reports clients whose tasks could not be listed, not that their tasks stopped.
Long Mapping Shell jobs (timeout >120 seconds) survive Client reconnects, Client process exits, and server restarts while their Job Manager keeps running. Short Shell jobs (timeout ≤120 seconds, including the default) are Client-owned and stop on Client exit, except with Linux/macOS `job_sandbox`, where all Shell jobs are Manager-owned. RPC operations retain
their existing Client/Server execution and task lifecycle.
Manager restarts cannot reattach lost anonymous process pipes; details and
retention are in [client mappings](client-mappings.md).
Never replay an uncertain start automatically: reconnect and list tasks first.
Schedules still execute on the server. Client execution is exposed through the
unified `/shell/exec` and `/task/*` APIs; there are no mapping-specific public
task or argv REST routes.

### Git inspection

Git inspection is a read-only RPC capability, not Shell execution. REST uses
`POST /rpc/git/<operation>` for the server workspace or
`POST /mapping/<mapping_name>/rpc/git/<operation>` for a mapped repository. Legacy mapping IDs remain accepted by the route for compatibility.
MCP uses the same `git` family through the generic `rpc_call` tool. Reads work
with Shell disabled, client `allow_exec=false`, and read-only mappings.

Supported read operations are `status`, `diff`, `diff_stat`, `log`,
`show`, `ls_files`, `branch`, `blame`, `tag`, and `stash`.
`branch` lists local/remote branches, `blame` takes one relative file path,
`tag` lists tags, and `stash` lists stash entries. Arguments live under `args`
object and are advertised by RPC Discovery metadata.

`cwd` must identify a repository root with an ordinary `.git` directory.
Read-only operations run directly in that repository, without copying the
worktree or object database. Git receives fixed arguments; external diff and
filter executables, hooks, system/user Git configuration, and network helpers
are disabled. Repository-local settings such as ignore rules remain in effect.
Git must be installed on the selected execution host. Mapping clients must
advertise the operation; there is no fallback to Shell or another host.

Limits: 100000 inspected Git metadata nodes, 4 simultaneous inspections per
process, 15-second default timeout (maximum 20), and 64 KiB output per stream.
No working-tree snapshot size limit applies. Linked worktrees and external
object alternates remain unsupported, but ordinary tracked or ignored symlinks
in the working tree are supported by native Git. Queries run against the live
repository, so a concurrent writer may change the observed state.

Responses are synchronous: 200 with `output`, `stderr`, `exit_code`,
`output_truncated`, and `stderr_truncated`; there is no task ID or polling.
Narrow queries when output is truncated. Errors include 409 for unsupported
layouts, 504 for deadline expiry, and 422 for Git errors. Log is TSV; other
outputs are Git text, not parsed rows.
MCP uses the generic `rpc_call` tool for both Git reads and mutations. Use
`family=git`; provide `mapping_id` for a mapped repository or omit it for the
server workspace. `add`, `commit`, `restore`, `checkout`, `branch_create`,
`branch_delete`, `tag_create`, `tag_delete`, `stash_push`, `stash_apply`,
`stash_pop`, `stash_drop`, `fetch`, `pull`, `push`, and `clone` run as RPC tasks
and use the normal task APIs; they do not require
Shell permission. Mutations require write permission and Plan Context, mapped
writes also require a writable mapping, and fetch/pull/push/clone additionally obey
the caller's network/domain policy. `branch_delete` never forces an unmerged
branch; `tag_create` does not overwrite; `stash_drop` requires an explicit
stash index. Complex arbitrary Git commands still require
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

`POST /shell/exec` creates an asynchronous task and returns `task_id`.
Server Shell retains its separate concurrency defaults of eight tasks per token
and sixteen globally. The shared Mapping Job Manager allows sixteen running long Shell
jobs globally and four per Mapping key, for Shell requests with timeout >120 seconds only.
Both default to a 120-second execution timeout; an explicit positive finite
timeout has no upper bound. Memory, CPU, and process restrictions follow
the execution backend's configured policy.

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

The current tool surface includes:

- Discovery: `discovery`
- portable REST delegation: `credential_get` and `credential_renew`
- generic RPC: `rpc_call` for advertised server or mapping RPC families such as Git and Archive
- Context: query, create, Plan tree, Plan update, and Note replacement
- Memory: query, get project Memory, add, revise, and archive
- files and transfer: bounded reads/queries, transactional edits, binary transfer, recycle, and resumable uploads
- schedules: grouped `schedule_read`, `schedule_write`, and `schedule_control`
- preview: independent browser preview URL
- Shell/tasks: run, list, status, output, stdin, interrupt, kill, and process listing

MCP binary chunks are bounded and Base64-encoded. Large transfers return complete authenticated `/transfer/...` URLs containing no read, control, or preview token. The client reuses its Bearer header. Downloads support GET, HEAD, ETag, and one Range; uploads support offset inspection, raw PATCH, commit, and cancel.

`discovery` defaults to compact Discovery and accepts `main`, `files`, `context`, `memory`, `paths`, `rpc`, `network`, `mcp`, `shell`, `schedules`, `web`, `authentication`, `errors` or `full`. `tools/list` is authoritative for current MCP schemas.

The Shell tools in `tools/list` use the same unified task IDs as REST:
`shell_exec` and `task_list` accept `target=auto|server|client`; `task_get` and
`task_output` report combined stdout and empty stderr for client tasks;
`task_stdin` accepts at most 16 KiB per client call and 256 KiB per server
call. `task_interrupt` and `task_kill` dispatch to the task's actual location.
Client execution requires a writable mapping with `allow_exec` and a connected
client advertising `execution.shell_command`.


## Temporary unsandboxed Shell

**Request approval proactively without executing a Shell command:**

REST `POST /shell/approval/request` accepts an explicit `target` (`"server"`
or an authorized Mapping ID), `writer_nonce`, a specific AI-written `reason`
(displayed on the approval page), and mutation Context
(`plan_id`, `taskname`, `message`). MCP `capability_call` uses
`family="shell"`, `operation="request_approval"`, and
`args={"target":"server","writer_nonce":"@Ab12@","reason":"Inspect the host environment"}` with normal outer Plan
Context. Targets are explicit because no command or `cwd` is provided for
automatic placement.

The response is HTTP 200 with `status="approval_required"`, a full
`approval_url`, `approval_expires_in`, `capability`, and exact `target` (or
`status="granted"` when already approved, or immediately for a Mapping without
`job_sandbox` that already permits native Shell: writable, `allow_exec`, and
advertising `execution.approval_required: false`). Open the URL for Workspace password
approval. This call never runs a command or implicitly approves subsequent
Shell calls. Execute with `approved=true` after approval. Mapping requests
require an authorized, connected, writable Mapping supporting approval;
Shell/write permissions are not bypassed.

Both REST `POST /shell/exec` and MCP `capability_call` family `shell`, operation
`exec` accept optional `approved` (boolean, default false) and `writer_nonce`.
For MCP these fields go inside `args`; mutation Context stays in outer
`plan_id`/`taskname`/`message`. For REST use existing body/header Context fields.

```json
{
  "family": "shell",
  "operation": "exec",
  "args": {"command": "whoami", "approved": true, "writer_nonce": "@Ab12@"},
  "plan_id": 123,
  "taskname": "inspect host",
  "message": "Inspect the approved execution target"
}
```

Without approval, execution returns `capability_approval_required` with an
explicit `shell.request_approval` instruction and **no URL**. Only a proactive
`request_approval` call can generate a thirty-minute single-use URL. Grants offer 10 minutes, 30 minutes, 2 hours, 6 hours or 24 hours (default
10 minutes), and are specific to the **Token Workspace** (stable `app_id`),
Conversation and selected execution target. Distinct Tokens pointing to the
same server directory need separate passwords and grants. Server approval does
not approve any Mapping. Changing cwd may require a separate approval. A new
Conversation needs its own approval.

Approved execution bypasses Server and Client sandboxes as the current OS user.
Mapping `allow_exec=false` and Client execution-disabled flags can be overridden
by this approved invocation; writable Mapping, caller write and Shell permissions
remain required. Older Clients lacking the `unsandboxed` capability must upgrade
and reconnect. Short jobs and long shared Job Manager jobs both support approval.
The Server injects Client-owned Shell authorization into the private
function RPC (for example,
`{"grants":[{"expires_at":<Client Unix time>,"unsandboxed":true}]}`).
The password and approval URL are never passed to the execution function.
The Client validates its own grant expiry before skipping the sandbox.
A Client-first upgrade can also recognize the prior private
`{"unsandboxed":true}` authorization format while the Server is on the old
protocol.

Configured sandbox path `deny` rules still apply to ordinary Shell, but
cannot constrain an explicitly approved unsandboxed host process; File API
`deny` is unaffected.

`approved=false` preserves ordinary Shell policy, including permanent
administrator-configured `shell_mode=full`. Explicit `approved=true` always checks
for approval, including for full Shell tokens, except on a Mapping that already
permits native Shell without `job_sandbox`: there `approved=true` is ignored and
the command runs as ordinary Shell. Expiry, password reset, revocation
or restart prevents new approved jobs without killing jobs already started.
Scheduled jobs do not inherit these conversation grants. Other API capabilities
cannot borrow Shell approval.

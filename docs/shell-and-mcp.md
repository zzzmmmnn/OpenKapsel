# Shell tasks and MCP

[Back to README](../README.md)

## Shell task lifecycle

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

`interrupt` sends SIGTERM to the process group and escalates after its grace period. `kill` sends SIGKILL immediately.

Finished output is persisted to files instead of remaining indefinitely in memory. Each token retains a bounded number of completed records, four by default, with configurable retention. Active task output remains available by cursor.

The restricted-sandbox process endpoint lists cgroup PIDs, commands, aggregate memory and CPU accounting, and OOM counters.

## MCP transport

Each Workspace has a Streamable HTTP MCP endpoint:

```text
https://ws.example.com/kapsel/w/<READ_TOKEN>/mcp
```

It is stateless JSON-RPC. Every call requires the matching Bearer control token; MCP has no anonymous read-only mode and no required session ID. Use `POST /mcp`; `GET /mcp` returns `405`.

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

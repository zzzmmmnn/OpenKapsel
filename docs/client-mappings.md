# Client mappings and execution

[Back to README](../README.md)

## Direction and storage

A Python client exports a local directory over an outbound WebSocket connection. File APIs expose it as a virtual child directory and operate directly over RPC. Native FUSE mounts are optional and are acquired only when a server Shell task or FastAPI application needs a real filesystem path. Neither registration nor provider connection starts a FUSE worker. No client FUSE driver, inbound client port, directory synchronization, or full server-side copy is required. See [RPC-first operation and migration](mapping-rpc-first.md).

Each mapping is independently registered for one workspace and a single child directory name. Multiple mappings may share a workspace. All caller permissions still apply. Provider tokens are independent of the rotating REST tokens and are stored hashed by the server. Editing or rotating a mapping disconnects the provider. Only one active provider is accepted per mapping.

Mapped content consumes client storage, not the workspace image quota. Server API transfer-size limits still apply. Offline access fails rather than falling back to a local backing directory. Files already cached/opened by application code are not a substitute for reconnecting; old provider handles become stale on reconnection.

## Server setup

Install the declared Python dependencies. RPC-only file operations do not need `/dev/fuse` or a native mount helper. For optional server-side native execution, also install Linux FUSE userspace support (`libfuse2` or the distribution's `libfuse2t64`, plus `fuse3` providing `fusermount`). The service unit allows `/dev/fuse`; do not run the main service as root or enable `allow_other`. Set `mapping_fuse_enabled=false` to prohibit native mounts altogether.

Set `"mappings_enabled": true` in the server configuration and restart the service. The default is false. The existing reverse proxy must forward WebSocket upgrades on the normal application prefix. Caddy's normal `reverse_proxy` handles this; no separate client-facing port is needed.

Open **Administration → Client mappings**, choose the workspace, directory name, writable state, and optional client execution permission. Save the generated client configuration: the provider token is shown only once. The name must not already exist. There is no fixed 16-registration limit. `max_active_mapping_mounts` defaults to 16 and limits concurrently active native FUSE mounts, not registrations or connected providers.

Expand an existing mapping to edit its directory name. Renaming changes only the server mountpoint: the mapping ID, provider credential, client root and recycle store remain unchanged. The provider disconnects and can reconnect with its existing configuration. Stop active transfers/tasks first; open handles and running sandboxes may still refer to the old mount. Existing destination names are never overwritten.

Under the server state directory, `mappings.sqlite3` holds registrations and `file-transfers` holds resumable transfer metadata. `mapping-run` next to Workspace Root holds private broker IPC. With the installed image helper, fixed-command transient `openkapsel-mapping-<id>.service` units run FUSE as the non-root service account in the host mount namespace. This makes mappings visible to both the service and rootless Podman's persistent namespace. The helper accepts only mapping IDs and relative workspace/directory names, not arbitrary commands or mount options. Without a helper, development-mode mounts stay in the server's own namespace; persistent Podman namespaces may not see them.

## Python client installation

The client requires Python 3.10+. To avoid installing scientific and web-server libraries on a client-only machine, run from a source checkout:

```sh
python3 -m venv .venv-client
.venv-client/bin/python -m pip install 'websocket-client>=1.8,<2' 'python-socks>=2.7,<3'
.venv-client/bin/python -m openkapsel.client --config /path/to/client.json
```

On Windows use `python` and `.venv-client\Scripts\python.exe`. A full package installation can instead use the `client` extra and the `openkapsel-client` command.

Keep the configuration outside the exported directory and source control. On POSIX systems use mode `0600`:

```json
{
  "url": "wss://host.example/kapsel/mapping-connect/<MAPPING_ID>",
  "token": "<MAPPING_TOKEN>",
  "root": "/path/to/local/project",
  "writable": true,
  "allow_exec": false,
  "auto_reload": true,
  "transport_timeout_seconds": 60,
  "rpc": {
    "git": true,
    "archive": true
  },
  "rpc_plugins": [],
  "sandbox": true,
  "proxy": "socks5://127.0.0.1:1080"
}
```

Supported proxy schemes are `http`, `socks4`, `socks4a`, `socks5`, and `socks5h`. Use the `a`/`h` variants for proxy-side DNS. Optional proxy credentials use URL userinfo. TLS verification remains enabled; a proxy connection failure never falls back to direct access. `transport_timeout_seconds` defaults to 60 seconds and controls client WebSocket connect/receive tolerance. The server separately waits up to `mapping_rpc_timeout_seconds` (90 seconds by default) for one RPC reply and treats mutation timeouts as ambiguous, never replaying them automatically. Use `--once` to disable automatic reconnection during diagnostics.

### Version handshake and local source reload

Mapping client 1.62.0+ keeps provider authentication in the HTTP WebSocket Upgrade. Once that Bearer credential succeeds, the server sends the first application frame with the mapping handshake version, full server version, a 44-character SHA-256/Base64 server source fingerprint, the minimum compatible client version, and a 30-second client-hello deadline. The provider is not online and cannot serve file/RPC/task traffic until it replies with a valid `client_hello` containing its full client version, its own 44-character client source fingerprint, and the existing capability document. The server then sends `ready`. There is no silent fallback to the old client-first hello.

Server and client fingerprints are separate deterministic change detectors. Shared protocol files affect both fingerprints; side-specific files affect only their corresponding fingerprint. Fingerprints hash an ordered, explicit source manifest using raw file bytes and the manifest itself. Fingerprint equality is not a compatibility requirement: compatibility is governed by `minimum_client_version` plus the existing RPC/capability versions.

`auto_reload` is optional. When `auto_reload=true` and `source_root` is omitted, the client uses the OpenKapsel project root that contains the currently running source modules; it does not use the process working directory. `source_root` remains an optional absolute-path override for advanced setups that want to reload into a different trusted checkout. The client never scans arbitrary directories and never imports candidate source just to inspect it; it reads the version/fingerprint as data. When a reload is selected, the process is replaced and the selected source root is inserted ahead of the current working directory/import path.

Before the first READY session, a client below the server minimum checks that local source. If a changed local source satisfies the minimum it reloads; otherwise required-version retries use delays of 0, 60, 120, then 300 seconds for the fourth and later attempts. Ordinary network reconnect failures do not advance this backoff.

After a successful READY session, reconnect compares the newly received server fingerprint with the last successful server fingerprint. A changed server fingerprint triggers an immediate local-source check. Even when the server fingerprint is unchanged, a disconnect triggers the same check when at least 24 hours have elapsed since the process last loaded/reloaded code. A changed compatible local client fingerprint reloads immediately. Optional reload is deferred while client-local tasks are still running; normal transport reconnects continue preserving the in-memory task runtime. A client below the server minimum never becomes READY merely to preserve tasks.

Reload state is stored atomically beside the client config as `<client.json>.state.json` with restrictive permissions. The successful server fingerprint is recorded only after READY, never just after seeing `server_hello`.

If local DNS returns a proxy's synthetic address (for example an address from `198.18.0.0/15`), use `socks5h` instead of `socks5`; this still uses SOCKS5, but sends the hostname to the proxy for resolution.

## Files, recycling, and transfers

Use normal file APIs and client RPC for mapped paths; explicit server Shell and FastAPI execution acquire native views only when needed. `GET /mappings` reports online state, writable state, client capabilities, mount state, and native mount reference counts. Mapping roots cannot be moved or deleted through file APIs; detach them through administration.

Updated clients advertise a generic `capabilities.rpc` map. Core file RPC is
always enabled and reports `available`; its version and supported operations
are still negotiated. Optional extensions report `available`, `unsupported`, or
`disabled`; the server derives `offline` when the provider session is absent.
The client configuration can independently enable or disable extensions with
`rpc.git`, `rpc.archive`, and registered plugin family names. The removed
`rpc.file` key is rejected: delete it from older client configurations before
starting the updated client. Read/write restrictions remain controlled by the
caller token, mapping permissions, and client `writable` setting.
Git is reported as `unsupported` when enabled but the local Git
executable is missing. Legacy `file_api` and `git_api` advertisements remain
accepted during rolling upgrades.

Git and Archive are client RPC plugins rather than branches hard-coded into the
filesystem provider. Built-in plugins are registered explicitly by the client.
Additional installed packages can be loaded with `rpc_plugins` entries in
`module:object` form. The object must expose a bounded family name, version,
family `description`, an `operations` mapping, `probe(config)`, and
`dispatch(files, operation, args)`. Every operation declares
`{description, input_schema, write}`; `write` defaults to `false` and is the
authoritative mutation declaration for that operation. `input_schema` is a
bounded JSON object schema. The client publishes both the compatible
operation-name list and the full `operation_specs` metadata in
`GET /mappings`. A derived family `read_only` value remains only for
rolling-upgrade compatibility. Loading is opt-in: merely installing a Python
package does not execute its plugin code.

Dynamic operations can be called without adding a server handler: first inspect
`GET /mappings`, then use
`POST /mappings/<id>/rpc/<family>/<operation>` with an `args` object, or the
MCP `rpc` tool. Each operation publishes `write` and `execution`. The
registry default is `execution=sync` for reads and `execution=task` for writes,
although plugins may declare either mode explicitly. `sync` returns the result
in the RPC response. `task` returns HTTP 202 and a unified
`client.<mapping>.<task>` ID immediately; poll `/tasks/<id>` or
`/tasks/<id>/output`, and use the ordinary interrupt/kill task controls.
RPC tasks live in the client runtime, survive provider WebSocket disconnects and
reconnects, and continue using client-local files; normal client process exit
terminates active tasks. Do not automatically replay an uncertain write task
start after transport loss: reconnect and query/list the original task first.

For `write=false`, read permission is sufficient and no Plan Context is
required. For `write=true`, the caller needs the control credential and token
write permission, the mapping must be enabled with `writable=true` in
administration, and `plan_id`, `taskname`, and `message` are required.
Task operations additionally accept optional `timeout_seconds`; the client
enforces its local `limits.max_seconds` policy (600 seconds by default, up to
86400). There is no FUSE/server fallback for generic plugin operations. An
explicitly configured plugin is trusted local code running in the mapping client
process, so install and register only code you trust; declaring `write` and
`execution` correctly is part of that trust boundary.

The file family currently uses version `3` and advertises its supported
operations. The server automatically sends one complete file operation over the
existing WebSocket when all its paths belong to the same mapping and the
operation is available. The client performs filesystem work locally and returns
the normal REST response. For example, SHA-256 calculation sends back the digest
rather than transferring the file to the server, and directory listing returns
metadata in one RPC.

The file RPC path supports list, stat/hash, text read (including byte offsets),
tree, search, text write, replace, mkdir, same-mapping move, recoverable delete,
and same-mapping manifest/replace/delete batches. Multi-file reads, filtered
search and recursive manifests require the corresponding client capabilities;
text codecs and exact newline preservation require file RPC version 3.

Binary downloads, static Web Preview, direct uploads, resumable upload commits,
shared snapshots/imports, cross-root copies/moves, and mixed-root batches use a
common guarded local/RPC backend. Root listings merge registered mappings without
opening native mountpoints or contacting providers. A root search, tree, or
recursive manifest sends one coarse query per visited mapping, with the remaining
depth and result/node budget. Search filtering and SHA-256 calculation stay on
the client; the server merges results rather than downloading remote files.
Search globs remain relative to the original request root. Slash-containing
globs across a mapping boundary require the client's `file_stream.search_prefix`
capability; older clients return an upgrade error rather than ignoring filters.
Search reports failed mappings in `unavailable_mappings` and sets `truncated=true`;
tree/recursive manifest entries use `is_mapping`, `mapping_id`, `unavailable`,
and `error`. In both cases successful local/other-mapping results remain usable.
Traversal crosses a mapping boundary through RPC;
an unavailable mapping remains identified rather than appearing as an empty
ordinary directory. Direct streaming clients advertise `file_stream.version=1`
and provide descriptor metadata, including device/inode identity and nanosecond
timestamps. Upgrade clients before using these paths with an RPC-first server.

File RPC is not a FUSE optimization anymore: unsupported client operations
return a capability error, and oversized requests return an explicit size error.
Legacy clients advertising disabled file RPC are still rejected, not overridden.
No ordinary file request mounts FUSE or silently accesses an existing native view.
RPC messages remain bounded to 1 MiB; raw file streams use bounded chunks. An
oversized response returns `mapping_response_too_large` (413): use a smaller page,
read limit, tree depth, or batch, or a binary transfer for large content.

A timeout or disconnect after dispatch is never automatically replayed. Inspect
the affected paths before retrying a mutation with an unknown result. This also
applies to an oversized response with `mutation_may_have_completed: true`.
Streams remain bound to one provider generation; reconnecting invalidates old
handles instead of redirecting in-progress I/O to a replacement provider.
Client path guards, protected internal directories, and mapping/client write
restrictions still apply. Unmounted backing directories are inaccessible.

Git RPC family `git` version `2` keeps `status`, `diff`,
`diff_stat`, `log`, `show`, and `ls_files` as `write=false,
execution=sync` sanitized-snapshot reads. It also provides common mutations
`add`, `commit`, `restore`, and `checkout` as `write=true,
execution=task`. Git write tasks do not require Shell/`allow_exec`, but do
require the normal writable-mapping/write-token/Plan authorization. They reject
linked worktrees, alternate object stores, symlinked/special Git metadata, and
repository config that enables includes, filters, hooks paths, fsmonitor,
external attributes, SSH/credential helpers, or signing. Hooks and signing are
also disabled on the invoked Git commands. Host Git is required when
`rpc.git=true`; a missing executable is advertised as `unsupported`. Git RPC
has no FUSE/server fallback. See
[Git inspection](shell-and-mcp.md#git-inspection) for read limits and layouts.

Archive RPC family `archive` version `1` keeps `list` and `read`
as `write=false, execution=sync` previews and adds `create` and `extract`
as `write=true, execution=task`. Create writes to a private
`.openkapsel/rpc-tasks` temporary file, fsyncs it, then renames it into the
requested destination only after success. Extract writes into a private temporary
directory and renames that directory into a previously absent destination only
after every member succeeds. Cancellation/failure removes the temporary artifact,
so a provider disconnect never exposes a half-written final archive or extraction
tree. Links/reparse points/special source or archive members are rejected.
Listing is capped at 100000 entries, one member preview at 256 KiB, and preview
offset at 16 MiB. Supported formats come from the current Python standard library:
normally `.zip`, `.tar`, `.tar.gz`/`.tgz`,
`.tar.bz2`/`.tbz2`, `.tar.xz`/`.txz`, and where available
`.tar.zst`/`.tzst`. Use `archive_list` and `archive_read` for previews;
use generic `rpc`/`kapsel_rpc` with the advertised schema for create/extract.

API deletion moves files to `.openkapsel/recycle` on the client. Recycle list/restore use `root=.` for the ordinary workspace or the mapping directory name for a client recycle store. Raw Shell deletion is still direct deletion. Symlinks, Windows reparse points, and special files are not exported in this version. POSIX `chmod` is unsupported on Windows; filesystem case sensitivity remains that of the client. Full distributed file-lock semantics are not promised.

`POST /fs/copy` starts a verified, resumable copy. `fs/move` between different roots uses verified copy followed by source recycling. Both return 202 with a transfer ID; poll `/fs/transfers/<id>` and use POST `/cancel` or `/resume` with mutation Context. A move is not atomic. `copied_source_retained` means the destination exists but the source still needs attention. Publication never silently overwrites an existing destination. Cancellation retains partial data on the destination for resumption, so it still consumes client/destination space.

## Client execution policy

Execution requires server caller Shell/write permissions, a writable mapping with client execution enabled, and client-local `allow_exec: true`. Sandbox defaults to true. The initial sandbox backend is Podman; it must be installed and its VM started where required. The image is configurable using `image`; default `docker.io/library/python:3.14-slim-trixie`. Network defaults off for sandboxed tasks (`network: true` enables it). Podman defaults are two concurrent tasks, 600 seconds, 256 MB memory, 64 processes, and one CPU per task.

To run native macOS/Windows tasks before native sandbox adapters are implemented, explicitly set `"sandbox": false`. This mode also works on Linux. It grants the task the client's OS-account permissions: `cwd`, mapping read/write configuration, and `network: false` do not confine an unsandboxed process. The client warns at startup. No missing sandbox ever causes automatic fallback to this mode.

The unified `POST /shell/exec` entry defaults to `target=auto`: a workspace-relative mapped `cwd` selects client execution. Set `target=server` to execute on the server or `target=client` to require a mapping. This requires client 1.60.0+ (`execution.shell_command`); offline/denied/older clients never cause server fallback. Use its returned task ID with ordinary `/tasks` APIs. See [execution placement](shell-and-mcp.md#execution-placement) for platform, input, output, and timeout details.

Mapping-specific task APIs also accept argv arrays and export-relative working directories. Output is combined stdout/stderr, capped at 2 MB per task, and retrieved incrementally as base64. Stdin accepts bounded chunks. Interrupt and force-kill are supported; native POSIX tasks use process groups and Windows uses process-tree termination. These are lifecycle controls, not sandbox boundaries, and deliberately detached native processes are outside the guarantee.

### Task lifetime across reconnects

With client 1.58.0 or later, one in-memory task manager spans all automatic reconnects. Network loss or a server restart does not kill tasks or reset their deadlines. After reconnect, list tasks or use the original task ID to read output, inspect exit status, send stdin, interrupt, or kill. Offline requests fail: they are not queued, and an unavailable client does not imply a stopped task. Never automatically replay a start request whose response was lost; reconnect and inspect the task list first.

Results completed while offline remain available. Uncollected results do not expire while the client process remains alive. A completed result becomes collected when a task GET reads through the end of its retained output; listing alone does not collect it. Collected results are pruned on subsequent requests after one hour, or beyond four collected records. The registry holds at most `max_tasks + 4` total records (six by default); when full it rejects new starts rather than discarding uncollected results. Per-task output remains capped at 2 MB, with truncation reported explicitly.

This is reconnect persistence, not process-restart persistence: stopping the client normally (including Ctrl+C and `--once` termination) kills active tasks and discards in-memory results. Client crashes, OS restarts, and detached native processes are not recoverable through this manager. File handles remain session-scoped and are closed on disconnect. Existing clients must be upgraded and restarted to use the new task lifetime.

When the total registry is full, starting a task may evict the oldest already-collected result before its one-hour deadline. Uncollected results are never evicted to make room.

Podman on macOS/Windows runs Linux workloads, not native platform tests. Linux Bubblewrap and native macOS/Windows sandbox adapters remain follow-up backends; this version does not claim they are implemented.

Local task limits can be set in `limits`: `max_tasks` (1–16), `max_seconds` (1–86400), `memory_mb`, `processes`, and `cpus`. CPU/memory/process limits are container controls; native unsandboxed mode only enforces concurrency, output bounds, and task deadlines. Client execution currently offers Podman or explicit native execution; additional sandbox backends can be added independently of the mapping transport.

`POST /recycle/purge` removes one selected recycle entry permanently. It requires the root selector, entry ID, normal mutation Context, and `confirm: true`.

## Structured and table RPC

The built-in `structured` and `tabular` families are enabled by default, with optional per-format dependencies. Set `rpc.structured` or `rpc.tabular` to false to disable a family. JSON/CSV work without additional parser packages. See [data-rpc.md](data-rpc.md) for installation, conditional edits, large CSV cursors and bounded read-only scans.

## Validation status

The deployment checks below describe the original always-mounted implementation.
For the RPC-first refactor, consult [validation and remaining deployment checks](mapping-rpc-first.md#validation). Automated regression coverage does not by itself validate a real Linux FUSE mount or host-helper namespace propagation; those remain deployment-level checks.

Validated with a Linux server and a native macOS client over a SOCKS5 proxy: REST read/write/rename, client-local recycle/restore, cross-root copy/move, Podman Shell access, client stdin/output/interrupt/kill, offline errors, and reconnect after service restart. A 300 MiB sparse client file was visible without consuming that size in the server workspace image; this is not a large-file throughput benchmark. Native Windows client operation has also been validated locally, including the Windows filesystem provider and native task/process handling; the native macOS client test suite is likewise validated locally.

Automated tests cover path containment, credential separation, CSRF, generation fencing, bounded tasks, transfer resume, and the fixed unprivileged mount launcher. Windows-specific tests remain part of the client CI matrix in addition to native local validation. Native Linux client execution, client-side Podman execution, real Linux FUSE mounting, host-helper namespace propagation, and project backend access still require environment-specific deployment validation.

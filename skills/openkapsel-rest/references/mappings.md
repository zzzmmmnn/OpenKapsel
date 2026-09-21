# Client-backed directories and execution

Fetch `GET /mappings` before using client-backed paths. It returns each mapping's
`id`, workspace-relative `path`, `online`, `writable`, `mounted`,
`mount_references`, `native_mounts_enabled`, and advertised client capabilities.
Files live on the client, not inside the server workspace image. On OpenKapsel
1.61.0+ RPC-first servers, `online=true` with `mounted=false` is normal: use file
and RPC endpoints without starting a native mount. Registration, provider
connection, and native filesystem view have independent lifetimes. Offline
operations fail; never recreate a mapping root or treat it as an empty local
directory. Runtime Discovery remains authoritative for older servers.

Clients advertise a generic `capabilities.rpc` map. Optional extensions report
`available`, `unsupported`, or `disabled`; the server derives `offline` from
provider connectivity. Core file RPC uses version 3 and is always enabled on
current clients. **rpc.file has been removed**; delete that key from older client
configurations rather than setting it to true or false. Permissions and operation
version checks still apply. File operations never fall back to FUSE, including
unsupported old clients, legacy disabled capabilities, or oversized requests.

Binary and mixed-root operations additionally require `capabilities.file_stream`
with `version=1`, `descriptor_stat=true`, and `directory_details=true`.
`search_prefix=true` supports query-root-relative filters in delegated searches.
Upgrade both server and client when these capabilities are missing; do not try
to repair compatibility by mounting a directory. Same-mapping reads, hashes and
searches run client-locally. Root listing uses virtual registration metadata;
root search, tree and recursive manifest delegate visited mapping subtrees with
remaining global limits. Search may return `unavailable_mappings` and
`truncated=true`; tree/manifest can contain unavailable nodes. These results are
incomplete, not proof that files do not exist.

The server waits up to `mapping_rpc_timeout_seconds` (90 seconds by default) for
one RPC reply. Client transport tolerance defaults to 60 seconds with pings every
10 seconds. A `mapping_response_too_large` error (413) needs a smaller result
budget, tree depth or batch; use binary transfer for large payloads. After a
timeout, disconnect, or `mutation_may_have_completed: true`, inspect affected
paths and existing tasks before retrying. Never automatically replay a write.

Git and Archive are client RPC plugins with no server/FUSE fallback. Git
version 2 exposes synchronous reads `status`, `diff`, `diff_stat`, `log`,
`show`, and `ls_files`, plus task mutations `add`, `commit`, `restore`,
and `checkout`. Archive version 1 exposes synchronous `list`/`read` plus
task mutations `create`/`extract`. Client config can independently enable
`rpc.git` and `rpc.archive`; Git reports `unsupported` when
enabled but the local `git` executable is missing. Additional trusted client
plugins can be registered explicitly with `rpc_plugins: ["module:object"]`;
merely installing a package does not load it.

Each plugin self-describes the family and every operation. In `GET /mappings`,
`capabilities.rpc.<family>.description` explains the family and
`operation_specs.<operation>` contains `description`, a JSON
`input_schema`, boolean `write`, and `execution` (`sync` or `task`).
When a plugin omits execution, the client registry defaults reads to `sync` and
writes to `task`, then advertises the resolved value explicitly. Dynamic
clients should inspect this metadata instead of hard-coding future families such
as doc/csv/sqlite. A family-level `read_only` value may be present for
rolling-upgrade compatibility, but operation metadata is authoritative.

Use `POST /mappings/<mapping_id>/rpc/<family>/<operation>`. A `sync`
operation returns its result directly. A `task` operation returns HTTP 202 and
a unified `client.<mapping>.<task>` id immediately; query it through the
ordinary `/tasks/<id>` and `/tasks/<id>/output` routes and use ordinary
interrupt/kill task controls. RPC tasks live in the client runtime, continue
across provider WebSocket disconnect/reconnect while that client process stays
alive, and retain bounded output/results. Do not automatically replay an
uncertain write-task start after a transport failure: reconnect, list/query the
original task first.

For `write=false`, read permission is enough and no Plan Context is required.
For `write=true`, the caller needs the control credential and token write
permission, the mapping must be administratively `writable=true`, and the body
must also include `plan_id`, `taskname`, and `message`. Task operations may
also include `timeout_seconds`; the client enforces its local `max_seconds`
policy (600 seconds by default). The server forwards exactly one start RPC and
never falls back to server/FUSE for a generic plugin operation.

Archive preview is also exposed through ordinary workspace routes: `GET /archive/list?path=<archive>&inner_path=&offset=0&limit=200` and `GET /archive/read?path=<archive>&member=<member>&offset=0&limit=65536&encoding=utf-8`. Local workspace archives are read on the server; mapped archives use the Archive client plugin. Preview never extracts members to disk, refuses link members as files, bounds listing/member reads, and supports the Python runtime's standard-library ZIP/tar formats such as `.zip`, `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`, `.tar.xz`/`.txz`, and where available `.tar.zst`/`.tzst`.

`GET /recycle/list?root=.` selects the ordinary workspace recycle bin. Use `root=<mapping-name>` for that client's recycle bin. `POST /recycle/restore` accepts the same `root` and `recycle_id`, plus normal mutation Context. Never infer a recycle root from the ID alone.

`POST /recycle/purge` permanently deletes one entry and requires `root`, `recycle_id`, `confirm: true`, and mutation Context. Use it only when permanent deletion is authorized; ordinary cleanup should use recoverable deletion instead.

## Native server execution

Only server Shell tasks and FastAPI workers that need native filesystem paths
acquire reference-counted FUSE leases. A server command leases its cwd mapping
automatically. Declare other dependencies with `mount_mappings`, an optional
array of at most 256 non-empty workspace mapping names or IDs. The field does
not change `target=auto` routing and non-empty dependencies are rejected when the
selected execution location is the client. Use `target=server` intentionally;
do not parse command strings or mount every mapping as a convenience.
See [shell.md](shell.md#native-mapping-dependencies) for an example.

FastAPI dependencies are declared in the application's `api/mappings.json`;
see [web-and-apps.md](web-and-apps.md#mapped-applications-and-native-dependencies).
Leases follow task/process or application-worker lifetime, not individual HTTP
requests. Idle unmounting leaves the provider and its RPC tasks connected. The
server may disable native views with `mapping_fuse_enabled=false`; ordinary file
operations, static preview and client execution still work. A native mount error
does not authorize automatic client/server fallback. The active mount limit is
not a limit on mapping registrations or online RPC providers.

## Structured and tabular data

The `structured` family reads/validates JSON, YAML and TOML, previews patches,
and performs conditional atomic write/patch tasks. The `tabular` family provides
read-only CSV/Excel inspection, cursor-based pages, and asynchronous segment
count/aggregation. CSV handles 2-10 GiB without whole-file loading or repeated
deep row-offset scans. Inspect `details.formats` for optional parser dependencies.
See [data-rpc.md](data-rpc.md) for argument examples, budgets and failure handling.

RPC task listings are summaries: completed tasks advertise `result_available`
without duplicating large result objects. Fetch `/tasks/<id>` or its output
endpoint for the result. This keeps a list of several table scans within the
transport response limit.

## Cross-root transfers

- `POST /fs/copy`: JSON `source`, `destination`, `plan_id`, `taskname`, `message`. The destination parent must exist. Overwrite is not supported.
- `POST /fs/move`: moving between different storage roots returns an asynchronous transfer, not an immediate rename.
- Both return HTTP 202 with an `id`. Poll `GET /fs/transfers/<id>`.
- `POST /fs/transfers/<id>/cancel` or `/resume`: supply normal mutation Context. Resume validates the source and partial destination before continuing. Do not start a second transfer to resume the first one.
- `completed` is success. `copied_source_retained` means a move copied the destination but could not safely recycle the source. Do not delete the source blindly.
- Partial data is staged on the destination storage, not buffered as an entire file on the server. Cancel preserves partial data for resumption.

Binary downloads/uploads, static preview, shares and cross-root transfers use
RPC without FUSE. Transfer staging is on the destination filesystem. Resumable
uploads retain a bounded server spool until publication; shares remain immutable
server-owned snapshots and consume share quota. In-progress handles are provider-
generation-bound. Resume the existing transfer after reconnect and inspection;
never redirect an uncertain write to a different mapping. Upload/transfer records
bind mapping IDs, so renamed/replaced registrations cannot redirect publication.
Pending legacy mapped uploads without recorded mapping identity must restart.

## Client tasks

Client execution is separate from server Shell. Only use it when requested or appropriate to the user's testing/compute task. Inspect the mapping's advertised platform and sandbox policy first; `native-unsandboxed` means the client's OS-account permissions, not confinement to the exported directory.

Prefer the unified `POST /shell/exec` with `target=auto` and workspace-relative
mapped cwd (see [shell.md](shell.md#start-and-inspect-tasks)). Use its returned
ID with ordinary `/tasks` endpoints. For literal argv instead of command strings,
the existing `POST /mappings/<mapping_id>/tasks` remains available:

```json
{
  "argv": ["python", "-m", "pytest"],
  "cwd": "tests",
  "timeout_seconds": 300,
  "plan_id": 1,
  "taskname": "test-client",
  "message": "Run tests on the mapped client"
}
```

`cwd` is relative to the client's exported root. A full host path is unnecessary. `argv` is an argument array, not a Shell command string; use an explicit interpreter only when Shell syntax is intended.

- `GET /mappings/<mapping_id>/tasks`: list tasks.
- `GET /mappings/<mapping_id>/tasks/<task_id>?offset=0`: status plus base64-encoded combined stdout/stderr; use `next_offset` for incremental output.
- `POST .../<task_id>/stdin`: base64 `data`, or `eof: true`, plus mutation Context.
- `POST .../<task_id>/interrupt` or `/kill`: mutation Context.

Shell/client-execution tasks require the control credential and enabled Shell
permission. Starting a Shell task additionally requires write permission, a
writable execution-enabled mapping, and client-local execution opt-in. RPC tasks
are separate: they do not require Shell or `allow_exec`; access follows the
selected operation's read/write metadata and mapping writable policy. Both task
kinds use the same client task store and unified `/tasks` query/output/control
routes. RPC tasks reject stdin.

Client tasks preserve execution across network reconnects, including results
completed while offline; the client process must remain alive. Reconnect, list
tasks, and query the original ID instead of automatically replaying an uncertain
start. Offline control requests fail rather than queue. Uncollected results
remain in memory until client exit; reading a completed task through the end of
retained output marks it collected (then one hour / four collected records).
Total records are bounded by max_tasks + 4; full registries reject new starts.
Task deadlines and the 2 MB output cap still apply offline. Normal client
shutdown kills active tasks; process restarts do not restore records. Provider
mapping credentials are managed separately and are not REST control tokens.

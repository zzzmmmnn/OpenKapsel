# Client-backed directories and execution

Fetch `GET /mappings` before using client-backed paths. It returns each mapping's `id`, workspace-relative `path`, `online`, `writable`, and advertised client execution capabilities. Files live on that client, not inside the server's workspace image. Use normal file APIs for mapped paths. Offline operations fail; do not recreate an offline mountpoint or assume it is empty.

Updated clients advertise a generic `capabilities.rpc` map. Each family reports `available`, `unsupported`, or `disabled`; the server derives `offline` when the provider is not connected. File RPC is version 3 and remains an optimization behind the normal file endpoints. It may fall back to FUSE only before dispatch when the family policy allows it; offline or administrator-disabled mappings never fall back. A `mapping_response_too_large` error (413) requires a smaller result limit, tree depth, or batch. After an ambiguous timeout or a response with `mutation_may_have_completed: true`, inspect the affected paths before repeating a mutation.

Git and Archive are client RPC plugins. Git uses version 2 and has no server/FUSE fallback. Archive uses version 1 with `list` and `read` and also has no fallback. Client config can independently enable `rpc.file`, `rpc.git`, and `rpc.archive`; Git reports `unsupported` when enabled but the local `git` executable is missing. Additional trusted client plugins can be registered explicitly with `rpc_plugins: ["module:object"]`; merely installing a package does not load it.

Each plugin self-describes the family and every operation. In `GET /mappings`,
`capabilities.rpc.<family>.description` explains the family and
`operation_specs.<operation>` contains `description` plus a JSON
`input_schema`. Dynamic clients should inspect this metadata instead of
hard-coding future families such as doc/csv/sqlite.

For a third-party family advertised with `read_only=true`, use `POST /mappings/<mapping_id>/rpc/<family>/<operation>` with JSON `{ "args": { ... } }`. The server checks the mapping, advertised family/operation, state, and read-only flag, then forwards exactly one RPC to the client. There is no implicit FUSE/server fallback. Generic write-capable plugins are rejected until they have a dedicated mutation permission and Context contract.

Archive preview is also exposed through ordinary workspace routes: `GET /archive/list?path=<archive>&inner_path=&offset=0&limit=200` and `GET /archive/read?path=<archive>&member=<member>&offset=0&limit=65536&encoding=utf-8`. Local workspace archives are read on the server; mapped archives use the Archive client plugin. Preview never extracts members to disk, refuses link members as files, bounds listing/member reads, and supports the Python runtime's standard-library ZIP/tar formats such as `.zip`, `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`, `.tar.xz`/`.txz`, and where available `.tar.zst`/`.tzst`.

`GET /recycle/list?root=.` selects the ordinary workspace recycle bin. Use `root=<mapping-name>` for that client's recycle bin. `POST /recycle/restore` accepts the same `root` and `recycle_id`, plus normal mutation Context. Never infer a recycle root from the ID alone.

`POST /recycle/purge` permanently deletes one entry and requires `root`, `recycle_id`, `confirm: true`, and mutation Context. Use it only when permanent deletion is authorized; ordinary cleanup should use recoverable deletion instead.

## Cross-root transfers

- `POST /fs/copy`: JSON `source`, `destination`, `plan_id`, `taskname`, `message`. The destination parent must exist. Overwrite is not supported.
- `POST /fs/move`: moving between different storage roots returns an asynchronous transfer, not an immediate rename.
- Both return HTTP 202 with an `id`. Poll `GET /fs/transfers/<id>`.
- `POST /fs/transfers/<id>/cancel` or `/resume`: supply normal mutation Context. Resume validates the source and partial destination before continuing. Do not start a second transfer to resume the first one.
- `completed` is success. `copied_source_retained` means a move copied the destination but could not safely recycle the source. Do not delete the source blindly.
- Partial data is staged on the destination storage, not buffered as an entire file on the server. Cancel preserves partial data for resumption.

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

These routes require the control credential and enabled Shell permission. Starting tasks additionally requires write permission, a writable execution-enabled mapping, and client-local execution opt-in. Client 1.58.0+ preserves tasks across network reconnects, including results completed while offline; the client process must remain alive. Reconnect, list tasks, and query the original ID instead of automatically replaying an uncertain start. Offline control requests fail rather than queue. Uncollected results remain in memory until client exit; reading a completed task through the end of retained output marks it collected (then one hour / four collected records). Total records are bounded by max_tasks + 4; full registries reject new starts. Task deadlines and the 2 MB output cap still apply offline. Normal client shutdown kills active tasks; process restarts do not restore records. Provider mapping credentials are managed separately and are not REST control tokens.

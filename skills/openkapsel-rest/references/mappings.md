# Client-backed directories and execution

Fetch `GET /mappings` before using client-backed paths. It returns each mapping's `id`, workspace-relative `path`, `online`, `writable`, and advertised client execution capabilities. Files live on that client, not inside the server's workspace image. Use normal file APIs for mapped paths. Offline operations fail; do not recreate an offline mountpoint or assume it is empty.

Clients advertising `capabilities.file_api.version = 1` execute supported same-mapping file operations in one RPC. Continue using the normal REST endpoints; no separate caller-facing RPC is needed. Keep batch items within one mapping when possible. A `mapping_response_too_large` error (413) requires a smaller result limit, tree depth, or batch. After an ambiguous timeout or a response with `mutation_may_have_completed: true`, inspect the affected paths before repeating a mutation.

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

Create a task with `POST /mappings/<mapping_id>/tasks`:

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

These routes require the control credential and enabled Shell permission. Starting tasks additionally requires write permission, a writable execution-enabled mapping, and client-local execution opt-in. Client disconnection terminates active tasks; never automatically replay a task whose result is uncertain. Provider mapping credentials are managed separately and are not REST control tokens.

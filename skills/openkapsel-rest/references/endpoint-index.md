# Non-MCP HTTP endpoint index

This inventory is for routing. Read the focused reference and runtime Discovery before constructing nontrivial requests.

## Discovery and workspace files

| Method | Route |
|---|---|
| `GET` | `<workspace_url>/` |
| `GET` | `<workspace_url>/discovery/{files,context,memory,shell,schedules,web,sharing,full}` |
| `POST` | `<workspace_url>/credentials/renew` |
| `GET` | `<workspace_url>/fs/query/list` |
| `GET` | `<workspace_url>/fs/read/text` |
| `GET` | `<workspace_url>/fs/query/stat` |
| `POST` | `<workspace_url>/fs/query/manifest` |
| `POST` | `<workspace_url>/fs/read/many` |
| `POST` | `<workspace_url>/rpc/git/<operation>` |
| `POST` | `<workspace_url>/rpc/archive/<operation>` |
| `POST` | `<workspace_url>/mappings/<mapping_name>/rpc/<family>/<operation>` |
| `GET` | `<workspace_url>/fs/query/find` |
| `GET` | `<workspace_url>/fs/query/search` |
| `GET` | `<workspace_url>/fs/query/tree` |
| `GET|HEAD|PUT` | `<workspace_url>/fs/content` |
| `POST` | `<workspace_url>/fs/write/mutate` |
| `POST` | `<workspace_url>/fs/read/large` |
| `POST` | `<workspace_url>/fs/write/large` |
| `POST` | `<workspace_url>/fs/write/mkdir` |
| `POST` | `<workspace_url>/fs/write/move` |
| `GET` | `<workspace_url>/recycle/list` |
| `POST` | `<workspace_url>/recycle/restore` |

## Resumable transfer

| Method | Route |
|---|---|
| `POST` | `<workspace_url>/uploads` |
| `GET|HEAD|PATCH|DELETE` | `<workspace_url>/uploads/<upload_id>` |
| `POST` | `<workspace_url>/uploads/<upload_id>/commit` |
| `GET|HEAD|PUT` | `<service-base>/transfer/fs/content` |
| `GET|HEAD|PATCH|DELETE` | `<service-base>/transfer/uploads/<upload_id>` |
| `POST` | `<service-base>/transfer/uploads/<upload_id>/commit` |

## Context and Memory

| Method | Route |
|---|---|
| `GET|POST` | `<workspace_url>/context` |
| `GET` | `<workspace_url>/context/plans/<plan_id>/tree` |
| `PATCH` | `<workspace_url>/context/plans/<plan_id>` |
| `PATCH` | `<workspace_url>/context/notes/<note_id>` |
| `GET|POST` | `<workspace_url>/memory` |
| `GET` | `<workspace_url>/memory/project` |
| `GET|PATCH|DELETE` | `<workspace_url>/memory/<memory_id>` |
| `GET` | `<workspace_url>/memory/<memory_id>/revisions` |

## Shell and tasks

| Method | Route |
|---|---|
| `GET|PUT|DELETE` | `<workspace_url>/env` |
| `POST` | `<workspace_url>/shell/exec` |
| `GET` | `<workspace_url>/tasks` |
| `GET` | `<workspace_url>/tasks/<task_id>` |
| `GET` | `<workspace_url>/tasks/<task_id>/output` |
| `GET` | `<workspace_url>/tasks/<task_id>/stream` |
| `POST` | `<workspace_url>/tasks/<task_id>/stdin` |
| `POST` | `<workspace_url>/tasks/<task_id>/interrupt` |
| `POST` | `<workspace_url>/tasks/<task_id>/kill` |
| `GET` | `<workspace_url>/sandbox/processes` |

Server `POST /shell/exec` accepts optional `mount_mappings` for extra native
dependencies; its cwd mapping is automatic. It does not change `target=auto`
routing, and client execution rejects non-empty declarations. See
[shell.md](shell.md#native-mapping-dependencies).

## Schedules

| Method | Route |
|---|---|
| `GET|POST` | `<workspace_url>/schedules` |
| `GET|PATCH|DELETE` | `<workspace_url>/schedules/<schedule_id>` |
| `POST` | `<workspace_url>/schedules/<schedule_id>/run` |
| `POST` | `<workspace_url>/schedules/<schedule_id>/pause` |
| `POST` | `<workspace_url>/schedules/<schedule_id>/resume` |
| `GET` | `<workspace_url>/schedules/<schedule_id>/runs` |
| `GET` | `<workspace_url>/schedule-runs/<run_id>` |

## Sharing, preview, and applications

| Method | Route |
|---|---|
| `POST` | `<workspace_url>/shares` |
| `GET` | `<service-base>/shares/<share_id>` |
| `POST` | `<workspace_url>/shares/<share_id>/import` |
| `DELETE` | `<workspace_url>/shares/<share_id>` |
| `GET|HEAD` | `<preview-base>/<workspace-relative-path>` |
| `GET|HEAD|POST|PUT|PATCH|DELETE` | `<preview-base>/<app-path>/api/<route>` |

## Skill discovery and distribution

| Method | Route |
|---|---|
| `GET|HEAD` | `<service-base>/skills/openkapsel-rest` |
| `GET|HEAD` | `<service-base>/skills/openkapsel-rest/SKILL.md` |
| `GET|HEAD` | `<service-base>/skills/openkapsel-rest/archive.zip` |
| `GET|HEAD` | `<service-base>/skills/openkapsel-rest/{agents,references,scripts}/<file>` |

There is intentionally no MCP route in this skill.
## Client-backed mappings and transfers

- `POST /recycle/purge`: permanently remove one explicitly confirmed recycle entry.

- `GET /mappings`: mapped roots, `online`, `mounted`, `mount_references`,
  `native_mounts_enabled`, execution/RPC and `file_stream` capabilities. Online
  and unmounted is normal; file endpoints never start native mounts.
- `POST /rpc/<family>/<operation>`: invoke one RPC operation on the server workspace for an explicitly registered server family. Inspect Discovery/operation metadata for `write` and `execution`; `sync` returns directly and `task` returns HTTP 202 plus a normal server task id. `write=false` requires read permission; `write=true` requires control/write permission plus `plan_id`/`taskname`/`message`. Server task operations use the ordinary `/tasks` lifecycle. There is no fallback to a mapping after the server target is selected.
- `POST /mappings/<mapping_name>/rpc/<family>/<operation>`: invoke one advertised client RPC operation. Resolve the name from `GET /mappings`; legacy mapping IDs remain accepted for compatibility. Inspect `operation_specs.<operation>.write` and `execution`. `sync` returns directly; `task` returns HTTP 202 + a unified client task id and may take optional `timeout_seconds`. Writes require control/write permission, an administratively writable mapping, and `plan_id`/`taskname`/`message`. Task starts survive provider reconnects while the client process lives; do not replay an uncertain write-task start. If a start returns `409 client_task_capacity_reached`, collect completed client task results by reading output through each final offset before retrying; listing alone does not release retained results. No server/FUSE fallback.
- `POST /rpc/archive/list`: browse a server-side ZIP/tar archive without extracting.
- `POST /rpc/archive/read`: read a bounded server-side archive member preview.
- For mapped archives use `/mappings/<mapping_name>/rpc/archive/<operation>`.
- `POST /fs/write/copy`: start an asynchronous copy.
- `GET /fs/transfers/<id>`: inspect transfer progress.
- `POST /fs/transfers/<id>/cancel` and `/resume`: control transfers.

See [mappings.md](mappings.md) for permissions, request fields, and root-scoped recycling.

`structured` and `tabular` use the same generic mapping RPC route. See [data-rpc.md](data-rpc.md); `tabular.scan` is a read-only task, not a mutating Shell operation.

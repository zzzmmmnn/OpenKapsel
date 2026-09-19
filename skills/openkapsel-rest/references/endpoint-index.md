# Non-MCP HTTP endpoint index

This inventory is for routing. Read the focused reference and runtime Discovery before constructing nontrivial requests.

## Discovery and workspace files

| Method | Route |
|---|---|
| `GET` | `<workspace_url>/` |
| `GET` | `<workspace_url>/discovery/{files,context,memory,shell,schedules,web,sharing,full}` |
| `POST` | `<workspace_url>/credentials/renew` |
| `GET` | `<workspace_url>/fs/list` |
| `GET` | `<workspace_url>/fs/read` |
| `GET` | `<workspace_url>/fs/stat` |
| `POST` | `<workspace_url>/fs/manifest` |
| `POST` | `<workspace_url>/fs/read_many` |
| `GET` | `<workspace_url>/git/status` |
| `GET` | `<workspace_url>/git/diff` |
| `GET` | `<workspace_url>/git/diff_stat` |
| `GET` | `<workspace_url>/git/log` |
| `GET` | `<workspace_url>/git/show` |
| `GET` | `<workspace_url>/git/ls_files` |
| `GET` | `<workspace_url>/fs/search` |
| `GET` | `<workspace_url>/fs/tree` |
| `GET|HEAD|PUT` | `<workspace_url>/fs/content` |
| `POST` | `<workspace_url>/fs/write` |
| `POST` | `<workspace_url>/fs/replace` |
| `POST` | `<workspace_url>/fs/replace/batch` |
| `POST` | `<workspace_url>/fs/mkdir` |
| `POST` | `<workspace_url>/fs/delete` |
| `POST` | `<workspace_url>/fs/delete/batch` |
| `POST` | `<workspace_url>/fs/move` |
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

- `GET /mappings`: mapped roots, online state, and capabilities.
- `POST /fs/copy`: start an asynchronous copy.
- `GET /fs/transfers/<id>`: inspect transfer progress.
- `POST /fs/transfers/<id>/cancel` and `/resume`: control transfers.
- `GET/POST /mappings/<mapping_id>/tasks`: list/start client tasks.
- `GET /mappings/<mapping_id>/tasks/<task_id>`: incremental client task output.
- `POST /mappings/<mapping_id>/tasks/<task_id>/stdin`, `/interrupt`, `/kill`: control a client task.

See [mappings.md](mappings.md) for permissions, request fields, and root-scoped recycling.

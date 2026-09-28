# Project Memory

Memory stores durable cross-task facts separately from the short operation log. Read `GET /discovery/memory` for the live limits and completion schemas.

## Memory shape

The semantic payload is intentionally small:

- `content`: one self-contained durable fact
- `tags`: exact indexed retrieval signals
- `path`: one canonical impact scope

New Memory and replacement content is limited to 256 characters. Existing legacy content longer than 256 remains readable/searchable and may keep that content when only tags or path are changed. Replacing the content must satisfy the current 256-character limit.

At least one tag is required; prefer 4–16 specific reusable tags.

Canonical path forms are:

- `server:<path>`
- `mapping:<mapping_id>:<path>`
- `storage:<provider_id>:<path>`
- `server:.` for Workspace-global scope

Path matching uses ancestor/descendant overlap only within one target namespace/id. `server:.` is global. Mapping paths normalize Windows separators and compare case-insensitively. Target-machine absolute roots such as `/home/...` and `C:/...` are preserved. Older Memory databases are upgraded on first open: archived rows and legacy `outdated`/`superseded`/`resolved`/`wontfix` rows are discarded with their tags, revisions, and feedback; retained multi-path rows are collapsed to one conservative common `path`, and obsolete legacy columns/path tables are removed.

## Read and retrieve

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/memory/project` | Bounded recent/helpful active Memory profile |
| `GET` | `/memory` | Query Memory by content text, exact tag, or overlapping canonical path |
| `GET` | `/memory/<memory_id>` | Read the current record and response `ETag` |
| `GET` | `/memory/<memory_id>/revisions?limit=100` | Read newest revisions and attribution |

`GET /memory` filters are `query`, exact `tag`, overlapping `path`, `include_archived=false`, and `limit` up to the published maximum. Results prefer recent content updates or confirmed helpful use. Related-Memory ranking considers up to 2,000 active candidates; ordinary query and revision-history requests remain capped at 200 entries.

## Create manually

`POST /memory` requires the Bearer token and an owning Plan:

```json
{
  "content": "Wait for the async request before resetting the login form.",
  "tags": ["auth", "login", "async", "reset"],
  "path": "server:frontend/auth",
  "plan_id": 42,
  "taskname": "auth-update",
  "message": "Record the verified login rule"
}
```

`path` is optional for manual creation and defaults to `server:.` when omitted. The response uses `memory_id`, starts at revision `1`, and includes an `ETag`.

## Revise or archive

`PATCH /memory/<memory_id>` may change only `content`, `tags`, or `path`, plus `plan_id`, `taskname`, `message`, and the current revision. Supply concurrency validation either as `If-Match` or JSON `expected_revision`; re-read and reconcile on `412 memory_revision_conflict`.

`DELETE /memory/<memory_id>` soft-archives while retaining revisions. Send `expected_revision`, `plan_id`, `taskname`, and `message`, or use `If-Match`.

## Plan-completion Memory

Every `debrief.items[]` entry directly creates one new Memory. Multiple entries create multiple Memory records:

```json
{
  "items": [
    {
      "content": "Wait for login completion before resetting the form.",
      "tags": ["auth", "login", "async", "reset"]
    },
    {
      "content": "Reconnect recreates the WebSocket after heartbeat closure.",
      "tags": ["client", "mapping", "websocket", "reconnect"]
    }
  ],
  "outcome": "succeeded",
  "memory_actions": [],
  "memory_feedback": [],
  "memory_conflicts": []
}
```

Each item has `content` of 1–256 characters and required tags. The AI does not repeat a path in the debrief. The server derives one common path scope for every item from successful write operations directly owned by that Plan:

- server-local, each mapping ID, and each Storage Provider ID are separate targets
- paths on one target collapse to the deepest common directory
- cross-target writes collapse to `server:.`
- Shell contributes only its runtime `cwd`
- no usable write path also yields `server:.`

`memory_actions` only mutates existing Memory:

- `update`: requires `memory_id`, `expected_revision`, and at least one changed `content`, `tags`, or `path`
- `archive`: requires `memory_id` and `expected_revision`

`memory_feedback` lists only existing revisions that materially helped. Merely retrieved or unhelpful Memory is omitted. Helpful feedback updates usage metadata without adding a Memory revision.

`memory_conflicts` lists verified contradictions. Each conflict must be handled in the same completion by updating that Memory's `content` to the verified fact or archiving it. The same Memory cannot be both helpful and conflicting in one debrief.

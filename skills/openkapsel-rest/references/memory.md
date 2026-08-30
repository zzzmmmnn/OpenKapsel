# Project Memory

Memory stores durable cross-task knowledge separately from the short operation log. Read `GET /discovery/memory` for live enums, limits, and the complete discriminated `memory_actions` schema.

## Read and retrieve

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/memory/project` | Bounded project profile prioritizing overview, architecture, and open high-severity issues |
| `GET` | `/memory` | Query newest-first Memory summaries |
| `GET` | `/memory/<memory_id>` | Read full current record and response `ETag` |
| `GET` | `/memory/<memory_id>/revisions?limit=100` | Read newest revisions and attribution |

`GET /memory` filters: `query`, `category`, `status`, `severity`, exact `tag`, overlapping workspace-relative `path`, `include_archived=false`, and `limit` up to the published maximum. Fetch full content by ID only when a summary is relevant.

Categories are `overview`, `architecture`, `convention`, `decision`, and `known_issue`. Tags are exact indexed relevance signals. Path matching overlaps: a record scoped to `frontend/auth` is relevant to `frontend/auth/login.js`.

## Create

`POST /memory` requires the Bearer token and:

```json
{
  "category": "decision",
  "key": "optional-stable-key",
  "title": "Short title",
  "content": "Self-contained durable knowledge.",
  "status": "active",
  "severity": null,
  "tags": ["auth", "api"],
  "paths": ["src/auth"],
  "plan_id": 42,
  "taskname": "auth-update",
  "message": "Record the authentication decision"
}
```

`key`, `status`, `severity`, `tags`, and `paths` are optional subject to category compatibility. Severity is only for `known_issue`. The response consistently uses `memory_id`, starts at revision `1`, and includes an `ETag`.

## Revise or archive

`PATCH /memory/<memory_id>` accepts changed Memory fields plus `plan_id`, `taskname`, `message`, and the current revision. Supply concurrency validation either as `If-Match: "<revision>"` or JSON `expected_revision`; re-read and reconcile on `412 memory_revision_conflict`.

`DELETE /memory/<memory_id>` soft-archives while retaining revisions. Send a JSON body containing `expected_revision`, `plan_id`, `taskname`, and `message`, or use `If-Match` instead of `expected_revision`.

## Plan-completion Memory actions

`PATCH /context/plans/<id>` may execute up to 20 actions in debrief order:

- `create`: requires `action`, `category`, `title`, `content`; optionally `key`, compatible `status`/`severity`, `tags`, and `paths`.
- `update`: requires `action`, `memory_id`, `expected_revision`, plus at least one changed Memory field.
- `resolve`: requires `action`, `memory_id`, `expected_revision`; only for a `known_issue`, forces `status=resolved`, and may revise its final lesson fields.
- `archive`: requires only `action`, `memory_id`, and `expected_revision`.

Use the exact JSON Schema from `discovery/context` or `discovery/memory` when constructing nontrivial actions. An empty array explicitly means retain no long-term Memory.

Memory titles are short; content can be substantially longer than Context operation messages. Prefer self-contained statements that remain useful without the originating task transcript.

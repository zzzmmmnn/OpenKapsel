# Context, Plans, Notes, and mutation attribution

Context is the workspace operation history and task graph. It is not a session that must be opened. Read `GET /discovery/context` for live limits and the full Plan-debrief schema.

## Find or create a Plan

Query active root Plans before starting a mutation-heavy task:

```text
GET /context?type=plan&status=in_progress&root_plans=true&limit=20
```

Other composable query filters are `id`, `query`, `type`, `status`, `taskname`, `actor_id`, exact normalized `path`, direct `plan_id`, `root_plans`, `before_id`, and `limit`. Results are newest first; use `next_before_id` for pagination. `plan_id` cannot combine with `root_plans=true`.

Create a root Plan:

```json
POST /context
{
  "type": "plan",
  "taskname": "fix-preview",
  "content": "Diagnose and correct preview loading.",
  "scope_paths": ["site"],
  "memory_tags": ["preview"]
}
```

Omit `plan_id` for a root Plan. Supply a parent Plan ID to create a sub-plan. The response includes `id`, related Memory summaries, and previously existing unfinished root Plans; it excludes the newly created Plan and all sub-plans from that hint list.

Plans are hierarchical but not global locks. Independent agents may use different Plans or sub-plans concurrently.

## Attach work to a Plan

Every ordinary modifying REST endpoint requires the owning Plan's `plan_id`, a stable task grouping `taskname`, and a short `message`. OpenKapsel automatically records the resulting operation as `running`, then `succeeded` or `failed`. It filters result metadata and does not retain bodies, commands, stdin, stdout, stderr, or credentials.

Ordinary reads should omit Context parameters. To intentionally record a read, pass `taskname` and `message` together as query parameters; `plan_id` is optional but recommended.

`actor_id` is a SHA-256 pseudonymous identifier derived from the read URL token. It distinguishes tokens that share one workspace without storing a raw token.

## Plan tree and updates

`GET /context/plans/<plan_id>/tree?max_depth=8&limit=200` returns flat depth-annotated Plans plus operations and Notes attached to them. Rebuild hierarchy from each record's `id` and `plan_id`. Observe truncation fields.

`PATCH /context/plans/<id>` requires `taskname` and accepts optional replacement `content`, optional `plan_id` (`null` moves to root), and optional `status`: `in_progress`, `completed`, or `cancelled`. Parent cycles and self-parenting are rejected.

Completing a Plan requires:

```json
{
  "taskname": "fix-preview",
  "status": "completed",
  "debrief": {
    "summary": "Corrected asset loading and verified the preview.",
    "outcome": "succeeded",
    "memory_actions": []
  }
}
```

`outcome` is `succeeded`, `partial`, or `no_change`. Use `memory_actions: []` when there is no durable project knowledge. Otherwise read [memory.md](memory.md) and use its action shapes. A completed Plan cannot be completed again.

## Notes

Create a Note with `POST /context`:

```json
{
  "type": "note",
  "taskname": "fix-preview",
  "plan_id": 42,
  "content": "The failing asset uses a root-relative URL."
}
```

Replace a Note with `PATCH /context/notes/<note_id>` and JSON `taskname`, `plan_id`, and replacement `content`. Replacement atomically creates a newer ID and removes the old row, so recent queries surface the edit.

Context IDs are positive integers. New `taskname` values are limited to 32 characters; Plan/Note content is limited to the server-published maximum.

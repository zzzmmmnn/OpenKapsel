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

## Create a plan and direct subplans in one call

First check `capabilities.context.plan_creation.atomic_subplans` in runtime
Discovery. Older REST servers may ignore unknown fields; do not assume an older
server accepted a batch. MCP `add_context` and REST `POST /context` use the same
fields and creation logic:

```json
{
  "type": "plan",
  "taskname": "feature",
  "content": "Implement and verify the feature.",
  "request_id": "feature-20260921-01",
  "scope_paths": ["src"],
  "subplans": [
    {"ref": "implementation", "content": "Implement the code."},
    {"ref": "verification", "content": "Add regression tests.", "taskname": "feature-tests"}
  ]
}
```

Use a new caller-generated `request_id` for a new logical creation. It is an
optional retry key, not a plan ID, credential, or JSON-RPC envelope ID. A UUID is
suitable. It accepts 1-128 ASCII letters/digits/`.`/`_`/`:`/`-`, starting with a
letter or digit.

The response keeps the normal top-level plan `id` and adds compact `subplans` in
request order. Example IDs below are illustrative:

```json
{
  "id": 2000,
  "type": "plan",
  "taskname": "feature",
  "plan_id": null,
  "request_id": "feature-20260921-01",
  "replayed": false,
  "subplans": [
    {"index": 0, "ref": "implementation", "id": 2001, "plan_id": 2000, "taskname": "feature", "status": "in_progress"},
    {"index": 1, "ref": "verification", "id": 2002, "plan_id": 2000, "taskname": "feature-tests", "status": "in_progress"}
  ]
}
```

All validation and INSERTs are all-or-nothing in one SQLite transaction. A bad
child, duplicate `ref`, invalid parent, or database failure creates neither the
root nor any children. Use each returned child ID directly as `plan_id` on later
operations. Children remain ordinary, independently updateable plans; creating
or completing the parent does not run or automatically complete its children.

`subplans` accepts at most 64 **direct** children. Every child requires `content`;
`taskname` inherits from the newly created parent when omitted. Optional `status`
defaults independently to `in_progress`. Optional unique `ref` labels are echoed
with the assigned IDs (1-64 characters, the same ASCII character set as
`request_id`). Refs are request-local, not globally unique identifiers. Optional
`scope_paths` and `memory_tags` are accepted on children. Child metadata is stored
in its Context `request` field, so refs can also be recovered using the Plan tree.

Nested `subplans`, child `plan_id`, and arbitrary child fields are rejected.
For deeper levels, a later call may supply an existing parent `plan_id`, thereby
creating a new sub-plan with its own direct children. Omitting `subplans` or using
`[]` creates one plan as before. Notes do not accept `subplans` or `request_id`.

Content and taskname retain their existing per-entry limits. The combined
normalized creation request is bounded to 256 KiB of UTF-8 JSON. There may be at
most 64 distinct scope paths and 32 Memory tags across the entire batch. Memory
relevance uses the combined plan content and the union of paths/tags in one
lookup; only one deduplicated, bounded `related_memory` array is returned.
Previously existing unfinished root hints also appear once, never on each child.

### Safe retries and current-state reads

With `request_id`, the first creation returns HTTP 201 and `replayed:false`.
Repeating the same normalized request in the same workspace and stable actor
returns HTTP 200, `replayed:true`, and the **original creation receipt**, including
all original IDs. It does not restore old content, status, or parent relations.
Query the Plan tree for current state; Memory/root-plan hints in creation replies
are refreshed advisory data, not part of the immutable receipt. MCP returns the
same fields through its normal tool result envelope.

Changing the request while reusing its key returns 409 `context_request_conflict`.
Retries survive server restart and normal credential rotation because keys live
in the Context database and use the stable actor identity. Two actors/workspaces
can independently use the same key. Concurrent matching requests create one batch.
Without a key, requests are independent and must not be blindly replayed after an
uncertain network failure.

Context pruning never silently frees a used key. If an original plan was pruned,
retry returns 409 `context_request_gone` instead of creating replacement IDs.
The workspace ledger retains up to 100000 keys; when full, new keyed requests fail
with 409 `context_request_limit`, while retained requests remain replayable.
Deleting/resetting the Context database also resets its IDs and retry ledger;
keys are not a recovery mechanism after deliberate database deletion.

## Attach work to a Plan

Every ordinary modifying REST endpoint requires the owning Plan's `plan_id`, a stable task grouping `taskname`, and a short `message`. OpenKapsel automatically records the resulting operation as `running`, then `succeeded` or `failed`. It filters result metadata and does not retain bodies, commands, stdin, stdout, stderr, or credentials.

Ordinary reads should omit Context parameters. To intentionally record a read, pass `taskname` and `message` together as query parameters; `plan_id` is optional but recommended.

`actor_id` is a SHA-256 pseudonymous identifier derived from the stable app identity. It distinguishes configurations that share one workspace and remains stable when credentials rotate.

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

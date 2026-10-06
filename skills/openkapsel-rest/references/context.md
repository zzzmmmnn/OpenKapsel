# Context, Plans, Notes, and mutation attribution

Context is the workspace operation history and task graph. It is not a session that must be opened. Read `GET /discovery/context` for live limits and the full Plan-debrief schema.

## Conversation

Conversation is the recent user/AI context log that owns new Plans. It is append-only and lives beside Plan state in the Context database.

Before creating one, query history:

```text
GET /conversation?limit=100
```

The response includes `next_conversation_id`. IDs are non-negative, start at `0`, and cannot skip; pass that exact value to creation:

```json
{
  "conversation_id": 0,
  "entries": [
    {"role": "user", "content": "User wants the reconnect behavior fixed."},
    {"role": "ai", "content": "AI will inspect and update the client RPC path."}
  ]
}
```

`POST /conversation` returns the caller-supplied `conversation_id`, `writer_nonce` in exact `@xxxx@` form, the created records, and AI instructions. `writer_nonce` is not an authentication token; OpenKapsel stores its original value directly and later uses it only as the Conversation writer nonce.

Append with `POST /conversation/<conversation_id>/entries`:

```json
{
  "writer_nonce": "@a1B2@",
  "entries": [
    {"role": "user", "content": "User clarified the timeout must not break heartbeat."}
  ]
}
```

Each record receives an immutable per-Conversation `sub_id`. `user` and `ai` content is limited to 1,000 characters and is that side's conversation-context summary; it may preserve important original wording verbatim and does not need extra compression when the source already fits. `summary` may contain up to 8,192 characters and is not tied to a fixed sub-ID. After 40 user/ai entries since the newest summary, append responses return `summary_status.recommended=true` and identify the summary source range from that newest summary itself (or sub_id 1) through the latest entry. After 49 user/ai entries, the 49th is accepted but another user/ai entry is rejected until `role: "summary"` is appended. Summary resets the counter.

`GET /conversation?query=<text>&limit=100` searches across Conversations. By default it searches only each Conversation's newest summary plus records after it. Add `full=true` for complete history. Add `conversation_id=<id>&start_sub_id=<n>&end_sub_id=<n>` for an inclusive range inside one Conversation. The hard result limit is 100, and every query response includes `next_conversation_id` for the next creation call.

Public Plan creation requires `conversation_id`, `writer_nonce`, and non-empty `conversation_entries`; they are committed atomically with the Plan batch. Every non-cancellation-only Plan update requires the same fields. Completion additionally requires at least one new `role: "ai"` Conversation record. Cancellation-only deliberately omits the writer nonce requirement so a lost session does not leave a Plan impossible to close.

Plan completion locks and preflights Context before Memory. The server starts `BEGIN IMMEDIATE` on the Plan's Context database, dry-runs the complete Plan+Conversation update in a SAVEPOINT, rolls that SAVEPOINT back while retaining the outer write lock, applies every debrief Memory create/update/archive/helpful-feedback mutation in one atomic Memory transaction, then reruns and commits the Plan+Conversation update on the same Context connection. Memory remains a separate database, so a process/database failure after Memory succeeds but before the final Context commit can still leave Memory ahead of the Plan. That Memory remains revisioned and can be corrected with `memory_update` or `memory_archive`; query/reconcile it before retrying completion because repeating `debrief.items` can create duplicate new Memory records.

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
  "memory_tags": ["preview"],
  "conversation_id": 123,
  "writer_nonce": "@a1B2@",
  "conversation_entries": [
    {"role": "ai", "content": "AI is starting the preview diagnosis Plan."}
  ]
}
```

Omit `plan_id` for a root Plan. Supply a parent Plan ID to create a sub-plan. The response includes `id`, related Memory summaries, and previously existing unfinished root Plans; it excludes the newly created Plan and all sub-plans from that hint list.

Plans are hierarchical but not global locks. Independent agents may use different Plans or sub-plans concurrently.

## Create a plan and direct subplans in one call

First check `capabilities.context.plan_creation.atomic_subplans` in runtime
Discovery. Older REST servers may ignore unknown fields; do not assume an older
server accepted a batch. MCP `context_add` and REST `POST /context` use the same
fields and creation logic:

```json
{
  "type": "plan",
  "taskname": "feature",
  "content": "Implement and verify the feature.",
  "request_id": "feature-20260921-01",
  "scope_paths": ["src"],
  "conversation_id": 123,
  "writer_nonce": "@a1B2@",
  "conversation_entries": [
    {"role": "ai", "content": "AI is creating the feature Plan tree."}
  ],
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
creating a new sub-plan with its own direct children. Root Plan creation requires
`subplans`; use `[]` when there are no direct children. Sub-plan creation under
an existing parent may omit `subplans`. Notes do not accept `subplans` or
`request_id`.

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

`PATCH /context/plans/<id>` requires `taskname` and the current positive `expected_revision`, then accepts optional replacement `content`, optional `plan_id` (`null` moves to root), and optional `status`: `in_progress`, `completed`, or `cancelled`. Every successful update increments `revision`; stale revisions fail with HTTP 412. Parent cycles and self-parenting are rejected.

Completing a Plan requires:

```json
{
  "taskname": "fix-preview",
  "expected_revision": 1,
  "status": "completed",
  "debrief": {
    "items": [
      {
        "content": "Corrected asset loading and verified the preview.",
        "tags": ["preview", "assets", "loading", "verification"]
      }
    ],
    "outcome": "succeeded",
    "memory_actions": [],
    "memory_feedback": [],
    "memory_conflicts": []
  }
}
```

`items` is the structured debrief: every item directly creates one new long-lived Memory from `content` plus its own `tags`. Content is limited to 1-256 characters; tags are required and 4-16 specific reusable tags are recommended. All items created by one Plan receive the same server-derived canonical path scope from that Plan's successful writes. Use `items: []` when there is no new durable fact. `outcome` is `succeeded`, `partial`, or `no_change`. `memory_actions` only updates or archives existing Memory. `memory_feedback` contains only existing revisions that materially helped. `memory_conflicts` contains verified contradictions and requires a content update or archive for the same Memory revision before completion. See [memory.md](memory.md) for path derivation and action shapes. A completed Plan cannot be completed again. Older stored debriefs may expose `legacy_summary` instead of structured items.

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

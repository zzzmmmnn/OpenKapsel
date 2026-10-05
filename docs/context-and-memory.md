# Context and Memory

[Back to README](../README.md)

## Conversation

Conversation is the append-only recent-dialogue context used to carry user/AI intent across tool calls and Plans. It is stored in the same Context SQLite database as Plans so Plan changes and their required Conversation appends can commit or roll back together.

Each Conversation has two identifiers:

- `conversation_id`: a caller-supplied searchable non-negative integer. IDs start at `0` and must be strictly sequential. Before creating a Conversation, query Conversation history and use the returned `next_conversation_id`; creation rejects any other ID.
- `writer_nonce`: a six-character writer nonce in exact `@xxxx@` form, where the four inner characters are ASCII letters or digits. It is not an authentication token. OpenKapsel stores the original value directly in the Conversation row and returns it from creation so the current session can prove it owns later appends.

Create a Conversation atomically with at least two complete records. The first record must use `role: "user"` and the second `role: "ai"`. Creation may contain additional records and returns an instruction string telling the AI to append materially new context.

Conversation records are immutable and append-only. Each record has a per-Conversation positive `sub_id`, `role`, `content`, and timestamp. `role` is one of `user`, `ai`, or `summary`. `user` and `ai` content is limited to 1,000 characters and represents that side's conversation-context summary. It may preserve important original wording verbatim and does not need to be compressed again when the source already fits within the limit. `summary` content may contain up to 8,192 characters.

`summary` is not tied to a fixed `sub_id`. Count only `user`/`ai` entries since the newest summary. Once that count reaches 20, every successful append response includes `summary_status` with `recommended: true` and a source range for the next compressed aggregate summary. The source range begins at the newest summary entry itself, or at `sub_id` 1 when no summary exists, and ends at the latest entry. Once 30 `user`/`ai` entries have accumulated, the 30th entry is still accepted, but `summary_status.required_before_next_user_ai` becomes `true`; the next `user`/`ai` entry is rejected until `role: "summary"` is appended. A summary resets the counter and may therefore appear at any `sub_id`.

Cross-Conversation queries return at most 100 records and, by default, consider only each Conversation's newest `summary` plus all records after it. Set `full=true` to search complete history. When `conversation_id` is specified, `start_sub_id` and `end_sub_id` select an inclusive range. Query responses also return `next_conversation_id`, which is the only valid ID for the next `conversation_create` call.

Plan integration is mandatory on public REST/MCP surfaces:

- Plan creation requires `conversation_id`, its `writer_nonce`, and at least one `conversation_entries` item. The Conversation append, root Plan, and direct sub-Plans are one Context SQLite transaction.
- Every non-cancellation-only Plan update requires the same writer nonce and at least one Conversation entry, committed atomically with the Plan revision update.
- Plan completion additionally requires at least one new `role: "ai"` Conversation entry and the ordinary completion debrief.
- A cancellation-only update intentionally requires no `writer_nonce` or Conversation entry, so another session can close an abandoned Plan after the original session state is lost.
- Parent and child Plans cannot be moved across Conversations. Legacy Plans with no Conversation can be attached when a valid Conversation-aware update is made.

REST endpoints are `POST /conversation`, `GET /conversation`, and `POST /conversation/<conversation_id>/entries`. MCP exposes `conversation_create`, `conversation_query`, and `conversation_append`.

## Context

Each Workspace owns private Context storage under its reserved `.openkapsel` directory. Context is an append-oriented operation history and Plan tracker; it is not a session that must be opened or closed. IDs are auto-incrementing integers.

Entry types:

- `operation`: automatic REST or MCP mutation history with `running`, `succeeded`, or `failed`
- `plan`: AI-authored hierarchy with `in_progress`, `completed`, or `cancelled`
- `note`: AI-authored finding attached to a Plan

A root Plan has no parent. A Sub Plan references its parent. Operations and Notes reference their owning Plan. Parent cycles and self-parenting are rejected. Plan reads expose a positive `revision`; updates preserve the ID, require the current `expected_revision`, and increment `revision` on success so stale competing writers are rejected. Note editing creates a replacement record and deletes the old one atomically so recent queries find the replacement.

Every ordinary mutation requires a valid `plan_id`, `taskname`, and `message`. Task names are limited to 32 Unicode characters and operation messages to 200. Plan and Note content may contain up to 32,768 characters.

Reads are not recorded by default. To record a read, supply both task name and message; a Plan ID is optional but recommended.

`actor_id` is a SHA-256 pseudonymous identifier derived from the stable internal application ID. It distinguishes multiple token records sharing a Workspace without storing raw credentials and remains unchanged when read or control credentials rotate.

Creating a Plan returns up to twenty previously existing, unfinished root Plans in `unfinished_root_plans`. It excludes Sub Plans and the newly created Plan. Counts and truncation fields describe the complete result.

Plan creation may also include up to 64 direct `subplans`. The root and every child are validated and inserted atomically in one transaction: a bad child, duplicate request-local `ref`, invalid parent, or database failure creates none of them. Each child requires `content`; omitted `taskname` inherits from the new parent, `status` defaults independently to `in_progress`, and optional `scope_paths`, `memory_tags`, and unique `ref` are retained. Nested `subplans` are rejected; create deeper levels in a later call using an existing child as `plan_id`.

An optional caller-generated `request_id` makes Plan creation safely retryable for the same workspace and stable actor. The first matching creation returns the new receipt; an identical retry returns the original root/child IDs with `replayed=true` instead of creating duplicates. Reusing the key for different normalized content conflicts. A replay is an immutable creation receipt, not current Plan state, so query the Plan tree after a retry when later edits may have changed status/content. Omitting `request_id` preserves independent-create behavior.

Plan completion requires a debrief containing `items`, `outcome`, `memory_actions`, `memory_feedback`, and `memory_conflicts`. Each `items[]` entry contains one `content` value of 1–256 characters and its own required `tags`; 4–16 specific reusable tags are recommended. Every item directly creates one new long-lived Memory, so multiple items create multiple Memories. Use `items: []` when the Plan produced no new durable fact.

Completion crosses two independent stores but protects the Context side before touching Memory. OpenKapsel first starts `BEGIN IMMEDIATE` on the Plan's Context SQLite database, verifies the current Plan revision, and dry-runs the complete Plan+Conversation update inside a SAVEPOINT. The dry-run is rolled back while the outer Context write transaction remains open, so no competing Context writer can invalidate that successful preflight. OpenKapsel then applies the debrief's Memory create/update/archive work and finally reruns the already-preflighted Plan+Conversation update on the same Context connection before committing the Context transaction.

Memory is still not atomic with Plan+Conversation because it lives in a separate database. If Memory fails, the held Context transaction rolls back and the Plan/Conversation remain unchanged. If Memory succeeds but the final Context write or commit suffers a database/process-level failure, already-written Memory remains valid and can be repaired through normal revisioned `memory_update` or `memory_archive`. Before retrying such a failed completion, query/reconcile those Memory records first: blindly repeating the same `debrief.items` can create duplicate new Memory records.

Context result metadata excludes file bodies, commands, stdin, stdout, stderr, tokens, and Authorization headers. Queries support ID, text, type, status, task name, actor, normalized path, Plan ID, root-only filtering, and cursors. Results are newest first and limited to 200. The Plan-tree endpoint returns flat depth-annotated Plans and attached entries.

Each Workspace retains up to 100,000 Context entries. Overflow removes the oldest Operations and Notes in batches while preserving referenced Plans.

## Project Memory

Long-lived Memory uses a separate private store under `.openkapsel`. Its semantic payload is deliberately small:

- `content`: the durable fact itself
- `tags`: exact-match semantic retrieval signals
- `path`: one canonical impact scope

System-managed metadata such as `memory_id`, revision, timestamps, source Plan, helpful-use counters, and archive state remains available but is not part of the AI-authored Memory meaning.

New Memory and rewritten Memory content is limited to 256 characters. Existing legacy records whose content is longer remain readable and searchable. Updating only their tags or path preserves the long content unchanged; replacing their content must satisfy the 256-character limit.

Every Memory requires at least one tag and supports up to 32. Prefer 4–16 specific reusable tags rather than broad filler tags.

### Canonical path scopes

Memory path scopes use one of these forms:

- `server:<path>` — path in the Workspace/server-local tree
- `mapping:<mapping_id>:<path>` — path on a specific mapped client machine
- `storage:<provider_id>:<path>` — path inside a specific Storage Provider
- `server:.` — Workspace-global scope

Path overlap uses ancestor/descendant relationship only inside the same namespace and target. Different mapping IDs and different Storage Provider IDs do not overlap. Mapping paths normalize `\` to `/` and compare case-insensitively so Windows paths remain stable. Mapping/storage target paths preserve target-machine absolute roots such as `/home/...` or `C:/...`. `server:.` is global and overlaps every server, mapping, or storage scope. On first open of an older Memory database, archived rows and rows whose legacy status is `outdated`, `superseded`, `resolved`, or `wontfix` are discarded with their tags, revisions, and feedback. Remaining legacy unprefixed paths are normalized as server-local scopes and each multi-path row is permanently collapsed to one conservative common `path`; obsolete path storage and legacy semantic columns are removed in the same schema migration.

Manual Memory creation may supply one explicit canonical `path`; omitting it uses `server:.`. Plan-completion Memory does not ask the AI to repeat a path. The server scans all successful direct-owned operations, across Context query pages, and derives one common path for every Memory created from that Plan's debrief:

1. Consider only successful write operations directly owned by the completing Plan; descendant Sub Plan operations are not mixed in.
2. Convert each operation's affected file to its containing directory. Directory operations and Shell working directories already represent directories.
3. For paths on the same server/mapping/provider target, choose the deepest common directory.
4. If the common directory reaches the target root, use that root. If operations cross server/mapping/provider namespaces or different mapping/provider IDs, use the Workspace-global `server:.`.
5. Shell contributes only its runtime `cwd`; OpenKapsel does not attempt to infer additional files changed inside an arbitrary Shell command.
6. If no useful write path is available, use `server:.`.

All `debrief.items` from the same Plan receive that same derived path scope.

### Retrieval and feedback

Plan creation may include `scope_paths` and `memory_tags`. `related_memory` ranks compact Memory results using path overlap, exact tags, text relevance, and a small bounded bonus for prior confirmed helpful use. Related-Memory ranking considers up to 2,000 recent/helpful active candidates; ordinary Memory queries and revision-history reads remain capped at 200 entries per request. Memory queries prefer the most recent content update or confirmed helpful use.

`memory_feedback` contains only existing Memory revisions that materially helped the completed Plan. Merely retrieved, irrelevant, or unhelpful Memory is omitted. Helpful feedback updates usage metadata without creating a new Memory revision.

`memory_conflicts` records verified contradictions. A conflicting Memory must be handled in the same completion by either updating its `content` to the verified fact or archiving it. The same Memory cannot be both helpful and conflicting in one debrief.

### Existing-Memory actions

New Memory is created directly by `debrief.items`. `memory_actions` therefore only mutates existing Memory:

| Action | Required fields | Effect |
|---|---|---|
| `update` | `action`, `memory_id`, `expected_revision`, and at least one of `content`, `tags`, or `path` | Conditional revision |
| `archive` | `action`, `memory_id`, `expected_revision` | Soft archive with history |

Updates and archives require the current revision to prevent silent multi-agent overwrite. REST accepts the ETag through `If-Match` or `expected_revision`. Discovery and MCP expose the same action schema and consistently identify records with `memory_id`.

`.openkapsel` is private from file APIs, preview, application workers, sharing, and restricted Shell. Full Shell is outside the sandbox boundary and can alter Workspace-private files.

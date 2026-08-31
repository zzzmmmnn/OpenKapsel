# Context and Memory

[Back to README](../README.md)

## Context

Each Workspace owns `.context/context.sqlite3`. Context is an append-oriented operation history and Plan tracker; it is not a session that must be opened or closed. IDs are auto-incrementing integers.

Entry types:

- `operation`: automatic REST or MCP mutation history with `running`, `succeeded`, or `failed`
- `plan`: AI-authored hierarchy with `in_progress`, `completed`, or `cancelled`
- `note`: AI-authored finding attached to a Plan

A root Plan has no parent. A Sub Plan references its parent. Operations and Notes reference their owning Plan. Parent cycles and self-parenting are rejected. Plan updates preserve the ID; Note editing creates a replacement record and deletes the old one atomically so recent queries find the replacement.

Every mutation requires a valid `plan_id`, `taskname`, and `message`. Task names are limited to 32 Unicode characters and operation messages to 200. Plan and Note content may contain up to 32,768 characters.

Reads are not recorded by default. To record a read, supply both task name and message; a Plan ID is optional but recommended.

`actor_id` is a SHA-256 pseudonymous identifier derived from the URL token. It distinguishes multiple token records sharing a Workspace without storing raw credentials.

Creating a Plan returns up to twenty previously existing, unfinished root Plans in `unfinished_root_plans`. It excludes Sub Plans and the newly created Plan. Counts and truncation fields describe the complete result.

Plan completion requires a debrief containing `summary`, `outcome`, and `memory_actions`. Context result metadata excludes file bodies, commands, stdin, stdout, stderr, tokens, and Authorization headers.

Queries support ID, text, type, status, task name, actor, normalized path, Plan ID, root-only filtering, and cursors. Results are newest first and limited to 200. The Plan-tree endpoint returns flat depth-annotated Plans and attached entries.

Each Workspace retains up to 100,000 Context entries. Overflow removes the oldest Operations and Notes in batches while preserving referenced Plans.

## Project Memory

Long-lived Memory uses the separate `.context/memory.sqlite3`. It retains cross-task overview, architecture, conventions, decisions, and known issues without counting toward Context retention.

Categories are:

- `overview`
- `architecture`
- `convention`
- `decision`
- `known_issue`

Records contain a title, up to 32,768 characters of content, an optional stable key, up to 32 exact-match tags, up to 64 workspace-relative paths, status, severity, and revision.

Path queries use overlap semantics: `frontend/auth` matches `frontend/auth/login.js`. Known issues can be `open`, `resolved`, or `wontfix`, with `high`, `medium`, or `low` severity.

Create a Plan before changing Memory. Update and archive operations require the current revision to prevent silent multi-agent overwrite. REST accepts the ETag through `If-Match` or `expected_revision`.

Plan creation may include `scope_paths` and `memory_tags`. `related_memory` ranks summaries using path overlap, exact tags, text relevance, and open-issue severity. Fetch full content by `memory_id` only when needed.

Plan completion accepts up to twenty ordered `memory_actions`:

| Action | Required fields | Effect |
|---|---|---|
| `create` | `action`, `category`, `title`, `content` | Create revision 1 |
| `update` | `action`, `memory_id`, `expected_revision`, and a changed field | Conditional revision |
| `resolve` | `action`, `memory_id`, `expected_revision` | Resolve a known issue |
| `archive` | `action`, `memory_id`, `expected_revision` | Soft archive with history |

An empty array explicitly retains no new long-lived Memory. Discovery and MCP share the same discriminated action schema. Responses consistently use `memory_id`.

`.context` is private from file APIs, preview, application workers, and restricted Shell. Full Shell is outside the sandbox boundary and can alter Workspace-private files.

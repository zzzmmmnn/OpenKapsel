"""MCP protocol constants and tool definitions for OpenKapsel."""

from __future__ import annotations

import copy
from typing import Any

from openkapsel.contract import (
    MUTATION_MAX_ITEMS,
    conversation_entries_schema,
    conversation_id_schema,
    memory_content_schema,
    memory_id_schema,
    memory_path_schema,
    memory_tags_schema,
    mutation_item_schema,
    nonnegative_schema,
    operation_message_schema,
    path_schema,
    plan_creation_properties,
    plan_debrief_schema,
    plan_id_schema,
    plan_memory_tags_schema,
    plan_scope_paths_schema,
    plan_status_schema,
    positive_schema,
    revision_schema,
    taskname_schema,
    text_encoding_schema,
    writer_nonce_schema,
)
from openkapsel.context.conversation import (
    DEFAULT_RECENT_CONVERSATION_COUNT,
    MAX_RECENT_CONVERSATION_PAGES,
)
from openkapsel.auth.tokens import TokenRecord
from openkapsel import __version__


MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = {"2025-03-26", "2025-06-18", MCP_PROTOCOL_VERSION}
SERVER_VERSION = __version__
PUBLIC_SERVER_VERSION = SERVER_VERSION.split(".", 1)[0]


def _object_schema(
    properties: dict[str, Any],
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


def _tool(
    name: str,
    title: str,
    description: str,
    schema: dict[str, Any],
    *,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
    context_message: bool = True,
) -> dict[str, Any]:
    if context_message:
        schema["properties"]["plan_id"] = plan_id_schema(
            description=(
                "Owning Plan id; modifying operations require this Plan to be in_progress."
                if not read_only
                else "Optional owning Plan id for recorded reads."
            )
        )
        schema["properties"]["taskname"] = taskname_schema()
        schema["properties"]["message"] = operation_message_schema()
        if not read_only:
            required = schema.setdefault("required", [])
            for field in ("plan_id", "taskname", "message"):
                if field not in required:
                    required.append(field)
    return {
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world,
        },
    }


PATH = path_schema()
NONNEGATIVE = nonnegative_schema()
POSITIVE = positive_schema()
TEXT_ENCODING = text_encoding_schema()
_MCP_SHARED_SCHEMA_DESCRIPTIONS = {
    PATH.get("description"),
    TEXT_ENCODING.get("description"),
}
_MCP_SHARED_SCHEMA_DESCRIPTIONS.discard(None)
# These ownership rules are in MCP initialize instructions and Discovery/context.
# Do not repeat the same explanatory prose in dozens of tools/list schemas;
# required fields, JSON types and Plan validation are unchanged.
_MCP_SHARED_SCHEMA_DESCRIPTIONS.update({
    "Owning Plan id; modifying operations require this Plan to be in_progress.",
    "Optional owning Plan id for recorded reads.",
})


ALL_TOOLS: tuple[dict[str, Any], ...] = (
    _tool("fs_read_files", "Read files", "Read one or more bounded text files with explicit encoding (default UTF-8), shared character offset, per-item status/content/etag and partial errors. Use paths with one item for a single-file read.",
          _object_schema({"paths": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                          "encoding": TEXT_ENCODING, "offset": {**NONNEGATIVE, "default": 0},
                          "limit": {"type": "integer", "minimum": 1}, "max_total_chars": {"type": "integer", "minimum": 1}}, ("paths",)), read_only=True),
    _tool("fs_manifest", "File manifest", "Batch stat with items or recursive metadata with recursive=true and path. Optional SHA256, bounded traversal; items and recursive mode are mutually exclusive.",
          _object_schema({"items": {"type": "array", "items": _object_schema({"path": {"type": "string"}, "size": {"type": "integer", "minimum": 0}, "sha256": {"type": "string"}}, ("path",))},
                          "recursive": {"type": "boolean"}, "path": {"type": "string"}, "depth": {"type": "integer", "minimum": 0}, "include_sha256": {"type": "boolean"}}), read_only=True),
    _tool(
        "rpc_call",
        "Call RPC plugin",
        "Call one RPC family operation on the server workspace or a mapping. Omit mapping_id for server execution; for mapped execution pass the workspace mapping name. Legacy mapping IDs remain accepted for compatibility. operation metadata publishes description/input_schema/write/execution. execution=sync returns directly; execution=task returns a task_id inspected through capability_call family=task operations get/output. write=true operations require write permission plus plan_id/taskname/message, and plan_id must reference an in_progress Plan; mapped writes also require a writable mapping. Git fetch/pull/clone require the caller network policy. No server/mapping fallback is attempted after a target is selected.",
        _object_schema({
            "mapping_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", "description": "Optional workspace mapping name. Omit to execute the RPC family on the server workspace; legacy mapping IDs are also accepted."},
            "family": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
            "operation": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
            "args": {"type": "object", "default": {}},
            "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": 86400, "description": "Optional client task deadline for execution=task; cannot exceed the client max_seconds policy."},
            "plan_id": plan_id_schema(
                description="Required owning Plan id when operation_specs.<operation>.write is true."
            ),
            "taskname": taskname_schema(
                description="Required task grouping name for a write RPC operation."
            ),
            "message": operation_message_schema(
                description="Required short reason for a write RPC operation."
            ),
        }, ("family", "operation")),
        read_only=False,
        context_message=False,
    ),

    _tool(
        "capability_call",
        "Call auxiliary capability",
        "Call one low-frequency native capability operation by family and operation. Load operation_specs on demand from the matching Discovery capability section: shell also owns task; schedules, web, sharing, and authentication own their families. Like rpc_call, args contains only operation-specific fields; mutation Context stays in outer plan_id/taskname/message when required, and its plan_id must reference an in_progress Plan.",
        _object_schema({
            "family": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
            "operation": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
            "args": {"type": "object", "default": {}},
            "plan_id": plan_id_schema(
                description="Owning Plan id when operation_specs.<operation>.mutation_context is required."
            ),
            "taskname": taskname_schema(
                description="Task grouping name when mutation Context is required, or for optional read recording."
            ),
            "message": operation_message_schema(
                description="Short operation reason when mutation Context is required, or for optional read recording."
            ),
        }, ("family", "operation")),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "credential_get",
        "Get workspace REST credentials",
        "Return the linked configuration's current REST workspace URL, control token, and credential expiration. This exports portable REST credentials from an authenticated MCP connection; it does not rotate them.",
        _object_schema({}),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "credential_renew",
        "Renew workspace REST credentials",
        "Atomically rotate the linked configuration's REST URL token and control token using the normal self-renewal window. The previous REST credentials become invalid immediately; the MCP connection remains valid.",
        _object_schema({}),
        read_only=False,
        destructive=True,
        context_message=False,
    ),
    _tool(
        "discovery",
        "Workspace information",
        "Return the compact Discovery index by default, or one detailed Discovery section.",
        _object_schema(
            {
                "section": {
                    "type": "string",
                    "enum": ["main", "files", "context", "memory", "paths", "rpc", "network", "mcp", "shell", "schedules", "web", "sharing", "authentication", "errors", "full"],
                    "default": "main",
                    "description": "Discovery section to return. Use full only for compatibility or comprehensive inspection.",
                }
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "conversation_create",
        "Create conversation",
        "Create one append-only Conversation using the caller-supplied next sequential non-negative conversation_id. Call conversation_query first and use next_conversation_id exactly. The first record must be user and the second ai. Returns an opaque writer_nonce plus append instructions. Optional request_id makes retries idempotent and replays the original writer_nonce.",
        _object_schema(
            {
                "conversation_id": conversation_id_schema(
                    description="Required next sequential id from conversation_query.next_conversation_id; first id is 0."
                ),
                "entries": conversation_entries_schema(
                    min_items=2,
                    description="Initial Conversation records; the first must be user and the second ai.",
                ),
                "request_id": {
                    "type": "string", "minLength": 1, "maxLength": 128,
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                    "description": "Optional stable retry key for conversation creation. Same actor and identical request returns original writer_nonce and replayed=true; changed request conflicts.",
                },
            },
            ("conversation_id", "entries"),
        ),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "conversation_append",
        "Append conversation",
        "Atomically append one or more immutable Conversation records using conversation_id plus the writer_nonce returned by conversation_create. user/ai records are per-side context summaries (max 1000 chars); summary is the aggregate checkpoint. Responses include summary_status.",
        _object_schema(
            {
                "conversation_id": conversation_id_schema(),
                "writer_nonce": writer_nonce_schema(),
                "entries": conversation_entries_schema(),
            },
            ("conversation_id", "writer_nonce", "entries"),
        ),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "conversation_query",
        "Query conversations",
        f"Return Conversation history as grouped conversations in forward reading order. Without conversation_id, page defaults to 1 and returns {DEFAULT_RECENT_CONVERSATION_COUNT} non-empty Conversations ordered by their last entry time, each from its newest summary (or sub_id 1) forward; page is 1-{MAX_RECENT_CONVERSATION_PAGES}. With conversation_id, return the newest at most 100 entries, reordered oldest-to-newest for reading; start_sub_id/end_sub_id first restrict the range. Query output gives each Conversation one UTC date; entries on that date use HH:MM, or HH:MM:SS when a sub_id range is used, and entries on another date include YYYY-MM-DD.",
        _object_schema(
            {
                "conversation_id": conversation_id_schema(),
                "start_sub_id": {"type": "integer", "minimum": 1},
                "end_sub_id": {"type": "integer", "minimum": 1},
                "page": {"type": "integer", "minimum": 1, "maximum": MAX_RECENT_CONVERSATION_PAGES, "default": 1},
            }
        ),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "context_query",
        "Query workspace context",
        "Query operation, plan, and note records by id, text, actor, or path, newest first.",
        _object_schema(
            {
                "id": {"type": "integer", "minimum": 1},
                "query": {"type": "string", "default": ""},
                "type": {
                    "type": "string",
                    "description": "Optional operation, plan, or note filter.",
                    "default": "",
                },
                "status": {
                    "type": "string",
                    "description": "Optional operation or plan status filter.",
                    "default": "",
                },
                "taskname": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Exact task grouping name filter.",
                },
                "actor_id": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Exact anonymous actor_id filter.",
                },
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Exact normalized recorded path, source, destination, or cwd filter.",
                },
                "plan_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Exact direct parent/owning plan id filter.",
                },
                "root_plans": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return only root plans whose plan_id is null; cannot be combined with plan_id.",
                },
                "before_id": {"type": "integer", "minimum": 1},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
            }
        ),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "context_plan_tree",
        "Get context plan tree",
        "Return a bounded plan subtree plus operations and notes directly attached to its plans.",
        _object_schema(
            {
                "plan_id": {"type": "integer", "minimum": 1},
                "max_depth": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 32,
                    "default": 8,
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 200,
                },
            },
            ("plan_id",),
        ),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "context_add",
        "Add workspace context",
        "Append an AI-authored plan or note. Every created Plan starts in_progress and creation never accepts status. Root Plan creation must include subplans; use [] when no direct children are needed. A sub-plan requires both its direct parent and hierarchy root to remain in_progress; a note requires its owning Plan to be in_progress. A plan may include up to 64 direct subplans, created atomically and returned with all IDs and optional refs. Child taskname inherits when omitted. Optional request_id deduplicates retries per workspace/actor; changed requests conflict. Hints are returned once for the whole batch.",
        _object_schema(
            {
                "type": {
                    "type": "string",
                    "description": "plan or note",
                },
                **plan_creation_properties(),
                "content": {"type": "string", "minLength": 1},
                "taskname": taskname_schema(),
                "plan_id": plan_id_schema(
                    description="Parent Plan for a sub-plan or owning Plan for a note; the referenced Plan must be in_progress. Omit only for a root Plan."
                ),
                "scope_paths": plan_scope_paths_schema(
                    description="Optional workspace-relative paths used to retrieve related Memory when creating a plan."
                ),
                "memory_tags": plan_memory_tags_schema(
                    description="Optional exact Memory tags used to retrieve related Memory when creating a plan."
                ),
            },
            ("type", "content", "taskname"),
        ),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "context_plan_update",
        "Update context plan",
        "Update a plan in place using its current revision as an optimistic concurrency precondition. Plan parentage is fixed at creation and cannot be changed by updates. Completion is rejected while any descendant Plan is in_progress; completed or cancelled descendants are allowed.",
        _object_schema(
            {
                "id": {"type": "integer", "minimum": 1},
                "expected_revision": revision_schema(),
                "taskname": taskname_schema(),
                "content": {"type": "string", "minLength": 1},
                "status": plan_status_schema(),
                "conversation_id": conversation_id_schema(
                    description="Owning Conversation id. Required for every Plan update except cancellation-only."
                ),
                "writer_nonce": writer_nonce_schema(
                    description="Writer nonce returned for the owning Conversation; required except cancellation-only and passed unchanged."
                ),
                "conversation_entries": conversation_entries_schema(
                    description="Conversation records committed atomically with the Plan update. Completion must include at least one role=ai."
                ),
                "debrief": {
                    **plan_debrief_schema(),
                    "description": "Required when completing a plan: items, outcome, memory_actions, memory_feedback, and memory_conflicts. Each item directly creates one new long-lived Memory; multiple items create multiple Memories. Each item has 1-256 character content plus tags (prefer 4-16). One path is derived by the server from successful writes owned by the Plan. memory_actions only updates or archives existing Memory.",
                },
            },
            ("id", "expected_revision", "taskname"),
        ),
        read_only=False,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "memory_query",
        "Query project memory",
        "Query active or archived project-level Memory by content text, exact tag, or overlapping canonical path scope.",
        _object_schema(
            {
                "query": {"type": "string", "default": ""},
                "tag": {"type": "string"},
                "path": {
                    "type": "string",
                    "description": "Canonical scope such as server:src, mapping:<id>:C:/repo, storage:<id>:docs, or server:. for global scope.",
                },
                "include_archived": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
            }
        ),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "memory_get",
        "Get project memory",
        "Read one Memory by stable memory_id, optionally including its revision history.",
        _object_schema(
            {
                "memory_id": memory_id_schema(),
                "include_revisions": {"type": "boolean", "default": False},
                "revision_limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
            },
            ("memory_id",),
        ),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "memory_project",
        "Get project memory profile",
        "Return a bounded recent/helpful profile of active project Memory entries.",
        _object_schema({}),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "memory_add",
        "Add project memory",
        "Create a revisioned project Memory with short content, exact tags, and one optional canonical path.",
        _object_schema(
            {
                "content": memory_content_schema(),
                "tags": memory_tags_schema(
                    description="At least one tag is required; prefer 4-16 specific reusable exact-match tags."
                ),
                "path": memory_path_schema(
                    description="Optional canonical scope; omitted defaults to server:."
                ),
            },
            ("content", "tags"),
        ),
        read_only=False,
    ),
    _tool(
        "memory_update",
        "Update project memory",
        "Update content, tags, or path of one Memory using its current revision as an optimistic concurrency precondition. Legacy content longer than 256 characters may remain unchanged, but replacement content is limited to 256.",
        _object_schema(
            {
                "memory_id": memory_id_schema(),
                "expected_revision": revision_schema(),
                "content": memory_content_schema(),
                "tags": memory_tags_schema(),
                "path": memory_path_schema(),
            },
            ("memory_id", "expected_revision"),
        ),
        read_only=False,
        idempotent=True,
    ),
    _tool(
        "memory_archive",
        "Archive project memory",
        "Soft-delete one Memory while retaining its revision history.",
        _object_schema(
            {
                "memory_id": memory_id_schema(),
                "expected_revision": revision_schema(),
            },
            ("memory_id", "expected_revision"),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "context_note_replace",
        "Replace context note",
        "Edit a note by atomically inserting a newer note and deleting the old row.",
        _object_schema(
            {
                "id": {"type": "integer", "minimum": 1},
                "taskname": taskname_schema(),
                "content": {"type": "string", "minLength": 1},
                "plan_id": plan_id_schema(
                    description="Owning Plan id; replacement notes require this Plan to be in_progress."
                ),
            },
            ("id", "taskname", "content", "plan_id"),
        ),
        read_only=False,
        destructive=True,
        context_message=False,
    ),
    _tool(
        "fs_list",
        "List files",
        "List a directory with file types, sizes, and modification times. The private .recycle directory is hidden.",
        _object_schema(
            {
                "path": {**PATH, "default": "."},
                "offset": {**NONNEGATIVE, "default": 0},
                "limit": {**POSITIVE, "maximum": 5000, "default": 1000},
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "share_create",
        "Create temporary share",
        "Copy one workspace file or directory into the temporary shared area and return a random share ID. Shares expire after one day by default.",
        _object_schema({"path": PATH}, ("path",)),
        read_only=False,
    ),
    _tool(
        "share_query",
        "Inspect temporary share",
        "List an ID-addressed temporary share without requiring the creator's token.",
        _object_schema(
            {
                "share_id": {"type": "string", "minLength": 1},
                "path": {"type": "string", "default": ""},
                "depth": {**NONNEGATIVE, "default": 1},
            },
            ("share_id",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "share_import",
        "Import temporary share",
        "Copy a temporary share into a new path in this token's workspace. Existing destinations are never overwritten.",
        _object_schema(
            {
                "share_id": {"type": "string", "minLength": 1},
                "destination": PATH,
                "create_parents": {"type": "boolean", "default": False},
            },
            ("share_id", "destination"),
        ),
        read_only=False,
    ),
    _tool(
        "share_delete",
        "Delete temporary share",
        "Delete a temporary share early. Only the token application that created it may delete it.",
        _object_schema({"share_id": {"type": "string", "minLength": 1}}, ("share_id",)),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "fs_stat",
        "Get file information",
        "Return selected metadata. SHA-256 is only calculated when requested in fields.",
        _object_schema(
            {
                "path": PATH,
                "fields": {
                    "type": "string",
                    "description": "Comma-separated fields: type,size,created_at,modified_at,changed_at,etag,content_type,sha256.",
                    "default": "type,size,created_at,modified_at,etag,content_type",
                },
            },
            ("path",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "fs_find",
        "Find files by name",
        "Recursively find files and directories whose basename contains a literal query. Mapped roots use indexed file_search acceleration when available and otherwise fall back to recursive traversal.",
        _object_schema(
            {
                "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                "path": {**PATH, "default": "."},
                "max_results": {**POSITIVE, "default": 100},
                "case_sensitive": {"type": "boolean", "default": False},
                "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": 60, "default": 5},
            },
            ("query",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "fs_grep",
        "Grep file contents",
        "Search UTF-8 text across files with a bounded recursive depth. Supports literal or regex matching; binary and oversized files are skipped.",
        _object_schema(
            {
                "query": {"type": "string", "minLength": 1},
                "path": {**PATH, "default": "."},
                "depth": {**NONNEGATIVE, "default": 8},
                "max_results": {**POSITIVE, "default": 100},
                "regex": {"type": "boolean", "default": False},
                "case_sensitive": {"type": "boolean", "default": True},
                "include": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
                "exclude": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
            },
            ("query",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "fs_tree",
        "List directory tree",
        "Return a nested directory tree up to the requested recursive depth.",
        _object_schema(
            {
                "path": {**PATH, "default": "."},
                "depth": {**NONNEGATIVE, "default": 2},
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "fs_read_binary",
        "Read binary chunk",
        "Read a bounded byte range as Base64 for files up to 32 MiB. Larger files require fs_read_large.",
        _object_schema(
            {
                "path": PATH,
                "offset": {**NONNEGATIVE, "default": 0},
                "length": {**POSITIVE, "maximum": 1048576, "default": 262144},
            },
            ("path",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "fs_read_large",
        "Read large-file range",
        "Read one explicit byte range from a file larger than 32 MiB. Offset and length are required; returns Base64 bytes, exact ETag and range SHA-256 for a guarded equal-length replacement.",
        _object_schema(
            {
                "path": PATH,
                "offset": NONNEGATIVE,
                "length": {**POSITIVE, "maximum": 262144},
            },
            ("path", "offset", "length"),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "fs_download",
        "Prepare raw file download",
        "Return a token-free REST URL for raw byte download with HTTP Range. Reuse the MCP Bearer authorization header.",
        _object_schema({"path": PATH}, ("path",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "web_preview_url",
        "Get web preview URL",
        "Return the independently scoped browser preview URL for a path inside this token's child workspace.",
        _object_schema(
            {
                "path": {**PATH, "default": "."},
            }
        ),
        read_only=True,
        idempotent=True,
        open_world=True,
    ),
    _tool(
        "fs_write",
        "Write text file",
        "Create a new text file, or replace an existing one when exact expected_etag is supplied. This convenience tool uses the transactional mutation engine; create parent directories explicitly first.",
        _object_schema(
            {
                "path": PATH,
                "content": {"type": "string"},
                "encoding": TEXT_ENCODING,
                "expected_etag": {
                    "type": ["string", "null"],
                    "description": "Omit/null for create-only. Supply the exact current ETag to replace an existing file.",
                    "default": None,
                },
            },
            ("path", "content"),
        ),
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    _tool(
        "fs_edit_text",
        "Edit exact text",
        "Replace exact text or insert before/after an exact match transactionally. Requires the exact current ETag; optional line or unique text-marker bounds limit the editable range.",
        _object_schema(
            {
                "operation": {
                    "type": "string",
                    "enum": ["replace", "insert_before", "insert_after"],
                    "description": "replace requires old + new; insert_before and insert_after require match + content.",
                },
                "path": PATH,
                "old": {
                    "type": "string", "minLength": 1,
                    "description": "Used only with operation=replace; exact text to replace. Required for replace.",
                },
                "new": {
                    "type": "string",
                    "description": "Used only with operation=replace; replacement text. Required for replace.",
                },
                "match": {
                    "type": "string", "minLength": 1,
                    "description": "Used only with operation=insert_before or insert_after; exact anchor text. Required for both insert operations.",
                },
                "content": {
                    "type": "string",
                    "description": "Used only with operation=insert_before or insert_after; text to insert. Required for both insert operations.",
                },
                "encoding": TEXT_ENCODING,
                "expected_matches": {"type": "integer", "minimum": 1, "default": 1},
                "expected_etag": {"type": "string", "minLength": 1},
                "start_line": {
                    "type": "integer", "minimum": 0, "default": 0,
                    "description": "Zero-based inclusive first line; omit to start at line 0.",
                },
                "end_line": {
                    "type": "integer", "minimum": 0,
                    "description": "Zero-based inclusive last line; omit to continue through EOF.",
                },
                "start_text": {
                    "type": "string", "minLength": 1,
                    "description": "Unique full-file start marker; inclusive, so the marker text itself is inside the range; may span lines; mutually exclusive with start_line.",
                },
                "end_text": {
                    "type": "string", "minLength": 1,
                    "description": "Unique full-file end marker; inclusive, so the marker text itself is inside the range; may span lines; mutually exclusive with end_line.",
                },
            },
            ("operation", "path", "expected_etag"),
        ),
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    _tool(
        "fs_mutate",
        "Transactional file mutation",
        "Apply one transaction across paths in a single filesystem domain. Existing paths require exact ETags. Supports exact text replacement and insert-before/insert-after with optional line bounds or unique multiline full-file text markers, JSON/YAML/TOML structured patch, create-only files, whole-file replacement, and recoverable path.delete for files/directories. Match-count mismatches report observed counts without publishing changes. All preconditions are checked before publication and ordinary errors roll back the whole request. Content mutation above 32 MiB is rejected.",
        _object_schema(
            {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MUTATION_MAX_ITEMS,
                    "items": mutation_item_schema(),
                    "description": "Mutation items; operation-specific fields and preconditions are validated by the server.",
                },
                "dry_run": {"type": "boolean", "default": False},
            },
            ("items",),
        ),
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    _tool(
        "fs_replace_large",
        "Replace large-file range",
        "Replace one exact byte range in a file larger than 32 MiB without changing file size. Requires the exact ETag and range SHA-256 returned by fs_read_large; replacement byte length must equal length.",
        _object_schema(
            {
                "path": PATH,
                "offset": NONNEGATIVE,
                "length": {"type": "integer", "minimum": 1, "maximum": 262144},
                "data_base64": {"type": "string"},
                "expected_etag": {"type": "string", "minLength": 1},
                "expected_range_sha256": {
                    "type": "string",
                    "minLength": 64,
                    "maxLength": 64,
                },
            },
            ("path", "offset", "length", "data_base64", "expected_etag", "expected_range_sha256"),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "fs_mkdir",
        "Create directory",
        "Create a directory, optionally creating missing parent directories.",
        _object_schema(
            {
                "path": PATH,
                "parents": {"type": "boolean", "default": False},
                "exist_ok": {"type": "boolean", "default": False},
            },
            ("path",),
        ),
        read_only=False,
        idempotent=True,
    ),
    _tool(
        "fs_move",
        "Move or rename path",
        "Move or rename a file or directory. Existing destinations are protected unless overwrite is explicitly true.",
        _object_schema(
            {
                "source": PATH,
                "destination": PATH,
                "overwrite": {"type": "boolean", "default": False},
                "create_parents": {"type": "boolean", "default": False},
            },
            ("source", "destination"),
        ),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "fs_delete",
        "Recycle path",
        "Transactionally recycle a file or directory. Requires the exact current ETag returned by fs_stat or read_files.",
        _object_schema(
            {
                "path": PATH,
                "expected_etag": {"type": "string", "minLength": 1},
            },
            ("path", "expected_etag"),
        ),
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    _tool(
        "recycle_list",
        "List recycle items",
        "List recoverably deleted items in the server, mapped client, or Storage Provider recycle bin.",
        _object_schema(
            {
                "offset": {**NONNEGATIVE, "default": 0},
                "limit": {**POSITIVE, "maximum": 5000, "default": 1000},
                "root": {"type": "string", "default": ".", "description": "'.' for server, or a mapped client/Storage Provider name"},
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "recycle_restore",
        "Restore recycle item",
        "Restore a recycle item to its original path within the selected backend. Refuses overwrite.",
        _object_schema({"recycle_id": {"type": "string"},
                        "root": {"type": "string", "default": ".", "description": "'.' for server, or a mapped client/Storage Provider name"}},
                       ("recycle_id",)),
        read_only=False,
        destructive=False,
    ),
    _tool(
        "upload_create",
        "Start resumable upload",
        "Create a token-bound resumable binary upload session for a new file. Existing destinations must first be moved to the recycle bin. The result includes token-free URLs for efficient raw-byte transfer.",
        _object_schema(
            {
                "path": PATH,
                "size": NONNEGATIVE,
                "sha256": {"type": ["string", "null"], "default": None},
                "create_parents": {"type": "boolean", "default": False},
            },
            ("path", "size"),
        ),
        read_only=False,
    ),
    _tool(
        "upload_chunk",
        "Upload binary chunk",
        "Append one Base64-encoded chunk at the current upload offset.",
        _object_schema(
            {
                "upload_id": {"type": "string"},
                "offset": NONNEGATIVE,
                "data_base64": {"type": "string"},
            },
            ("upload_id", "offset", "data_base64"),
        ),
        read_only=False,
    ),
    _tool(
        "upload_status",
        "Get upload status",
        "Return the current offset, expected size, and expiry for an upload session.",
        _object_schema({"upload_id": {"type": "string"}}, ("upload_id",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "upload_commit",
        "Finish upload",
        "Verify size and optional SHA-256, then atomically commit the uploaded file.",
        _object_schema({"upload_id": {"type": "string"}}, ("upload_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "upload_cancel",
        "Abort upload",
        "Cancel an incomplete upload and remove its temporary data.",
        _object_schema({"upload_id": {"type": "string"}}, ("upload_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "schedule_read",
        "Read schedules",
        "Read schedules or schedule runs. operation=list|get|run_list|run_get.",
        _object_schema(
            {
                "operation": {"type": "string", "enum": ["list", "get", "run_list", "run_get"]},
                "schedule_id": {"type": "string"},
                "run_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            },
            ("operation",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "schedule_write",
        "Create or update schedule",
        "Create or update a schedule. create needs name/schedule/command; update needs schedule_id/expected_revision.",
        _object_schema(
            {
                "operation": {"type": "string", "enum": ["create", "update"]},
                "schedule_id": {"type": "string"},
                "expected_revision": {"type": "integer", "minimum": 1},
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "schedule": {"type": "object"},
                "command": {"type": "string", "minLength": 1, "maxLength": 100000},
                "cwd": {"type": "string"},
                "timeout_seconds": {"type": ["number", "null"], "minimum": 0.1, "maximum": 86400},
                "overlap_policy": {"type": "string", "enum": ["skip"]},
                "misfire_policy": {"type": "string", "enum": ["skip", "coalesce"]},
                "run_context": {"type": "object"},
            },
            ("operation",),
        ),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "schedule_control",
        "Control schedule",
        "End, execute, pause, or resume one schedule. end preserves the schedule and run history; status defaults to stopped and may be stopped or completed.",
        _object_schema(
            {
                "operation": {"type": "string", "enum": ["end", "execute", "pause", "resume"]},
                "schedule_id": {"type": "string"},
                "status": {"type": "string", "enum": ["stopped", "completed"], "default": "stopped"},
            },
            ("operation", "schedule_id"),
        ),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "shell_exec",
        "Run shell command",
        "Start an asynchronous Shell task. target=auto routes a mapped cwd to its client and other cwd to the server; client failures do not fall back. Returned task_id values use capability_call family=task operations. Client execution uses client-local policy and environment.",
        _object_schema(
            {
                "command": {"type": "string", "minLength": 1},
                "mount_mappings": {"type": "array", "items": {"type": "string"}, "maxItems": 256, "description": "Server-only native mapping dependencies by name or ID. Mapped cwd is automatic; command text is not inspected."},
                "target": {"type": "string", "enum": ["auto", "server", "client"], "default": "auto"},
                "cwd": {
                    "type": "string",
                    "description": "Working directory. Relative paths use the token workspace; external absolute paths must be in the token's extra accessible directory list (full shell commands themselves are unsandboxed).",
                    "default": ".",
                },
                "timeout_seconds": {
                    "type": ["number", "null"],
                    "minimum": 0.1,
                    "maximum": 86400,
                    "default": None,
                },
                "interactive": {
                    "type": "boolean",
                    "description": "Keep stdin open for task_stdin calls.",
                    "default": False,
                },
            },
            ("command",),
        ),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "task_get",
        "Get task status",
        "Poll a server or client task for status, exit code, output, and output cursors; use family=task operation=output to continue reading.",
        _object_schema({"task_id": {"type": "string"}}, ("task_id",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "task_list",
        "List shell tasks",
        "List server token tasks and workspace client tasks without full output. target=auto includes both; unavailable_mappings reports clients whose tasks could not be queried.",
        _object_schema(
            {
                "offset": {**NONNEGATIVE, "default": 0},
                "limit": {**POSITIVE, "maximum": 1000, "default": 100},
                "status": {"type": "string", "default": ""},
                "target": {"type": "string", "enum": ["auto", "server", "client"], "default": "auto"},
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "sandbox_processes",
        "List sandbox processes",
        "List restricted Shell processes and aggregate resource usage.",
        _object_schema(
            {
                "offset": {**NONNEGATIVE, "default": 0},
                "limit": {**POSITIVE, "maximum": 1000, "default": 100},
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "task_output",
        "Read incremental task output",
        "Read task output from byte cursors, optionally waiting for new output. Client output may be combined in stdout; advance the returned next offsets.",
        _object_schema(
            {
                "task_id": {"type": "string"},
                "stdout_offset": {**NONNEGATIVE, "default": 0},
                "stderr_offset": {**NONNEGATIVE, "default": 0},
                "limit": {**POSITIVE, "maximum": 262144, "default": 65536},
                "wait_seconds": {"type": "number", "minimum": 0, "maximum": 30, "default": 0},
            },
            ("task_id",),
        ),
        read_only=True,
    ),
    _tool(
        "task_stdin",
        "Send task input",
        "Send UTF-8 or Base64 input to an interactive task and optionally close stdin; data and close=true may be sent together.",
        _object_schema(
            {
                "task_id": {"type": "string"},
                "data": {"type": "string"},
                "data_base64": {"type": "string"},
                "close": {"type": "boolean", "default": False},
            },
            ("task_id",),
        ),
        read_only=False,
    ),
    _tool(
        "task_interrupt",
        "Interrupt task",
        "Request normal termination of a running task. Use family=task operation=kill only when immediate forced termination is required.",
        _object_schema({"task_id": {"type": "string"}}, ("task_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "task_kill",
        "Force-kill task",
        "Force-stop a running task immediately.",
        _object_schema({"task_id": {"type": "string"}}, ("task_id",)),
        read_only=False,
        destructive=True,
    ),
)


_AUX_CONTEXT_FIELDS = {"plan_id", "taskname", "message"}

# Low-frequency tool definitions remain internal execution contracts. They are
# no longer advertised individually through tools/list; capability_call selects
# one operation and Discovery publishes its schema only when requested.
_AUXILIARY_OPERATION_MAP: dict[
    str,
    dict[str, tuple[str, str | None, tuple[str, ...] | None, tuple[str, ...], str]],
] = {
    "credential": {
        "get": ("credential_get", None, (), (), "sync"),
        "renew": ("credential_renew", None, (), (), "sync"),
    },
    "sharing": {
        "create": ("share_create", None, None, ("path",), "sync"),
        "query": ("share_query", None, None, ("share_id",), "sync"),
        "import": ("share_import", None, None, ("share_id", "destination"), "sync"),
        "delete": ("share_delete", None, None, ("share_id",), "sync"),
    },
    "web": {
        "preview_url": ("web_preview_url", None, None, (), "sync"),
    },
    "schedule": {
        "list": ("schedule_read", "list", (), (), "sync"),
        "get": ("schedule_read", "get", ("schedule_id",), ("schedule_id",), "sync"),
        "run_list": (
            "schedule_read", "run_list", ("schedule_id", "limit"), ("schedule_id",), "sync"
        ),
        "run_get": ("schedule_read", "run_get", ("run_id",), ("run_id",), "sync"),
        "create": (
            "schedule_write", "create",
            ("name", "schedule", "command", "cwd", "timeout_seconds", "overlap_policy", "misfire_policy", "run_context"),
            ("name", "schedule", "command"), "sync",
        ),
        "update": (
            "schedule_write", "update",
            ("schedule_id", "expected_revision", "name", "schedule", "command", "cwd", "timeout_seconds", "overlap_policy", "misfire_policy", "run_context"),
            ("schedule_id", "expected_revision"), "sync",
        ),
        "end": ("schedule_control", "end", ("schedule_id", "status"), ("schedule_id",), "sync"),
        "execute": ("schedule_control", "execute", ("schedule_id",), ("schedule_id",), "sync"),
        "pause": ("schedule_control", "pause", ("schedule_id",), ("schedule_id",), "sync"),
        "resume": ("schedule_control", "resume", ("schedule_id",), ("schedule_id",), "sync"),
    },
    "shell": {
        "exec": ("shell_exec", None, None, ("command",), "task"),
        "processes": ("sandbox_processes", None, None, (), "sync"),
    },
    "task": {
        "get": ("task_get", None, None, ("task_id",), "sync"),
        "list": ("task_list", None, None, (), "sync"),
        "output": ("task_output", None, None, ("task_id",), "sync"),
        "stdin": ("task_stdin", None, None, ("task_id",), "sync"),
        "interrupt": ("task_interrupt", None, None, ("task_id",), "sync"),
        "kill": ("task_kill", None, None, ("task_id",), "sync"),
    },
}
_AUXILIARY_TOOL_NAMES = {
    entry[0]
    for operations in _AUXILIARY_OPERATION_MAP.values()
    for entry in operations.values()
}


def _tool_index() -> dict[str, dict[str, Any]]:
    return {tool["name"]: tool for tool in ALL_TOOLS}


def _authorized_tool_names(record: TokenRecord, recycle_enabled: bool) -> set[str]:
    names = {
        "discovery",
        "credential_get",
        "credential_renew",
        "share_query",
        "share_delete",
        "conversation_create",
        "conversation_append",
        "context_add",
        "context_plan_update",
        "context_note_replace",
        "memory_add",
        "memory_update",
        "memory_archive",
    }
    if record.can_read or record.can_write:
        names.add("rpc_call")
    if record.can_read:
        names.update({"fs_read_files", "fs_manifest"})
        names.update({
            "conversation_query", "context_query", "context_plan_tree",
            "memory_query", "memory_get", "memory_project",
            "fs_list", "fs_stat", "fs_read_binary", "fs_read_large", "fs_download",
            "fs_find", "fs_grep", "fs_tree", "share_create",
        })
        if record.can_preview:
            names.add("web_preview_url")
        if recycle_enabled:
            names.add("recycle_list")
    if record.can_write:
        names.update({
            "fs_write", "fs_edit_text", "fs_mutate", "fs_replace_large", "fs_mkdir",
            "fs_move", "upload_create", "upload_chunk", "upload_status", "upload_commit",
            "upload_cancel", "share_import",
        })
        if recycle_enabled:
            names.update({"fs_delete", "recycle_restore"})
    if record.can_read or record.can_write:
        names.update({"task_get", "task_list", "task_output", "task_interrupt", "task_kill"})
    if record.shell_mode != "none":
        names.update({"shell_exec", "task_stdin"})
        if record.can_schedule:
            names.update({"schedule_read", "schedule_write", "schedule_control"})
    if record.shell_mode == "restricted":
        names.add("sandbox_processes")
    return names


def _auxiliary_operation_schema(
    tool: dict[str, Any],
    fields: tuple[str, ...] | None,
    required: tuple[str, ...],
) -> dict[str, Any]:
    source = tool["inputSchema"]["properties"]
    selected = (
        [name for name in source if name not in _AUX_CONTEXT_FIELDS | {"operation"}]
        if fields is None
        else list(fields)
    )
    return _object_schema(
        {name: copy.deepcopy(source[name]) for name in selected},
        required,
    )


def auxiliary_operations_for(
    record: TokenRecord,
    recycle_enabled: bool,
) -> dict[str, dict[str, Any]]:
    authorized = _authorized_tool_names(record, recycle_enabled)
    tools = _tool_index()
    result: dict[str, dict[str, Any]] = {}
    for family, operations in _AUXILIARY_OPERATION_MAP.items():
        specs: dict[str, Any] = {}
        for operation, (tool_name, _injected_operation, fields, required, execution) in operations.items():
            if tool_name not in authorized:
                continue
            tool = tools[tool_name]
            write = not tool["annotations"]["readOnlyHint"]
            mutation_context = all(
                field in tool["inputSchema"].get("required", [])
                for field in ("plan_id", "taskname", "message")
            )
            specs[operation] = {
                "description": tool["description"],
                "input_schema": _auxiliary_operation_schema(tool, fields, required),
                "write": write,
                "execution": execution,
                "mutation_context": mutation_context,
                "optional_read_context": not write and bool(
                    _AUX_CONTEXT_FIELDS & tool["inputSchema"]["properties"].keys()
                ),
            }
        if specs:
            result[family] = {"operation_specs": specs}
    return result


def resolve_auxiliary_operation(
    record: TokenRecord,
    recycle_enabled: bool,
    family: str,
    operation: str,
) -> tuple[dict[str, Any], str, str | None, dict[str, Any]]:
    family_ops = _AUXILIARY_OPERATION_MAP.get(family)
    if family_ops is None or operation not in family_ops:
        raise KeyError("unknown auxiliary capability operation")
    tool_name, injected_operation, fields, required, _execution = family_ops[operation]
    if tool_name not in _authorized_tool_names(record, recycle_enabled):
        raise PermissionError("auxiliary capability operation is not authorized")
    tool = _tool_index()[tool_name]
    schema = _auxiliary_operation_schema(tool, fields, required)
    return tool, tool_name, injected_operation, schema



def _compact_public_schema_descriptions(value: Any) -> None:
    if isinstance(value, dict):
        if value.get("description") in _MCP_SHARED_SCHEMA_DESCRIPTIONS:
            value.pop("description", None)
        for child in value.values():
            _compact_public_schema_descriptions(child)
    elif isinstance(value, list):
        for child in value:
            _compact_public_schema_descriptions(child)


def tools_for(
    record: TokenRecord,
    recycle_enabled: bool,
    mcp_binary_chunk_bytes: int = 256 * 1024,
) -> list[dict[str, Any]]:
    authorized = _authorized_tool_names(record, recycle_enabled)
    public_names = authorized - _AUXILIARY_TOOL_NAMES
    if auxiliary_operations_for(record, recycle_enabled):
        public_names.add("capability_call")
    selected = [copy.deepcopy(tool) for tool in ALL_TOOLS if tool["name"] in public_names]
    for tool in selected:
        _compact_public_schema_descriptions(tool["inputSchema"])
        if tool["name"] == "fs_read_binary":
            length = tool["inputSchema"]["properties"]["length"]
            length["maximum"] = mcp_binary_chunk_bytes
            length["default"] = mcp_binary_chunk_bytes
    return selected


def validate_arguments(tool: dict[str, Any], arguments: dict[str, Any]) -> None:
    schema = tool["inputSchema"]
    properties = schema["properties"]
    unexpected = sorted(set(arguments) - set(properties))
    if unexpected:
        raise ValueError(f"unexpected argument(s): {', '.join(unexpected)}")
    missing = [key for key in schema.get("required", []) if key not in arguments]
    if missing:
        raise ValueError(f"missing required argument(s): {', '.join(missing)}")
    for key, value in arguments.items():
        rule = properties[key]
        allowed = rule.get("type")
        allowed_types = allowed if isinstance(allowed, list) else [allowed]
        valid = False
        for expected in allowed_types:
            if expected == "null" and value is None:
                valid = True
            elif expected == "string" and isinstance(value, str):
                valid = True
            elif expected == "boolean" and isinstance(value, bool):
                valid = True
            elif expected == "integer" and isinstance(value, int) and not isinstance(value, bool):
                valid = True
            elif expected == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
                valid = True
            elif expected == "array" and isinstance(value, list):
                valid = True
            elif expected == "object" and isinstance(value, dict):
                valid = True
        if not valid:
            raise ValueError(f"{key} has an invalid type")
        if value is not None and "minimum" in rule and value < rule["minimum"]:
            raise ValueError(f"{key} must be >= {rule['minimum']}")
        if value is not None and "maximum" in rule and value > rule["maximum"]:
            raise ValueError(f"{key} must be <= {rule['maximum']}")
        if isinstance(value, str) and len(value) < rule.get("minLength", 0):
            raise ValueError(f"{key} is too short")
        if isinstance(value, str) and len(value) > rule.get("maxLength", len(value)):
            raise ValueError(f"{key} is too long")
        if isinstance(value, list) and len(value) > rule.get("maxItems", len(value)):
            raise ValueError(f"{key} contains too many items")
        if value is not None and "enum" in rule and value not in rule["enum"]:
            raise ValueError(f"{key} must be one of: {', '.join(map(str, rule['enum']))}")

"""MCP protocol constants and tool definitions for OpenKapsel."""

from __future__ import annotations

import copy
from typing import Any

from .memory_contracts import plan_debrief_schema
from .context_plans import creation_properties
from .tokens import TokenRecord
from .git_operations import GIT_OPERATIONS, git_tool_properties
from . import __version__


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
        schema["properties"]["plan_id"] = {
            "type": "integer",
            "minimum": 1,
            "description": (
                "Required owning plan id for a modifying operation. For a recorded "
                "read it is optional and associates the read with that plan."
            ),
        }
        schema["properties"]["taskname"] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 32,
            "description": (
                "Required task grouping name for a modifying operation. For reads, "
                "taskname and message are optional as a pair."
            ),
        }
        schema["properties"]["message"] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": (
                "Required brief reason for a modifying operation. For reads, taskname "
                "and message are optional as a pair; an unlabelled read is not recorded."
            ),
        }
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


PATH = {
    "type": "string",
    "description": "Path relative to the token workspace, or an absolute path inside it or an authorized extra directory.",
}
NONNEGATIVE = {"type": "integer", "minimum": 0}
POSITIVE = {"type": "integer", "minimum": 1}
from .text_encoding import ENCODINGS
TEXT_ENCODING = {"type": "string", "enum": list(ENCODINGS), "default": "utf-8",
                 "description": "Explicit file encoding; strict conversion. LF/CRLF/CR are preserved literally. UTF-16 requires explicit endian; BOM is preserved as U+FEFF."}


ALL_TOOLS: tuple[dict[str, Any], ...] = (
    _tool("read_files", "Read multiple files", "Read bounded text files with explicit encoding (default UTF-8), per-item status/content/etag and partial errors. No write or Shell permission required.",
          _object_schema({"paths": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                          "encoding": TEXT_ENCODING, "limit": {"type": "integer", "minimum": 1}, "max_total_chars": {"type": "integer", "minimum": 1}}, ("paths",)), read_only=True),
    _tool("file_manifest", "File manifest", "Batch stat with items or recursive metadata with recursive=true and path. Optional SHA256, bounded traversal; items and recursive mode are mutually exclusive.",
          _object_schema({"items": {"type": "array", "items": _object_schema({"path": {"type": "string"}, "size": {"type": "integer", "minimum": 0}, "sha256": {"type": "string"}}, ("path",))},
                          "recursive": {"type": "boolean"}, "path": {"type": "string"}, "depth": {"type": "integer", "minimum": 0}, "include_sha256": {"type": "boolean"}}), read_only=True),
    *(_tool("git_" + operation, "Git " + operation.replace("_", " "),
            "Read-only Git inspection using a bounded sanitized snapshot, locally or in one mapped client RPC. Read permission only: no Shell/write/allow_exec required. Synchronous text result, no task. Ordinary SHA-1 .git directory required; no linked worktrees/alternates/symlinks. Snapshot max 128 MiB/100000 nodes, output 64 KiB per stream, timeout at most 20s. Source config/hooks/filters are not loaded. Git must be installed on the host.",
            _object_schema(git_tool_properties(operation)), read_only=True)
      for operation in GIT_OPERATIONS),
    _tool(
        "archive_list",
        "List archive contents",
        "Browse one ZIP or standard-library tar archive without extracting it. Mapped paths use the Archive RPC plugin; ordinary workspace paths are inspected locally.",
        _object_schema({
            "path": PATH,
            "inner_path": {"type": "string", "default": "", "description": "Archive-internal directory path."},
            "offset": NONNEGATIVE,
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
        }, ("path",)),
        read_only=True,
    ),
    _tool(
        "archive_read",
        "Read archive member",
        "Read a bounded member preview from one ZIP or standard-library tar archive without extracting it. Returns text when decoding succeeds and Base64 bytes always.",
        _object_schema({
            "path": PATH,
            "member": {"type": "string", "minLength": 1},
            "offset": {"type": "integer", "minimum": 0, "maximum": 16777216, "default": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 262144, "default": 65536},
            "encoding": TEXT_ENCODING,
        }, ("path", "member")),
        read_only=True,
    ),
    _tool(
        "rpc",
        "Call mapping RPC plugin",
        "Call one dynamic RPC plugin operation on a mapping. Inspect mappings first: operation_specs.<operation> publishes description/input_schema/write/execution. execution=sync returns the result directly; execution=task returns a task_id immediately and continues on the client across provider reconnects—poll it with get_task/read_task_output and do not replay a write RPC after transport uncertainty. write=true operations require write permission, control authorization, a writable mapping, and plan_id/taskname/message. New plugin families require no new MCP tool. No server/FUSE fallback is attempted.",
        _object_schema({
            "mapping_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{24}$"},
            "family": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
            "operation": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
            "args": {"type": "object", "default": {}},
            "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": 86400, "description": "Optional client task deadline for execution=task; cannot exceed the client max_seconds policy."},
            "plan_id": {"type": "integer", "minimum": 1, "description": "Required owning Plan id when operation_specs.<operation>.write is true."},
            "taskname": {"type": "string", "minLength": 1, "maxLength": 32, "description": "Required task grouping name for a write RPC operation."},
            "message": {"type": "string", "minLength": 1, "maxLength": 200, "description": "Required short reason for a write RPC operation."},
        }, ("mapping_id", "family", "operation")),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "get_workspace_credentials",
        "Get workspace REST credentials",
        "Return the linked configuration's current REST workspace URL, control token, and credential expiration. This exports portable REST credentials from an authenticated MCP connection; it does not rotate them.",
        _object_schema({}),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "renew_workspace_credentials",
        "Renew workspace REST credentials",
        "Atomically rotate the linked configuration's REST URL token and control token using the normal self-renewal window. The previous REST credentials become invalid immediately; the MCP connection remains valid.",
        _object_schema({}),
        read_only=False,
        destructive=True,
        context_message=False,
    ),
    _tool(
        "workspace_info",
        "Workspace information",
        "Return the compact Discovery index by default, or one detailed Discovery section.",
        _object_schema(
            {
                "section": {
                    "type": "string",
                    "enum": ["main", "files", "context", "memory", "shell", "schedules", "web", "sharing", "full"],
                    "default": "main",
                    "description": "Discovery section to return. Use full only for compatibility or comprehensive inspection.",
                }
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "query_context",
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
        "get_plan_tree",
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
        "add_context",
        "Add workspace context",
        "Append an AI-authored plan or note. A plan may include up to 64 direct subplans, created atomically and returned with all IDs and optional refs. Child taskname inherits when omitted. Optional request_id deduplicates retries per workspace/actor; changed requests conflict. Hints are returned once for the whole batch.",
        _object_schema(
            {
                "type": {
                    "type": "string",
                    "description": "plan or note",
                },
                **creation_properties(),
                "content": {"type": "string", "minLength": 1},
                "taskname": {"type": "string", "minLength": 1, "maxLength": 32},
                "plan_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Parent plan for a sub-plan; required owning plan for a note. Omit only for a root plan.",
                },
                "status": {
                    "type": "string",
                    "enum": ["in_progress", "completed", "cancelled"],
                    "description": "Plan status; omit for notes and defaults to in_progress for plans.",
                },
                "scope_paths": {
                    "type": "array",
                    "maxItems": 64,
                    "description": "Optional workspace-relative paths used to retrieve related Memory when creating a plan.",
                },
                "memory_tags": {
                    "type": "array",
                    "maxItems": 32,
                    "description": "Optional exact Memory tags used to retrieve related Memory when creating a plan.",
                },
            },
            ("type", "content", "taskname"),
        ),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "update_plan",
        "Update context plan",
        "Update a plan in place, including its task grouping, content, or status.",
        _object_schema(
            {
                "id": {"type": "integer", "minimum": 1},
                "taskname": {"type": "string", "minLength": 1, "maxLength": 32},
                "content": {"type": "string", "minLength": 1},
                "plan_id": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                    "description": "Optional new parent plan id; null moves the plan to the root.",
                },
                "status": {
                    "type": "string",
                    "enum": ["in_progress", "completed", "cancelled"],
                },
                "debrief": {
                    **plan_debrief_schema(),
                    "description": "Required when completing a plan: summary, outcome, and memory_actions (an empty array means retain no Memory).",
                },
            },
            ("id", "taskname"),
        ),
        read_only=False,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "query_memory",
        "Query project memory",
        "Query active or archived project-level Memory by text, category, status, severity, exact tag, or overlapping path.",
        _object_schema(
            {
                "query": {"type": "string", "default": ""},
                "category": {"type": "string"},
                "status": {"type": "string"},
                "severity": {"type": "string"},
                "tag": {"type": "string"},
                "path": {"type": "string"},
                "include_archived": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
            }
        ),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "get_memory",
        "Get project memory",
        "Read one Memory by stable memory_id, optionally including its revision history.",
        _object_schema(
            {
                "memory_id": {"type": "string", "minLength": 1},
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
        "get_project_memory",
        "Get project memory profile",
        "Return a bounded project profile containing overview, architecture, conventions, decisions, and open known issues.",
        _object_schema({}),
        read_only=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "add_memory",
        "Add project memory",
        "Create a revisioned project Memory linked to the plan that discovered or decided it.",
        _object_schema(
            {
                "category": {"type": "string"},
                "key": {"type": "string"},
                "title": {"type": "string", "minLength": 1},
                "content": {"type": "string", "minLength": 1},
                "status": {"type": "string"},
                "severity": {"type": "string"},
                "tags": {"type": "array", "maxItems": 32},
                "paths": {"type": "array", "maxItems": 64},
                "plan_id": {"type": "integer", "minimum": 1},
                "taskname": {"type": "string", "minLength": 1, "maxLength": 32},
                "message": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            ("category", "title", "content", "plan_id", "taskname", "message"),
        ),
        read_only=False,
        context_message=False,
    ),
    _tool(
        "update_memory",
        "Update project memory",
        "Update one Memory using its current revision as an optimistic concurrency precondition.",
        _object_schema(
            {
                "memory_id": {"type": "string", "minLength": 1},
                "expected_revision": {"type": "integer", "minimum": 1},
                "category": {"type": "string"},
                "key": {"type": ["string", "null"]},
                "title": {"type": "string", "minLength": 1},
                "content": {"type": "string", "minLength": 1},
                "status": {"type": "string"},
                "severity": {"type": ["string", "null"]},
                "tags": {"type": "array", "maxItems": 32},
                "paths": {"type": "array", "maxItems": 64},
                "plan_id": {"type": "integer", "minimum": 1},
                "taskname": {"type": "string", "minLength": 1, "maxLength": 32},
                "message": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            ("memory_id", "expected_revision", "plan_id", "taskname", "message"),
        ),
        read_only=False,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "archive_memory",
        "Archive project memory",
        "Soft-delete one Memory while retaining its revision history.",
        _object_schema(
            {
                "memory_id": {"type": "string", "minLength": 1},
                "expected_revision": {"type": "integer", "minimum": 1},
                "plan_id": {"type": "integer", "minimum": 1},
                "taskname": {"type": "string", "minLength": 1, "maxLength": 32},
                "message": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            ("memory_id", "expected_revision", "plan_id", "taskname", "message"),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
        context_message=False,
    ),
    _tool(
        "replace_note",
        "Replace context note",
        "Edit a note by atomically inserting a newer note and deleting the old row.",
        _object_schema(
            {
                "id": {"type": "integer", "minimum": 1},
                "taskname": {"type": "string", "minLength": 1, "maxLength": 32},
                "content": {"type": "string", "minLength": 1},
                "plan_id": {"type": "integer", "minimum": 1},
            },
            ("id", "taskname", "content", "plan_id"),
        ),
        read_only=False,
        destructive=True,
        context_message=False,
    ),
    _tool(
        "list_files",
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
        "create_share",
        "Create temporary share",
        "Copy one workspace file or directory into the temporary shared area and return a random share ID. Shares expire after one day by default.",
        _object_schema({"path": PATH}, ("path",)),
        read_only=False,
    ),
    _tool(
        "inspect_share",
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
        "import_share",
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
        "delete_share",
        "Delete temporary share",
        "Delete a temporary share early. Only the token application that created it may delete it.",
        _object_schema({"share_id": {"type": "string", "minLength": 1}}, ("share_id",)),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "read_file",
        "Read text file",
        "Read a text window, UTF-8 by default. Offset and limit count decoded Unicode characters, preserving literal newlines.",
        _object_schema(
            {
                "path": PATH,
                "offset": {**NONNEGATIVE, "default": 0},
                "encoding": TEXT_ENCODING,
                "limit": {**POSITIVE, "default": 65536},
            },
            ("path",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "stat_file",
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
        "search_files",
        "Search file contents",
        "Search UTF-8 text across files with a bounded recursive depth. Binary and oversized files are skipped.",
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
        "list_tree",
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
        "read_binary_chunk",
        "Read binary chunk",
        "Read a bounded byte range as Base64. Use REST fs/content with HTTP Range for large transfers.",
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
        "prepare_download",
        "Prepare raw file download",
        "Return a token-free REST URL for raw byte download with HTTP Range. Reuse the MCP Bearer authorization header.",
        _object_schema({"path": PATH}, ("path",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "get_web_preview_url",
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
        "write_file",
        "Write text file",
        "Create or atomically overwrite text in the requested encoding (default UTF-8), without newline translation. Set expected_etag for conditional writes.",
        _object_schema(
            {
                "path": PATH,
                "content": {"type": "string"},
                "encoding": TEXT_ENCODING,
                "create_parents": {"type": "boolean", "default": False},
                "expected_etag": {
                    "type": ["string", "null"],
                    "description": "Optional current ETag, or * to require that the file exists.",
                    "default": None,
                },
            },
            ("path", "content"),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "replace_text",
        "Replace exact text",
        "Replace exact text in the requested encoding (default UTF-8), preserving untouched newlines. By default old must occur once. Set expected_etag for conditional edits.",
        _object_schema(
            {
                "path": PATH,
                "old": {"type": "string", "minLength": 1},
                "encoding": TEXT_ENCODING,
                "new": {"type": "string"},
                "expected_matches": {"type": "integer", "minimum": 1, "default": 1},
                "replace_all": {"type": "boolean", "default": False},
                "expected_etag": {
                    "type": ["string", "null"],
                    "description": "Optional current ETag, or * to require that the file exists.",
                    "default": None,
                },
            },
            ("path", "old", "new"),
        ),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "create_directory",
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
        "move_path",
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
        "delete_path",
        "Recycle path",
        "Recoverably delete a file or directory by moving it into this child workspace's private .recycle directory.",
        _object_schema({"path": PATH}, ("path",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "list_recycle",
        "List recycle items",
        "List recoverably deleted items from this child workspace.",
        _object_schema(
            {
                "offset": {**NONNEGATIVE, "default": 0},
                "limit": {**POSITIVE, "maximum": 5000, "default": 1000},
            }
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "restore_recycle",
        "Restore recycle item",
        "Restore a recycle item to its original path. Refuses to overwrite an existing path.",
        _object_schema({"recycle_id": {"type": "string"}}, ("recycle_id",)),
        read_only=False,
        destructive=False,
    ),
    _tool(
        "start_upload",
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
        "get_upload",
        "Get upload status",
        "Return the current offset, expected size, and expiry for an upload session.",
        _object_schema({"upload_id": {"type": "string"}}, ("upload_id",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "finish_upload",
        "Finish upload",
        "Verify size and optional SHA-256, then atomically commit the uploaded file.",
        _object_schema({"upload_id": {"type": "string"}}, ("upload_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "abort_upload",
        "Abort upload",
        "Cancel an incomplete upload and remove its temporary data.",
        _object_schema({"upload_id": {"type": "string"}}, ("upload_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "list_schedules",
        "List schedules",
        "List persistent Shell schedules owned by this stable token application.",
        _object_schema({}),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "get_schedule",
        "Get schedule",
        "Return one persistent Shell schedule and its current revision.",
        _object_schema({"schedule_id": {"type": "string"}}, ("schedule_id",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "create_schedule",
        "Create schedule",
        "Create a once, interval, or strict six-field cron Shell schedule. The configured run context defaults to this mutation's plan, task name, and message.",
        _object_schema(
            {
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "schedule": {"type": "object"},
                "command": {"type": "string", "minLength": 1, "maxLength": 100000},
                "cwd": {"type": "string", "default": "."},
                "timeout_seconds": {"type": ["number", "null"], "minimum": 0.1, "maximum": 86400, "default": None},
                "overlap_policy": {"type": "string", "enum": ["skip"], "default": "skip"},
                "misfire_policy": {"type": "string", "enum": ["skip", "coalesce"], "default": "skip"},
                "run_context": {"type": "object"},
            },
            ("name", "schedule", "command"),
        ),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "update_schedule",
        "Update schedule",
        "Conditionally update a non-running schedule. Supply run_context only when changing the Context attached to future runs.",
        _object_schema(
            {
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
            ("schedule_id", "expected_revision"),
        ),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "delete_schedule",
        "Delete schedule",
        "Delete a schedule that is not currently running.",
        _object_schema({"schedule_id": {"type": "string"}}, ("schedule_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "run_schedule_now",
        "Run schedule now",
        "Explicitly dispatch one schedule immediately while preserving its next planned occurrence.",
        _object_schema({"schedule_id": {"type": "string"}}, ("schedule_id",)),
        read_only=False,
        destructive=True,
        open_world=True,
    ),
    _tool(
        "pause_schedule",
        "Pause schedule",
        "Pause future dispatches without terminating an already running task.",
        _object_schema({"schedule_id": {"type": "string"}}, ("schedule_id",)),
        read_only=False,
    ),
    _tool(
        "resume_schedule",
        "Resume schedule",
        "Resume a paused schedule and compute its next occurrence from now.",
        _object_schema({"schedule_id": {"type": "string"}}, ("schedule_id",)),
        read_only=False,
    ),
    _tool(
        "list_schedule_runs",
        "List schedule runs",
        "List recent dispatch records for one schedule.",
        _object_schema(
            {
                "schedule_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            },
            ("schedule_id",),
        ),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "get_schedule_run",
        "Get schedule run",
        "Return one schedule dispatch record and its linked Shell task id.",
        _object_schema({"run_id": {"type": "string"}}, ("run_id",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "run_shell",
        "Run shell command",
        "Start an asynchronous Shell task. target=auto routes a mapped cwd to its client and other cwd to the server. Never falls back on client errors. Use the returned task_id with normal task tools. Client Shell uses its own execution/sandbox policy, not server limits or environment; output is combined. Native Windows uses cmd.exe, POSIX/Podman uses /bin/sh.",
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
                    "description": "Keep stdin open for send_task_input calls.",
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
        "get_task",
        "Get task status",
        "Poll a server or client task for status, exit code and output. Client stdout/stderr are combined in stdout; the initial 64 KiB includes stdout_next_offset. Use read_task_output with that cursor for the remaining bytes.",
        _object_schema({"task_id": {"type": "string"}}, ("task_id",)),
        read_only=True,
        idempotent=True,
    ),
    _tool(
        "list_tasks",
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
        "list_sandbox_processes",
        "List sandbox processes",
        "List processes in this token's restricted-shell cgroup and return aggregate PID, memory, CPU, and OOM counters.",
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
        "read_task_output",
        "Read incremental task output",
        "Read task output from byte cursors, optionally waiting for new output. Server tasks have separate stdout and stderr. Client tasks combine both streams in stdout (output_combined=true); stderr is empty. Advance each returned next_offset. Client retained output is capped at 2 MiB.",
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
        "send_task_input",
        "Send task input",
        "Write UTF-8 or Base64 input to an interactive server or client task and optionally close stdin. A client task accepts at most 16 KiB per call (server tasks: 256 KiB). Data and close=true may be sent together.",
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
        "interrupt_task",
        "Interrupt task",
        "Interrupt a running task. Server tasks receive SIGTERM and escalate to SIGKILL after a grace period; client tasks receive SIGINT on POSIX/Podman or CTRL_BREAK on native Windows. Use kill_task for immediate force termination.",
        _object_schema({"task_id": {"type": "string"}}, ("task_id",)),
        read_only=False,
        destructive=True,
    ),
    _tool(
        "kill_task",
        "Force-kill task",
        "Force-kill a running task. Server and POSIX/Podman client tasks receive SIGKILL; native Windows client tasks use taskkill /T /F. This does not wait for graceful termination.",
        _object_schema({"task_id": {"type": "string"}}, ("task_id",)),
        read_only=False,
        destructive=True,
    ),
)


def tools_for(
    record: TokenRecord,
    recycle_enabled: bool,
    mcp_binary_chunk_bytes: int = 256 * 1024,
) -> list[dict[str, Any]]:
    readable = {
        "workspace_info",
        "get_workspace_credentials",
        "renew_workspace_credentials",
        "inspect_share",
        "delete_share",
        "add_context",
        "update_plan",
        "replace_note",
        "add_memory",
        "update_memory",
        "archive_memory",
    }
    if record.can_read or record.can_write:
        readable.add("rpc")
    if record.can_read:
        readable.update({"read_files", "file_manifest", "archive_list", "archive_read"})
        readable.update("git_" + operation for operation in GIT_OPERATIONS)
        readable.update(
            {
                "query_context",
                "get_plan_tree",
                "query_memory",
                "get_memory",
                "get_project_memory",
                "list_files",
                "read_file",
                "stat_file",
                "read_binary_chunk",
                "prepare_download",
                "search_files",
                "list_tree",
                "create_share",
            }
        )
        if record.can_preview:
            readable.add("get_web_preview_url")
        if recycle_enabled:
            readable.add("list_recycle")
    if record.can_write:
        readable.update(
            {
                "write_file",
                "replace_text",
                "create_directory",
                "move_path",
                "start_upload",
                "upload_chunk",
                "get_upload",
                "finish_upload",
                "abort_upload",
                "import_share",
            }
        )
        if recycle_enabled:
            readable.update({"delete_path", "restore_recycle"})
    if record.can_read or record.can_write:
        readable.update(
            {
                "get_task",
                "list_tasks",
                "read_task_output",
                "interrupt_task",
                "kill_task",
            }
        )
    if record.shell_mode != "none":
        readable.update(
            {
                "run_shell",
                "send_task_input",
            }
        )
        if record.can_schedule:
            readable.update(
                {
                    "list_schedules",
                    "get_schedule",
                    "create_schedule",
                    "update_schedule",
                    "delete_schedule",
                    "run_schedule_now",
                    "pause_schedule",
                    "resume_schedule",
                    "list_schedule_runs",
                    "get_schedule_run",
                }
            )
    if record.shell_mode == "restricted":
        readable.add("list_sandbox_processes")
    selected = [copy.deepcopy(tool) for tool in ALL_TOOLS if tool["name"] in readable]
    for tool in selected:
        if tool["name"] == "read_binary_chunk":
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

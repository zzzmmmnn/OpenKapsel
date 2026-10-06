"""Shared public machine-readable contracts for OpenKapsel API surfaces."""

from __future__ import annotations

import copy
from typing import Any

from openkapsel.files.text_encoding import ENCODINGS


PLAN_STATUSES = frozenset({"in_progress", "completed", "cancelled"})
MAX_CONTEXT_CONTENT_CHARS = 32_768
MAX_CONTEXT_OPERATION_MESSAGE_CHARS = 200
MAX_CONTEXT_TASKNAME_CHARS = 32

MAX_MEMORY_CONTENT_CHARS = 256
MAX_MEMORY_TAGS = 32
MAX_MEMORY_SCOPE_PATHS = 64
MAX_MEMORY_TAG_CHARS = 64
MAX_MEMORY_PATH_CHARS = 4_096
MAX_MEMORY_CHANGE_MESSAGE_CHARS = 200

MAX_CONVERSATION_CONTENT_CHARS = 1_000
MAX_CONVERSATION_SUMMARY_CHARS = 8_192
MAX_CONVERSATION_BATCH_ENTRIES = 100
CONVERSATION_ROLES = ("user", "ai", "summary")

PLAN_COMPLETION_MEMORY_GUIDANCE = (
    "Each debrief.items entry creates one new Memory from content plus tags. "
    "memory_actions only updates or archives existing Memory; memory_feedback lists only Memory "
    "that materially helped; every memory_conflicts item must be resolved by updating or archiving "
    "that Memory in the same debrief. If completion fails ambiguously after Memory may have changed, "
    "query current Memory before retrying debrief.items to avoid duplicate Memory."
)


_PATH_SCHEMA = {
    "type": "string",
    "description": (
        "Path relative to the token workspace, or an absolute path inside it or an "
        "authorized extra directory."
    ),
}
_NONNEGATIVE_SCHEMA = {"type": "integer", "minimum": 0}
_POSITIVE_SCHEMA = {"type": "integer", "minimum": 1}
_TEXT_ENCODING_SCHEMA = {
    "type": "string",
    "enum": list(ENCODINGS),
    "default": "utf-8",
    "description": (
        "Explicit file encoding; strict conversion. LF/CRLF/CR are preserved literally. "
        "UTF-16 requires explicit endian; BOM is preserved as U+FEFF."
    ),
}


def path_schema() -> dict[str, Any]:
    return copy.deepcopy(_PATH_SCHEMA)


def nonnegative_schema() -> dict[str, Any]:
    return copy.deepcopy(_NONNEGATIVE_SCHEMA)


def positive_schema() -> dict[str, Any]:
    return copy.deepcopy(_POSITIVE_SCHEMA)


def text_encoding_schema() -> dict[str, Any]:
    return copy.deepcopy(_TEXT_ENCODING_SCHEMA)


def plan_id_schema(*, nullable: bool = False, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": ["integer", "null"] if nullable else "integer", "minimum": 1}
    if description:
        schema["description"] = description
    return schema


def revision_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "integer", "minimum": 1}
    if description:
        schema["description"] = description
    return schema


def taskname_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": MAX_CONTEXT_TASKNAME_CHARS}
    if description:
        schema["description"] = description
    return schema


def operation_message_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": MAX_CONTEXT_OPERATION_MESSAGE_CHARS}
    if description:
        schema["description"] = description
    return schema


def plan_status_schema(*, description: str | None = None, default: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "enum": sorted(PLAN_STATUSES)}
    if default is not None:
        schema["default"] = default
    if description:
        schema["description"] = description
    return schema


def conversation_id_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "integer", "minimum": 0}
    if description:
        schema["description"] = description
    return schema


def writer_nonce_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "minLength": 1}
    schema["description"] = description or (
        "Opaque writer nonce returned by conversation_create; retain it for that Conversation "
        "and pass it back unchanged when appending or updating its Plan context."
    )
    return schema


def conversation_role_schema() -> dict[str, Any]:
    return {"type": "string", "enum": list(CONVERSATION_ROLES)}


def conversation_entry_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["role", "content"],
        "properties": {
            "role": conversation_role_schema(),
            "content": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CONVERSATION_SUMMARY_CHARS,
                "description": (
                    f"user/ai max {MAX_CONVERSATION_CONTENT_CHARS} chars; "
                    f"summary max {MAX_CONVERSATION_SUMMARY_CHARS} chars"
                ),
            },
        },
    }


def conversation_entries_schema(
    *,
    min_items: int = 1,
    description: str | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "minItems": min_items,
        "maxItems": MAX_CONVERSATION_BATCH_ENTRIES,
        "items": conversation_entry_schema(),
    }
    if description:
        schema["description"] = description
    return schema


def memory_id_schema() -> dict[str, Any]:
    return {"type": "string", "minLength": 1}


def memory_content_schema() -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": MAX_MEMORY_CONTENT_CHARS}


def memory_tags_schema(*, description: str | None = None) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": 1,
        "maxItems": MAX_MEMORY_TAGS,
        "description": description or "At least one exact-match tag is required; prefer 4-16 specific reusable tags.",
        "items": {"type": "string", "minLength": 1, "maxLength": MAX_MEMORY_TAG_CHARS},
    }


def memory_path_schema(*, description: str | None = None) -> dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_MEMORY_PATH_CHARS,
        "description": description or (
            "One canonical Memory scope: server:<path>, mapping:<mapping_id>:<path>, or "
            "storage:<provider_id>:<path>. server:. is the workspace-global root."
        ),
    }


def plan_scope_paths_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "maxItems": MAX_MEMORY_SCOPE_PATHS,
        "items": {"type": "string", "minLength": 1, "maxLength": MAX_MEMORY_PATH_CHARS},
    }
    if description:
        schema["description"] = description
    return schema


def plan_memory_tags_schema(*, description: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "maxItems": MAX_MEMORY_TAGS,
        "items": {"type": "string", "minLength": 1, "maxLength": MAX_MEMORY_TAG_CHARS},
    }
    if description:
        schema["description"] = description
    return schema


MAX_SUBPLANS = 64
MAX_PLAN_REQUEST_BYTES = 256 * 1024
MAX_PLAN_REQUESTS = 100_000
PLAN_REQUEST_ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
PLAN_REF_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}"


def plan_creation_properties() -> dict[str, Any]:
    """Return the shared Plan creation extension schema used by MCP and Discovery."""
    return {
        "subplans": {
            "type": "array",
            "maxItems": MAX_SUBPLANS,
            "description": (
                "Direct child plans created atomically with this plan. Root Plan creation requires "
                "this field; use [] when there are no direct children. It remains optional when "
                "creating a Plan under an existing parent. Children inherit taskname when omitted. "
                "No nested subplans or child plan_id; use a later call with a parent ID for deeper levels."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["content"],
                "properties": {
                    "ref": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                        "pattern": "^" + PLAN_REF_PATTERN + "$",
                        "description": "Optional unique request-local label, echoed beside the assigned child ID.",
                    },
                    "content": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_CONTEXT_CONTENT_CHARS,
                    },
                    "taskname": taskname_schema(),
                    "status": plan_status_schema(default="in_progress"),
                    "scope_paths": plan_scope_paths_schema(),
                    "memory_tags": plan_memory_tags_schema(),
                },
            },
        },
        "conversation_id": conversation_id_schema(
            description="Non-negative Conversation id that owns this Plan creation."
        ),
        "writer_nonce": writer_nonce_schema(
            description=(
                "Opaque writer nonce returned by conversation_create for this Conversation; "
                "required for Plan creation and passed unchanged."
            )
        ),
        "conversation_entries": conversation_entries_schema(
            description="One or more append-only Conversation records committed atomically with Plan creation."
        ),
        "request_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^" + PLAN_REQUEST_ID_PATTERN + "$",
            "description": (
                "Optional caller-generated retry key, scoped to this workspace and stable actor. "
                "Reuse only with the same plan request: returns original IDs and replayed=true; "
                "changed content is a conflict. Plans only."
            ),
        },
    }


MUTATION_MAX_ITEMS = 1000

MUTATION_OPERATIONS = (
    "text.replace",
    "text.insert_before",
    "text.insert_after",
    "structured.patch",
    "file.create",
    "file.replace",
    "path.delete",
)

_MUTATION_OPERATION_CONTRACTS: dict[str, Any] = {
    "text.replace": {
        "required": ["expected_etag", "replacements"],
        "optional": ["encoding", "start_line", "end_line", "start_text", "end_text"],
        "description": "Replace one or more exact text values inside an optional bounded text range.",
    },
    "text.insert_before": {
        "required": ["expected_etag", "match", "content"],
        "optional": [
            "encoding",
            "expected_count",
            "start_line",
            "end_line",
            "start_text",
            "end_text",
        ],
        "description": "Insert content immediately before each exact anchor match.",
    },
    "text.insert_after": {
        "required": ["expected_etag", "match", "content"],
        "optional": [
            "encoding",
            "expected_count",
            "start_line",
            "end_line",
            "start_text",
            "end_text",
        ],
        "description": "Insert content immediately after each exact anchor match.",
    },
    "structured.patch": {
        "required": ["expected_etag", "operations"],
        "optional": ["format"],
        "description": "Apply guarded JSON/YAML/TOML test/add/replace/remove operations.",
    },
    "file.create": {
        "required": ["content"],
        "optional": ["encoding"],
        "description": "Create a new standard-size text file; the destination must not exist.",
    },
    "file.replace": {
        "required": ["expected_etag", "content"],
        "optional": ["encoding"],
        "description": "Replace an existing standard-size text file.",
    },
    "path.delete": {
        "required": ["expected_etag"],
        "optional": [],
        "description": "Recoverably delete an existing workspace file or directory.",
    },
}


def mutation_operation_contracts() -> dict[str, Any]:
    return copy.deepcopy(_MUTATION_OPERATION_CONTRACTS)


_REPLACEMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "old": {
            "type": "string",
            "minLength": 1,
            "description": "Exact non-empty source text.",
        },
        "new": {
            "type": "string",
            "description": "Replacement text; may be empty.",
        },
        "expected_count": {
            "type": "integer",
            "minimum": 1,
            "default": 1,
            "description": "Required exact occurrence count for this replacement rule.",
        },
    },
    "required": ["old", "new"],
    "additionalProperties": False,
}

_STRUCTURED_OPERATION_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["test", "add", "replace", "remove"],
        },
        "path": {
            "type": "string",
            "description": "JSON Pointer path.",
        },
        "value": {
            "description": "Value used by test/add/replace; omit for remove.",
        },
    },
    "required": ["op", "path"],
    "additionalProperties": False,
}

_MUTATION_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "One transactional mutation item. op and path are always required; consult "
        "x-openkapsel-operation-contracts for operation-specific required and optional fields."
    ),
    "properties": {
        "op": {
            "type": "string",
            "enum": list(MUTATION_OPERATIONS),
        },
        "path": _PATH_SCHEMA,
        "expected_etag": {
            "type": "string",
            "minLength": 1,
            "description": "Exact prior ETag required for every existing target; omit for file.create.",
        },
        "encoding": _TEXT_ENCODING_SCHEMA,
        "content": {
            "type": "string",
            "description": (
                "Text content for file.create/file.replace, or inserted text for "
                "text.insert_before/text.insert_after."
            ),
        },
        "match": {
            "type": "string",
            "minLength": 1,
            "description": "Exact insertion anchor for text.insert_before/text.insert_after.",
        },
        "expected_count": {
            "type": "integer",
            "minimum": 1,
            "default": 1,
            "description": "Exact insertion-anchor occurrence count.",
        },
        "replacements": {
            "type": "array",
            "minItems": 1,
            "items": _REPLACEMENT_SCHEMA,
            "description": "Exact replacement rules for text.replace.",
        },
        "start_line": {
            "type": "integer",
            "minimum": 0,
            "description": "Zero-based inclusive start line for text operations; omit for line 0.",
        },
        "end_line": {
            "type": "integer",
            "minimum": 0,
            "description": "Zero-based inclusive end line for text operations; omit for EOF.",
        },
        "start_text": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Unique full-file inclusive start marker for text operations; may span lines and "
                "is mutually exclusive with start_line."
            ),
        },
        "end_text": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Unique full-file inclusive end marker for text operations; may span lines and "
                "is mutually exclusive with end_line."
            ),
        },
        "operations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": _STRUCTURED_OPERATION_SCHEMA,
            "description": "Structured patch operations for structured.patch.",
        },
        "format": {
            "type": "string",
            "enum": ["json", "yaml", "toml"],
            "description": (
                "Optional explicit structured format; otherwise inferred from .json/.yaml/.yml/.toml."
            ),
        },
    },
    "required": ["op", "path"],
    "additionalProperties": False,
    "x-openkapsel-operation-contracts": _MUTATION_OPERATION_CONTRACTS,
}


def mutation_item_schema() -> dict[str, Any]:
    return copy.deepcopy(_MUTATION_ITEM_SCHEMA)


_MUTATION_ITEM_EXAMPLE: dict[str, Any] = {
    "op": "text.replace",
    "path": "<file>",
    "expected_etag": "<exact prior ETag>",
    "replacements": [
        {"old": "<exact>", "new": "<exact>", "expected_count": 1},
    ],
}


def mutation_item_example() -> dict[str, Any]:
    return copy.deepcopy(_MUTATION_ITEM_EXAMPLE)


_MEMORY_CONTENT = memory_content_schema()
_MEMORY_TAGS = memory_tags_schema()
_MEMORY_PATH = memory_path_schema()
_MEMORY_ID = memory_id_schema()
_REVISION = revision_schema()



def _action_object(
    action: str,
    properties: dict[str, Any],
    required: list[str],
    description: str,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "type": "object",
        "description": description,
        "properties": {"action": {"const": action}, **properties},
        "required": ["action", *required],
        "additionalProperties": False,
        **extra,
    }


_MEMORY_UPDATE_FIELDS = {
    "content": _MEMORY_CONTENT,
    "tags": _MEMORY_TAGS,
    "path": _MEMORY_PATH,
}
_MEMORY_UPDATE = _action_object(
    "update",
    {
        "memory_id": _MEMORY_ID,
        "expected_revision": _REVISION,
        **_MEMORY_UPDATE_FIELDS,
    },
    ["memory_id", "expected_revision"],
    "Conditionally revise content, tags, or path of an existing Memory.",
    minProperties=4,
)
_MEMORY_ARCHIVE = _action_object(
    "archive",
    {
        "memory_id": _MEMORY_ID,
        "expected_revision": _REVISION,
    },
    ["memory_id", "expected_revision"],
    "Soft-archive an existing Memory while retaining all revisions.",
)
MEMORY_ACTIONS = ("update", "archive")

_MEMORY_ACTIONS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "maxItems": 20,
    "description": (
        "Optional mutations for existing Memory during Plan completion. New Memory is created "
        "directly from debrief.items; memory_actions is only for update or archive."
    ),
    "items": {
        "oneOf": [_MEMORY_UPDATE, _MEMORY_ARCHIVE],
        "discriminator": {"propertyName": "action"},
    },
}
_MEMORY_FEEDBACK_SCHEMA: dict[str, Any] = {
    "type": "array",
    "maxItems": 20,
    "description": (
        "Memories that materially helped complete this Plan. Omit unhelpful or merely retrieved "
        "Memory; use [] when none helped."
    ),
    "items": {
        "type": "object",
        "properties": {
            "memory_id": _MEMORY_ID,
            "revision": _REVISION,
        },
        "required": ["memory_id", "revision"],
        "additionalProperties": False,
    },
}
_MEMORY_CONFLICTS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "maxItems": 20,
    "description": (
        "Verified Memory conflicts found during the Plan. Every item must be handled in the same "
        "debrief by updating content or archiving the conflicting Memory."
    ),
    "items": {
        "type": "object",
        "properties": {
            "memory_id": _MEMORY_ID,
            "revision": _REVISION,
            "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
        "required": ["memory_id", "revision", "reason"],
        "additionalProperties": False,
    },
}
_DEBRIEF_ITEMS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "maxItems": 20,
    "description": (
        "Each item directly creates one new long-lived Memory for the completing Plan. Multiple "
        "items create multiple Memories. Use [] when no new Memory should be created."
    ),
    "items": {
        "type": "object",
        "properties": {
            "content": _MEMORY_CONTENT,
            "tags": _MEMORY_TAGS,
        },
        "required": ["content", "tags"],
        "additionalProperties": False,
    },
}


def memory_feedback_schema() -> dict[str, Any]:
    return copy.deepcopy(_MEMORY_FEEDBACK_SCHEMA)


def memory_conflicts_schema() -> dict[str, Any]:
    return copy.deepcopy(_MEMORY_CONFLICTS_SCHEMA)


def memory_actions_schema() -> dict[str, Any]:
    return copy.deepcopy(_MEMORY_ACTIONS_SCHEMA)


def debrief_items_schema() -> dict[str, Any]:
    return copy.deepcopy(_DEBRIEF_ITEMS_SCHEMA)


def plan_debrief_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "items": debrief_items_schema(),
            "outcome": {"type": "string", "enum": ["succeeded", "partial", "no_change"]},
            "memory_actions": memory_actions_schema(),
            "memory_feedback": memory_feedback_schema(),
            "memory_conflicts": memory_conflicts_schema(),
        },
        "required": [
            "items",
            "outcome",
            "memory_actions",
            "memory_feedback",
            "memory_conflicts",
        ],
        "additionalProperties": False,
    }

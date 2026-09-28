"""Shared machine-readable contracts for Plan completion Memory actions."""

from __future__ import annotations

import copy
from typing import Any


_CONTENT = {"type": "string", "minLength": 1, "maxLength": 256}
_TAGS = {
    "type": "array",
    "minItems": 1,
    "maxItems": 32,
    "uniqueItems": True,
    "description": "At least one exact-match tag is required; prefer 4-16 specific reusable tags.",
    "items": {"type": "string", "minLength": 1, "maxLength": 64},
}
_PATH = {
    "type": "string",
    "minLength": 1,
    "maxLength": 4096,
    "description": (
        "One canonical Memory scope: server:<path>, mapping:<mapping_id>:<path>, or "
        "storage:<provider_id>:<path>. server:. is the workspace-global root."
    ),
}
_MEMORY_ID = {"type": "string", "pattern": "^mem_[A-Za-z0-9_-]+$"}
_REVISION = {"type": "integer", "minimum": 1}


def _object(
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


_UPDATE_FIELDS = {
    "content": _CONTENT,
    "tags": _TAGS,
    "path": _PATH,
}
_UPDATE = _object(
    "update",
    {
        "memory_id": _MEMORY_ID,
        "expected_revision": _REVISION,
        **_UPDATE_FIELDS,
    },
    ["memory_id", "expected_revision"],
    "Conditionally revise content, tags, or path of an existing Memory.",
    anyOf=[{"required": [field]} for field in _UPDATE_FIELDS],
)

_ARCHIVE = _object(
    "archive",
    {
        "memory_id": _MEMORY_ID,
        "expected_revision": _REVISION,
    },
    ["memory_id", "expected_revision"],
    "Soft-archive an existing Memory while retaining all revisions.",
)

_MEMORY_ACTIONS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "maxItems": 20,
    "description": (
        "Optional mutations for existing Memory during Plan completion. New Memory is created "
        "directly from debrief.items; memory_actions is only for update or archive."
    ),
    "items": {
        "oneOf": [_UPDATE, _ARCHIVE],
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


def memory_feedback_schema() -> dict[str, Any]:
    return copy.deepcopy(_MEMORY_FEEDBACK_SCHEMA)


def memory_conflicts_schema() -> dict[str, Any]:
    return copy.deepcopy(_MEMORY_CONFLICTS_SCHEMA)


def memory_actions_schema() -> dict[str, Any]:
    """Return a copy so Discovery and MCP builders cannot mutate shared state."""
    return copy.deepcopy(_MEMORY_ACTIONS_SCHEMA)


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
            "content": _CONTENT,
            "tags": _TAGS,
        },
        "required": ["content", "tags"],
        "additionalProperties": False,
    },
}


def debrief_items_schema() -> dict[str, Any]:
    return copy.deepcopy(_DEBRIEF_ITEMS_SCHEMA)


def plan_debrief_schema() -> dict[str, Any]:
    """Return the full Plan completion debrief JSON Schema."""
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

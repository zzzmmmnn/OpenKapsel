"""Shared machine-readable contracts for Plan completion Memory actions."""

from __future__ import annotations

import copy
from typing import Any


_CATEGORY = {
    "type": "string",
    "enum": ["overview", "architecture", "convention", "decision", "known_issue"],
}
_STATUS = {
    "type": "string",
    "enum": [
        "current",
        "suspected_stale",
        "outdated",
        "active",
        "superseded",
        "open",
        "resolved",
        "wontfix",
    ],
}
_SEVERITY = {"type": ["string", "null"], "enum": ["high", "medium", "low", None]}
_KEY = {"type": ["string", "null"], "minLength": 1, "maxLength": 256}
_TITLE = {"type": "string", "minLength": 1, "maxLength": 256}
_CONTENT = {"type": "string", "minLength": 1, "maxLength": 32768}
_TAGS = {
    "type": "array",
    "maxItems": 32,
    "uniqueItems": True,
    "items": {"type": "string", "minLength": 1, "maxLength": 64},
}
_PATHS = {
    "type": "array",
    "maxItems": 64,
    "uniqueItems": True,
    "items": {"type": "string", "minLength": 1, "maxLength": 4096},
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


_CREATE = _object(
    "create",
    {
        "category": _CATEGORY,
        "key": _KEY,
        "title": _TITLE,
        "content": _CONTENT,
        "status": _STATUS,
        "severity": _SEVERITY,
        "tags": _TAGS,
        "paths": _PATHS,
    },
    ["category", "title", "content"],
    "Create revision 1 of a new Memory. The completing Plan becomes its source plan.",
)

_UPDATE_FIELDS = {
    "category": _CATEGORY,
    "key": _KEY,
    "title": _TITLE,
    "content": _CONTENT,
    "status": _STATUS,
    "severity": _SEVERITY,
    "tags": _TAGS,
    "paths": _PATHS,
}
_UPDATE = _object(
    "update",
    {
        "memory_id": _MEMORY_ID,
        "expected_revision": _REVISION,
        **_UPDATE_FIELDS,
    },
    ["memory_id", "expected_revision"],
    "Conditionally revise an existing Memory; expected_revision must equal its current revision.",
    anyOf=[{"required": [field]} for field in _UPDATE_FIELDS],
)

_RESOLVE_FIELDS = {
    "category": _CATEGORY,
    "key": _KEY,
    "title": _TITLE,
    "content": _CONTENT,
    "severity": _SEVERITY,
    "tags": _TAGS,
    "paths": _PATHS,
}
_RESOLVE = _object(
    "resolve",
    {
        "memory_id": _MEMORY_ID,
        "expected_revision": _REVISION,
        **_RESOLVE_FIELDS,
    },
    ["memory_id", "expected_revision"],
    "Resolve an existing known_issue. OpenKapsel forces status=resolved; other supplied fields revise its final lesson.",
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
        "Required when completing a Plan. Use [] when the task produced no project-level "
        "knowledge worth retaining. Actions run in array order."
    ),
    "items": {
        "oneOf": [_CREATE, _UPDATE, _RESOLVE, _ARCHIVE],
        "discriminator": {"propertyName": "action"},
    },
}


def memory_actions_schema() -> dict[str, Any]:
    """Return a copy so Discovery and MCP builders cannot mutate shared state."""
    return copy.deepcopy(_MEMORY_ACTIONS_SCHEMA)


def plan_debrief_schema() -> dict[str, Any]:
    """Return the full Plan completion debrief JSON Schema."""
    return {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 32768},
            "outcome": {"type": "string", "enum": ["succeeded", "partial", "no_change"]},
            "memory_actions": memory_actions_schema(),
        },
        "required": ["summary", "outcome", "memory_actions"],
        "additionalProperties": False,
    }

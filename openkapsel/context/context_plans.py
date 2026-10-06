"""Bounded atomic plan creation and durable request deduplication.

The request ledger deliberately has no cascading foreign key: pruning old Context
must never silently make an old request_id reusable. Replays are creation receipts,
not current-state reads; callers use context_query/context_plan_tree for current state.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from contextlib import closing
from typing import Any

from openkapsel.context.conversation import (
    append_conversation,
    conversation_summary_status,
    normalize_entries,
    validate_conversation_id,
    validate_writer_nonce,
    verify_writer_nonce,
)

from openkapsel.context.context_store import ContextStore, _utc_now
from openkapsel.context.memory_store import MemoryStore, MAX_MEMORY_SCOPE_PATHS
from openkapsel.contract import (
    MAX_PLAN_REQUEST_BYTES,
    MAX_PLAN_REQUESTS,
    MAX_SUBPLANS,
    PLAN_REF_PATTERN,
    PLAN_REQUEST_ID_PATTERN,
)


class PlanRequestConflict(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(value: Any, validator: Any) -> str:
    text = validator(value)
    if "\x00" in text or any(0xD800 <= ord(char) <= 0xDFFF for char in text):
        raise ValueError("plan text must not contain NUL or unpaired Unicode surrogates")
    return text


def _plan_scope_paths(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_MEMORY_SCOPE_PATHS:
        raise ValueError(f"scope_paths must be an array of at most {MAX_MEMORY_SCOPE_PATHS} paths")
    paths: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("scope_paths entries must be non-empty strings")
        raw = item.strip().replace("\\", "/")
        if raw.startswith("/"):
            raise ValueError("scope_paths must be workspace-relative")
        path = posixpath.normpath(raw)
        if path == ".." or path.startswith("../"):
            raise ValueError("scope_paths must stay inside the workspace")
        if len(path) > 4096:
            raise ValueError("scope_paths entry exceeds 4096 characters")
        if path not in paths:
            paths.append(path)
    return paths


def normalize_plan_request(body: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(body, dict) or body.get("type", "plan") != "plan":
        raise ValueError("batch creation requires type=plan")
    # Legacy singleton REST calls ignored extra attribution fields. New batch/key
    # requests are strict so misspelled plan fields cannot be silently ignored.
    if "status" in body:
        raise ValueError("plan creation does not accept status; all plans start in_progress")
    allowed = {
        "type", "content", "taskname", "plan_id", "scope_paths",
        "memory_tags", "subplans", "request_id", "message",
        "conversation_id", "writer_nonce", "conversation_entries",
    }
    if ("subplans" in body or "request_id" in body) and set(body) - allowed:
        raise ValueError("plan creation contains unknown fields")

    def node(raw: dict[str, Any], inherited_taskname: str | None = None) -> dict[str, Any]:
        paths = _plan_scope_paths(raw.get("scope_paths"))
        tags = MemoryStore._validate_tags(raw.get("memory_tags"))
        for value in paths + tags:
            _text(value, lambda item: item)
        return {
            "content": _text(raw.get("content"), ContextStore._validate_content),
            "taskname": _text(raw.get("taskname", inherited_taskname), ContextStore._validate_taskname),
            "status": "in_progress", "scope_paths": paths, "memory_tags": tags,
        }

    parent = body.get("plan_id")
    if parent is not None:
        ContextStore._validate_plan_id_value(parent)
        if parent > 2**63 - 1:
            raise ValueError("plan_id exceeds the database ID range")
    root = node(body)
    root["plan_id"] = parent
    if parent is None and "subplans" not in body:
        raise ValueError(
            "root plan creation requires subplans; use [] when there are no direct child plans"
        )
    children = body.get("subplans", [])
    if not isinstance(children, list) or len(children) > MAX_SUBPLANS:
        raise ValueError(f"subplans must be an array of at most {MAX_SUBPLANS} direct children")
    normalized, refs = [], set()
    for index, child in enumerate(children):
        if not isinstance(child, dict):
            raise ValueError(f"subplans[{index}] must be a direct child object with only supported fields")
        if "status" in child:
            raise ValueError(f"subplans[{index}] does not accept status; all plans start in_progress")
        if set(child) - {"ref", "content", "taskname", "scope_paths", "memory_tags"}:
            raise ValueError(f"subplans[{index}] must be a direct child object with only supported fields")
        for field in ("scope_paths", "memory_tags"):
            if field in child and not isinstance(child[field], list):
                raise ValueError(f"subplans[{index}].{field} must be an array")
        item = node(child, root["taskname"])
        if "ref" in child:
            ref = child["ref"]
            if not isinstance(ref, str) or not re.fullmatch(PLAN_REF_PATTERN, ref):
                raise ValueError("subplan ref must contain 1-64 ASCII letters, digits, dots, underscores, colons or hyphens, starting with a letter or digit")
            if ref in refs:
                raise ValueError("subplan refs must be unique within this request")
            refs.add(ref)
            item["ref"] = ref
        normalized.append(item)
    conversation_id = validate_conversation_id(body.get("conversation_id"))
    writer_nonce = validate_writer_nonce(body.get("writer_nonce"))
    conversation_entries = normalize_entries(body.get("conversation_entries"), minimum=1)
    request = {
        "root": root,
        "subplans": normalized,
        "conversation_id": conversation_id,
        "conversation_entries": conversation_entries,
    }
    encoded = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_PLAN_REQUEST_BYTES:
        raise ValueError(f"combined plan request exceeds {MAX_PLAN_REQUEST_BYTES} UTF-8 bytes")
    # Keep one bounded Memory lookup instead of N nearly identical lookups and N
    # repeated hint payloads. Validate the union before inserting any plan.
    paths = list(dict.fromkeys(p for item in [root, *normalized] for p in item["scope_paths"]))
    tags = list(dict.fromkeys(t for item in [root, *normalized] for t in item["memory_tags"]))
    MemoryStore._validate_scope_paths(paths)
    MemoryStore._validate_tags(tags)
    request_id = body.get("request_id")
    if "request_id" in body and (not isinstance(request_id, str) or not re.fullmatch(PLAN_REQUEST_ID_PATTERN, request_id)):
        raise ValueError("request_id must contain 1-128 ASCII letters, digits, dots, underscores, colons or hyphens, starting with a letter or digit")
    return {
        **request,
        "writer_nonce": writer_nonce,
        "request_id": request_id,
        "fingerprint": hashlib.sha256(encoded).hexdigest(),
        "hint_paths": paths,
        "hint_tags": tags,
        "hint_content": "\n".join(item["content"] for item in [root, *normalized]),
    }


def _insert_plan(
    store: ContextStore,
    connection: Any,
    node: dict[str, Any],
    parent: int | None,
    actor_id: str | None,
    now: str,
    conversation_id: int,
) -> dict[str, Any]:
    metadata = {key: node[key] for key in ("ref", "scope_paths", "memory_tags") if node.get(key)}
    cursor = connection.execute(
        "INSERT INTO context_entries (created_at, updated_at, entry_type, content, taskname, plan_status, plan_id, conversation_id, actor_id, request_json) "
        "VALUES (?, ?, 'plan', ?, ?, ?, ?, ?, ?, ?)",
        (
            now,
            now,
            node["content"],
            node["taskname"],
            node["status"],
            parent,
            conversation_id,
            actor_id,
            store._encode_json(metadata or None),
        ),
    )
    entry_id = int(cursor.lastrowid)
    store._insert_paths(connection, entry_id, {"path": node["scope_paths"]})
    row = connection.execute("SELECT * FROM context_entries WHERE id = ?", (entry_id,)).fetchone()
    return store._serialize(row)


def create_plans(store: ContextStore, body: dict[str, Any], *, actor_id: str | None = None) -> dict[str, Any]:
    spec = normalize_plan_request(body)
    if actor_id is not None:
        actor_id = store._validate_actor_id(actor_id)
    key = spec["request_id"]
    if key is not None and actor_id is None:
        raise ValueError("request_id requires a stable actor_id")
    with store._lock:
        store._ensure_available()
        with closing(store._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            conversation_id = verify_writer_nonce(
                connection,
                spec["conversation_id"],
                spec["writer_nonce"],
            )
            if key is not None:
                previous = connection.execute(
                    "SELECT fingerprint, response_json FROM context_plan_requests WHERE actor_id = ? AND request_id = ?",
                    (actor_id, key),
                ).fetchone()
                if previous is not None:
                    if previous["fingerprint"] != spec["fingerprint"]:
                        raise PlanRequestConflict("context_request_conflict", "request_id was already used with a different plan request")
                    receipt = json.loads(previous["response_json"])
                    ids = [receipt["id"], *(child["id"] for child in receipt["subplans"])]
                    retained = connection.execute(
                        "SELECT COUNT(*) FROM context_entries WHERE entry_type = 'plan' AND id IN (" + ",".join("?" for _ in ids) + ")", ids,
                    ).fetchone()[0]
                    if retained != len(ids):
                        raise PlanRequestConflict("context_request_gone", "one or more original plans were pruned; this request_id cannot create replacements")
                    return dict(receipt, replayed=True)
                count = connection.execute("SELECT COUNT(*) FROM context_plan_requests").fetchone()[0]
                if count >= MAX_PLAN_REQUESTS:
                    raise PlanRequestConflict("context_request_limit", "workspace plan request ledger is full; existing request IDs remain replayable")
            parent = spec["root"]["plan_id"]
            if parent is not None:
                store._validate_plan_parent(
                    connection,
                    parent,
                    require_root_in_progress=True,
                )
                parent_row = connection.execute(
                    "SELECT conversation_id FROM context_entries "
                    "WHERE id = ? AND entry_type = 'plan'",
                    (parent,),
                ).fetchone()
                if (
                    parent_row is not None
                    and parent_row["conversation_id"] is not None
                    and int(parent_row["conversation_id"]) != conversation_id
                ):
                    raise ValueError("parent plan belongs to a different conversation")
            appended_conversation_entries = append_conversation(
                connection,
                conversation_id=conversation_id,
                writer_nonce=spec["writer_nonce"],
                entries=spec["conversation_entries"],
            )
            now = _utc_now()
            root = _insert_plan(
                store,
                connection,
                spec["root"],
                parent,
                actor_id,
                now,
                conversation_id,
            )
            children = []
            for index, node in enumerate(spec["subplans"]):
                entry = _insert_plan(
                    store,
                    connection,
                    node,
                    root["id"],
                    actor_id,
                    now,
                    conversation_id,
                )
                child = {
                    field: entry[field]
                    for field in ("id", "plan_id", "taskname", "status", "revision")
                }
                child["index"] = index
                if "ref" in node:
                    child["ref"] = node["ref"]
                children.append(child)
            root.update(
                subplans=children,
                scope_paths=spec["root"]["scope_paths"],
                memory_tags=spec["root"]["memory_tags"],
                conversation_entries=appended_conversation_entries,
                conversation_summary_status=conversation_summary_status(
                    connection, conversation_id
                ),
            )
            ids = (root["id"], *(child["id"] for child in children))
            # Protect every member of the just-created batch even at trim limits.
            store._trim_if_needed(connection, protected_ids=ids)
            if key is not None:
                root.update(request_id=key, replayed=False)
                connection.execute(
                    "INSERT INTO context_plan_requests (actor_id, request_id, fingerprint, created_at, response_json) VALUES (?, ?, ?, ?, ?)",
                    (actor_id, key, spec["fingerprint"], now, store._encode_json(root)),
                )
    return root

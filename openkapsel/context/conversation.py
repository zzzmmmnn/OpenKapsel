"""Append-only conversation summaries stored beside Context/Plan state."""
from __future__ import annotations

import re
import secrets
import sqlite3
import string
from datetime import datetime, timezone
from typing import Any

MAX_CONVERSATION_CONTENT_CHARS = 1000
MAX_CONVERSATION_SUMMARY_CHARS = 8192
MAX_CONVERSATION_QUERY_LIMIT = 100
CONVERSATION_SENDERS = {"user", "ai", "summary"}
CONVERSATION_WRITE_PROVE_PATTERN = re.compile(r"^@[A-Za-z0-9]{4}@$")
_CONVERSATION_ALPHABET = string.ascii_letters + string.digits

CONVERSATION_INSTRUCTIONS = (
    "Conversation IDs are caller-supplied sequential non-negative integers. Before conversation_create, "
    "call conversation_query and use its next_conversation_id exactly; the first Conversation id is 0. "
    "This conversation is append-only. Preserve materially new user and AI context with conversation_append, "
    "using the conversation_id together with its write_prove. Use sender=user for the user's side and sender=ai "
    "for the AI's side. user/ai content is limited to 1000 characters and represents that side's conversation "
    "context summary; it may keep important original wording verbatim and does not need extra compression when "
    "the source already fits the limit. Every 30th entry is reserved for sender=summary: after entries 1-29, "
    "append a compressed aggregate summary before the next ordinary entry; repeat for 31-59, 61-89, and so on. "
    "summary content may be up to 8192 characters and must compress the preceding window while preserving its "
    "important context. Plan creation and non-cancelling Plan updates require this conversation id, its "
    "write_prove, and at least one atomic conversation entry."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize_conversation_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY CHECK (id >= 0),
            created_at TEXT NOT NULL,
            write_prove TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS conversation_entries (
            conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
            sub_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            sender TEXT NOT NULL CHECK (sender IN ('user', 'ai', 'summary')),
            content TEXT NOT NULL,
            PRIMARY KEY (conversation_id, sub_id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS conversation_entries_created "
        "ON conversation_entries(created_at DESC, conversation_id DESC, sub_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS conversation_entries_sender "
        "ON conversation_entries(sender, created_at DESC)"
    )


def generate_write_prove() -> str:
    return "@" + "".join(secrets.choice(_CONVERSATION_ALPHABET) for _ in range(4)) + "@"


def validate_write_prove(value: Any) -> str:
    if not isinstance(value, str) or not CONVERSATION_WRITE_PROVE_PATTERN.fullmatch(value):
        raise ValueError("write_prove must use exactly @xxxx@ with four ASCII letters or digits")
    return value


def validate_conversation_id(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("conversation_id must be a non-negative integer")
    if value > 2**63 - 1:
        raise ValueError("conversation_id exceeds the database ID range")
    return value


def next_conversation_id(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT MAX(id) AS max_id FROM conversations").fetchone()
    maximum = row["max_id"] if row is not None else None
    return 0 if maximum is None else int(maximum) + 1


def normalize_entries(
    entries: Any,
    *,
    minimum: int = 1,
    require_initial_pair: bool = False,
    require_ai: bool = False,
) -> list[dict[str, str]]:
    if not isinstance(entries, list) or len(entries) < minimum:
        raise ValueError(f"conversation entries must contain at least {minimum} item(s)")
    if len(entries) > MAX_CONVERSATION_QUERY_LIMIT:
        raise ValueError(f"conversation entries cannot contain more than {MAX_CONVERSATION_QUERY_LIMIT} items")
    normalized: list[dict[str, str]] = []
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or set(item) != {"sender", "content"}:
            raise ValueError(f"conversation entry {index} must contain only sender and content")
        sender = item.get("sender")
        if sender not in CONVERSATION_SENDERS:
            raise ValueError("conversation sender must be user, ai, or summary")
        content = item.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("conversation content must be a non-empty string")
        maximum = (
            MAX_CONVERSATION_SUMMARY_CHARS
            if sender == "summary"
            else MAX_CONVERSATION_CONTENT_CHARS
        )
        if len(content) > maximum:
            raise ValueError(
                f"conversation {sender} content exceeds {maximum} characters"
            )
        normalized.append({"sender": sender, "content": content})
    if require_initial_pair:
        if len(normalized) < 2 or normalized[0]["sender"] != "user" or normalized[1]["sender"] != "ai":
            raise ValueError("conversation creation requires first entry sender=user and second entry sender=ai")
    if require_ai and not any(item["sender"] == "ai" for item in normalized):
        raise ValueError("completing a plan requires at least one sender=ai conversation entry")
    return normalized


def verify_write_prove(
    connection: sqlite3.Connection,
    conversation_id: Any,
    write_prove: Any,
) -> int:
    conversation_id = validate_conversation_id(conversation_id)
    write_prove = validate_write_prove(write_prove)
    row = connection.execute(
        "SELECT write_prove FROM conversations WHERE id = ?",
        (conversation_id,),
    ).fetchone()
    if row is None:
        raise KeyError("conversation does not exist")
    if row["write_prove"] != write_prove:
        raise PermissionError("conversation write_prove does not match")
    return conversation_id


def _append_locked(
    connection: sqlite3.Connection,
    conversation_id: int,
    entries: list[dict[str, str]],
) -> list[dict[str, Any]]:
    row = connection.execute(
        "SELECT COALESCE(MAX(sub_id), 0) AS last_id FROM conversation_entries WHERE conversation_id = ?",
        (conversation_id,),
    ).fetchone()
    last_id = int(row["last_id"])
    now = _utc_now()
    created: list[dict[str, Any]] = []
    for item in entries:
        sub_id = last_id + 1
        summary_slot = sub_id % 30 == 0
        if summary_slot and item["sender"] != "summary":
            raise ValueError(
                f"conversation entry {sub_id} must be sender=summary before another ordinary entry"
            )
        if not summary_slot and item["sender"] == "summary":
            raise ValueError(
                f"conversation summary is only allowed at sub_id {((sub_id + 29) // 30) * 30}"
            )
        connection.execute(
            """
            INSERT INTO conversation_entries (
                conversation_id, sub_id, created_at, sender, content
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (conversation_id, sub_id, now, item["sender"], item["content"]),
        )
        created.append(
            {
                "conversation_id": conversation_id,
                "sub_id": sub_id,
                "created_at": now,
                "sender": item["sender"],
                "content": item["content"],
            }
        )
        last_id = sub_id
    return created


def create_conversation(
    connection: sqlite3.Connection,
    conversation_id: Any,
    entries: Any,
) -> dict[str, Any]:
    conversation_id = validate_conversation_id(conversation_id)
    expected_id = next_conversation_id(connection)
    if conversation_id != expected_id:
        raise ValueError(
            f"conversation_id must equal next_conversation_id {expected_id}"
        )
    normalized = normalize_entries(entries, minimum=2, require_initial_pair=True)
    write_prove = generate_write_prove()
    connection.execute(
        "INSERT INTO conversations (id, created_at, write_prove) VALUES (?, ?, ?)",
        (conversation_id, _utc_now(), write_prove),
    )
    created = _append_locked(connection, conversation_id, normalized)
    return {
        "conversation_id": conversation_id,
        "write_prove": write_prove,
        "entries": created,
        "instructions": CONVERSATION_INSTRUCTIONS,
    }


def append_conversation(
    connection: sqlite3.Connection,
    *,
    conversation_id: Any,
    write_prove: Any,
    entries: Any,
    require_ai: bool = False,
) -> list[dict[str, Any]]:
    conversation_id = verify_write_prove(connection, conversation_id, write_prove)
    normalized = normalize_entries(entries, minimum=1, require_ai=require_ai)
    return _append_locked(connection, conversation_id, normalized)


def query_conversations(
    connection: sqlite3.Connection,
    *,
    conversation_id: int | None = None,
    query: str = "",
    sender: str | None = None,
    start_sub_id: int | None = None,
    end_sub_id: int | None = None,
    full: bool = False,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], int, int]:
    if not 1 <= limit <= MAX_CONVERSATION_QUERY_LIMIT:
        raise ValueError(f"conversation limit must be between 1 and {MAX_CONVERSATION_QUERY_LIMIT}")
    if conversation_id is not None:
        conversation_id = validate_conversation_id(conversation_id)
    elif start_sub_id is not None or end_sub_id is not None:
        raise ValueError("sub_id ranges require conversation_id")
    for name, value in (("start_sub_id", start_sub_id), ("end_sub_id", end_sub_id)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise ValueError(f"{name} must be a positive integer")
    if start_sub_id is not None and end_sub_id is not None and start_sub_id > end_sub_id:
        raise ValueError("start_sub_id cannot exceed end_sub_id")
    if sender is not None and sender not in CONVERSATION_SENDERS:
        raise ValueError("conversation sender must be user, ai, or summary")
    if not isinstance(query, str):
        raise ValueError("conversation query must be a string")
    query = query.strip()
    if len(query) > MAX_CONVERSATION_SUMMARY_CHARS:
        raise ValueError(f"conversation query exceeds {MAX_CONVERSATION_SUMMARY_CHARS} characters")

    clauses: list[str] = []
    values: list[Any] = []
    if conversation_id is not None:
        clauses.append("e.conversation_id = ?")
        values.append(conversation_id)
    elif not full:
        clauses.append(
            "e.sub_id >= COALESCE(("
            "SELECT MAX(s.sub_id) FROM conversation_entries AS s "
            "WHERE s.conversation_id = e.conversation_id AND s.sender = 'summary'"
            "), 1)"
        )
    if sender is not None:
        clauses.append("e.sender = ?")
        values.append(sender)
    if start_sub_id is not None:
        clauses.append("e.sub_id >= ?")
        values.append(start_sub_id)
    if end_sub_id is not None:
        clauses.append("e.sub_id <= ?")
        values.append(end_sub_id)
    if query:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("e.content LIKE ? ESCAPE '\\'")
        values.append(f"%{escaped}%")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    total = int(
        connection.execute(
            "SELECT COUNT(*) FROM conversation_entries AS e" + where,
            values,
        ).fetchone()[0]
    )
    rows = connection.execute(
        "SELECT e.conversation_id, e.sub_id, e.created_at, e.sender, e.content "
        "FROM conversation_entries AS e"
        + where
        + " ORDER BY e.created_at DESC, e.conversation_id DESC, e.sub_id DESC LIMIT ?",
        [*values, limit],
    ).fetchall()
    return [
        {
            "conversation_id": int(row["conversation_id"]),
            "sub_id": int(row["sub_id"]),
            "created_at": row["created_at"],
            "sender": row["sender"],
            "content": row["content"],
        }
        for row in rows
    ], total, next_conversation_id(connection)

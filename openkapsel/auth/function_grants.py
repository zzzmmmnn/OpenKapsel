"""Volatile function-owned authorizations with independent Client-owned expiries.

The Server validates only the generic grants/expires_at envelope. Each item's
scope and other fields belong to the Client; expiry bookkeeping is kept apart
from its JSON and the Server never rewrites Client timestamps.
"""
from __future__ import annotations

import json
import math
import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Callable

from openkapsel.auth.capability_grants import PENDING_SECONDS, MAX_SECONDS


def _json_copy(value):
    """Bounded JSON round-trip avoids mutable references escaping the store."""
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(data.encode("utf-8")) > 128 * 1024:
        raise ValueError("approval data exceeds 128 KiB")
    return json.loads(data)


def _validated_auth(auth):
    if not isinstance(auth, dict) or not isinstance(auth.get("grants"), list):
        raise ValueError("function auth requires a grants list")
    for item in auth["grants"]:
        if (not isinstance(item, dict) or "expires_at" not in item
                or type(item["expires_at"]) not in (int, float)
                or not 0 <= item["expires_at"] <= 10**13
                or not math.isfinite(item["expires_at"])):
            raise ValueError("each grant requires a finite numeric expires_at")
    return auth


def _semantic_auth(auth):
    """Compare Client proposals on confirmation without clock-dependent values."""
    return {**auth, "grants": [
        {key: value for key, value in item.items() if key != "expires_at"}
        for item in auth["grants"]
    ]}


@dataclass(frozen=True)
class FunctionRequest:
    workspace: str
    conversation_id: int
    target: str
    function: str
    request: Any
    display: Any
    deadline: float
    reason: str = ""
    attempts: int = 0


@dataclass(frozen=True)
class FunctionAuth:
    auth: Any
    deadlines: tuple[float, ...]
    revision: int


class FunctionGrants:
    """Store Client auth scoped by Workspace, Conversation, target and function."""

    def __init__(self):
        self.lock = threading.RLock()
        self.pending_requests: dict[str, FunctionRequest] = {}
        self.active: dict[tuple[str, int, str, str], FunctionAuth] = {}
        self.confirmations: dict[str, tuple[str, Any, int, int]] = {}

    def _prune(self):
        now = time.monotonic()
        self.pending_requests = {k: v for k, v in self.pending_requests.items()
                                 if v.deadline > now}
        active = {}
        for key, entry in self.active.items():
            keep = [i for i, deadline in enumerate(entry.deadlines) if deadline > now]
            if len(keep) == len(entry.deadlines):
                active[key] = entry
            elif keep:
                # Only remove expired list items. Preserve all other Client
                # fields and every original expires_at exactly as returned.
                auth = dict(entry.auth)
                auth["grants"] = [entry.auth["grants"][i] for i in keep]
                active[key] = replace(entry, auth=auth,
                                      deadlines=tuple(entry.deadlines[i] for i in keep))
        self.active = active
        self.confirmations = {k: v for k, v in self.confirmations.items()
                              if k in self.pending_requests}
        return now

    def request(self, workspace: str, conversation_id: int, target: str,
                function: str, request: Any, *, display: Any = None, reason: str = "") -> str:
        if (not all(isinstance(item, str) and item for item in
                    (workspace, target, function))
                or type(conversation_id) is not int or conversation_id < 0):
            raise ValueError("invalid function approval binding")
        requested = _json_copy(request)
        displayed = _json_copy(display)
        with self.lock:
            now = self._prune()
            if sum(item.workspace == workspace for item in self.pending_requests.values()) >= 32:
                raise ValueError("too many pending function approvals")
            ticket = secrets.token_urlsafe(24)
            self.pending_requests[ticket] = FunctionRequest(
                workspace, conversation_id, target, function,
                requested, displayed, now + PENDING_SECONDS, reason,
            )
            return ticket

    def pending(self, ticket: str) -> FunctionRequest | None:
        with self.lock:
            self._prune()
            return self.pending_requests.get(ticket)

    def current(self, workspace: str, conversation_id: int, target: str,
                function: str) -> Any:
        with self.lock:
            self._prune()
            entry = self.active.get((workspace, conversation_id, target, function))
            return _json_copy(entry.auth) if entry else None

    def password_attempt(self, ticket: str, verify: Callable[[str], bool]) -> bool:
        """Keep per-ticket limits in addition to the shared address budget."""
        with self.lock:
            self._prune()
            entry = self.pending_requests.get(ticket)
            if entry is None:
                raise ValueError("function approval expired or used")
        # Password resets hold the password store lock before revoking this
        # store. Do not invert that lock order by calling verify under ours.
        valid = verify(entry.workspace)
        with self.lock:
            self._prune()
            current = self.pending_requests.get(ticket)
            if current is None:
                raise ValueError("function approval expired or revoked")
            if not valid:
                attempts = current.attempts + 1
                if attempts >= 5:
                    del self.pending_requests[ticket]
                else:
                    self.pending_requests[ticket] = replace(current, attempts=attempts)
                return False
            return True

    @staticmethod
    def _deadlines(previous, updated, started, seconds):
        """Match unchanged opaque items; calibrate new ones without touching JSON.

        Newly returned expiry minus the approved duration yields an estimate
        of the Client's clock at grant time. Server monotonic 'started' is an
        earlier, conservative reference (RPC latency can only shorten TTL).
        Keep old monotonic deadlines so a later Client clock change cannot
        extend earlier approvals.
        """
        old = list(zip(previous.auth["grants"], previous.deadlines)) if previous else []
        deadlines = [None] * len(updated["grants"])
        fresh = []
        for i, item in enumerate(updated["grants"]):
            match = next((j for j, (prior, _) in enumerate(old) if prior == item), None)
            if match is None:
                fresh.append(i)
            else:
                deadlines[i] = old.pop(match)[1]
        if fresh:
            client_now = max(updated["grants"][i]["expires_at"] for i in fresh) - seconds
            for i in fresh:
                deadlines[i] = started + updated["grants"][i]["expires_at"] - client_now
        return tuple(deadlines)

    def _candidate(self, pending, seconds, grant):
        key = (pending.workspace, pending.conversation_id,
               pending.target, pending.function)
        previous = self.active.get(key)
        started = time.monotonic()
        old_auth = _json_copy(previous.auth) if previous else None
        updated = _validated_auth(_json_copy(grant(old_auth, _json_copy(pending.request),
                                                     seconds)))
        deadlines = self._deadlines(previous, updated, started, seconds)
        if not deadlines or all(deadline <= time.monotonic() for deadline in deadlines):
            raise ValueError("function grant has no active authorization")
        return key, previous, updated, deadlines

    def approve(self, ticket: str, *, seconds: int,
                grant: Callable[[Any, Any, int], Any], browser: str | None = None) -> Any:
        """Revalidate Client grant at confirmation; publish only on success."""
        if type(seconds) is not int or not 60 <= seconds <= MAX_SECONDS:
            raise ValueError("invalid function approval duration")
        with self.lock:
            self._prune()
            pending = self.pending_requests.get(ticket)
            if pending is None:
                raise ValueError("function approval expired or used")
            key, previous, updated, deadlines = self._candidate(pending, seconds, grant)
            now = self._prune()
            if self.pending_requests.get(ticket) is not pending or pending.deadline <= now:
                raise ValueError("function approval expired or revoked")
            if browser is not None:
                prepared = self.confirmations.get(ticket)
                if (prepared is None or prepared[0] != browser
                        or prepared[2] != seconds
                        or prepared[3] != (previous.revision if previous else 0)
                        or _semantic_auth(prepared[1]) != _semantic_auth(updated)):
                    raise ValueError("approval changed; request a new confirmation")
            revision = previous.revision + 1 if previous else 1
            self.active[key] = FunctionAuth(updated, deadlines, revision)
            del self.pending_requests[ticket]
            self.confirmations.pop(ticket, None)
            self._prune()
            return _json_copy(self.active[key].auth) if key in self.active else None

    def prepare_confirmation(self, ticket: str, *, browser: str, seconds: int,
                             grant: Callable[[Any, Any, int], Any]) -> Any:
        if type(seconds) is not int or not 60 <= seconds <= MAX_SECONDS:
            raise ValueError("invalid function approval duration")
        with self.lock:
            self._prune()
            pending = self.pending_requests.get(ticket)
            if pending is None:
                raise ValueError("function approval expired or used")
            _, previous, updated, _ = self._candidate(pending, seconds, grant)
            if self.pending_requests.get(ticket) is not pending or pending.deadline <= time.monotonic():
                raise ValueError("function approval expired or revoked")
            self.confirmations[ticket] = (browser, updated, seconds,
                                          previous.revision if previous else 0)
            return _json_copy(updated)

    def confirmation(self, ticket: str, browser: str):
        with self.lock:
            self._prune()
            value = self.confirmations.get(ticket)
            return (_json_copy(value[1]), value[2]) if value and value[0] == browser else None

    def revoke(self, workspace: str, conversation_id: int, target: str,
               function: str) -> None:
        with self.lock:
            key = (workspace, conversation_id, target, function)
            self.active.pop(key, None)
            self.pending_requests = {k: v for k, v in self.pending_requests.items()
                if (v.workspace, v.conversation_id, v.target, v.function) != key}
            self.confirmations = {k: v for k, v in self.confirmations.items()
                                  if k in self.pending_requests}

    def list_grants(self, workspace: str) -> list[dict]:
        with self.lock:
            now = self._prune()
            return [
                {
                    "conversation_id": conv, "target": target,
                    "function": function,
                    "remaining_seconds": max(0, int(max(value.deadlines) - now)),
                }
                for (owner, conv, target, function), value in self.active.items()
                if owner == workspace
            ]

    def revoke_workspace(self, workspace: str) -> None:
        with self.lock:
            self.active = {key: value for key, value in self.active.items()
                           if key[0] != workspace}
            self.pending_requests = {key: value for key, value in self.pending_requests.items()
                                     if value.workspace != workspace}
            self.confirmations = {k: v for k, v in self.confirmations.items()
                                  if k in self.pending_requests}

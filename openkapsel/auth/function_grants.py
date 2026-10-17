"""Opaque memory-only authorizations for function-owned approval.

The control server does not parse, combine or evaluate the returned auth JSON.
Only the corresponding execution function may interpret it.  Browser/password
verification is performed by the HTTP control layer before commit().
"""
from __future__ import annotations

import json
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
    deadline: float
    revision: int


class FunctionGrants:
    """Store opaque auth by Workspace, Conversation, target and function."""

    def __init__(self):
        self.lock = threading.RLock()
        self.pending_requests: dict[str, FunctionRequest] = {}
        self.active: dict[tuple[str, int, str, str], FunctionAuth] = {}
        self.confirmations: dict[str, tuple[str, Any, int, int]] = {}

    def _prune(self):
        now = time.monotonic()
        self.pending_requests = {k: v for k, v in self.pending_requests.items()
                                 if v.deadline > now}
        self.active = {k: v for k, v in self.active.items()
                       if v.deadline > now}
        self.confirmations = {k: v for k, v in self.confirmations.items() if k in self.pending_requests}
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

    def approve(self, ticket: str, *, seconds: int,
                grant: Callable[[Any, Any], Any], browser: str | None = None) -> Any:
        """Grant callback decides the full merged auth; save only on success.

        Calling grant while locked keeps the old auth consistent.  The function
        must be side-effect-free; a remote callback may fail without granting.
        """
        if type(seconds) is not int or not 60 <= seconds <= MAX_SECONDS:
            raise ValueError("invalid function approval duration")
        with self.lock:
            self._prune()
            pending = self.pending_requests.get(ticket)
            if pending is None:
                raise ValueError("function approval expired or used")
            key = (pending.workspace, pending.conversation_id,
                   pending.target, pending.function)
            previous = self.active.get(key)
            old_auth = _json_copy(previous.auth) if previous else None
            updated = _json_copy(grant(old_auth, _json_copy(pending.request)))
            if self.pending_requests.get(ticket) is not pending or pending.deadline <= time.monotonic():
                raise ValueError("function approval expired or revoked")
            if browser is not None:
                prepared = self.confirmations.get(ticket)
                if (prepared is None or prepared[0] != browser
                        or prepared[1] != updated
                        or prepared[3] != (previous.revision if previous else 0)):
                    raise ValueError("approval changed; request a new confirmation")
            revision = previous.revision + 1 if previous else 1
            self.active[key] = FunctionAuth(
                updated, time.monotonic() + seconds, revision,
            )
            del self.pending_requests[ticket]
            self.confirmations.pop(ticket, None)
            return _json_copy(updated)

    def prepare_confirmation(self, ticket: str, *, browser: str, seconds: int,
                             grant: Callable[[Any, Any], Any]) -> Any:
        if type(seconds) is not int or not 60 <= seconds <= MAX_SECONDS:
            raise ValueError("invalid function approval duration")
        with self.lock:
            self._prune()
            pending = self.pending_requests.get(ticket)
            if pending is None:
                raise ValueError("function approval expired or used")
            key = (pending.workspace, pending.conversation_id, pending.target, pending.function)
            previous = self.active.get(key)
            updated = _json_copy(grant(_json_copy(previous.auth) if previous else None,
                                       _json_copy(pending.request)))
            if self.pending_requests.get(ticket) is not pending or pending.deadline <= time.monotonic():
                raise ValueError("function approval expired or revoked")
            self.confirmations[ticket] = (browser, updated, seconds, previous.revision if previous else 0)
            return _json_copy(updated)

    def confirmation(self, ticket: str, browser: str):
        with self.lock:
            self._prune()
            value = self.confirmations.get(ticket)
            return (_json_copy(value[1]), value[2]) if value and value[0] == browser else None

    def revoke(self, workspace: str, conversation_id: int, target: str,
               function: str) -> None:
        with self.lock:
            self.active.pop((workspace, conversation_id, target, function), None)
            self.pending_requests = {k: v for k, v in self.pending_requests.items()
                if (v.workspace, v.conversation_id, v.target, v.function) !=
                   (workspace, conversation_id, target, function)}

    def list_grants(self, workspace: str) -> list[dict]:
        with self.lock:
            now = self._prune()
            return [
                {
                    "conversation_id": conv, "target": target,
                    "function": function, "remaining_seconds": max(0, int(value.deadline - now)),
                }
                for (owner, conv, target, function), value in self.active.items()
                if owner == workspace
            ]

    def revoke_workspace(self, workspace: str) -> None:
        with self.lock:
            self.active = {key: value for key, value in self.active.items()
                           if key[0] != workspace}
            self.pending_requests = {
                key: value for key, value in self.pending_requests.items()
                if value.workspace != workspace
            }
            self.confirmations = {k: v for k, v in self.confirmations.items() if k in self.pending_requests}

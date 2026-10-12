"""Workspace passwords and memory-only time-bound capability approvals."""
from __future__ import annotations

import secrets
import hashlib
import hmac
import re
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from openkapsel.auth.security import hash_password, verify_password

CAPABILITIES = frozenset({"shell.elevated", "files.write"})
PENDING_SECONDS = 300
DEFAULT_SECONDS = 600
MAX_SECONDS = 24 * 3600
MAX_PENDING = 512
MAX_ATTEMPTS = 5


@dataclass
class Pending:
    workspace: str
    conversation_id: int
    target: str
    capability: str
    deadline: float
    attempts: int = 0


class CapabilityGrants:
    """Single-server grant store; only password hashes are persisted."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._browser_key = secrets.token_bytes(32)
        self.pending_requests: dict[str, Pending] = {}
        self.active: dict[tuple[str, int, str, str], float] = {}
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS workspace_passwords ("
                       "workspace TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
            db.commit()

    def configured(self, workspace: str) -> bool:
        with self.lock, closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT 1 FROM workspace_passwords WHERE workspace=?",
                             (workspace,)).fetchone()
            return row is not None

    def set_password(self, workspace: str, password: str) -> None:
        if not isinstance(workspace, str) or not isinstance(password, str) or not 12 <= len(password) <= 1024:
            raise ValueError("workspace password must contain 12-1024 characters")
        encoded = hash_password(password)
        with self.lock, closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO workspace_passwords (workspace,password_hash) "
                       "VALUES (?,?) ON CONFLICT(workspace) DO UPDATE SET "
                       "password_hash=excluded.password_hash", (workspace, encoded))
            db.commit()
            self.revoke_workspace(workspace)

    def _check_password(self, workspace: str, password: str) -> bool:
        if not isinstance(password, str) or len(password) > 1024:
            return False
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT password_hash FROM workspace_passwords WHERE workspace=?",
                             (workspace,)).fetchone()
        return bool(row and verify_password(password, row[0]))

    def verify_workspace_password(self, workspace: str, password: str) -> bool:
        """Also reusable as the workspace-password check for OAuth consent."""
        with self.lock:
            return self._check_password(workspace, password)

    def _expire(self):
        now = time.monotonic()
        self.pending_requests = {key: item for key, item in self.pending_requests.items()
                                 if item.deadline > now}
        self.active = {key: end for key, end in self.active.items() if end > now}
        return now

    def request(self, workspace: str, conversation_id: int, target: str, capability: str) -> str:
        if not isinstance(workspace, str) or not target or capability not in CAPABILITIES:
            raise ValueError("invalid capability approval request")
        if type(conversation_id) is not int or conversation_id < 0:
            raise ValueError("invalid conversation id")
        with self.lock:
            now = self._expire()
            if len(self.pending_requests) >= MAX_PENDING:
                raise RuntimeError("too many pending capability approvals")
            ticket = secrets.token_urlsafe(24)
            self.pending_requests[ticket] = Pending(
                workspace, conversation_id, target, capability, now + PENDING_SECONDS)
            return ticket

    def pending(self, ticket: str) -> Pending | None:
        with self.lock:
            self._expire()
            return self.pending_requests.get(ticket)

    def granted(self, workspace: str, conversation_id: int, target: str, capability: str) -> bool:
        with self.lock:
            now = self._expire()
            return self.active.get((workspace, conversation_id, target, capability), 0) > now

    def approve(self, ticket: str, password: str, seconds: int = DEFAULT_SECONDS) -> Pending:
        if type(seconds) is not int or not 60 <= seconds <= MAX_SECONDS:
            raise ValueError("grant duration must be 1 to 1440 minutes")
        with self.lock:
            now = self._expire()
            item = self.pending_requests.get(ticket)
            if item is None:
                raise ValueError("approval expired or already used")
            if item.attempts >= MAX_ATTEMPTS:
                del self.pending_requests[ticket]
                raise PermissionError("approval attempts exhausted")
            item.attempts += 1
            if not self._check_password(item.workspace, password):
                if item.attempts >= MAX_ATTEMPTS:
                    del self.pending_requests[ticket]
                raise PermissionError("workspace password incorrect")
            now = time.monotonic()
            if item.deadline <= now:
                del self.pending_requests[ticket]
                raise ValueError("approval expired or already used")
            self.active[(item.workspace, item.conversation_id, item.target,
                         item.capability)] = now + seconds
            del self.pending_requests[ticket]
            return item

    def revoke(self, workspace: str, conversation_id: int, target: str, capability: str) -> None:
        with self.lock:
            self.active.pop((workspace, conversation_id, target, capability), None)

    def revoke_workspace(self, workspace: str) -> None:
        with self.lock:
            self.active = {key: end for key, end in self.active.items() if key[0] != workspace}
            self.pending_requests = {ticket: item for ticket, item in self.pending_requests.items()
                                     if item.workspace != workspace}

    def list_grants(self, workspace: str) -> list[dict]:
        with self.lock:
            now = self._expire()
            return [{"conversation_id": conv, "target": target, "capability": capability,
                     "remaining_seconds": max(0, int(expiry - now))}
                    for (scope, conv, target, capability), expiry in self.active.items()
                    if scope == workspace]

    def remove_workspace(self, workspace: str) -> None:
        with self.lock, closing(sqlite3.connect(self.path)) as db:
            db.execute("DELETE FROM workspace_passwords WHERE workspace=?", (workspace,))
            db.commit()
            self.revoke_workspace(workspace)

    def browser_proof(self, ticket: str, cookie: str) -> str:
        return hmac.new(self._browser_key, (ticket + ":" + cookie).encode(), hashlib.sha256).hexdigest()

    def verify_browser(self, ticket: str, cookie: str | None, proof: str) -> bool:
        return bool(cookie and isinstance(proof, str) and re.fullmatch(r"[0-9a-f]{64}", proof) and
                    hmac.compare_digest(self.browser_proof(ticket, cookie), proof))

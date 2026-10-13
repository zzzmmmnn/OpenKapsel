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

CAPABILITIES = frozenset({"shell.elevated", "files.read", "files.write"})
PENDING_SECONDS = 300
DEFAULT_SECONDS = 600
MAX_SECONDS = 24 * 3600
MAX_PENDING_PER_TOKEN = 32
MAX_ATTEMPTS = 5


@dataclass
class Pending:
    workspace: str
    conversation_id: int
    target: str
    capability: str
    deadline: float
    path: str = ""
    attempts: int = 0


class CapabilityGrants:
    """Token-scoped grant store, keyed by stable app_id; only hashes persist."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._browser_key = secrets.token_bytes(32)
        self.pending_requests: dict[str, Pending] = {}
        self.active: dict[tuple[str, int, str, str, str], float] = {}
        with closing(sqlite3.connect(self.path)) as db:
            # Token app_id is the stable Workspace identity. Never reuse the
            # legacy path_prefix-keyed workspace_passwords table: a directory
            # can be shared by different Tokens with independent credentials.
            db.execute("CREATE TABLE IF NOT EXISTS token_passwords ("
                       "token_app_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
            db.commit()

    def configured(self, workspace: str) -> bool:
        with self.lock, closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT 1 FROM token_passwords WHERE token_app_id=?",
                             (workspace,)).fetchone()
            return row is not None

    def set_password(self, workspace: str, password: str) -> None:
        if not isinstance(workspace, str) or not isinstance(password, str) or not 6 <= len(password) <= 1024:
            raise ValueError("workspace password must contain 6-1024 characters")
        encoded = hash_password(password, min_length=6)
        with self.lock, closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO token_passwords (token_app_id,password_hash) "
                       "VALUES (?,?) ON CONFLICT(token_app_id) DO UPDATE SET "
                       "password_hash=excluded.password_hash", (workspace, encoded))
            db.commit()
            self.revoke_workspace(workspace)

    def _check_password(self, workspace: str, password: str) -> bool:
        if not isinstance(password, str) or len(password) > 1024:
            return False
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT password_hash FROM token_passwords WHERE token_app_id=?",
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

    def request(self, workspace: str, conversation_id: int, target: str, capability: str, path: str = "") -> str:
        if not isinstance(workspace, str) or not target or capability not in CAPABILITIES:
            raise ValueError("invalid capability approval request")
        if not isinstance(path, str) or (path and (capability not in {"files.read", "files.write"} or not path.startswith("/"))):
            raise ValueError("invalid approval path")
        if type(conversation_id) is not int or conversation_id < 0:
            raise ValueError("invalid conversation id")
        with self.lock:
            now = self._expire()
            # Pending approvals are scoped to the requesting Token (app_id).
            # One Token must not exhaust the request quota of another.
            if sum(item.workspace == workspace for item in self.pending_requests.values()) >= MAX_PENDING_PER_TOKEN:
                raise RuntimeError("too many pending capability approvals for token")
            ticket = secrets.token_urlsafe(24)
            self.pending_requests[ticket] = Pending(
                workspace, conversation_id, target, capability, now + PENDING_SECONDS, path=path)
            return ticket

    def pending(self, ticket: str) -> Pending | None:
        with self.lock:
            self._expire()
            return self.pending_requests.get(ticket)

    def granted(self, workspace: str, conversation_id: int, target: str, capability: str, path: str = "") -> bool:
        with self.lock:
            now = self._expire()
            return self.active.get((workspace, conversation_id, target, capability, path), 0) > now

    def granted_path(self, workspace: str, conversation_id: int, target: str,
                     capability: str, path: str) -> str | None:
        """Return the narrowest approved absolute directory containing path."""
        from pathlib import PurePosixPath
        if not path.startswith("/"):
            return None
        candidate = PurePosixPath(path)
        with self.lock:
            now = self._expire()
            scopes = [
                scope for (owner, conv, dest, permission, scope), expiry in self.active.items()
                if owner == workspace and conv == conversation_id and dest == target
                and permission == capability and scope and expiry > now
                and (candidate == PurePosixPath(scope) or PurePosixPath(scope) in candidate.parents)
            ]
        return max(scopes, key=len) if scopes else None

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
                         item.capability, item.path)] = now + seconds
            del self.pending_requests[ticket]
            return item

    def revoke(self, workspace: str, conversation_id: int, target: str, capability: str, path: str = "") -> None:
        with self.lock:
            self.active.pop((workspace, conversation_id, target, capability, path), None)

    def revoke_workspace(self, workspace: str) -> None:
        with self.lock:
            self.active = {key: end for key, end in self.active.items() if key[0] != workspace}
            self.pending_requests = {ticket: item for ticket, item in self.pending_requests.items()
                                     if item.workspace != workspace}

    def list_grants(self, workspace: str) -> list[dict]:
        with self.lock:
            now = self._expire()
            return [{"conversation_id": conv, "target": target, "capability": capability, "path": path,
                     "remaining_seconds": max(0, int(expiry - now))}
                    for (scope, conv, target, capability, path), expiry in self.active.items()
                    if scope == workspace]

    def remove_workspace(self, workspace: str) -> None:
        with self.lock, closing(sqlite3.connect(self.path)) as db:
            db.execute("DELETE FROM token_passwords WHERE token_app_id=?", (workspace,))
            db.commit()
            self.revoke_workspace(workspace)

    def browser_proof(self, ticket: str, cookie: str) -> str:
        return hmac.new(self._browser_key, (ticket + ":" + cookie).encode(), hashlib.sha256).hexdigest()

    def verify_browser(self, ticket: str, cookie: str | None, proof: str) -> bool:
        return bool(cookie and isinstance(proof, str) and re.fullmatch(r"[0-9a-f]{64}", proof) and
                    hmac.compare_digest(self.browser_proof(ticket, cookie), proof))

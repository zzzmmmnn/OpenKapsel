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

CAPABILITIES = frozenset({"shell.unsandboxed", "files.read", "files.write"})
PENDING_SECONDS = 300
DEFAULT_SECONDS = 600
MAX_SECONDS = 24 * 3600
MAX_PENDING_PER_TOKEN = 32
MAX_APPROVAL_REASON_CHARS = 500
MAX_ATTEMPTS = 5
PASSWORD_SETUP_SECONDS = 15 * 60


@dataclass
class Pending:
    workspace: str
    conversation_id: int
    target: str
    capability: str
    deadline: float
    path: str = ""
    reason: str = ""
    original_path: str = ""
    resolved_path: str = ""
    scope_is_directory: bool = True
    confirmation_cookie: str = ""
    confirmation_seconds: int = 0
    attempts: int = 0


class CapabilityGrants:
    """Token-scoped grant store, keyed by stable app_id; only hashes persist."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._browser_key = secrets.token_bytes(32)
        # Password setup links are volatile, one at a time per Token. They
        # never leave process memory, and a restart revokes all outstanding URLs.
        self.password_setup_links: dict[str, tuple[str, float]] = {}
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
            self.password_setup_links = {
                ticket: item for ticket, item in self.password_setup_links.items()
                if item[0] != workspace
            }

    def create_password_setup_link(self, workspace: str) -> str:
        """Admin-only caller creates a single live, 15-minute, one-use link."""
        if not isinstance(workspace, str) or not workspace:
            raise ValueError("invalid Token Workspace")
        with self.lock:
            now = time.monotonic()
            self.password_setup_links = {
                key: (owner, expires) for key, (owner, expires)
                in self.password_setup_links.items()
                if expires > now and owner != workspace
            }
            ticket = secrets.token_urlsafe(32)
            self.password_setup_links[ticket] = (workspace, now + PASSWORD_SETUP_SECONDS)
            return ticket

    def password_setup_workspace(self, ticket: str) -> str | None:
        with self.lock:
            entry = self.password_setup_links.get(ticket)
            if entry is None:
                return None
            if entry[1] <= time.monotonic():
                self.password_setup_links.pop(ticket, None)
                return None
            return entry[0]

    def consume_password_setup_link(self, ticket: str, password: str, confirmation: str) -> str:
        """Atomically replace the Token password and redeem this link once."""
        if not isinstance(password, str) or not isinstance(confirmation, str):
            raise ValueError("password fields are required")
        if not hmac.compare_digest(password.encode(), confirmation.encode()):
            raise ValueError("passwords do not match")
        with self.lock:
            workspace = self.password_setup_workspace(ticket)
            if workspace is None:
                raise ValueError("password setup link is expired or already used")
            self.set_password(workspace, password)
            return workspace

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

    def request(self, workspace: str, conversation_id: int, target: str, capability: str,
                path: str = "", *, reason: str = "", original_path: str = "",
                resolved_path: str = "", scope_is_directory: bool = True) -> str:
        if not isinstance(workspace, str) or not target or capability not in CAPABILITIES:
            raise ValueError("invalid capability approval request")
        if (not isinstance(path, str) or
            (path and (capability not in {"files.read", "files.write"}
                       or not path.startswith("/") or ".." in path.split("/")
                       or "\\x00" in path or "\\\\" in path))):
            raise ValueError("invalid approval path")
        if (not isinstance(original_path, str) or len(original_path) > 4096
            or (original_path and (not original_path.startswith("/")
                or ".." in original_path.split("/") or "\x00" in original_path
                or "\\" in original_path))):
            raise ValueError("invalid approval original path")
        if (not isinstance(resolved_path, str) or len(resolved_path) > 4096
            or (resolved_path and (not resolved_path.startswith("/")
                or ".." in resolved_path.split("/") or "\x00" in resolved_path
                or "\\" in resolved_path))):
            raise ValueError("invalid resolved approval path")
        if (not isinstance(reason, str) or len(reason) > MAX_APPROVAL_REASON_CHARS
            or any(ord(c) < 32 and c not in "\\n\\r\\t" for c in reason)):
            raise ValueError("reason must be a bounded text description (maximum 500 characters)")
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
                workspace, conversation_id, target, capability, now + PENDING_SECONDS,
                path=path, reason=reason, original_path=original_path,
                resolved_path=resolved_path, scope_is_directory=scope_is_directory)
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
        # PurePosixPath preserves '..' rather than resolving it. Never let a
        # lexical ancestor match authorize a path that escapes the subtree.
        if ".." in path.split("/") or "\\x00" in path or "\\\\" in path:
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

    def has_scoped_grant(self, workspace: str, conversation_id: int,
                         target: str, capability: str) -> bool:
        """Presence only: never disclose approved canonical scopes in a prompt."""
        with self.lock:
            now = self._expire()
            return any(owner == workspace and conv == conversation_id and dest == target
                       and permission == capability and scope and deadline > now
                       for (owner, conv, dest, permission, scope), deadline in self.active.items())

    def authenticate_file(self, ticket: str, password: str, seconds: int) -> Pending:
        """Validate password before touching an external path; do NOT grant yet."""
        if type(seconds) is not int or not 60 <= seconds <= MAX_SECONDS:
            raise ValueError("grant duration must be 1 to 1440 minutes")
        with self.lock:
            self._expire()
            item = self.pending_requests.get(ticket)
            if item is None or not item.path or item.capability not in {"files.read", "files.write"}:
                raise ValueError("approval expired or not a scoped File request")
            if item.attempts >= MAX_ATTEMPTS:
                self.pending_requests.pop(ticket, None)
                raise PermissionError("approval attempts exhausted")
            if not self._check_password(item.workspace, password):
                item.attempts += 1
                if item.attempts >= MAX_ATTEMPTS:
                    self.pending_requests.pop(ticket, None)
                raise PermissionError("workspace password incorrect")
            return item

    def prepare_file_confirmation(self, ticket: str, cookie: str, path: str,
                                  resolved_path: str, seconds: int) -> None:
        """Bind a password-verified ticket to the actual real directory and browser."""
        with self.lock:
            self._expire()
            item = self.pending_requests.get(ticket)
            if item is None:
                raise ValueError("approval expired")
            if (not path.startswith("/") or ".." in path.split("/")
                or not resolved_path.startswith("/") or ".." in resolved_path.split("/")):
                raise ValueError("invalid resolved approval directory")
            if not item.original_path:
                item.original_path = item.path
            item.path = path
            item.resolved_path = resolved_path
            item.confirmation_seconds = seconds
            item.confirmation_cookie = self.browser_proof(ticket, cookie)

    def verify_file_confirmation_browser(self, ticket: str, cookie: str) -> bool:
        with self.lock:
            self._expire()
            item = self.pending_requests.get(ticket)
            return bool(item and item.confirmation_cookie and
                        hmac.compare_digest(item.confirmation_cookie,
                                            self.browser_proof(ticket, cookie)))

    def confirm_file(self, ticket: str, cookie: str) -> Pending:
        """Grant only the browser that passed the password and reviewed the path."""
        with self.lock:
            now = self._expire()
            item = self.pending_requests.get(ticket)
            if (item is None or not item.confirmation_cookie or
                not hmac.compare_digest(item.confirmation_cookie,
                                        self.browser_proof(ticket, cookie))):
                raise PermissionError("file confirmation requires the authenticated browser")
            self.active[(item.workspace, item.conversation_id, item.target,
                         item.capability, item.path)] = now + item.confirmation_seconds
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
            # Rotating, disabling or reassigning the Token must also revoke
            # outstanding delegated password setup URLs.
            self.password_setup_links = {
                ticket: item for ticket, item in self.password_setup_links.items()
                if item[0] != workspace
            }

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
            self.password_setup_links = {
                key: item for key, item in self.password_setup_links.items()
                if item[0] != workspace
            }

    def browser_proof(self, ticket: str, cookie: str) -> str:
        return hmac.new(self._browser_key, (ticket + ":" + cookie).encode(), hashlib.sha256).hexdigest()

    def verify_browser(self, ticket: str, cookie: str | None, proof: str) -> bool:
        return bool(cookie and isinstance(proof, str) and re.fullmatch(r"[0-9a-f]{64}", proof) and
                    hmac.compare_digest(self.browser_proof(ticket, cookie), proof))

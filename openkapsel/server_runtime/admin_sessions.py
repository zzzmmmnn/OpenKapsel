"""Administrator sessions and login rate limiting."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from openkapsel.random_ids import token_urlsafe_alnum

@dataclass(frozen=True)
class AdminSession:
    id: str
    csrf: str
    expires_at: float


class AdminSessions:
    def __init__(self) -> None:
        self._sessions: dict[str, AdminSession] = {}
        self._lock = threading.Lock()

    def create(self) -> AdminSession:
        session = AdminSession(
            id=token_urlsafe_alnum(32),
            csrf=token_urlsafe_alnum(24),
            expires_at=time.time() + 12 * 60 * 60,
        )
        with self._lock:
            self._prune_locked()
            self._sessions[session.id] = session
        return session

    def get(self, session_id: str | None) -> AdminSession | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.expires_at <= time.time():
                self._sessions.pop(session_id, None)
                return None
            return session

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def delete_others(self, keep_session_id: str) -> None:
        with self._lock:
            self._sessions = {
                session_id: session
                for session_id, session in self._sessions.items()
                if session_id == keep_session_id
            }

    def _prune_locked(self) -> None:
        now = time.time()
        for session_id, session in list(self._sessions.items()):
            if session.expires_at <= now:
                self._sessions.pop(session_id, None)


class AdminLoginLimiter:
    """Escalating in-memory per-address limiter for password guessing."""

    RETENTION_SECONDS = 24 * 60 * 60
    INITIAL_FAILURES = 3
    WINDOW_STEP_SECONDS = 60

    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allowed(self, address: str) -> bool:
        return self.retry_after(address) == 0

    def retry_after(self, address: str) -> int:
        with self._lock:
            now = time.time()
            attempts = self._recent_locked(address, now)
            blocked_until = self._blocked_until(attempts)
            if blocked_until <= now:
                return 0
            return max(1, int(blocked_until - now + 0.999))

    def failed(self, address: str) -> None:
        with self._lock:
            now = time.time()
            attempts = self._recent_locked(address, now)
            attempts.append(now)
            self._failures[address] = attempts

    def succeeded(self, address: str) -> None:
        with self._lock:
            self._failures.pop(address, None)

    def _recent_locked(self, address: str, now: float) -> list[float]:
        cutoff = now - self.RETENTION_SECONDS
        attempts = [item for item in self._failures.get(address, []) if item >= cutoff]
        if attempts:
            self._failures[address] = attempts
        else:
            self._failures.pop(address, None)
        return attempts

    def _blocked_until(self, attempts: list[float]) -> float:
        blocked_until = 0.0
        for count in range(self.INITIAL_FAILURES, len(attempts) + 1):
            window = (count - self.INITIAL_FAILURES + 1) * self.WINDOW_STEP_SECONDS
            blocked_until = max(blocked_until, attempts[-count] + window)
        return blocked_until

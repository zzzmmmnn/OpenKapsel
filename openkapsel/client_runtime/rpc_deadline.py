"""Cooperative per-worker deadlines for synchronous Client RPC work.

A server RPC timeout stops waiting, not the remote Python worker. This
context is thread-local to one RPC and deliberately does not forcefully
interrupt a filesystem mutation after it enters its commit/rollback phase.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import time

from openkapsel.errors import ApiError

_ACTIVE = ContextVar("openkapsel_client_rpc_deadline", default=None)


@contextmanager
def deadline_scope(seconds: float, cancelled=None):
    deadline = time.monotonic() + seconds
    parent = _ACTIVE.get()
    if parent is not None:
        deadline = min(deadline, parent[0])
        parent_cancelled = parent[1]
        if parent_cancelled is not None:
            own_cancelled = cancelled
            def combined_cancelled():
                return parent_cancelled() or (own_cancelled is not None and own_cancelled())
            cancelled = combined_cancelled
    token = _ACTIVE.set((deadline, cancelled))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def remaining_seconds(default: float = 75.0) -> float:
    state = _ACTIVE.get()
    return max(0.0, state[0] - time.monotonic()) if state else default


def check_deadline():
    state = _ACTIVE.get()
    if state is None:
        return
    deadline, cancelled = state
    if cancelled is not None and cancelled():
        raise ApiError(504, "client_rpc_cancelled", "Client RPC transport closed during operation")
    if time.monotonic() >= deadline:
        raise ApiError(504, "client_rpc_timeout", "Client RPC execution time limit exceeded")

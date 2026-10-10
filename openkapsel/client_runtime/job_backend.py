"""Stable local Job interface across in-process and shared Manager backends.

The existing Mapping WebSocket task operation names and result shapes are
unchanged. Only the backend owns process/job lifecycle; ClientRuntime is a
transport proxy. Manager IPC has its own versioned JSON byte protocol.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class JobBackend(Protocol):
    def dispatch(self, operation: str, args: dict[str, Any]) -> Any:
        """Handle task_start/get/list/stdin/interrupt/kill."""

    def capabilities(self) -> dict[str, Any]:
        """Advertise execution policy and job persistence."""

    def has_active_jobs(self) -> bool:
        """True only for jobs owned by this Client process (reload guard)."""

    def close(self) -> None:
        """Release local resources without interrupting external jobs."""

"""Shared API exception types."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    """An expected API error that can be returned as JSON."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers or {}


class McpError(Exception):
    """A JSON-RPC/MCP protocol error."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

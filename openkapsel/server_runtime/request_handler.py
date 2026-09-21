"""Composite HTTP request handler."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler

from openkapsel.api.discovery import DiscoveryMixin
from openkapsel.api.mcp_handlers import McpHandlersMixin
from openkapsel.api.preview_handlers import PreviewHandlersMixin
from openkapsel.api.skill_handlers import SkillHandlersMixin
from openkapsel.auth.admin_handlers import AdminHandlersMixin
from openkapsel.auth.oauth_handlers import OAuthHandlersMixin
from openkapsel.auth.static_mcp import StaticMcpHandlersMixin
from openkapsel.context.context_handlers import ContextCreationMixin
from openkapsel.context.memory_handlers import MemoryHandlersMixin
from openkapsel.execution.environment_handlers import EnvironmentHandlersMixin
from openkapsel.execution.sandbox import SandboxMixin
from openkapsel.execution.schedule_handlers import ScheduleHandlersMixin
from openkapsel.execution.shell_routing import ShellRoutingMixin
from openkapsel.files.archive_handlers import ArchiveHandlersMixin
from openkapsel.files.file_handlers import FileHandlersMixin
from openkapsel.files.git_handlers import GitHandlersMixin
from openkapsel.files.share_handlers import ShareHandlersMixin
from openkapsel.mapping.mapping_handlers import MappingHandlersMixin

from .context_http import ContextHttpMixin
from .dispatch import RequestDispatchMixin
from .http_support import HttpSupportMixin
from .task_http import TaskHttpMixin


class WorkspaceRequestHandler(
    RequestDispatchMixin,
    ContextHttpMixin,
    TaskHttpMixin,
    HttpSupportMixin,
    ContextCreationMixin,
    ShellRoutingMixin,
    GitHandlersMixin,
    ArchiveHandlersMixin,
    MappingHandlersMixin,
    AdminHandlersMixin,
    OAuthHandlersMixin,
    StaticMcpHandlersMixin,
    DiscoveryMixin,
    EnvironmentHandlersMixin,
    FileHandlersMixin,
    McpHandlersMixin,
    MemoryHandlersMixin,
    ShareHandlersMixin,
    SkillHandlersMixin,
    PreviewHandlersMixin,
    ScheduleHandlersMixin,
    SandboxMixin,
    BaseHTTPRequestHandler,
):
    protocol_version = "HTTP/1.1"

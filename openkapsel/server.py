"""Dependency-free OpenKapsel HTTP server.

The URL token is a capability: anyone who has it receives its configured file,
network, and shell permissions. Put this server behind HTTPS when it is reachable
over a network.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import sqlite3
import stat
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .admin_ui import render_discovery, render_http_error
from .admin_handlers import AdminHandlersMixin
from .api_workers import ApiWorkerManager
from .cgroups import (
    BUBBLEWRAP_PROCESS_OVERHEAD,
    SandboxLimits,
    TokenCgroupManager,
)
from .context_store import (
    MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
    MAX_CONTEXT_QUERY_LIMIT,
    MAX_CONTEXT_TASKNAME_CHARS,
    ContextStore,
)
from .discovery import DiscoveryMixin
from .errors import ApiError
from .environment_handlers import EnvironmentHandlersMixin
from .file_handlers import FileHandlersMixin
from .mcp_handlers import McpHandlersMixin
from .memory_handlers import MemoryHandlersMixin
from .memory_store import MemoryStore
from .network_proxy import (
    DEFAULT_NETWORK_DOMAINS,
    configure_proxy_limits,
    normalize_domain_rules,
    prepare_proxy_root,
)
from .preview_handlers import PreviewHandlersMixin
from .recycle import RecycleBin, RecycleError
from .routes import EndpointSpec, match_endpoint
from .sandbox import SandboxMixin
from .schedule_handlers import ScheduleHandlersMixin
from .sandbox_backends import SandboxRegistry
from .safe_paths import ParentHandle, SafePathAccess, SafePathError
from .security import (
    hash_password,
    is_password_hash_supported,
    password_hash_needs_upgrade,
    verify_password,
)
from .scheduler import SchedulerManager
from .scheduler_store import ScheduleStore
from .shell_execution import start_shell_task
from .share_handlers import ShareHandlersMixin
from .share_store import ShareStore
from .skill_handlers import SkillHandlersMixin
from .tasks import TaskRegistry
from .tokens import CONTAINER_IMAGE_RE, CredentialRenewalNotDue, TokenStore
from .uploads import UploadRegistry
from .workspace_layout import INTERNAL_DIRECTORY
from .workspace_images import WorkspaceImageClient


LOGGER = logging.getLogger("openkapsel")


@dataclass(frozen=True)
class ServerConfig:
    root: Path
    token: str | None = None
    name: str = "OpenKapsel"
    token_data_file: Path | None = None
    admin_username: str | None = None
    admin_password_hash: str | None = None
    public_base_url: str | None = None
    preview_base_url: str | None = None
    url_base_path: str = ""
    config_file: Path | None = None
    bubblewrap_path: Path = Path("/usr/bin/bwrap")
    rootlesskit_path: Path = Path("/usr/bin/rootlesskit")
    podman_path: Path = Path("/usr/bin/podman")
    podman_image: str = "docker.io/library/python:3.12-slim"
    podman_runtime: str = "crun"
    sandbox_backends: tuple[str, ...] = ("bubblewrap",)
    sandbox_default_backend: str = "bubblewrap"
    max_body_bytes: int = 2 * 1024 * 1024
    max_read_chars: int = 1024 * 1024
    default_read_chars: int = 64 * 1024
    max_task_output_bytes: int = 2 * 1024 * 1024
    max_concurrent_shell_tasks: int = 16
    max_concurrent_shell_tasks_per_token: int = 8
    max_http_connections: int = 128
    http_socket_timeout_seconds: float = 30.0
    max_sse_streams: int = 16
    max_sse_streams_per_token: int = 4
    max_sse_duration_seconds: float = 60 * 60
    task_history_dir: Path | None = None
    finished_task_retention_seconds: int = 60 * 60
    max_finished_tasks_per_token: int = 4
    sandbox_cgroup_enabled: bool = False
    default_command_timeout: float | None = None
    max_direct_upload_bytes: int = 32 * 1024 * 1024
    max_file_bytes: int = 10 * 1024 * 1024 * 1024
    upload_chunk_bytes: int = 4 * 1024 * 1024
    mcp_binary_chunk_bytes: int = 256 * 1024
    upload_ttl_seconds: int = 24 * 60 * 60
    max_incomplete_upload_bytes: int = 20 * 1024 * 1024 * 1024
    max_text_replace_bytes: int = 32 * 1024 * 1024
    transfer_buffer_bytes: int = 1024 * 1024
    max_concurrent_transfers: int = 4
    max_search_results: int = 1000
    max_search_file_bytes: int = 8 * 1024 * 1024
    max_tree_nodes: int = 5000
    max_recursion_depth: int = 32
    max_batch_file_operations: int = 1000
    upload_state_dir: Path | None = None
    api_worker_dir: Path | None = None
    network_proxy_dir: Path | None = None
    max_network_proxy_connections: int = 64
    max_network_proxy_connections_per_instance: int = 16
    network_proxy_header_timeout_seconds: float = 15.0
    default_network_domains: tuple[str, ...] = DEFAULT_NETWORK_DOMAINS
    api_worker_idle_seconds: int = 600
    api_max_body_bytes: int = 16 * 1024 * 1024
    workspace_image_socket: Path | None = None
    share_dir: Path | None = None
    share_ttl_seconds: int = 24 * 60 * 60
    max_share_entries: int = 10
    max_share_bytes: int = 256 * 1024 * 1024
    schedule_misfire_grace_seconds: int = 300

    def __post_init__(self) -> None:
        resolved = self.root.expanduser().resolve()
        if not resolved.is_dir():
            raise ValueError(f"workspace root is not a directory: {resolved}")
        if self.token is not None and (not self.token or "/" in self.token):
            raise ValueError("token must be non-empty and must not contain '/'")
        if bool(self.admin_username) != bool(self.admin_password_hash):
            raise ValueError("admin username and password hash must be configured together")
        if self.admin_password_hash is not None and not is_password_hash_supported(
            self.admin_password_hash
        ):
            raise ValueError("admin password hash is not a supported encoded password hash")
        base_path = self.url_base_path.strip()
        if base_path in {"", "/"}:
            base_path = ""
        elif not base_path.startswith("/") or base_path.endswith("/") or any(
            item in base_path for item in {"?", "#", ".."}
        ):
            raise ValueError("url_base_path must look like '/kapsel' without a trailing slash")
        if self.public_base_url is not None:
            public = urlsplit(self.public_base_url)
            if (
                public.scheme not in {"http", "https"}
                or not public.netloc
                or public.path not in {"", "/"}
                or public.query
                or public.fragment
            ):
                raise ValueError("public_base_url must be an http(s) origin without a path")
        if self.preview_base_url is not None:
            preview = urlsplit(self.preview_base_url)
            if (
                preview.scheme not in {"http", "https"}
                or not preview.netloc
                or preview.path not in {"", "/"}
                or preview.query
                or preview.fragment
            ):
                raise ValueError("preview_base_url must be an http(s) origin without a path")
            if self.public_base_url is not None and (
                preview.scheme.lower(),
                preview.netloc.lower(),
            ) == (public.scheme.lower(), public.netloc.lower()):
                raise ValueError("preview_base_url must use a different origin from public_base_url")
        if min(
            self.max_body_bytes,
            self.max_read_chars,
            self.default_read_chars,
            self.max_task_output_bytes,
            self.max_concurrent_shell_tasks,
            self.max_concurrent_shell_tasks_per_token,
            self.max_http_connections,
            self.max_sse_streams,
            self.max_sse_streams_per_token,
            self.finished_task_retention_seconds,
            self.max_finished_tasks_per_token,
            self.max_direct_upload_bytes,
            self.max_file_bytes,
            self.upload_chunk_bytes,
            self.mcp_binary_chunk_bytes,
            self.upload_ttl_seconds,
            self.max_incomplete_upload_bytes,
            self.max_text_replace_bytes,
            self.transfer_buffer_bytes,
            self.max_concurrent_transfers,
            self.max_search_results,
            self.max_search_file_bytes,
            self.max_tree_nodes,
            self.max_recursion_depth,
            self.max_batch_file_operations,
            self.max_network_proxy_connections,
            self.max_network_proxy_connections_per_instance,
            self.api_worker_idle_seconds,
            self.api_max_body_bytes,
            self.share_ttl_seconds,
            self.max_share_entries,
            self.max_share_bytes,
            self.schedule_misfire_grace_seconds,
        ) < 1:
            raise ValueError("size and task limits must be positive")
        if min(
            self.http_socket_timeout_seconds,
            self.max_sse_duration_seconds,
            self.network_proxy_header_timeout_seconds,
        ) <= 0:
            raise ValueError("HTTP and proxy timeout limits must be positive")
        if self.default_read_chars > self.max_read_chars:
            raise ValueError("default_read_chars cannot exceed max_read_chars")
        if self.max_sse_streams_per_token > self.max_sse_streams:
            raise ValueError("max_sse_streams_per_token cannot exceed max_sse_streams")
        if self.max_network_proxy_connections_per_instance > self.max_network_proxy_connections:
            raise ValueError(
                "max_network_proxy_connections_per_instance cannot exceed "
                "max_network_proxy_connections"
            )
        if self.http_socket_timeout_seconds > 300:
            raise ValueError("http_socket_timeout_seconds cannot exceed 300 seconds")
        if self.max_sse_duration_seconds > 86_400:
            raise ValueError("max_sse_duration_seconds cannot exceed 86400 seconds")
        if self.network_proxy_header_timeout_seconds > 300:
            raise ValueError("network_proxy_header_timeout_seconds cannot exceed 300 seconds")
        if self.finished_task_retention_seconds > 60 * 60:
            raise ValueError("finished task retention cannot exceed 3600 seconds")
        if self.max_finished_tasks_per_token > 4:
            raise ValueError("finished task retention cannot exceed 4 tasks per token")
        if self.default_command_timeout is not None and not 0.1 <= self.default_command_timeout <= 86_400:
            raise ValueError("default command timeout must be between 0.1 and 86400 seconds")
        object.__setattr__(self, "root", resolved)
        object.__setattr__(self, "url_base_path", base_path)
        if self.token_data_file is not None:
            object.__setattr__(self, "token_data_file", self.token_data_file.expanduser().resolve())
        if self.config_file is not None:
            object.__setattr__(self, "config_file", self.config_file.expanduser().resolve())
        if self.workspace_image_socket is not None:
            socket_path = self.workspace_image_socket.expanduser()
            if not socket_path.is_absolute():
                raise ValueError("workspace_image_socket must be an absolute path")
            object.__setattr__(self, "workspace_image_socket", socket_path)
        task_history_dir = self.task_history_dir
        if task_history_dir is None:
            if self.token_data_file is not None:
                task_history_dir = self.token_data_file.parent / "tasks"
            elif self.config_file is not None:
                task_history_dir = self.config_file.parent / "tasks"
            else:
                task_history_dir = resolved.parent / "tasks"
        task_history_dir = task_history_dir.expanduser().resolve()
        try:
            task_history_dir.relative_to(resolved)
        except ValueError:
            pass
        else:
            raise ValueError("task_history_dir must be outside workspace_root")
        object.__setattr__(self, "task_history_dir", task_history_dir)
        object.__setattr__(self, "bubblewrap_path", self.bubblewrap_path.expanduser().resolve())
        object.__setattr__(self, "rootlesskit_path", self.rootlesskit_path.expanduser().resolve())
        object.__setattr__(self, "podman_path", self.podman_path.expanduser().resolve())
        allowed_backends = {"bubblewrap", "podman"}
        if not self.sandbox_backends or len(set(self.sandbox_backends)) != len(self.sandbox_backends):
            raise ValueError("sandbox_backends must contain unique backend names")
        if not set(self.sandbox_backends) <= allowed_backends:
            raise ValueError("sandbox_backends may contain only bubblewrap and podman")
        if self.sandbox_default_backend not in self.sandbox_backends:
            raise ValueError("sandbox_default_backend must be enabled in sandbox_backends")
        podman_image = self.podman_image.strip()
        if "podman" in self.sandbox_backends and not CONTAINER_IMAGE_RE.fullmatch(podman_image):
            raise ValueError("podman_image must be a valid container image reference")
        object.__setattr__(self, "podman_image", podman_image)
        if "podman" in self.sandbox_backends and not self.podman_runtime.strip():
            raise ValueError("podman_runtime must be set when the Podman backend is enabled")
        object.__setattr__(
            self,
            "default_network_domains",
            normalize_domain_rules(list(self.default_network_domains)),
        )
        upload_state_dir = self.upload_state_dir
        if upload_state_dir is None:
            if self.token_data_file is not None:
                upload_state_dir = self.token_data_file.parent / "uploads"
            elif self.config_file is not None:
                upload_state_dir = self.config_file.parent / "uploads"
            else:
                upload_state_dir = self.root.parent / ".openkapsel-uploads"
        object.__setattr__(self, "upload_state_dir", upload_state_dir.expanduser().resolve())
        api_worker_dir = self.api_worker_dir
        if api_worker_dir is None:
            api_worker_dir = self.upload_state_dir.parent / "api-workers"
        object.__setattr__(self, "api_worker_dir", api_worker_dir.expanduser().resolve())
        network_proxy_dir = self.network_proxy_dir
        if network_proxy_dir is None:
            network_proxy_dir = self.api_worker_dir.parent / "network-proxies"
        network_proxy_dir = network_proxy_dir.expanduser().resolve()
        try:
            network_proxy_dir.relative_to(resolved)
        except ValueError:
            pass
        else:
            raise ValueError("network_proxy_dir must be outside workspace_root")
        object.__setattr__(self, "network_proxy_dir", network_proxy_dir)
        share_dir = self.share_dir
        if share_dir is None:
            if self.token_data_file is not None:
                share_dir = self.token_data_file.parent / "shares"
            elif self.config_file is not None:
                share_dir = self.config_file.parent / "shares"
            else:
                share_dir = resolved.parent / ".openkapsel-shares"
        share_dir = share_dir.expanduser().resolve()
        try:
            share_dir.relative_to(resolved)
        except ValueError:
            pass
        else:
            raise ValueError("share_dir must be outside workspace_root")
        object.__setattr__(self, "share_dir", share_dir)

    @property
    def admin_enabled(self) -> bool:
        return self.admin_username is not None and self.admin_password_hash is not None


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
            id=secrets.token_urlsafe(32),
            csrf=secrets.token_urlsafe(24),
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




class WorkspaceHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: ServerConfig):
        self.config = config
        self.request_queue_size = min(config.max_http_connections, 128)
        self.connection_slots = threading.BoundedSemaphore(config.max_http_connections)
        self.sse_slots = threading.BoundedSemaphore(config.max_sse_streams)
        self.sse_lock = threading.Lock()
        self.sse_streams_by_token: dict[str, int] = {}
        self.admin_password_hash = config.admin_password_hash or ""
        self.admin_password_lock = threading.Lock()
        self.recycle_bins: dict[Path, RecycleBin] = {}
        self.recycle_bins_lock = threading.Lock()
        self.context_stores: dict[Path, ContextStore] = {}
        self.context_stores_lock = threading.Lock()
        self.memory_stores: dict[Path, MemoryStore] = {}
        self.memory_stores_lock = threading.Lock()
        self.tokens = TokenStore(config.root, config.token_data_file, config.token)
        self.workspace_images = WorkspaceImageClient(config.workspace_image_socket)
        self.workspace_admin_lock = threading.RLock()
        self.admin_sessions = AdminSessions()
        self.admin_login_limiter = AdminLoginLimiter()
        configure_proxy_limits(
            config.max_network_proxy_connections,
            config.max_network_proxy_connections_per_instance,
            config.network_proxy_header_timeout_seconds,
        )
        prepare_proxy_root(config.network_proxy_dir)
        self.cgroups = TokenCgroupManager(enabled=config.sandbox_cgroup_enabled)
        self.sandboxes = SandboxRegistry(
            enabled=config.sandbox_backends,
            default=config.sandbox_default_backend,
            bubblewrap_path=config.bubblewrap_path,
            rootlesskit_path=config.rootlesskit_path,
            podman_path=config.podman_path,
            podman_image=config.podman_image,
            podman_runtime=config.podman_runtime,
            aggregate_resources=self.cgroups.available,
        )
        self.api_workers = ApiWorkerManager(
            worker_root=config.api_worker_dir,
            bubblewrap_path=config.bubblewrap_path,
            rootlesskit_path=config.rootlesskit_path,
            cgroups=self.cgroups,
            network_proxy_root=config.network_proxy_dir,
            idle_seconds=config.api_worker_idle_seconds,
        )
        self.tasks = TaskRegistry(config, self.cgroups)
        self.uploads = UploadRegistry(
            config.upload_state_dir,
            ttl_seconds=config.upload_ttl_seconds,
            max_file_bytes=config.max_file_bytes,
            max_incomplete_bytes=config.max_incomplete_upload_bytes,
            recommended_chunk_size=config.upload_chunk_bytes,
        )
        self.shares = ShareStore(
            config.share_dir,
            ttl_seconds=config.share_ttl_seconds,
            max_entries=config.max_share_entries,
            max_bytes=config.max_share_bytes,
            max_depth=config.max_recursion_depth,
            max_query_nodes=config.max_tree_nodes,
        )
        self.transfer_slots = threading.BoundedSemaphore(config.max_concurrent_transfers)
        super().__init__(address, WorkspaceRequestHandler)
        self.scheduler = SchedulerManager(self)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n"
                    b"Content-Length: 20\r\n"
                    b"Retry-After: 1\r\n\r\n"
                    b"service unavailable\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            request.settimeout(self.config.http_socket_timeout_seconds)
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()

    def acquire_sse_stream(self, token: str) -> str | None:
        if not self.sse_slots.acquire(blocking=False):
            return "global"
        with self.sse_lock:
            current = self.sse_streams_by_token.get(token, 0)
            if current >= self.config.max_sse_streams_per_token:
                self.sse_slots.release()
                return "token"
            self.sse_streams_by_token[token] = current + 1
        return None

    def release_sse_stream(self, token: str) -> None:
        with self.sse_lock:
            current = self.sse_streams_by_token.get(token, 0)
            if current <= 1:
                self.sse_streams_by_token.pop(token, None)
            else:
                self.sse_streams_by_token[token] = current - 1
        self.sse_slots.release()

    def server_close(self) -> None:
        self.api_workers.close()
        self.scheduler.close()
        self.tasks.close()
        super().server_close()

    def recycle_for(self, scope_root: Path) -> RecycleBin:
        if scope_root == self.config.root:
            raise RecycleError(
                HTTPStatus.BAD_REQUEST,
                "child_workspace_required",
                "recycle operations require a child workspace; update this token's directory in admin",
            )
        with self.recycle_bins_lock:
            recycle = self.recycle_bins.get(scope_root)
            if recycle is None:
                try:
                    recycle = RecycleBin(scope_root)
                except ValueError as exc:
                    raise RecycleError(HTTPStatus.CONFLICT, "recycle_unavailable", str(exc)) from None
                self.recycle_bins[scope_root] = recycle
            return recycle

    def context_for(self, scope_root: Path) -> ContextStore:
        with self.context_stores_lock:
            store = self.context_stores.get(scope_root)
            if store is None:
                try:
                    store = ContextStore(scope_root)
                except (OSError, sqlite3.Error, ValueError) as exc:
                    raise ApiError(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "context_unavailable",
                        str(exc),
                    ) from None
                self.context_stores[scope_root] = store
            return store

    def memory_for(self, scope_root: Path) -> MemoryStore:
        with self.memory_stores_lock:
            store = self.memory_stores.get(scope_root)
            if store is None:
                try:
                    store = MemoryStore(scope_root)
                except (OSError, sqlite3.Error, ValueError) as exc:
                    raise ApiError(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "memory_unavailable",
                        str(exc),
                    ) from None
                self.memory_stores[scope_root] = store
            return store

    def schedules_for(self, scope_root: Path) -> ScheduleStore:
        return self.scheduler.store_for(scope_root)

    def change_admin_password(self, old_password: str, new_password: str) -> None:
        with self.admin_password_lock:
            if not verify_password(old_password, self.admin_password_hash):
                raise ValueError("The current password is incorrect")
            self._store_admin_password_hash_locked(hash_password(new_password))

    def upgrade_admin_password_hash(self, password: str) -> None:
        """Upgrade a successfully verified legacy password hash in place."""
        with self.admin_password_lock:
            if not password_hash_needs_upgrade(self.admin_password_hash):
                return
            if not verify_password(password, self.admin_password_hash):
                return
            self._store_admin_password_hash_locked(hash_password(password))

    def _store_admin_password_hash_locked(self, new_hash: str) -> None:
        config_path = self.config.config_file
        if config_path is None:
            raise ValueError("the running service has no writable configuration file")
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"could not read configuration file: {exc}") from None
        admin = payload.get("admin")
        if not isinstance(admin, dict):
            raise ValueError("configuration file is missing the admin object")
        admin["password_hash"] = new_hash
        admin.pop("password_sha256", None)
        mode = config_path.stat().st_mode & 0o777
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=config_path.parent,
                prefix=f".{config_path.name}.",
                delete=False,
            ) as handle:
                temp_name = handle.name
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, mode)
            os.replace(temp_name, config_path)
        except OSError as exc:
            raise ValueError(f"could not write configuration file: {exc}") from None
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass
        self.admin_password_hash = new_hash


class WorkspaceRequestHandler(
    AdminHandlersMixin,
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
    server: WorkspaceHTTPServer
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        """Avoid exposing the Python runtime and stdlib HTTP server versions."""
        return "OpenKapsel"

    def end_headers(self) -> None:
        # Capability URLs must never be disclosed through browser referrers.
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urlsplit(self.path)
            if self._is_dedicated_preview_request():
                route = self._preview_authenticated_route(parsed.path)
                api_target = self._resolve_web_api_target(route)
                if api_target is not None:
                    self._handle_web_api(method, api_target, parsed.query)
                    return
                self._discard_request_body()
                if method not in {"GET", "HEAD"}:
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                self._handle_web_preview(
                    route,
                    parsed.path,
                    parsed.query,
                    head_only=method == "HEAD",
                )
                return
            request_path = self._strip_url_base_path(parsed.path)
            if request_path == "/skills" or request_path.startswith("/skills/"):
                self._dispatch_skill(method, request_path)
                return
            if request_path == "/admin" or request_path.startswith("/admin/"):
                if method != "POST":
                    self._discard_request_body()
                self._dispatch_admin(method, request_path, parsed.query)
                return
            if request_path.startswith("/shares/") and method == "GET":
                parts = request_path.split("/")
                if len(parts) != 3 or not parts[2]:
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                self._discard_request_body()
                self._handle_share_query(parts[2], parse_qs(parsed.query, keep_blank_values=True))
                return
            if request_path == "/transfer" or request_path.startswith("/transfer/"):
                route = self._control_authenticated_transfer_route(request_path)
            else:
                route = self._authenticated_route(request_path)
            api_target = self._resolve_web_api_target(route)
            if api_target is not None:
                self._handle_web_api(method, api_target, parsed.query)
                return
            query = parse_qs(parsed.query, keep_blank_values=True)
            if method == "GET" and route in ("", "/"):
                self._prepare_context_tracking(None, query)
                self._discard_request_body()
                discovery = self._discovery()
                if self._wants_html():
                    self._send_html(
                        HTTPStatus.OK,
                        render_discovery(discovery),
                        headers={"Vary": "Authorization"},
                    )
                else:
                    self._send_json(
                        HTTPStatus.OK,
                        discovery,
                        headers={"Vary": "Authorization"},
                    )
            elif method in {"GET", "HEAD"} and (route == "/web" or route.startswith("/web/")):
                self._prepare_context_tracking(None, query)
                self._discard_request_body()
                self._handle_web_preview(
                    route,
                    parsed.path,
                    parsed.query,
                    head_only=method == "HEAD",
                )
            else:
                matched_endpoint = match_endpoint(method, route)
                if matched_endpoint is None:
                    self._prepare_context_tracking(None, query)
                    self._discard_request_body()
                    raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
                endpoint, route_match = matched_endpoint
                if endpoint.control_required:
                    self._require_control_token()
                self._prepare_context_tracking(endpoint, query)
                if not endpoint.request_body:
                    self._discard_request_body()
                self._dispatch_endpoint(endpoint, route_match, query, method)
        except ApiError as exc:
            error_payload: dict[str, Any] = {
                "error": {"code": exc.code, "message": exc.message}
            }
            if exc.details is not None:
                error_payload["error"]["details"] = exc.details
            if self._wants_html():
                self._finalize_context_operation(exc.status, error_payload)
                self._send_html(
                    exc.status,
                    render_http_error(exc.status, exc.code, exc.message),
                    headers=exc.headers,
                )
                return
            self._send_json(exc.status, error_payload, headers=exc.headers)
        except (BrokenPipeError, ConnectionResetError):
            self._finalize_context_operation(
                499,
                {"error": {"code": "client_disconnected", "message": "client disconnected"}},
            )
            return
        except Exception:
            request_id = secrets.token_hex(6)
            LOGGER.error("unhandled request error %s\n%s", request_id, traceback.format_exc())
            error_payload = {
                "error": {
                    "code": "internal_error",
                    "message": "internal server error",
                    "request_id": request_id,
                }
            }
            if self._wants_html():
                self._finalize_context_operation(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    error_payload,
                )
                self._send_html(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    render_http_error(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "internal server error",
                        request_id,
                    ),
                )
                return
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                error_payload,
            )

    def _authenticated_route(self, path: str) -> str:
        parts = path.split("/")
        if len(parts) < 3 or parts[1] != "w":
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        supplied = unquote(parts[2])
        route = "/" + "/".join(parts[3:]) if len(parts) > 3 else ""
        record = None
        if self.server.config.preview_base_url is None:
            record = self.server.tokens.authenticate_preview(supplied)
            if record is not None:
                route = "/web" + route
        if record is None:
            record = self.server.tokens.authenticate(supplied)
            if route == "/web" or route.startswith("/web/"):
                record = None
        if record is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        try:
            scope_root = self.server.tokens.scope_root(record)
        except ValueError:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist") from None
        self.token_record = record
        self.token_scope_root = scope_root
        self.control_authorized = False
        authorization_values = self.headers.get_all("Authorization") or []
        if authorization_values:
            if len(authorization_values) != 1:
                self._raise_invalid_control_token()
            scheme, separator, credential = authorization_values[0].partition(" ")
            if (
                not separator
                or scheme.lower() != "bearer"
                or not credential
                or credential != credential.strip()
                or any(char.isspace() for char in credential)
            ):
                self._raise_invalid_control_token()
            control_record = self.server.tokens.authenticate_control(credential)
            if control_record is None:
                self._raise_invalid_control_token()
            if not secrets.compare_digest(control_record.token, record.token):
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "token_binding_mismatch",
                    "the Bearer token does not belong to this read-only workspace URL",
                )
            self.control_authorized = True
        return route

    def _control_authenticated_transfer_route(self, path: str) -> str:
        route = path.removeprefix("/transfer")
        if route != "/fs/content" and not route.startswith("/uploads/"):
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        authorization_values = self.headers.get_all("Authorization") or []
        if len(authorization_values) != 1:
            if not authorization_values:
                self._require_control_token()
            self._raise_invalid_control_token()
        scheme, separator, credential = authorization_values[0].partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not credential
            or credential != credential.strip()
            or any(char.isspace() for char in credential)
        ):
            self._raise_invalid_control_token()
        record = self.server.tokens.authenticate_control(credential)
        if record is None:
            self._raise_invalid_control_token()
        try:
            scope_root = self.server.tokens.scope_root(record)
        except ValueError:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist") from None
        self.token_record = record
        self.token_scope_root = scope_root
        self.control_authorized = True
        return route

    def _preview_authenticated_route(self, path: str) -> str:
        parts = path.split("/")
        if len(parts) < 2 or parts[0] != "" or not parts[1]:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        supplied = unquote(parts[1])
        record = self.server.tokens.authenticate_preview(supplied)
        if record is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        try:
            scope_root = self.server.tokens.scope_root(record)
        except ValueError:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist") from None
        self.token_record = record
        self.token_scope_root = scope_root
        self.control_authorized = False
        tail = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
        return "/web" + tail

    def _is_dedicated_preview_request(self) -> bool:
        configured = self.server.config.preview_base_url
        if configured is None:
            return False
        expected_host = urlsplit(configured).hostname
        try:
            request_host = urlsplit("//" + self.headers.get("Host", "")).hostname
        except ValueError:
            return False
        return bool(
            expected_host
            and request_host
            and hmac.compare_digest(request_host.lower(), expected_host.lower())
        )

    def _wants_html(self) -> bool:
        return self.command == "GET" and "text/html" in self.headers.get("Accept", "").lower()

    def _base_path(self) -> str:
        return f"{self.server.config.url_base_path}/w/{quote(self.token_record.token, safe='')}"

    def _strip_url_base_path(self, path: str) -> str:
        prefix = self.server.config.url_base_path
        if not prefix:
            return path
        if path == prefix:
            return "/"
        if not path.startswith(prefix + "/"):
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        return path[len(prefix) :]

    def _dispatch_endpoint(
        self,
        endpoint: EndpointSpec,
        route_match: Any,
        query: dict[str, list[str]],
        method: str,
    ) -> None:
        handler = getattr(self, endpoint.handler)
        args: tuple[Any, ...] = ()
        kwargs: dict[str, Any] = {}
        if endpoint.invocation in {"query", "query_head"}:
            args = (query,)
        elif endpoint.invocation in {"param", "param_query", "param_head"}:
            if endpoint.parameter is None:
                raise RuntimeError(f"endpoint {endpoint.name} has no path parameter")
            parameter = route_match.group(endpoint.parameter)
            args = (parameter, query) if endpoint.invocation == "param_query" else (parameter,)
        if endpoint.invocation in {"query_head", "param_head"}:
            kwargs["head_only"] = method == "HEAD"
        if endpoint.transfer_slot:
            self._run_transfer(handler, *args, **kwargs)
        else:
            handler(*args, **kwargs)

    def _require_control_token(self) -> None:
        if getattr(self, "control_authorized", False):
            return
        raise ApiError(
            HTTPStatus.UNAUTHORIZED,
            "control_token_required",
            "this endpoint requires Authorization: Bearer <CONTROL_TOKEN>",
            headers={"WWW-Authenticate": 'Bearer realm="OpenKapsel"'},
        )

    def _handle_credentials_renew(self) -> None:
        previous_token = self.token_record.token
        try:
            record = self.server.tokens.renew_credentials_if_due(previous_token)
        except CredentialRenewalNotDue as exc:
            raise ApiError(
                HTTPStatus.CONFLICT,
                "credentials_renewal_not_due",
                str(exc),
                details={
                    "credentials_expires_at": exc.expires_at,
                    "remaining_seconds": exc.remaining_seconds,
                    "renewal_window_seconds": 2 * 24 * 60 * 60,
                },
            ) from None
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.CONFLICT,
                "credentials_cannot_be_renewed",
                str(exc),
            ) from None
        workspace_url = (
            f"{self._public_base_url().rstrip('/')}/w/"
            f"{quote(record.token, safe='')}/"
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "read_token": record.token,
                "control_token": record.control_token,
                "workspace_url": workspace_url,
                "credentials_expires_at": record.credentials_expires_at,
            },
            headers={"Cache-Control": "no-store"},
        )

    def _prepare_context_tracking(
        self,
        endpoint: EndpointSpec | None,
        query: dict[str, list[str]],
    ) -> None:
        """Require messages for mutations and optionally track named reads."""
        self._context_deferred_operation: str | None = None
        self._context_entry_id: int | None = None
        self._context_operation: str | None = None
        if endpoint is None or endpoint.context_mode == "none":
            return
        operation = endpoint.context_operation(self.command)
        if operation is None:
            raise RuntimeError(f"endpoint {endpoint.name} has no context operation")
        if endpoint.context_mode == "deferred":
            self._context_deferred_operation = operation
            return
        if endpoint.context_mode == "header":
            message = self._context_header_message() or ""
            taskname = self._context_header_taskname() or ""
            self._begin_context_operation(
                operation,
                taskname,
                message,
                self._context_header_plan_id(),
                self._context_request_details(query),
                plan_required=True,
            )
            return
        message_values = query.get("message", [])
        message = message_values[0].strip() if message_values else ""
        taskname_values = query.get("taskname", [])
        taskname = taskname_values[0].strip() if taskname_values else ""
        plan_id_values = query.get("plan_id", [])
        plan_id = plan_id_values[0].strip() if plan_id_values else None
        if message or taskname:
            self._require_control_token()
            self._begin_context_operation(
                operation,
                taskname,
                message,
                plan_id,
                self._context_request_details(query),
                plan_required=False,
            )

    def _begin_context_operation(
        self,
        operation: str,
        taskname: Any,
        message: Any,
        plan_id: Any,
        request: dict[str, Any] | None = None,
        *,
        plan_required: bool,
    ) -> int:
        if not isinstance(taskname, str) or not taskname.strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_taskname_required",
                "recorded operations require a non-empty taskname",
            )
        if not isinstance(message, str) or not message.strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_message_required",
                "recorded operations require a non-empty message",
            )
        if len(taskname.strip()) > MAX_CONTEXT_TASKNAME_CHARS:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_taskname_too_long",
                f"taskname cannot exceed {MAX_CONTEXT_TASKNAME_CHARS} characters",
            )
        if len(message.strip()) > MAX_CONTEXT_OPERATION_MESSAGE_CHARS:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "context_message_too_long",
                f"message cannot exceed {MAX_CONTEXT_OPERATION_MESSAGE_CHARS} characters",
            )
        parsed_plan_id = self._parse_operation_plan_id(
            plan_id,
            required=plan_required,
        )
        try:
            entry_id = self.server.context_for(self.token_scope_root).add(
                "operation",
                message,
                taskname=taskname,
                actor_id=self.token_record.actor_id,
                operation=operation,
                status="running",
                plan_id=parsed_plan_id,
                request=request,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_plan",
                str(exc),
            ) from None
        except (OSError, sqlite3.Error) as exc:
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "context_unavailable",
                f"cannot record operation context: {exc}",
            ) from None
        self._context_entry_id = entry_id
        self._context_operation = operation
        return entry_id

    def _begin_deferred_context_operation(self, body: dict[str, Any]) -> None:
        operation = getattr(self, "_context_deferred_operation", None)
        if operation is None or getattr(self, "_context_entry_id", None) is not None:
            return
        self._begin_context_operation(
            operation,
            body.get("taskname", self._context_header_taskname()),
            body.get("message", self._context_header_message()),
            body.get("plan_id", self._context_header_plan_id()),
            self._context_request_details(body),
            plan_required=True,
        )

    def _context_header_message(self) -> str | None:
        return self._context_header_value("OpenKapsel-Message")

    def _context_header_taskname(self) -> str | None:
        return self._context_header_value("OpenKapsel-Taskname")

    def _context_header_plan_id(self) -> str | None:
        return self._context_header_value("OpenKapsel-Plan-Id")

    @staticmethod
    def _parse_operation_plan_id(value: Any, *, required: bool) -> int | None:
        if value is None or value == "":
            if required:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "context_plan_id_required",
                    "modifying operations require a positive plan_id",
                )
            return None
        if isinstance(value, bool):
            parsed = 0
        elif isinstance(value, int):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = int(value.strip())
            except ValueError:
                parsed = 0
        else:
            parsed = 0
        if parsed < 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_plan_id",
                "plan_id must be a positive integer",
            )
        return parsed

    def _context_header_value(self, name: str) -> str | None:
        """Decode UTF-8 header bytes preserved by HTTP's latin-1 header mapping."""
        raw = self.headers.get(name)
        if raw is None:
            return None
        try:
            return raw.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return raw

    @classmethod
    def _context_request_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        blocked = {
            "message",
            "taskname",
            "plan_id",
            "content",
            "old",
            "new",
            "command",
            "data",
            "data_base64",
            "control_token",
            "token",
            "variables",
            "rc",
        }
        return {
            str(key): cls._context_safe_value(item)
            for key, item in value.items()
            if key not in blocked
        }

    @classmethod
    def _context_safe_value(cls, value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:2_000]
        if isinstance(value, list):
            return [cls._context_safe_value(item) for item in value[:50]]
        if isinstance(value, dict):
            return {
                str(key): cls._context_safe_value(item)
                for key, item in list(value.items())[:50]
                if str(key).lower() not in {
                    "content",
                    "data",
                    "data_base64",
                    "stdout",
                    "stderr",
                    "authorization",
                    "control_token",
                    "token",
                }
            }
        return str(value)[:2_000]

    def _finalize_context_operation(
        self,
        status: int,
        payload: dict[str, Any] | None,
    ) -> int | None:
        entry_id = getattr(self, "_context_entry_id", None)
        operation = getattr(self, "_context_operation", None)
        if entry_id is None or operation is None:
            return None
        self._context_entry_id = None
        self._context_operation = None
        succeeded = 200 <= int(status) < 400
        safe_payload = self._context_safe_value(payload or {})
        if succeeded:
            summary = f"{operation} succeeded with HTTP {int(status)}"
            target = None
            if isinstance(payload, dict):
                target = payload.get("path") or payload.get("destination")
                if target is None:
                    target = payload.get("task_id") or payload.get("upload_id")
            if target:
                summary += f": {str(target)[:2_000]}"
        else:
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            code = error.get("code") if isinstance(error, dict) else None
            summary = f"{operation} failed with HTTP {int(status)}"
            if code:
                summary += f": {code}"
        try:
            self.server.context_for(self.token_scope_root).finish_operation(
                entry_id,
                succeeded=succeeded,
                result_summary=summary,
                result=safe_payload if isinstance(safe_payload, dict) else None,
            )
        except (KeyError, OSError, sqlite3.Error, ValueError):
            LOGGER.exception("could not finalize context operation %s", entry_id)
        return entry_id

    @staticmethod
    def _raise_invalid_control_token() -> None:
        raise ApiError(
            HTTPStatus.UNAUTHORIZED,
            "invalid_control_token",
            "the Bearer control token is invalid or expired",
            headers={
                "WWW-Authenticate": 'Bearer realm="OpenKapsel", error="invalid_token"'
            },
        )

    def _admin_path(self) -> str:
        return f"{self.server.config.url_base_path}/admin"





    def _handle_context_query(self, query: dict[str, list[str]]) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        entry_id = (
            self._query_int(query, "id", 0, minimum=1)
            if "id" in query
            else None
        )
        before_id = (
            self._query_int(query, "before_id", 0, minimum=1)
            if "before_id" in query
            else None
        )
        limit = self._query_int(
            query,
            "limit",
            100,
            minimum=1,
            maximum=MAX_CONTEXT_QUERY_LIMIT,
        )
        entry_type = self._query_one(query, "type", "").strip() or None
        entry_status = self._query_one(query, "status", "").strip() or None
        taskname = self._query_one(query, "taskname", "").strip() or None
        actor_id = self._query_one(query, "actor_id", "").strip() or None
        path = self._query_one(query, "path", "").strip() or None
        plan_id = (
            self._query_int(query, "plan_id", 0, minimum=1)
            if "plan_id" in query
            else None
        )
        root_plans = self._query_bool(query, "root_plans", False)
        search = self._query_one(query, "query", "")
        try:
            entries, total = self.server.context_for(self.token_scope_root).query(
                entry_id=entry_id,
                query=search,
                entry_type=entry_type,
                entry_status=entry_status,
                taskname=taskname,
                actor_id=actor_id,
                path=path,
                plan_id=plan_id,
                root_plans=root_plans,
                before_id=before_id,
                limit=limit,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_query",
                str(exc),
            ) from None
        self._send_json(
            HTTPStatus.OK,
            {
                "entries": entries,
                "limit": limit,
                "total": total,
                "truncated": len(entries) < total,
                "next_before_id": entries[-1]["id"] if len(entries) < total else None,
            },
        )

    def _handle_context_add(self) -> None:
        body = self._read_json()
        entry_type = self._required_string(body, "type")
        if entry_type not in {"plan", "note"}:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_type",
                "manually added context type must be plan or note",
            )
        content = self._required_string(body, "content")
        taskname = self._required_string(body, "taskname")
        try:
            raw_plan_id = body.get("plan_id")
            if entry_type == "note" and raw_plan_id is None:
                raise ValueError("notes must reference a plan_id")
            plan_id = (
                self._parse_operation_plan_id(raw_plan_id, required=True)
                if raw_plan_id is not None
                else None
            )
            plan_status = body.get("status")
            if plan_status is not None and not isinstance(plan_status, str):
                raise ValueError("status must be a string")
            if entry_type == "note" and plan_status is not None:
                raise ValueError("note context cannot have a plan status")
            entry_id = self.server.context_for(self.token_scope_root).add(
                entry_type,
                content,
                taskname=taskname,
                actor_id=self.token_record.actor_id,
                plan_status=plan_status,
                plan_id=plan_id,
            )
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                str(exc),
            ) from None
        entries, _ = self.server.context_for(self.token_scope_root).query(
            entry_id=entry_id,
        )
        entry = entries[0]
        if entry_type == "plan":
            scope_paths = body.get("scope_paths")
            memory_tags = body.get("memory_tags")
            entry["scope_paths"] = scope_paths or []
            entry["memory_tags"] = memory_tags or []
            entry["related_memory"] = self._related_memories(
                content,
                scope_paths,
                memory_tags,
            )
            unfinished = self.server.context_for(
                self.token_scope_root
            ).unfinished_root_plan_hints(exclude_plan_id=entry_id)
            entry["unfinished_root_plans"] = unfinished["plans"]
            entry["unfinished_root_plans_total"] = unfinished["total"]
            entry["unfinished_root_plans_truncated"] = unfinished["truncated"]
        self._send_json(HTTPStatus.CREATED, entry)

    @staticmethod
    def _parse_context_entry_id(value: str) -> int:
        try:
            entry_id = int(value)
        except ValueError:
            entry_id = 0
        if entry_id < 1:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_id",
                "context id must be a positive integer",
            )
        return entry_id

    def _handle_context_plan_update(self, value: str) -> None:
        entry_id = self._parse_context_entry_id(value)
        body = self._read_json()
        taskname = self._required_string(body, "taskname")
        content = (
            self._required_string(body, "content")
            if "content" in body
            else None
        )
        plan_status = body.get("status")
        if plan_status is not None and not isinstance(plan_status, str):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                "status must be a string",
            )
        try:
            changes: dict[str, Any] = {
                "taskname": taskname,
                "content": content,
                "plan_status": plan_status,
            }
            completed_debrief: dict[str, Any] | None = None
            if plan_status == "completed":
                existing_entries, _ = self.server.context_for(self.token_scope_root).query(
                    entry_id=entry_id,
                )
                if not existing_entries or existing_entries[0]["type"] != "plan":
                    raise KeyError("context entry does not exist")
                if existing_entries[0]["status"] == "completed":
                    raise ValueError("plan is already completed")
                completed_debrief = self._apply_memory_debrief(
                    entry_id,
                    taskname,
                    body.get("debrief"),
                )
                changes["debrief"] = completed_debrief
                changes["actor_id"] = self.token_record.actor_id
            elif "debrief" in body:
                raise ValueError("plan debrief is only valid when status is completed")
            if "plan_id" in body:
                changes["plan_id"] = (
                    None
                    if body["plan_id"] is None
                    else self._parse_operation_plan_id(
                        body["plan_id"],
                        required=True,
                    )
                )
            entry = self.server.context_for(self.token_scope_root).update_plan(
                entry_id,
                **changes,
            )
            if completed_debrief is not None:
                entry["debrief"] = completed_debrief
        except KeyError as exc:
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "context_not_found",
                str(exc.args[0]),
            ) from None
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                str(exc),
            ) from None
        self._send_json(HTTPStatus.OK, entry)

    def _handle_context_note_replace(self, value: str) -> None:
        entry_id = self._parse_context_entry_id(value)
        body = self._read_json()
        taskname = self._required_string(body, "taskname")
        content = self._required_string(body, "content")
        plan_id = self._parse_operation_plan_id(
            body.get("plan_id"),
            required=True,
        )
        try:
            entry = self.server.context_for(self.token_scope_root).replace_note(
                entry_id,
                taskname=taskname,
                content=content,
                actor_id=self.token_record.actor_id,
                plan_id=plan_id,
            )
        except KeyError as exc:
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "context_not_found",
                str(exc.args[0]),
            ) from None
        except ValueError as exc:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_context_entry",
                str(exc),
            ) from None
        self._send_json(HTTPStatus.CREATED, entry)

    def _handle_context_plan_tree(
        self,
        value: str,
        query: dict[str, list[str]],
    ) -> None:
        plan_id = self._parse_context_entry_id(value.rstrip("/"))
        max_depth = self._query_int(
            query,
            "max_depth",
            8,
            minimum=0,
            maximum=32,
        )
        limit = self._query_int(
            query,
            "limit",
            200,
            minimum=1,
            maximum=MAX_CONTEXT_QUERY_LIMIT,
        )
        try:
            payload = self.server.context_for(self.token_scope_root).plan_tree(
                plan_id,
                max_depth=max_depth,
                limit=limit,
            )
        except ValueError as exc:
            message = str(exc)
            status = (
                HTTPStatus.NOT_FOUND
                if message == "plan_id does not exist"
                else HTTPStatus.BAD_REQUEST
            )
            raise ApiError(
                status,
                "context_plan_not_found" if status == HTTPStatus.NOT_FOUND else "invalid_context_plan",
                message,
            ) from None
        self._send_json(HTTPStatus.OK, payload)

    def _handle_shell_exec(self) -> None:
        body = self._read_json()
        command = self._required_string(body, "command")
        cwd_value = body.get("cwd", "")
        timeout = body.get("timeout_seconds", self.server.config.default_command_timeout)
        interactive = self._optional_bool(body, "interactive", False)
        task = start_shell_task(
            self.server,
            self.token_record,
            self.token_scope_root,
            command=command,
            cwd_value=cwd_value,
            timeout_seconds=timeout,
            interactive=interactive,
        )
        self._send_json(
            HTTPStatus.ACCEPTED,
            {"task_id": task.id, "status": task.status, "status_url": f"{self._base_path()}/tasks/{task.id}"},
        )

    def _full_shell_process_environment(self) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ),
            "HOME": str(self.token_scope_root),
            "TMPDIR": "/tmp",
            "OPENKAPSEL_WORKSPACE": str(self.token_scope_root),
        }
        for name in ("LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM"):
            value = os.environ.get(name)
            if value and "\x00" not in value:
                environment[name] = value
        return environment

    def _handle_task(self, task_id: str) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        if not task_id or "/" in task_id:
            raise ApiError(HTTPStatus.NOT_FOUND, "task_not_found", "task does not exist")
        self._send_json(
            HTTPStatus.OK,
            self.server.tasks.get(task_id, self.token_record.token).serialize(),
        )

    def _handle_task_list(self, query: dict[str, list[str]]) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 100, minimum=1, maximum=1000)
        status = self._query_one(query, "status", "").strip() or None
        if status not in {None, "running", "finished"}:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_status", "status must be running or finished")
        tasks, total = self.server.tasks.list(self.token_record.token, offset, limit, status)
        self._send_json(
            HTTPStatus.OK,
            {
                "tasks": tasks,
                "offset": offset,
                "limit": limit,
                "total": total,
                "truncated": offset + len(tasks) < total,
            },
        )

    def _handle_sandbox_processes(self, query: dict[str, list[str]]) -> None:
        if self.token_record.shell_mode != "restricted":
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "sandbox_not_enabled",
                "process inspection is available only for restricted Shell tokens",
            )
        offset = self._query_int(query, "offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 100, minimum=1, maximum=1000)
        configured_backend = self.token_record.sandbox_backend
        effective_backend = (
            self.server.config.sandbox_default_backend
            if configured_backend == "auto"
            else configured_backend
        )
        payload = self.server.cgroups.inspect(
            self.token_record.token,
            self._sandbox_limits(backend=effective_backend),
            task_roots=self.server.tasks.process_roots(self.token_record.token),
            offset=offset,
            limit=limit,
        )
        self._send_json(HTTPStatus.OK, payload)

    def _sandbox_limits(self, *, backend: str | None = None) -> SandboxLimits:
        return SandboxLimits(
            max_processes=self.token_record.sandbox_max_processes,
            memory_bytes=self.token_record.sandbox_memory_mb * 1024 * 1024,
            cpu_percent=self.token_record.sandbox_cpu_percent,
            process_overhead=(
                BUBBLEWRAP_PROCESS_OVERHEAD if backend == "bubblewrap" else 0
            ),
        )

    def _handle_task_interrupt(self, task_id: str) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        task = self.server.tasks.interrupt(task_id, self.token_record.token)
        self._send_json(HTTPStatus.OK, task.serialize())

    def _handle_task_kill(self, task_id: str) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        task = self.server.tasks.kill(task_id, self.token_record.token)
        self._send_json(HTTPStatus.OK, task.serialize())

    def _handle_task_stdin(self, task_id: str) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        body = self._read_json()
        text_data = body.get("data")
        base64_data = body.get("data_base64")
        if text_data is not None and base64_data is not None:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "provide data or data_base64, not both")
        if text_data is None and base64_data is None:
            data = b""
        elif text_data is not None:
            if not isinstance(text_data, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "data must be a string")
            data = text_data.encode("utf-8")
        else:
            if not isinstance(base64_data, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "data_base64 must be a string")
            try:
                data = base64.b64decode(base64_data, validate=True)
            except (binascii.Error, ValueError):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_base64", "data_base64 is not valid Base64") from None
        if len(data) > 256 * 1024:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "input_too_large", "task input is limited to 262144 bytes per request")
        close = self._optional_bool(body, "close", False)
        try:
            task = self.server.tasks.write_stdin(task_id, self.token_record.token, data, close)
        except ValueError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "not_interactive", str(exc)) from None
        except BrokenPipeError as exc:
            raise ApiError(HTTPStatus.CONFLICT, "stdin_closed", str(exc)) from None
        self._send_json(
            HTTPStatus.OK,
            {"task_id": task.id, "bytes_written": len(data), "stdin_closed": close},
        )

    def _handle_task_output(self, task_id: str, query: dict[str, list[str]]) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        stdout_offset = self._query_int(query, "stdout_offset", 0, minimum=0)
        stderr_offset = self._query_int(query, "stderr_offset", 0, minimum=0)
        limit = self._query_int(query, "limit", 65536, minimum=1, maximum=262144)
        wait_seconds = self._query_float(query, "wait_seconds", 0.0, minimum=0.0, maximum=30.0)
        deadline = time.monotonic() + wait_seconds
        while True:
            task = self.server.tasks.get(task_id, self.token_record.token)
            stdout = task.stdout.read_from(stdout_offset, limit)
            stderr = task.stderr.read_from(stderr_offset, limit)
            if (
                stdout["data"]
                or stderr["data"]
                or stdout["gap"]
                or stderr["gap"]
                or task.status == "finished"
                or time.monotonic() >= deadline
            ):
                break
            time.sleep(0.05)
        self._send_json(
            HTTPStatus.OK,
            {
                "task_id": task.id,
                "status": task.status,
                "stdout": stdout,
                "stderr": stderr,
                "finished": task.status == "finished",
                "exit_code": task.exit_code,
                "interrupted": task.interrupted,
                "force_killed": task.force_killed,
            },
        )

    def _handle_task_stream(self, task_id: str, query: dict[str, list[str]]) -> None:
        if self.token_record.shell_mode == "none":
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", "shell permission is not granted")
        stdout_offset = self._query_int(query, "stdout_offset", 0, minimum=0)
        stderr_offset = self._query_int(query, "stderr_offset", 0, minimum=0)
        task = self.server.tasks.get(task_id, self.token_record.token)
        limited_by = self.server.acquire_sse_stream(self.token_record.token)
        if limited_by is not None:
            raise ApiError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "too_many_streams",
                "the concurrent SSE stream limit has been reached",
                details={
                    "scope": limited_by,
                    "max_global": self.server.config.max_sse_streams,
                    "max_per_token": self.server.config.max_sse_streams_per_token,
                },
                headers={"Retry-After": "1"},
            )
        try:
            context_id = self._finalize_context_operation(
                HTTPStatus.OK,
                {"task_id": task.id, "status": task.status, "stream": True},
            )
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            if context_id is not None:
                self.send_header("OpenKapsel-Context-ID", str(context_id))
            self.end_headers()
            self.close_connection = True
            started_at = time.monotonic()
            last_heartbeat = started_at
            while True:
                stdout = task.stdout.read_from(stdout_offset, 65536)
                stderr = task.stderr.read_from(stderr_offset, 65536)
                if stdout["data"] or stderr["data"] or stdout["gap"] or stderr["gap"]:
                    stdout_offset = stdout["next_offset"]
                    stderr_offset = stderr["next_offset"]
                    self._send_sse(
                        "output",
                        {"task_id": task.id, "status": task.status, "stdout": stdout, "stderr": stderr},
                    )
                    last_heartbeat = time.monotonic()
                if task.status == "finished":
                    self._send_sse("done", task.summary())
                    return
                now = time.monotonic()
                if now - started_at >= self.server.config.max_sse_duration_seconds:
                    self._send_sse(
                        "reconnect",
                        {
                            "task_id": task.id,
                            "status": task.status,
                            "reason": "stream_duration_limit",
                            "stdout_offset": stdout_offset,
                            "stderr_offset": stderr_offset,
                        },
                    )
                    return
                if now - last_heartbeat >= 10:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    last_heartbeat = now
                time.sleep(0.05)
        finally:
            self.server.release_sse_stream(self.token_record.token)

    def _send_sse(self, event: str, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        self.wfile.write(f"event: {event}\ndata: {data}\n\n".encode("utf-8"))
        self.wfile.flush()



    def _resolve_path(self, value: str, *, write: bool = False) -> Path:
        root = self.token_scope_root
        if "\x00" in value:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_path",
                "path must not contain a NUL byte",
            )
        candidate = Path(value).expanduser() if value else root
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve(strict=False)
        self._assert_inside_root(resolved)
        if write:
            self._assert_path_writable(resolved)
        for checked in (candidate.absolute(), resolved):
            try:
                relative_to_workspace = checked.relative_to(self.token_scope_root)
            except ValueError:
                continue
            if INTERNAL_DIRECTORY in relative_to_workspace.parts:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "reserved_path",
                    "workspace internal directories are not available through file endpoints",
                )
        if any(self._is_internal_transfer_name(part) for part in resolved.parts):
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "reserved_path",
                "temporary transfer files are not available through file endpoints",
            )
        return resolved

    def _safe_path_access(self) -> SafePathAccess:
        return SafePathAccess(
            (
                self.token_scope_root,
                *(Path(item.path) for item in self.token_record.allowed_paths),
            )
        )

    def _safe_open_descriptor(
        self,
        path: Path,
        flags: int = os.O_RDONLY,
        mode: int = 0o600,
    ) -> int:
        try:
            return self._safe_path_access().open(path, flags, mode)
        except SafePathError as exc:
            self._raise_safe_path_error(exc)

    def _safe_parent(self, path: Path, *, create_parents: bool = False) -> ParentHandle:
        try:
            return self._safe_path_access().parent(path, create_parents=create_parents)
        except SafePathError as exc:
            self._raise_safe_path_error(exc)

    @staticmethod
    def _raise_safe_path_error(exc: SafePathError) -> None:
        if exc.errno == errno.ENOENT:
            raise ApiError(HTTPStatus.NOT_FOUND, "path_not_found", "path does not exist") from None
        if exc.errno in {errno.EACCES, errno.EPERM}:
            raise ApiError(HTTPStatus.FORBIDDEN, "path_access_denied", str(exc)) from None
        raise ApiError(
            HTTPStatus.CONFLICT,
            "path_changed",
            "path changed while the operation was being authorized; retry the request",
        ) from None

    @staticmethod
    def _is_internal_transfer_name(name: str) -> bool:
        return (
            name.startswith(".")
            and (
                ".openkapsel-upload-upload_" in name
                or ".openkapsel-put-" in name
                or name.startswith(".openkapsel-share-")
            )
        )

    def _assert_path_writable(self, path: Path) -> None:
        try:
            path.relative_to(self.token_scope_root)
        except ValueError:
            pass
        else:
            return
        matching = []
        for grant in self.token_record.allowed_paths:
            try:
                path.relative_to(grant.path)
            except ValueError:
                continue
            matching.append(grant)
        if not matching:
            raise ApiError(HTTPStatus.FORBIDDEN, "path_outside_root", "path is not authorized")
        grant = max(matching, key=lambda item: len(Path(item.path).parts))
        if grant.read_only:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "read_only_path",
                f"extra accessible path is read-only: {grant.path}",
            )

    def _assert_inside_root(self, path: Path) -> None:
        for root in (self.token_scope_root, *(Path(item.path) for item in self.token_record.allowed_paths)):
            try:
                path.relative_to(root)
            except ValueError:
                continue
            return
        raise ApiError(
            HTTPStatus.FORBIDDEN,
            "path_outside_root",
            "path is outside the token workspace and extra accessible paths",
        )

    @staticmethod
    def _require_permission(granted: bool, message: str) -> None:
        if not granted:
            raise ApiError(HTTPStatus.FORBIDDEN, "permission_denied", message)

    def _run_transfer(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        if not self.server.transfer_slots.acquire(blocking=False):
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "transfer_limit_reached",
                "too many file transfers are currently running",
            )
        try:
            return operation(*args, **kwargs)
        finally:
            self.server.transfer_slots.release()

    def _atomic_write(
        self,
        path: Path,
        content: str,
        *,
        expected_etag: str | None = None,
        create_parents: bool = False,
    ) -> tuple[bool, os.stat_result]:
        try:
            parent = self._safe_parent(path, create_parents=create_parents)
        except ApiError as exc:
            if exc.code == "path_not_found":
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "parent_not_found",
                    "parent directory does not exist",
                ) from None
            raise
        with parent:
            previous_stat = parent.lstat()
            if previous_stat is not None and not stat.S_ISREG(previous_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            mode = previous_stat.st_mode & 0o777 if previous_stat is not None else 0o600
            temp_name = f".{path.name}.openkapsel-put-{secrets.token_hex(12)}"
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temp_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent.fd,
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = None
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.fchmod(handle.fileno(), mode)
                current_stat = parent.lstat()
                current_etag = self._stat_etag(current_stat) if current_stat is not None else None
                self._check_expected_etag(expected_etag, current_etag)
                os.replace(
                    temp_name,
                    parent.name,
                    src_dir_fd=parent.fd,
                    dst_dir_fd=parent.fd,
                )
                temp_name = ""
                final_descriptor = parent.open(os.O_RDONLY)
                try:
                    final_stat = os.fstat(final_descriptor)
                finally:
                    os.close(final_descriptor)
            # Some build caches (notably timestamp-based Python .pyc files)
            # compare mtimes at whole-second precision plus file size. A
            # same-length edit followed immediately by a build could otherwise
            # reuse stale output. Ensure an overwritten file advances at that
            # precision when the atomic replacement happened in the same second.
                if previous_stat is not None:
                    if previous_stat.st_mtime_ns // 1_000_000_000 == final_stat.st_mtime_ns // 1_000_000_000:
                        final_descriptor = parent.open(os.O_RDONLY)
                        try:
                            next_second_ns = (
                                max(previous_stat.st_mtime_ns, final_stat.st_mtime_ns) // 1_000_000_000 + 1
                            ) * 1_000_000_000
                            os.utime(
                                final_descriptor,
                                ns=(final_stat.st_atime_ns, next_second_ns),
                            )
                            final_stat = os.fstat(final_descriptor)
                        finally:
                            os.close(final_descriptor)
                return previous_stat is None, final_stat
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if temp_name:
                    try:
                        os.unlink(temp_name, dir_fd=parent.fd)
                    except FileNotFoundError:
                        pass

    def _read_json(self) -> dict[str, Any]:
        if hasattr(self, "_mcp_tool_arguments"):
            body = self._mcp_tool_arguments
            self._begin_deferred_context_operation(body)
            return body
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "content_type", "Content-Type must be application/json")
        length = self._request_content_length(required=True)
        if length > self.server.config.max_body_bytes:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "request body is too large")
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_json", "request body must be valid UTF-8 JSON")
        if not isinstance(body, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "JSON body must be an object")
        self._begin_deferred_context_operation(body)
        return body

    @staticmethod
    def _required_string(body: dict[str, Any], key: str, allow_empty: bool = False) -> str:
        value = body.get(key)
        if not isinstance(value, str) or (not allow_empty and not value):
            qualifier = "a string" if allow_empty else "a non-empty string"
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be {qualifier}")
        return value

    @staticmethod
    def _optional_bool(body: dict[str, Any], key: str, default: bool) -> bool:
        value = body.get(key, default)
        if not isinstance(value, bool):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be boolean")
        return value

    @staticmethod
    def _optional_expected_etag(body: dict[str, Any]) -> str | None:
        value = body.get("expected_etag")
        if value is None:
            return None
        if not isinstance(value, str) or not value or any(
            character in value for character in "\r\n,"
        ):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "expected_etag must be one non-empty ETag string, *, or null",
            )
        return value

    @staticmethod
    def _query_one(query: dict[str, list[str]], key: str, default: str) -> str:
        values = query.get(key)
        return values[0] if values else default

    def _required_query(self, query: dict[str, list[str]], key: str) -> str:
        value = self._query_one(query, key, "")
        if not value:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"query parameter {key} is required")
        return value

    def _query_int(
        self,
        query: dict[str, list[str]],
        key: str,
        default: int,
        minimum: int,
        maximum: int | None = None,
    ) -> int:
        raw = self._query_one(query, key, str(default))
        try:
            value = int(raw)
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be an integer")
        if value < minimum or (maximum is not None and value > maximum):
            bounds = f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be {bounds}")
        return value

    def _query_float(
        self,
        query: dict[str, list[str]],
        key: str,
        default: float,
        minimum: float,
        maximum: float,
    ) -> float:
        raw = self._query_one(query, key, str(default))
        try:
            value = float(raw)
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be a number") from None
        if not minimum <= value <= maximum:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                f"{key} must be between {minimum} and {maximum}",
            )
        return value

    def _query_bool(self, query: dict[str, list[str]], key: str, default: bool) -> bool:
        raw = self._query_one(query, key, "true" if default else "false").strip().lower()
        if raw in {"1", "true", "yes"}:
            return True
        if raw in {"0", "false", "no"}:
            return False
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", f"{key} must be boolean")

    @staticmethod
    def _query_fields(
        query: dict[str, list[str]],
        key: str,
        defaults: set[str],
        allowed: set[str],
    ) -> set[str]:
        values = query.get(key)
        if not values:
            return set(defaults)
        requested = {
            field.strip()
            for value in values
            for field in value.split(",")
            if field.strip()
        }
        unknown = sorted(requested - allowed)
        if unknown:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_fields",
                f"unknown field(s): {', '.join(unknown)}",
                {"allowed": sorted(allowed)},
            )
        return requested

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _search_files(self, root: Path, depth: int):
        root_descriptor = self._safe_open_descriptor(root, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            root_stat = os.fstat(root_descriptor)
        finally:
            os.close(root_descriptor)
        if stat.S_ISREG(root_stat.st_mode):
            yield root
            return
        if not stat.S_ISDIR(root_stat.st_mode):
            return
        stack = [(root, 0)]
        while stack:
            directory, level = stack.pop()
            descriptor: int | None = None
            try:
                descriptor = self._safe_path_access().open(directory, os.O_RDONLY)
                with os.scandir(descriptor) as iterator:
                    entries = []
                    for entry in iterator:
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        entries.append((entry.name, entry_stat))
                entries.sort(key=lambda item: item[0].casefold(), reverse=True)
            except (OSError, SafePathError):
                continue
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            directories = []
            for name, entry_stat in entries:
                entry = directory / name
                if self._is_hidden_internal_path(directory, entry) or stat.S_ISLNK(entry_stat.st_mode):
                    continue
                if stat.S_ISREG(entry_stat.st_mode):
                    yield entry
                elif stat.S_ISDIR(entry_stat.st_mode) and level < depth:
                    directories.append((entry, level + 1))
            stack.extend(directories)

    def _tree_node(
        self,
        root: Path,
        path: Path,
        max_depth: int,
        level: int,
        state: dict[str, Any],
    ) -> dict[str, Any]:
        if state["count"] >= self.server.config.max_tree_nodes:
            state["truncated"] = True
            return {"name": path.name or str(path), "path": str(path), "truncated": True}
        state["count"] += 1
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            file_stat = os.fstat(descriptor)
            if stat.S_ISDIR(file_stat.st_mode):
                kind = "directory"
            elif stat.S_ISREG(file_stat.st_mode):
                kind = "file"
            else:
                kind = "other"
            entries: list[tuple[str, os.stat_result]] = []
            if kind == "directory" and level < max_depth:
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        entries.append((entry.name, entry_stat))
        finally:
            os.close(descriptor)
        node: dict[str, Any] = {
            "name": path.name or str(path),
            "path": str(path),
            "type": kind,
            "size": file_stat.st_size,
            "modified_at": datetime.fromtimestamp(file_stat.st_mtime, timezone.utc).isoformat(),
        }
        if kind == "directory" and level < max_depth:
            children = []
            entries.sort(
                key=lambda item: (
                    not stat.S_ISDIR(item[1].st_mode),
                    item[0].casefold(),
                )
            )
            for name, entry_stat in entries:
                entry = path / name
                if self._is_hidden_internal_path(path, entry):
                    continue
                if state["count"] >= self.server.config.max_tree_nodes:
                    state["truncated"] = True
                    break
                if stat.S_ISLNK(entry_stat.st_mode):
                    state["count"] += 1
                    children.append(
                        {
                            "name": name,
                            "path": str(entry),
                            "type": "symlink",
                            "size": entry_stat.st_size,
                            "modified_at": datetime.fromtimestamp(
                                entry_stat.st_mtime,
                                timezone.utc,
                            ).isoformat(),
                        }
                    )
                    continue
                try:
                    children.append(self._tree_node(root, entry, max_depth, level + 1, state))
                except ApiError as exc:
                    if exc.code not in {"path_not_found", "path_changed"}:
                        raise
            node["children"] = children
        return node

    def _is_hidden_internal_path(self, parent: Path, entry: Path) -> bool:
        try:
            parent.relative_to(self.token_scope_root)
        except ValueError:
            workspace_internal = False
        else:
            workspace_internal = entry.name == INTERNAL_DIRECTORY
        return (
            workspace_internal
            or self._is_internal_transfer_name(entry.name)
        )

    def _content_length(self, maximum: int) -> int:
        length = self._request_content_length(required=True)
        if length > maximum:
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"request body exceeds the {maximum}-byte limit",
            )
        return length

    def _request_content_length(self, *, required: bool) -> int:
        if self.headers.get_all("Transfer-Encoding", []):
            self.close_connection = True
            raise ApiError(
                HTTPStatus.NOT_IMPLEMENTED,
                "unsupported_transfer_encoding",
                "Transfer-Encoding request bodies are not supported; send Content-Length",
            )
        raw_values = self.headers.get_all("Content-Length", [])
        values = [item.strip() for raw in raw_values for item in raw.split(",")]
        if not values:
            if required:
                raise ApiError(
                    HTTPStatus.LENGTH_REQUIRED,
                    "length_required",
                    "Content-Length is required",
                )
            return 0
        if len(values) != 1 or not values[0].isdigit():
            self.close_connection = True
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_length",
                "Content-Length must be one non-negative decimal integer",
            )
        return int(values[0])

    def _discard_request_body(self) -> None:
        length = self._request_content_length(required=False)
        if length == 0:
            return
        if length > self.server.config.max_body_bytes:
            self.close_connection = True
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"unexpected request body exceeds the {self.server.config.max_body_bytes}-byte limit",
            )
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(remaining, self.server.config.transfer_buffer_bytes))
            if not chunk:
                self.close_connection = True
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "incomplete_body",
                    "request body ended before Content-Length",
                )
            remaining -= len(chunk)

    @staticmethod
    def _stat_etag(stat: os.stat_result) -> str:
        source = f"{stat.st_dev}:{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}".encode("ascii")
        return f'"{hashlib.sha256(source).hexdigest()[:32]}"'

    @staticmethod
    def _valid_sha256(value: str) -> bool:
        return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)

    def _check_if_match(self, current_etag: str | None) -> None:
        supplied = self.headers.get("If-Match")
        if supplied is None:
            return
        matches = any(
            self._expected_etag_matches(candidate.strip(), current_etag)
            for candidate in supplied.split(",")
        )
        if not matches:
            raise ApiError(
                HTTPStatus.PRECONDITION_FAILED,
                "etag_mismatch",
                "If-Match does not match the current file",
                {"actual_etag": current_etag},
            )

    def _check_expected_etag(
        self,
        supplied: str | None,
        current_etag: str | None,
    ) -> None:
        if supplied is None:
            return
        if not self._expected_etag_matches(supplied, current_etag):
            raise ApiError(
                HTTPStatus.PRECONDITION_FAILED,
                "etag_mismatch",
                "expected_etag does not match the current file",
                {"actual_etag": current_etag},
            )

    @staticmethod
    def _expected_etag_matches(supplied: str, current_etag: str | None) -> bool:
        if supplied == "*":
            return current_etag is not None
        return current_etag is not None and hmac.compare_digest(supplied, current_etag)

    @staticmethod
    def _parse_byte_range(value: str, size: int) -> tuple[int, int]:
        if not value.startswith("bytes=") or "," in value:
            raise ApiError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "invalid_range",
                "only one byte range is supported",
                {"size": size},
            )
        spec = value.removeprefix("bytes=").strip()
        if "-" not in spec:
            raise ApiError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "invalid_range",
                "invalid byte range",
                {"size": size},
            )
        start_raw, end_raw = spec.split("-", 1)
        try:
            if not start_raw:
                suffix = int(end_raw)
                if suffix <= 0 or size == 0:
                    raise ValueError
                start = max(0, size - suffix)
                end = size - 1
            else:
                start = int(start_raw)
                end = int(end_raw) if end_raw else size - 1
                if start < 0 or start >= size or end < start:
                    raise ValueError
                end = min(end, size - 1)
        except ValueError:
            raise ApiError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "invalid_range",
                "byte range is outside the file",
                {"size": size},
            ) from None
        return start, end

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        if getattr(self, "_capturing_mcp_tool", False):
            self._mcp_tool_response = (status, payload)
            return
        context_id = self._finalize_context_operation(status, payload)
        if context_id is not None:
            payload = dict(payload)
            payload["context_id"] = context_id
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if status >= 400:
            # Some authorization failures happen before a POST body is read.
            # Closing the connection prevents unread bytes from being mistaken
            # for the next request on an HTTP/1.1 keep-alive connection.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_empty(self, status: int, headers: dict[str, str] | None = None) -> None:
        if getattr(self, "_capturing_mcp_tool", False):
            self._mcp_tool_response = (status, {})
            return
        context_id = self._finalize_context_operation(status, {})
        headers = dict(headers or {})
        if context_id is not None:
            headers["OpenKapsel-Context-ID"] = str(context_id)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.address_string(), fmt % args)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_server(host: str, port: int, config: ServerConfig) -> WorkspaceHTTPServer:
    return WorkspaceHTTPServer((host, port), config)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-operable workspace HTTP server")
    parser.add_argument(
        "--config",
        default=os.environ.get("WORKSPACE_CONFIG", "config.json"),
        help="JSON configuration file (default: config.json)",
    )
    parser.add_argument("--host", help="override listen_host from config")
    parser.add_argument("--port", type=int, help="override listen_port from config")
    parser.add_argument("--root", help="override workspace_root from config")
    parser.add_argument("--token", default=os.environ.get("WORKSPACE_TOKEN"))
    parser.add_argument("--name", help="override workspace_name from config")
    parser.add_argument("--token-data-file", help="override token_data_file from config")
    parser.add_argument("--public-base-url", help="override optional public_base_url origin")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def load_config(args: argparse.Namespace) -> tuple[str, int, ServerConfig]:
    config_path = Path(args.config).expanduser().resolve()
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"config file does not exist: {config_path}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read config {config_path}: {exc}") from None
    if not isinstance(payload, dict):
        raise ValueError("config root must be a JSON object")
    admin = payload.get("admin")
    if not isinstance(admin, dict):
        raise ValueError("config field admin must be an object")

    def config_path_value(value: Any, field_name: str) -> Path:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"config field {field_name} must be a non-empty path")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = config_path.parent / candidate
        return candidate.resolve()

    root_value = args.root if args.root is not None else payload.get("workspace_root")
    root = config_path_value(root_value, "workspace_root")
    token_file_value = (
        args.token_data_file
        if args.token_data_file is not None
        else payload.get("token_data_file", "state/tokens.json")
    )
    token_data_file = config_path_value(token_file_value, "token_data_file")
    bubblewrap_path = config_path_value(
        payload.get("bubblewrap_path", "/usr/bin/bwrap"), "bubblewrap_path"
    )
    rootlesskit_path = config_path_value(
        payload.get("rootlesskit_path", "/usr/bin/rootlesskit"), "rootlesskit_path"
    )
    podman_path = config_path_value(
        payload.get("podman_path", "/usr/bin/podman"), "podman_path"
    )
    sandbox_backends_value = payload.get("sandbox_backends", ["bubblewrap"])
    if (
        not isinstance(sandbox_backends_value, list)
        or not sandbox_backends_value
        or not all(isinstance(item, str) for item in sandbox_backends_value)
    ):
        raise ValueError("config field sandbox_backends must be a non-empty string array")
    sandbox_backends = tuple(sandbox_backends_value)
    sandbox_default_backend = payload.get("sandbox_default_backend", sandbox_backends[0])
    if not isinstance(sandbox_default_backend, str):
        raise ValueError("config field sandbox_default_backend must be a string")
    podman_image = payload.get("podman_image", "docker.io/library/python:3.12-slim")
    if not isinstance(podman_image, str):
        raise ValueError("config field podman_image must be a string")
    podman_runtime = payload.get("podman_runtime", "crun")
    if not isinstance(podman_runtime, str):
        raise ValueError("config field podman_runtime must be a string")
    default_network_domains_value = payload.get(
        "default_network_domains", list(DEFAULT_NETWORK_DOMAINS)
    )
    if (
        not isinstance(default_network_domains_value, list)
        or not all(isinstance(item, str) for item in default_network_domains_value)
    ):
        raise ValueError("config field default_network_domains must be a string array")
    upload_state_value = payload.get("upload_state_dir")
    upload_state_dir = (
        config_path_value(upload_state_value, "upload_state_dir")
        if upload_state_value is not None
        else None
    )
    share_dir_value = payload.get("share_dir")
    share_dir = (
        config_path_value(share_dir_value, "share_dir")
        if share_dir_value is not None
        else None
    )
    task_history_dir = config_path_value(
        payload.get("task_history_dir", "state/tasks"), "task_history_dir"
    )
    host = args.host if args.host is not None else payload.get("listen_host", "127.0.0.1")
    port = args.port if args.port is not None else payload.get("listen_port")
    if not isinstance(host, str) or not host:
        raise ValueError("config field listen_host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("config field listen_port must be an integer between 0 and 65535")
    username = admin.get("username")
    password_hash = admin.get("password_hash", admin.get("password_sha256"))
    if not isinstance(username, str) or not username:
        raise ValueError("config field admin.username must be a non-empty string")
    if not isinstance(password_hash, str):
        raise ValueError("config field admin.password_hash must be set with set_password.py")

    bootstrap_token = args.token if args.token is not None else payload.get("bootstrap_token")
    public_base_url = (
        args.public_base_url
        if args.public_base_url is not None
        else payload.get("public_base_url")
    )
    preview_base_url = payload.get("preview_base_url")
    if preview_base_url is not None and not isinstance(preview_base_url, str):
        raise ValueError("config field preview_base_url must be an http(s) origin")
    sandbox_cgroup_enabled = payload.get("sandbox_cgroup_enabled", False)
    if not isinstance(sandbox_cgroup_enabled, bool):
        raise ValueError("config field sandbox_cgroup_enabled must be boolean")
    finished_task_retention_minutes = payload.get("finished_task_retention_minutes", 60)
    if (
        isinstance(finished_task_retention_minutes, bool)
        or not isinstance(finished_task_retention_minutes, int)
        or not 1 <= finished_task_retention_minutes <= 60
    ):
        raise ValueError("config field finished_task_retention_minutes must be between 1 and 60")
    max_finished_tasks_per_token = payload.get("max_finished_tasks_per_token", 4)
    if (
        isinstance(max_finished_tasks_per_token, bool)
        or not isinstance(max_finished_tasks_per_token, int)
        or not 1 <= max_finished_tasks_per_token <= 4
    ):
        raise ValueError("config field max_finished_tasks_per_token must be between 1 and 4")
    name = args.name if args.name is not None else payload.get("workspace_name", "OpenKapsel")
    config = ServerConfig(
        root=root,
        token=bootstrap_token,
        name=name,
        token_data_file=token_data_file,
        admin_username=username,
        admin_password_hash=password_hash,
        public_base_url=public_base_url,
        preview_base_url=preview_base_url,
        url_base_path=payload.get("url_base_path", ""),
        config_file=config_path,
        bubblewrap_path=bubblewrap_path,
        rootlesskit_path=rootlesskit_path,
        podman_path=podman_path,
        podman_image=podman_image,
        podman_runtime=podman_runtime,
        sandbox_backends=sandbox_backends,
        sandbox_default_backend=sandbox_default_backend,
        max_task_output_bytes=int(payload.get("max_task_output_mb", 2)) * 1024 * 1024,
        max_concurrent_shell_tasks=int(payload.get("max_concurrent_shell_tasks", 16)),
        max_concurrent_shell_tasks_per_token=int(
            payload.get("max_concurrent_shell_tasks_per_token", 8)
        ),
        max_http_connections=int(payload.get("max_http_connections", 128)),
        http_socket_timeout_seconds=float(
            payload.get("http_socket_timeout_seconds", 30)
        ),
        max_sse_streams=int(payload.get("max_sse_streams", 16)),
        max_sse_streams_per_token=int(payload.get("max_sse_streams_per_token", 4)),
        max_sse_duration_seconds=float(payload.get("max_sse_duration_seconds", 3600)),
        task_history_dir=task_history_dir,
        finished_task_retention_seconds=finished_task_retention_minutes * 60,
        max_finished_tasks_per_token=max_finished_tasks_per_token,
        sandbox_cgroup_enabled=sandbox_cgroup_enabled,
        default_command_timeout=payload.get("default_command_timeout"),
        max_direct_upload_bytes=int(payload.get("max_direct_upload_mb", 32)) * 1024 * 1024,
        max_file_bytes=int(payload.get("max_file_size_gb", 10)) * 1024 * 1024 * 1024,
        upload_chunk_bytes=int(payload.get("rest_chunk_size_mb", 4)) * 1024 * 1024,
        mcp_binary_chunk_bytes=int(payload.get("mcp_binary_chunk_kb", 256)) * 1024,
        upload_ttl_seconds=int(payload.get("upload_ttl_hours", 24)) * 60 * 60,
        max_incomplete_upload_bytes=int(payload.get("max_incomplete_upload_gb", 20)) * 1024 * 1024 * 1024,
        max_text_replace_bytes=int(payload.get("max_text_replace_mb", 32)) * 1024 * 1024,
        max_concurrent_transfers=int(payload.get("max_concurrent_transfers", 4)),
        max_search_results=int(payload.get("max_search_results", 1000)),
        max_search_file_bytes=int(payload.get("max_search_file_mb", 8)) * 1024 * 1024,
        max_tree_nodes=int(payload.get("max_tree_nodes", 5000)),
        max_recursion_depth=int(payload.get("max_recursion_depth", 32)),
        max_batch_file_operations=int(payload.get("max_batch_file_operations", 1000)),
        upload_state_dir=upload_state_dir,
        api_worker_dir=config_path_value(
            payload.get("api_worker_dir", "api-workers"), "api_worker_dir"
        ),
        network_proxy_dir=config_path_value(
            payload.get("network_proxy_dir", "network-proxies"), "network_proxy_dir"
        ),
        max_network_proxy_connections=int(
            payload.get("max_network_proxy_connections", 64)
        ),
        max_network_proxy_connections_per_instance=int(
            payload.get("max_network_proxy_connections_per_instance", 16)
        ),
        network_proxy_header_timeout_seconds=float(
            payload.get("network_proxy_header_timeout_seconds", 15)
        ),
        default_network_domains=tuple(default_network_domains_value),
        api_worker_idle_seconds=int(payload.get("api_worker_idle_seconds", 600)),
        api_max_body_bytes=int(payload.get("api_max_body_mb", 16)) * 1024 * 1024,
        workspace_image_socket=(
            config_path_value(payload["workspace_image_socket"], "workspace_image_socket")
            if payload.get("workspace_image_socket") is not None
            else None
        ),
        share_dir=share_dir,
        share_ttl_seconds=int(payload.get("share_ttl_hours", 24)) * 60 * 60,
        max_share_entries=int(payload.get("max_share_entries", 10)),
        max_share_bytes=int(payload.get("max_share_mb", 256)) * 1024 * 1024,
        schedule_misfire_grace_seconds=int(
            payload.get("schedule_misfire_grace_seconds", 300)
        ),
    )
    return host, port, config


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        host_value, port_value, config = load_config(args)
    except ValueError as exc:
        raise SystemExit(f"configuration error: {exc}") from None
    server = create_server(host_value, port_value, config)
    host, port = server.server_address[:2]
    local_base = f"http://{host}:{port}{config.url_base_path}"
    print(f"OpenKapsel listening on {local_base}")
    if config.token:
        print(f"Bootstrap workspace URL: {local_base}/w/{quote(config.token, safe='')}/")
    if config.admin_enabled:
        print(f"Admin console: {local_base}/admin")
    print(f"Workspace root: {config.root}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

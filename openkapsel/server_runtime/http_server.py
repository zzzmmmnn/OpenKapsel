"""Server-owned runtime resources and HTTP listener lifecycle."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import tempfile
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

from openkapsel.auth.oauth_consent import ConsentLimiter, ConsentProtector
from openkapsel.auth.oauth_store import OAuthStore
from openkapsel.auth.security import hash_password, password_hash_needs_upgrade, verify_password
from openkapsel.auth.static_mcp import StaticMcpStore
from openkapsel.auth.tokens import TokenStore
from openkapsel.context.context_store import ContextStore
from openkapsel.context.memory_store import MemoryStore
from openkapsel.errors import ApiError
from openkapsel.execution.api_workers import ApiWorkerManager
from openkapsel.execution.cgroups import TokenCgroupManager
from openkapsel.execution.network_proxy import configure_proxy_limits, prepare_proxy_root
from openkapsel.execution.sandbox_backends import SandboxRegistry
from openkapsel.execution.scheduler import SchedulerManager
from openkapsel.execution.scheduler_store import ScheduleStore
from openkapsel.execution.tasks import TaskRegistry
from openkapsel.files.recycle import RecycleBin, RecycleError
from openkapsel.files.share_store import ShareStore
from openkapsel.files.uploads import UploadRegistry
from openkapsel.mapping.mapping_manager import MappingManager
from openkapsel.mapping.mapping_transfers import FileTransferManager
from openkapsel.rpc_plugins import load_server_rpc_registry
from openkapsel.storage.storage_manager import StorageProviderManager
from openkapsel.storage.storage_oauth import StorageOAuthFlows
from openkapsel.workspace.workspace_images import WorkspaceImageClient

from .admin_sessions import AdminLoginLimiter, AdminSessions
from .config import ServerConfig

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
        self.oauth = OAuthStore(config.upload_state_dir.parent / "oauth.sqlite3")
        self.oauth_consent = ConsentProtector()
        self.oauth_consent_limiter = ConsentLimiter()
        self.static_mcp = StaticMcpStore(config.upload_state_dir.parent / "static-mcp.sqlite3")
        self.workspace_images = WorkspaceImageClient(config.workspace_image_socket)
        self.storage_providers = StorageProviderManager(
            config.root, config.upload_state_dir.parent, self.workspace_images
        )
        self.storage_oauth = StorageOAuthFlows()
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
        # Move the manager into its delegated leaf before spawning FUSE workers;
        # otherwise their presence prevents enabling cgroup v2 controllers.
        self.mappings = MappingManager(
            config.root,
            config.upload_state_dir.parent,
            enabled=config.mappings_enabled,
            mount_helper=self.workspace_images if self.workspace_images.enabled else None,
            rpc_timeout_seconds=config.mapping_rpc_timeout_seconds,
            provider_idle_timeout_seconds=config.mapping_provider_idle_timeout_seconds,
            fuse_enabled=config.mapping_fuse_enabled,
            max_active_mounts=config.max_active_mapping_mounts,
            mount_idle_seconds=config.mapping_mount_idle_seconds,
        )
        self.mappings.workspace_available = lambda workspace: any(record.valid and record.path_prefix == workspace for record in self.tokens.list())
        self.storage_providers.workspace_available = self.mappings.workspace_available
        self.storage_providers.client_mapping_reserved = lambda workspace, name: any(
            row["name"] == name for row in self.mappings.store.list(workspace)
        )
        self.storage_providers.start()
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
            mappings=self.mappings,
        )
        self.tasks = TaskRegistry(config, self.cgroups)
        self.rpc_registry = load_server_rpc_registry()
        self.rpc_capabilities = self.rpc_registry.capability_map({})
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
        self.file_transfers = FileTransferManager(config.upload_state_dir.parent / "file-transfers", self.mappings, self.recycle_for, self.transfer_slots)
        from .request_handler import WorkspaceRequestHandler

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
        self.rpc_registry.close()
        self.file_transfers.close()
        self.storage_providers.close()
        self.mappings.close()
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

"""Server configuration and command-line parsing."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from openkapsel.auth.security import is_password_hash_supported
from openkapsel.auth.tokens import CONTAINER_IMAGE_RE
from openkapsel.execution.network_proxy import DEFAULT_NETWORK_DOMAINS, normalize_domain_rules

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
    mapping_rpc_timeout_seconds: float = 90.0
    mapping_provider_idle_timeout_seconds: float = 60.0
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
    mappings_enabled: bool = False
    mapping_fuse_enabled: bool = True
    max_active_mapping_mounts: int = 16
    mapping_mount_idle_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not isinstance(self.mappings_enabled, bool):
            raise ValueError("mappings_enabled must be boolean")
        if not isinstance(self.mapping_fuse_enabled, bool):
            raise ValueError("mapping_fuse_enabled must be boolean")
        if type(self.max_active_mapping_mounts) is not int or not 1 <= self.max_active_mapping_mounts <= 256:
            raise ValueError("max_active_mapping_mounts must be between 1 and 256")
        if isinstance(self.mapping_mount_idle_seconds, bool) or not isinstance(self.mapping_mount_idle_seconds, (int, float)) or not 0 <= self.mapping_mount_idle_seconds <= 3600:
            raise ValueError("mapping_mount_idle_seconds must be between 0 and 3600")
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
            self.mapping_rpc_timeout_seconds,
            self.mapping_provider_idle_timeout_seconds,
            self.max_sse_duration_seconds,
            self.network_proxy_header_timeout_seconds,
        ) <= 0:
            raise ValueError("HTTP, mapping, and proxy timeout limits must be positive")
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
        if not 1 <= self.mapping_rpc_timeout_seconds <= 600:
            raise ValueError("mapping_rpc_timeout_seconds must be between 1 and 600 seconds")
        if not 10 <= self.mapping_provider_idle_timeout_seconds <= 600:
            raise ValueError("mapping_provider_idle_timeout_seconds must be between 10 and 600 seconds")
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
        mappings_enabled=payload.get("mappings_enabled", False),
        mapping_fuse_enabled=payload.get("mapping_fuse_enabled", True),
        max_active_mapping_mounts=payload.get("max_active_mapping_mounts", 16),
        mapping_mount_idle_seconds=payload.get("mapping_mount_idle_seconds", 30),
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
        mapping_rpc_timeout_seconds=float(
            payload.get("mapping_rpc_timeout_seconds", 90)
        ),
        mapping_provider_idle_timeout_seconds=float(
            payload.get("mapping_provider_idle_timeout_seconds", 60)
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

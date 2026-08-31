"""Shared Shell launch policy for HTTP requests and scheduled executions."""

from __future__ import annotations

import os
from http import HTTPStatus
from pathlib import Path
from typing import Any

from .cgroups import BUBBLEWRAP_PROCESS_OVERHEAD, SandboxLimits
from .environment_store import EnvironmentConfigError, EnvironmentStore
from .errors import ApiError
from .sandbox_backends import SandboxLaunch, SandboxSpec
from .tokens import PathGrant, TokenRecord
from .workspace_layout import INTERNAL_DIRECTORY, ensure_workspace_layout


def full_shell_process_environment(scope_root: Path) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        "HOME": str(scope_root),
        "TMPDIR": "/tmp",
        "OPENKAPSEL_WORKSPACE": str(scope_root),
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM"):
        value = os.environ.get(name)
        if value and "\x00" not in value:
            environment[name] = value
    return environment


def validated_path_grants(record: TokenRecord) -> tuple[PathGrant, ...]:
    for grant in record.allowed_paths:
        configured = Path(grant.path)
        try:
            resolved = configured.resolve(strict=True)
        except OSError:
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "extra_path_unavailable",
                f"extra accessible directory is unavailable: {grant.path}",
            ) from None
        if resolved != configured or not resolved.is_dir():
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "extra_path_changed",
                f"extra accessible directory changed after authorization: {grant.path}",
            )
    return record.allowed_paths


def sandbox_hidden_paths(scope_root: Path) -> tuple[Path, ...]:
    hidden: list[Path] = [ensure_workspace_layout(scope_root).root]
    for current, directories, _files in os.walk(scope_root, followlinks=False):
        parent = Path(current)
        for name in tuple(directories):
            path = parent / name
            if path.is_symlink() or name == INTERNAL_DIRECTORY:
                directories.remove(name)
            if name == INTERNAL_DIRECTORY and path.is_dir() and not path.is_symlink():
                hidden.append(path)
    return tuple(sorted(set(hidden), key=lambda path: len(path.parts)))


def resolve_shell_cwd(scope_root: Path, record: TokenRecord, value: str) -> Path:
    if not isinstance(value, str):
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", "cwd must be a string")
    if "\x00" in value:
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_path",
            "cwd contains an invalid NUL byte",
        )
    raw = Path(value or ".").expanduser()
    candidate = raw if raw.is_absolute() else scope_root / raw
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_directory", "cwd is not a directory") from None
    if not resolved.is_dir():
        raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_directory", "cwd is not a directory")
    try:
        resolved.relative_to(scope_root)
        return resolved
    except ValueError:
        pass
    for grant in validated_path_grants(record):
        try:
            resolved.relative_to(Path(grant.path))
            return resolved
        except ValueError:
            continue
    raise ApiError(
        HTTPStatus.FORBIDDEN,
        "path_outside_scope",
        "cwd is outside the token workspace and additional accessible paths",
    )


def sandbox_limits(record: TokenRecord, backend: str | None) -> SandboxLimits:
    return SandboxLimits(
        max_processes=record.sandbox_max_processes,
        memory_bytes=record.sandbox_memory_mb * 1024 * 1024,
        cpu_percent=record.sandbox_cpu_percent,
        process_overhead=BUBBLEWRAP_PROCESS_OVERHEAD if backend == "bubblewrap" else 0,
    )


def sandbox_launch(
    server: Any,
    record: TokenRecord,
    scope_root: Path,
    command: str,
    cwd: Path,
    environment_file: Path | None,
) -> SandboxLaunch:
    try:
        backend = server.sandboxes.resolve(record.sandbox_backend)
    except LookupError as exc:
        raise ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "sandbox_backend_disabled",
            str(exc),
        ) from None
    except RuntimeError as exc:
        raise ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "sandbox_unavailable",
            str(exc),
        ) from None
    spec = SandboxSpec(
        command=command,
        cwd=cwd,
        scope_root=scope_root,
        can_write=record.can_write,
        network_mode=record.network_mode,
        allowed_domains=record.allowed_domains,
        proxy_root=server.config.network_proxy_dir,
        allowed_paths=validated_path_grants(record),
        hidden_paths=sandbox_hidden_paths(scope_root),
        limits=SandboxLimits(
            max_processes=record.sandbox_max_processes,
            memory_bytes=record.sandbox_memory_mb * 1024 * 1024,
            cpu_percent=record.sandbox_cpu_percent,
        ),
        owner_token=record.token,
        sandbox_image=record.sandbox_image,
        environment_file=environment_file,
    )
    try:
        return backend.build_shell(spec)
    except RuntimeError as exc:
        raise ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "sandbox_unavailable",
            str(exc),
        ) from None


def start_shell_task(
    server: Any,
    record: TokenRecord,
    scope_root: Path,
    *,
    command: str,
    cwd_value: str,
    timeout_seconds: float | None,
    interactive: bool = False,
):
    if record.shell_mode == "none":
        raise ApiError(
            HTTPStatus.FORBIDDEN,
            "permission_denied",
            "shell permission is not granted",
        )
    if not command or len(command) > 100_000:
        raise ApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "command_too_large",
            "command is empty or too long",
        )
    cwd = resolve_shell_cwd(scope_root, record, cwd_value)
    if timeout_seconds is not None and (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0.1 <= float(timeout_seconds) <= 86_400
    ):
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "timeout_seconds must be null or a number between 0.1 and 86400",
        )
    timeout = None if timeout_seconds is None else float(timeout_seconds)
    try:
        environment_file = EnvironmentStore(scope_root).shell_file(record.app_id)
    except EnvironmentConfigError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_environment", str(exc)) from None
    except OSError:
        raise ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "environment_unavailable",
            "environment configuration is unavailable",
        ) from None
    sandboxed = record.shell_mode == "restricted"
    network_access = record.shell_mode == "full" or record.network_mode != "none"
    launch = None
    if sandboxed:
        launch = sandbox_launch(
            server, record, scope_root, command, cwd, environment_file
        )
    backend_name = None if launch is None else launch.backend
    resource_limits = None
    if sandboxed and server.config.sandbox_cgroup_enabled:
        resource_limits = sandbox_limits(record, backend_name)
    controller = None if launch is None else launch.controller
    try:
        return server.tasks.start(
            command,
            cwd,
            timeout,
            owner_token=record.token,
            argv=None if launch is None else launch.argv,
            stdin_data=None if launch is None else launch.stdin_data,
            interactive=interactive,
            sandboxed=sandboxed,
            sandbox_backend=backend_name,
            sandbox_controller=controller,
            environment_file=environment_file,
            process_environment=(
                None if sandboxed else full_shell_process_environment(scope_root)
            ),
            network_access=network_access,
            resource_limits=resource_limits,
        )
    except Exception:
        if controller is not None:
            controller.cleanup()
        raise

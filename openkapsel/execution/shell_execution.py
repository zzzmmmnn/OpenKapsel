"""Shared Shell launch policy for HTTP requests and scheduled executions."""

from __future__ import annotations

import os
from http import HTTPStatus
from pathlib import Path
from typing import Any

from openkapsel.execution.cgroups import BUBBLEWRAP_PROCESS_OVERHEAD, SandboxLimits
from openkapsel.execution.environment_store import EnvironmentConfigError, EnvironmentStore
from openkapsel.errors import ApiError
from openkapsel.execution.sandbox_backends import SandboxLaunch, SandboxSpec
from openkapsel.auth.tokens import PathGrant, TokenRecord
from openkapsel.auth.path_access import effective_path_access
from openkapsel.workspace.workspace_layout import INTERNAL_DIRECTORY, ensure_workspace_layout


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
        if resolved != configured or not (
                resolved.is_dir() or (grant.access in {"protect", "deny"} and resolved.is_file())):
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "extra_path_changed",
                f"extra accessible directory changed after authorization: {grant.path}",
            )
    # Preserve protect barriers for native backends: more-specific explicit
    # grants may reopen them. Drop any permit below an absolute deny.
    denied = [Path(grant.path) for grant in record.allowed_paths if grant.access == "deny"]
    return tuple(
        grant for grant in record.allowed_paths
        if grant.access != "deny" and not any(
            parent == Path(grant.path) or parent in Path(grant.path).parents
            for parent in denied
        )
    )


def sandbox_hidden_paths(scope_root: Path, *, mapping_roots=(), grants=()) -> tuple[Path, ...]:
    hidden: list[Path] = [ensure_workspace_layout(scope_root).root]
    mapped = set(mapping_roots)
    for current, directories, _files in os.walk(scope_root, followlinks=False):
        parent = Path(current)
        for name in tuple(directories):
            path = parent / name
            # Providers reject private paths themselves. Walking a remote export
            # here would turn every Shell startup into an unbounded network scan.
            if path in mapped:
                directories.remove(name)
                continue
            if path.is_symlink() or name == INTERNAL_DIRECTORY:
                directories.remove(name)
            if name == INTERNAL_DIRECTORY and path.is_dir() and not path.is_symlink():
                hidden.append(path)
    active_grants = [scope_root, *(
        Path(grant.path) for grant in grants if grant.access != "deny"
    )]
    for grant in grants:
        path = Path(grant.path)
        if grant.access == "deny":
            # Only absolute deny is a hard overlay. Protect is represented
            # as an ordinary sandbox mask so a deeper explicit rw can reopen
            # its own subtree without exposing the protected parent.
            if any(path == base or base in path.parents for base in active_grants):
                hidden.append(path)
        else:
            internal = path / ".openkapsel"
            if internal.is_dir() and not internal.is_symlink():
                hidden.append(internal)
    reduced = []
    for path in sorted(set(hidden), key=lambda p: (len(p.parts), str(p))):
        if not any(parent == path or parent in path.parents for parent in reduced):
            reduced.append(path)
    return tuple(reduced)


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
    # Refuse configured protection before accepting a path merely because it
    # is inside the workspace. The sandbox also masks it, but resolving cwd
    # to an inaccessible directory must fail rather than launching a job.
    policy = effective_path_access(resolved, scope_root, record.can_write, record.allowed_paths)
    if policy in {"protect", "deny"}:
        raise ApiError(HTTPStatus.FORBIDDEN, "path_access_denied", "Shell cwd is protected or denied")
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
    mount_ids=(),
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
    manager = getattr(server, "mappings", None)
    rows = manager.store.list(record.path_prefix) if manager is not None else []
    native = tuple(manager.mount_path(r) for r in rows if r["id"] in mount_ids)
    denied = tuple(manager.mount_path(r) for r in rows if r["id"] not in mount_ids)
    spec = SandboxSpec(
        native_mapping_paths=native,
        denied_mapping_paths=denied,
        mapping_mask_source=manager.empty_view() if denied else None,
        command=command,
        cwd=cwd,
        scope_root=scope_root,
        can_write=record.can_write,
        network_mode=record.network_mode,
        allowed_domains=record.allowed_domains,
        proxy_root=server.config.network_proxy_dir,
        allowed_paths=validated_path_grants(record),
        hidden_paths=sandbox_hidden_paths(scope_root, mapping_roots=(
            tuple(server.mappings.mount_path(row) for row in server.mappings.store.list(record.path_prefix))
            if hasattr(server, "mappings") else ()
        ), grants=record.allowed_paths),
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


def start_shell_task(server, record, scope_root, *, command, cwd_value,
                     timeout_seconds, interactive=False, mount_mappings=(), unsandboxed=False,
                     authorize_launch=None):
    """Authorize dependencies and mount before cwd resolution or sandbox setup."""
    if record.shell_mode == "none":
        raise ApiError(403, "permission_denied", "shell permission is not granted")
    if unsandboxed and any(rule.access == "deny" for rule in record.allowed_paths):
        raise ApiError(403, "absolute_deny", "Unsandboxed Shell cannot bypass absolute deny paths")
    if not isinstance(cwd_value, str) or "\x00" in cwd_value:
        raise ApiError(400, "invalid_path", "cwd must be a NUL-free string")
    if not isinstance(command, str) or not command or len(command) > 100000:
        raise ApiError(400, "invalid_request", "command must contain 1-100000 characters")
    if timeout_seconds is not None and (isinstance(timeout_seconds, bool) or
            not isinstance(timeout_seconds, (int, float)) or not .1 <= timeout_seconds < float("inf")):
        raise ApiError(400, "invalid_request", "invalid command timeout")
    raw = Path(cwd_value or ".").expanduser()
    candidate = Path(os.path.abspath(raw if raw.is_absolute() else scope_root / raw))
    manager = getattr(server, "mappings", None)
    if manager is None or manager.at_path(candidate) is None:
        candidate = candidate.resolve(strict=False)
    policy = effective_path_access(candidate, scope_root, record.can_write,
                                  record.allowed_paths)
    if policy in (None, "deny"):
        raise ApiError(403, "path_outside_scope", "cwd is denied or outside authorized paths")
    lease = None
    if manager is not None:
        try:
            rows = manager.execution_mappings(record.path_prefix, candidate, mount_mappings)
            if rows:
                lease = manager.acquire(rows)
        except ValueError as exc:
            raise ApiError(400, "invalid_mapping_dependency", str(exc)) from None
        except OSError as exc:
            raise ApiError(503, "mapping_mount_unavailable", str(exc), {"errno": exc.errno}) from None
    elif mount_mappings:
        raise ApiError(409, "mappings_unavailable", "mapping manager is unavailable")
    try:
        return _start_shell_task(server, record, scope_root, command=command,
            cwd_value=cwd_value, timeout_seconds=timeout_seconds,
            interactive=interactive, mount_lease=lease, unsandboxed=unsandboxed,
            authorize_launch=authorize_launch)
    except BaseException:
        if lease is not None:
            lease.close()
        raise


def _start_shell_task(
    server: Any,
    record: TokenRecord,
    scope_root: Path,
    *,
    command: str,
    cwd_value: str,
    timeout_seconds: float | None,
    interactive: bool = False,
    mount_lease=None,
    unsandboxed=False,
    authorize_launch=None,
):
    if record.shell_mode == "none":
        raise ApiError(
            HTTPStatus.FORBIDDEN,
            "permission_denied",
            "shell permission is not granted",
        )
    if unsandboxed and any(rule.access == "deny" for rule in record.allowed_paths):
        raise ApiError(HTTPStatus.FORBIDDEN, "absolute_deny",
                       "Unsandboxed Shell cannot bypass absolute deny paths")
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
        or not 0.1 <= float(timeout_seconds) < float("inf")
    ):
        raise ApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "timeout_seconds must be null or a positive finite number",
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
    sandboxed = record.shell_mode == "restricted" and not unsandboxed
    network_access = unsandboxed or record.shell_mode == "full" or record.network_mode != "none"
    launch = None
    if sandboxed:
        launch = sandbox_launch(
            server, record, scope_root, command, cwd, environment_file,
            mount_ids=mount_lease.ids if mount_lease else (),
        )
    backend_name = None if launch is None else launch.backend
    resource_limits = None
    if sandboxed and server.config.sandbox_cgroup_enabled:
        resource_limits = sandbox_limits(record, backend_name)
    controller = None if launch is None else launch.controller
    try:
        if authorize_launch is not None:
            authorize_launch()
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
            mount_lease=mount_lease,
        )
    except Exception:
        if controller is not None:
            controller.cleanup()
        raise

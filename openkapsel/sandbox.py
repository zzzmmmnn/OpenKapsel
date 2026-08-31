"""Restricted-shell sandbox policy adapter for HTTP handlers."""

from __future__ import annotations

import os
from http import HTTPStatus
from pathlib import Path

from .cgroups import SandboxLimits
from .errors import ApiError
from .sandbox_backends import SandboxBackend, SandboxLaunch, SandboxSpec
from .tokens import PathGrant
from .workspace_layout import INTERNAL_DIRECTORY, ensure_workspace_layout


class SandboxMixin:
    """Validate token policy and delegate command construction to a backend."""

    def _sandbox_spec(
        self, command: str, cwd: Path, environment_file: Path | None = None
    ) -> SandboxSpec:
        return SandboxSpec(
            command=command,
            cwd=cwd,
            scope_root=self.token_scope_root,
            can_write=self.token_record.can_write,
            network_mode=self.token_record.network_mode,
            allowed_domains=self.token_record.allowed_domains,
            proxy_root=self.server.config.network_proxy_dir,
            allowed_paths=self._validated_path_grants(),
            hidden_paths=self._sandbox_hidden_paths(),
            limits=SandboxLimits(
                max_processes=self.token_record.sandbox_max_processes,
                memory_bytes=self.token_record.sandbox_memory_mb * 1024 * 1024,
                cpu_percent=self.token_record.sandbox_cpu_percent,
            ),
            owner_token=self.token_record.token,
            sandbox_image=self.token_record.sandbox_image,
            environment_file=environment_file,
        )

    def _build_with_backend(
        self,
        backend: SandboxBackend,
        command: str,
        cwd: Path,
        environment_file: Path | None = None,
    ) -> SandboxLaunch:
        try:
            return backend.build_shell(
                self._sandbox_spec(command, cwd, environment_file)
            )
        except RuntimeError as exc:
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "sandbox_unavailable",
                str(exc),
            ) from None

    def _sandbox_launch(
        self, command: str, cwd: Path, environment_file: Path | None = None
    ) -> SandboxLaunch:
        try:
            backend = self.server.sandboxes.resolve(self.token_record.sandbox_backend)
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
        return self._build_with_backend(backend, command, cwd, environment_file)

    def _bubblewrap_argv(self, command: str, cwd: Path) -> tuple[tuple[str, ...], bytes | None]:
        """Compatibility shim for older extensions and tests."""
        backend = self.server.sandboxes.backends.get("bubblewrap")
        if backend is None:
            raise ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "sandbox_backend_disabled",
                "sandbox backend 'bubblewrap' is not enabled",
            )
        launch = self._build_with_backend(backend, command, cwd)
        return launch.argv, launch.stdin_data

    def _sandbox_hidden_paths(self) -> tuple[Path, ...]:
        hidden: list[Path] = [ensure_workspace_layout(self.token_scope_root).root]
        for current, directories, _files in os.walk(self.token_scope_root, followlinks=False):
            parent = Path(current)
            for name in tuple(directories):
                path = parent / name
                if path.is_symlink() or name == INTERNAL_DIRECTORY:
                    directories.remove(name)
                if name == INTERNAL_DIRECTORY and path.is_dir() and not path.is_symlink():
                    hidden.append(path)
        return tuple(sorted(set(hidden), key=lambda path: len(path.parts)))

    def _validated_path_grants(self) -> tuple[PathGrant, ...]:
        for grant in self.token_record.allowed_paths:
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
        return self.token_record.allowed_paths

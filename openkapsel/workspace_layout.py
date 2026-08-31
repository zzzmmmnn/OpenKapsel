"""Private per-workspace storage layout and legacy-directory migration."""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


INTERNAL_DIRECTORY = ".openkapsel"
RECYCLE_DIRECTORY = "recycle"
SQL_DIRECTORY = "sql"
CONTEXT_DIRECTORY = "context"
ENV_DIRECTORY = "env"
SCHEDULER_DIRECTORY = "scheduler"
LAYOUT_VERSION_FILE = "layout-version"
LAYOUT_VERSION = 1
LEGACY_DIRECTORIES = {
    ".recycle": RECYCLE_DIRECTORY,
    ".sql": SQL_DIRECTORY,
    ".context": CONTEXT_DIRECTORY,
}


class WorkspaceLayoutError(ValueError):
    """The private workspace layout is unsafe or cannot be migrated."""


@dataclass(frozen=True)
class WorkspaceLayout:
    workspace: Path
    root: Path
    recycle: Path
    sql: Path
    context: Path
    env: Path
    scheduler: Path
    version_file: Path


def paths_for(workspace: Path) -> WorkspaceLayout:
    workspace = Path(workspace).resolve(strict=True)
    root = workspace / INTERNAL_DIRECTORY
    return WorkspaceLayout(
        workspace=workspace,
        root=root,
        recycle=root / RECYCLE_DIRECTORY,
        sql=root / SQL_DIRECTORY,
        context=root / CONTEXT_DIRECTORY,
        env=root / ENV_DIRECTORY,
        scheduler=root / SCHEDULER_DIRECTORY,
        version_file=root / LAYOUT_VERSION_FILE,
    )


def _require_real_directory(path: Path, description: str) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise WorkspaceLayoutError(f"{description} must be a real directory: {path}")


def _directory_has_entries(path: Path) -> bool:
    return next(path.iterdir(), None) is not None


def _prepare_directory(path: Path, description: str) -> None:
    _require_real_directory(path, description)
    path.mkdir(mode=0o700, exist_ok=True)
    path.chmod(0o700)


def _write_version(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise WorkspaceLayoutError(f"workspace layout version must be a real file: {path}")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(f"{LAYOUT_VERSION}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _merge_legacy_directory(source: Path, destination: Path) -> None:
    _require_real_directory(source, "legacy workspace storage")
    if not source.exists():
        _prepare_directory(destination, "workspace private storage")
        return
    _require_real_directory(destination, "workspace private storage")
    if not destination.exists():
        os.replace(source, destination)
        destination.chmod(0o700)
        return
    source_has_entries = _directory_has_entries(source)
    destination_has_entries = _directory_has_entries(destination)
    if source_has_entries and destination_has_entries:
        raise WorkspaceLayoutError(
            f"legacy and current workspace storage both contain data: {source} and {destination}"
        )
    if source_has_entries:
        destination.rmdir()
        os.replace(source, destination)
        destination.chmod(0o700)
        return
    source.rmdir()
    destination.chmod(0o700)


def _ensure_version(layout: WorkspaceLayout) -> None:
    if layout.version_file.exists():
        if layout.version_file.is_symlink() or not layout.version_file.is_file():
            raise WorkspaceLayoutError(
                f"workspace layout version must be a real file: {layout.version_file}"
            )
        try:
            version = int(layout.version_file.read_text(encoding="ascii").strip())
        except (OSError, UnicodeError, ValueError) as exc:
            raise WorkspaceLayoutError(
                f"workspace layout version is invalid: {layout.version_file}"
            ) from exc
        if version != LAYOUT_VERSION:
            raise WorkspaceLayoutError(
                f"unsupported workspace layout version {version}: {layout.version_file}"
            )
        layout.version_file.chmod(0o600)
    else:
        _write_version(layout.version_file)


def ensure_workspace_layout(workspace: Path) -> WorkspaceLayout:
    """Create or migrate one workspace's private storage layout."""
    layout = paths_for(workspace)
    _require_real_directory(layout.workspace, "workspace")
    _prepare_directory(layout.root, "workspace .openkapsel storage")
    for legacy_name, current_name in LEGACY_DIRECTORIES.items():
        _merge_legacy_directory(
            layout.workspace / legacy_name,
            layout.root / current_name,
        )
    _prepare_directory(layout.env, "workspace environment storage")
    _prepare_directory(layout.scheduler, "workspace scheduler storage")
    _ensure_version(layout)
    return layout


def ensure_workspace_directory(workspace: Path, name: str) -> Path:
    """Recreate one private store without coupling it to sibling stores."""
    if name not in {
        RECYCLE_DIRECTORY,
        SQL_DIRECTORY,
        CONTEXT_DIRECTORY,
        ENV_DIRECTORY,
        SCHEDULER_DIRECTORY,
    }:
        raise ValueError(f"unknown workspace private directory: {name}")
    layout = paths_for(workspace)
    _prepare_directory(layout.root, "workspace .openkapsel storage")
    directory = layout.root / name
    _prepare_directory(directory, f"workspace {name} storage")
    _ensure_version(layout)
    return directory


def remove_empty_workspace_layout(workspace: Path) -> None:
    """Remove a newly-created layout only when every private store is empty."""
    layout = paths_for(workspace)
    layout.version_file.unlink()
    for directory in (
        layout.scheduler,
        layout.env,
        layout.context,
        layout.sql,
        layout.recycle,
    ):
        directory.rmdir()
    layout.root.rmdir()

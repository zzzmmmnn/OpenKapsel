"""Recoverable deletion support inside one child workspace."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any

from .safe_paths import DIRECTORY_FLAGS, NOFOLLOW_FLAGS, SafePathAccess, SafePathError
from .workspace_layout import (
    INTERNAL_DIRECTORY,
    RECYCLE_DIRECTORY,
    ensure_workspace_directory,
    ensure_workspace_layout,
)


METADATA_FILE = ".openkapsel_recycle.json"
RECYCLE_ID_PATTERN = re.compile(r"\A\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{8}\Z")


class RecycleError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class RecycleBin:
    """Moves deleted paths into the child workspace's private recycle store."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.root = ensure_workspace_layout(self.workspace_root).recycle
        self._paths = SafePathAccess((self.workspace_root,))
        self._lock = threading.RLock()
        try:
            descriptor = self._open_root()
        except RecycleError as exc:
            raise ValueError(exc.message) from None
        else:
            os.close(descriptor)

    def _open_root(self) -> int:
        """Recreate and open the private recycle directory without following links."""
        try:
            self.root = ensure_workspace_directory(
                self.workspace_root, RECYCLE_DIRECTORY
            )
            descriptor = os.open(self.root, DIRECTORY_FLAGS)
            os.fchmod(descriptor, 0o700)
            return descriptor
        except (OSError, ValueError) as exc:
            raise RecycleError(
                HTTPStatus.CONFLICT,
                "recycle_unavailable",
                f"{self.root} must be a real directory, not a file or symlink: {exc}",
            ) from None

    def recycle(self, path: Path) -> dict[str, Any]:
        with self._lock:
            original_relative = self._relative_to_workspace(path)
            if not original_relative.parts:
                raise RecycleError(
                    HTTPStatus.FORBIDDEN,
                    "root_protected",
                    "the token workspace root cannot be deleted",
                )
            root_fd = self._open_root()
            try:
                try:
                    source_parent = self._paths.parent(path)
                except SafePathError as exc:
                    self._path_error(exc)
                with source_parent:
                    source_stat = source_parent.lstat()
                    if source_stat is None:
                        raise RecycleError(HTTPStatus.NOT_FOUND, "path_not_found", "path does not exist")
                    deleted_at = datetime.now(timezone.utc)
                    recycle_id = deleted_at.strftime("%Y%m%dT%H%M%S.%fZ") + "-" + secrets.token_hex(4)
                    os.mkdir(recycle_id, mode=0o700, dir_fd=root_fd)
                    entry_fd = os.open(recycle_id, DIRECTORY_FLAGS, dir_fd=root_fd)
                    try:
                        metadata = {
                            "version": 1,
                            "id": recycle_id,
                            "deleted_at": deleted_at.isoformat(),
                            "original_path": str(original_relative),
                            "type": "directory" if stat.S_ISDIR(source_stat.st_mode) else "file",
                            "size": source_stat.st_size,
                        }
                        self._write_metadata(entry_fd, metadata)
                        stored_parent_fd = self._open_relative_parent(
                            entry_fd,
                            original_relative.parts[:-1],
                            create=True,
                        )
                        try:
                            os.rename(
                                source_parent.name,
                                original_relative.parts[-1],
                                src_dir_fd=source_parent.fd,
                                dst_dir_fd=stored_parent_fd,
                            )
                        finally:
                            os.close(stored_parent_fd)
                    finally:
                        os.close(entry_fd)
                    return self._public_record(metadata)
            except RecycleError:
                raise
            except OSError as exc:
                raise RecycleError(HTTPStatus.CONFLICT, "recycle_failed", str(exc)) from None
            finally:
                os.close(root_fd)

    def list_items(self, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
        with self._lock:
            root_fd = self._open_root()
            try:
                records: list[dict[str, Any]] = []
                with os.scandir(root_fd) as iterator:
                    names = sorted((entry.name for entry in iterator), reverse=True)
                for name in names:
                    if not RECYCLE_ID_PATTERN.fullmatch(name):
                        continue
                    try:
                        entry_fd = os.open(name, DIRECTORY_FLAGS, dir_fd=root_fd)
                        try:
                            metadata = self._load_metadata(entry_fd, name)
                            original = self._metadata_relative(metadata)
                            stored_parent_fd = self._open_relative_parent(
                                entry_fd,
                                original.parts[:-1],
                                create=False,
                            )
                            try:
                                os.stat(original.parts[-1], dir_fd=stored_parent_fd, follow_symlinks=False)
                            finally:
                                os.close(stored_parent_fd)
                            records.append(self._public_record(metadata))
                        finally:
                            os.close(entry_fd)
                    except (OSError, ValueError, KeyError, json.JSONDecodeError, RecycleError):
                        continue
                return records[offset : offset + limit], len(records)
            except OSError as exc:
                raise RecycleError(HTTPStatus.CONFLICT, "recycle_unavailable", str(exc)) from None
            finally:
                os.close(root_fd)

    def restore(self, recycle_id: str) -> dict[str, Any]:
        if not RECYCLE_ID_PATTERN.fullmatch(recycle_id):
            raise RecycleError(HTTPStatus.NOT_FOUND, "recycle_not_found", "recycle item does not exist")
        with self._lock:
            root_fd = self._open_root()
            try:
                try:
                    entry_fd = os.open(recycle_id, DIRECTORY_FLAGS, dir_fd=root_fd)
                except OSError:
                    raise RecycleError(HTTPStatus.NOT_FOUND, "recycle_not_found", "recycle item does not exist") from None
                try:
                    metadata = self._load_metadata(entry_fd, recycle_id)
                    original_relative = self._metadata_relative(metadata)
                    original = self.workspace_root.joinpath(*original_relative.parts)
                    stored_parent_fd = self._open_relative_parent(
                        entry_fd,
                        original_relative.parts[:-1],
                        create=False,
                    )
                    try:
                        try:
                            os.stat(
                                original_relative.parts[-1],
                                dir_fd=stored_parent_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            raise RecycleError(
                                HTTPStatus.NOT_FOUND,
                                "recycle_not_found",
                                "recycle item does not exist",
                            ) from None
                        try:
                            target_parent = self._paths.parent(original, create_parents=True)
                        except SafePathError as exc:
                            self._path_error(exc)
                        with target_parent:
                            if target_parent.lstat() is not None:
                                raise RecycleError(
                                    HTTPStatus.CONFLICT,
                                    "restore_target_exists",
                                    "the original path already exists; move it before restoring",
                                )
                            os.rename(
                                original_relative.parts[-1],
                                target_parent.name,
                                src_dir_fd=stored_parent_fd,
                                dst_dir_fd=target_parent.fd,
                            )
                    finally:
                        os.close(stored_parent_fd)
                finally:
                    os.close(entry_fd)
                self._remove_tree(root_fd, recycle_id)
                result = self._public_record(metadata)
                result.update({"restored": True, "path": str(original)})
                result.pop("stored_path", None)
                return result
            except RecycleError:
                raise
            except OSError as exc:
                raise RecycleError(HTTPStatus.CONFLICT, "restore_failed", str(exc)) from None
            finally:
                os.close(root_fd)

    @staticmethod
    def _write_metadata(entry_fd: int, metadata: dict[str, Any]) -> None:
        descriptor = os.open(
            METADATA_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW_FLAGS,
            0o600,
            dir_fd=entry_fd,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _load_metadata(self, entry_fd: int, recycle_id: str) -> dict[str, Any]:
        try:
            descriptor = os.open(METADATA_FILE, os.O_RDONLY | NOFOLLOW_FLAGS, dir_fd=entry_fd)
        except OSError:
            raise RecycleError(HTTPStatus.NOT_FOUND, "recycle_not_found", "recycle item does not exist") from None
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            details = os.fstat(handle.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_size > 64 * 1024:
                raise ValueError("invalid recycle metadata")
            metadata = json.load(handle)
        if metadata.get("version") != 1 or metadata.get("id") != recycle_id:
            raise ValueError("invalid recycle metadata")
        self._metadata_relative(metadata)
        return metadata

    @staticmethod
    def _metadata_relative(metadata: dict[str, Any]) -> Path:
        original = Path(str(metadata["original_path"]))
        if not original.parts or original.is_absolute() or any(part in {"", ".", ".."} for part in original.parts):
            raise ValueError("invalid original path in recycle metadata")
        return original

    @staticmethod
    def _open_relative_parent(base_fd: int, parts: tuple[str, ...], *, create: bool) -> int:
        descriptor = os.dup(base_fd)
        try:
            for part in parts:
                try:
                    next_fd = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    next_fd = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @classmethod
    def _remove_tree(cls, parent_fd: int, name: str) -> None:
        descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            with os.scandir(descriptor) as iterator:
                entries = [(entry.name, entry.stat(follow_symlinks=False)) for entry in iterator]
            for child_name, details in entries:
                if stat.S_ISDIR(details.st_mode):
                    cls._remove_tree(descriptor, child_name)
                else:
                    os.unlink(child_name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(name, dir_fd=parent_fd)

    def _public_record(self, metadata: dict[str, Any]) -> dict[str, Any]:
        original = self._metadata_relative(metadata)
        return {
            "recycle_id": str(metadata["id"]),
            "deleted_at": str(metadata["deleted_at"]),
            "original_path": str(original),
            "stored_path": str(
                Path(INTERNAL_DIRECTORY)
                / RECYCLE_DIRECTORY
                / str(metadata["id"])
                / original
            ),
            "type": str(metadata["type"]),
            "size": int(metadata["size"]),
        }

    def _relative_to_workspace(self, path: Path) -> Path:
        try:
            return path.resolve(strict=False).relative_to(self.workspace_root)
        except ValueError:
            raise RecycleError(
                HTTPStatus.FORBIDDEN,
                "path_outside_root",
                "path escapes workspace root",
            ) from None

    @staticmethod
    def _path_error(exc: SafePathError) -> None:
        if exc.errno == 2:
            raise RecycleError(HTTPStatus.NOT_FOUND, "path_not_found", "path does not exist") from None
        raise RecycleError(HTTPStatus.CONFLICT, "path_changed", "path changed during the operation") from None

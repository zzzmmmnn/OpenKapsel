"""Descriptor-anchored filesystem operations for token-authorized paths.

Authorization decides which absolute path is allowed. This module makes the
subsequent kernel operation stay below that authorized root even if another
process replaces a path component with a symlink between validation and use.
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
NOFOLLOW_FLAGS = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class SafePathError(OSError):
    """The authorized path changed or could not be traversed safely."""


@dataclass
class ParentHandle:
    """An opened parent directory plus one untrusted final component."""

    fd: int
    name: str
    path: Path

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "ParentHandle":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def lstat(self) -> os.stat_result | None:
        try:
            return os.stat(self.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def open(self, flags: int, mode: int = 0o600) -> int:
        return os.open(self.name, flags | NOFOLLOW_FLAGS, mode, dir_fd=self.fd)

    def unlink(self, *, directory: bool = False) -> None:
        if directory:
            os.rmdir(self.name, dir_fd=self.fd)
        else:
            os.unlink(self.name, dir_fd=self.fd)


class SafePathAccess:
    """Open absolute authorized paths relative to stable directory handles."""

    def __init__(self, roots: Iterable[Path]):
        normalized = {Path(root).absolute() for root in roots}
        self.roots = tuple(sorted(normalized, key=lambda item: len(item.parts), reverse=True))

    def anchor(self, path: Path) -> tuple[Path, tuple[str, ...]]:
        absolute = path.absolute()
        for root in self.roots:
            try:
                relative = absolute.relative_to(root)
            except ValueError:
                continue
            if any(part in {"", ".", ".."} for part in relative.parts):
                break
            return root, relative.parts
        raise SafePathError(errno.EPERM, "path is outside authorized roots", str(path))

    def open(self, path: Path, flags: int = os.O_RDONLY, mode: int = 0o600) -> int:
        root, parts = self.anchor(path)
        descriptor = self._open_root(root)
        try:
            if not parts:
                return descriptor
            for part in parts[:-1]:
                next_descriptor = self._open_directory(part, descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            result = os.open(parts[-1], flags | NOFOLLOW_FLAGS, mode, dir_fd=descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise self._safe_error(path, exc) from None
        os.close(descriptor)
        return result

    def parent(self, path: Path, *, create_parents: bool = False) -> ParentHandle:
        root, parts = self.anchor(path)
        if not parts:
            raise SafePathError(errno.EPERM, "authorized root has no parent operation", str(path))
        descriptor = self._open_root(root)
        try:
            for part in parts[:-1]:
                try:
                    next_descriptor = self._open_directory(part, descriptor)
                except FileNotFoundError:
                    if not create_parents:
                        raise
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    next_descriptor = self._open_directory(part, descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            return ParentHandle(descriptor, parts[-1], path)
        except OSError as exc:
            os.close(descriptor)
            raise self._safe_error(path, exc) from None

    def mkdir(self, path: Path, *, parents: bool, exist_ok: bool) -> bool:
        with self.parent(path, create_parents=parents) as parent:
            current = parent.lstat()
            if current is not None:
                if exist_ok and stat.S_ISDIR(current.st_mode):
                    return False
                raise FileExistsError(errno.EEXIST, "path already exists", str(path))
            os.mkdir(parent.name, mode=0o700, dir_fd=parent.fd)
            return True

    def rename(
        self,
        source: Path,
        destination: Path,
        *,
        overwrite: bool,
        create_parents: bool,
    ) -> bool:
        with self.parent(source) as source_parent, self.parent(
            destination,
            create_parents=create_parents,
        ) as destination_parent:
            source_stat = source_parent.lstat()
            if source_stat is None:
                raise FileNotFoundError(errno.ENOENT, "source path does not exist", str(source))
            destination_stat = destination_parent.lstat()
            if destination_stat is not None and not overwrite:
                raise FileExistsError(errno.EEXIST, "destination path exists", str(destination))
            operation = os.replace if overwrite else os.rename
            operation(
                source_parent.name,
                destination_parent.name,
                src_dir_fd=source_parent.fd,
                dst_dir_fd=destination_parent.fd,
            )
            return destination_stat is not None

    @staticmethod
    def _open_root(root: Path) -> int:
        try:
            return os.open(root, DIRECTORY_FLAGS)
        except OSError as exc:
            raise SafePathAccess._safe_error(root, exc) from None

    @staticmethod
    def _open_directory(name: str, parent_fd: int) -> int:
        return os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)

    @staticmethod
    def _safe_error(path: Path, exc: OSError) -> SafePathError:
        message = "path changed or contains a symbolic link"
        if exc.errno == errno.ENOENT:
            message = "path does not exist"
        elif exc.errno == errno.ENOTDIR:
            message = "path component is not a directory"
        return SafePathError(exc.errno or errno.EIO, message, str(path))

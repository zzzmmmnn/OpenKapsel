"""Locked, fail-closed loading for mapping client configuration."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_CLIENT_CONFIG_BYTES = 1024 * 1024
REEXEC_CONFIG_FD_ENV = "OPENKAPSEL_CLIENT_CONFIG_FD"
REEXEC_CONFIG_SHA256_ENV = "OPENKAPSEL_CLIENT_CONFIG_SHA256"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ClientConfigError(RuntimeError):
    """Base class for client configuration ownership/integrity failures."""


class ClientConfigLockedError(ClientConfigError):
    """The selected configuration is already owned by another client."""


class ClientConfigChangedError(ClientConfigError):
    """The configuration changed across an automatic client re-exec."""


def _lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise ClientConfigLockedError("client configuration is already locked") from exc
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
        return

    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise ClientConfigLockedError("client configuration is already locked") from exc


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
        return

    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        data = os.read(fd, min(65536, MAX_CLIENT_CONFIG_BYTES + 1 - total))
        if not data:
            break
        chunks.append(data)
        total += len(data)
        if total > MAX_CLIENT_CONFIG_BYTES:
            raise ClientConfigError(
                f"client configuration exceeds {MAX_CLIENT_CONFIG_BYTES} bytes"
            )
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)


class ClientConfigLock:
    """Hold one client config exclusively and pin its startup content digest."""

    def __init__(self, path: Path, fd: int, config: dict[str, Any], digest: str):
        self.path = path
        self.fd = fd
        self.config = config
        self.sha256 = digest
        self._closed = False

    @classmethod
    def acquire(cls, path: str | Path) -> "ClientConfigLock":
        path = Path(path).expanduser().resolve()
        expected = os.environ.pop(REEXEC_CONFIG_SHA256_ENV, None)
        inherited = os.environ.pop(REEXEC_CONFIG_FD_ENV, None)
        fd: int | None = None
        locked_here = False
        try:
            if inherited is not None and os.name != "nt":
                if not inherited.isdecimal():
                    raise ClientConfigChangedError(
                        "automatic reload supplied an invalid configuration descriptor"
                    )
                fd = int(inherited)
                try:
                    os.fstat(fd)
                except OSError as exc:
                    raise ClientConfigChangedError(
                        "automatic reload lost the locked configuration descriptor"
                    ) from exc
                os.set_inheritable(fd, False)
                current = path.stat()
                opened = os.fstat(fd)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ClientConfigChangedError(
                        "client configuration path was replaced while the client was running"
                    )
            else:
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags)
                _lock(fd)
                locked_here = True

            details = os.fstat(fd)
            if not stat.S_ISREG(details.st_mode):
                raise ClientConfigError("client configuration must be a regular file")
            if os.name != "nt" and details.st_mode & 0o077:
                raise ClientConfigError(
                    "client configuration contains credentials: chmod 600 it first"
                )

            payload = _read_all(fd)
            digest = hashlib.sha256(payload).hexdigest()
            if expected is not None:
                if not _SHA256.fullmatch(expected) or not hmac.compare_digest(digest, expected):
                    raise ClientConfigChangedError(
                        "client configuration changed during automatic reload"
                    )
            try:
                config = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ClientConfigError("client configuration must be valid UTF-8 JSON") from exc
            if not isinstance(config, dict):
                raise ClientConfigError("client configuration must be a JSON object")
            return cls(path, fd, config, digest)
        except Exception:
            if fd is not None:
                try:
                    if locked_here:
                        _unlock(fd)
                except OSError:
                    pass
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def exec_descriptor(self) -> int | None:
        """Prepare the held POSIX lock to survive exec; Windows re-locks by path."""
        if os.name == "nt":
            return None
        if self._closed:
            raise ClientConfigError("client configuration lock is closed")
        os.set_inheritable(self.fd, True)
        return self.fd

    def restore_noninheritable(self) -> None:
        if os.name != "nt" and not self._closed:
            os.set_inheritable(self.fd, False)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _unlock(self.fd)
        except OSError:
            pass
        finally:
            os.close(self.fd)

"""Client and privileged storage engine for sparse ext4 workspace images."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


IMAGE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
MIN_IMAGE_BYTES = 64 * 1024 * 1024
MAX_IMAGE_BYTES = 16 * 1024 * 1024 * 1024 * 1024
MAX_RPC_BYTES = 64 * 1024


class WorkspaceImageError(RuntimeError):
    """A safe, user-facing workspace image error."""


@dataclass(frozen=True)
class WorkspaceImage:
    name: str
    size_bytes: int
    allocated_bytes: int
    mounted: bool

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "WorkspaceImage":
        return cls(
            name=str(value["name"]),
            size_bytes=int(value["size_bytes"]),
            allocated_bytes=int(value.get("allocated_bytes", value["size_bytes"])),
            mounted=bool(value["mounted"]),
        )


def validate_image_name(value: str) -> str:
    name = value.strip()
    if not IMAGE_NAME_RE.fullmatch(name) or name.startswith("."):
        raise WorkspaceImageError("image name must contain 1-64 letters, digits, underscores, or hyphens and start with a letter or digit")
    return name


def validate_image_size(value: int) -> int:
    if isinstance(value, bool) or not MIN_IMAGE_BYTES <= value <= MAX_IMAGE_BYTES:
        raise WorkspaceImageError("image size must be between 64 MiB and 16 TiB")
    return value


class WorkspaceImageClient:
    """Small newline-delimited JSON client for the root image helper."""

    def __init__(self, socket_path: Path | None, timeout: float = 120.0):
        self.socket_path = socket_path
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return self.socket_path is not None

    def list(self) -> list[WorkspaceImage]:
        payload = self._request("list")
        return [WorkspaceImage.from_dict(item) for item in payload.get("images", [])]

    def create(self, name: str, size_bytes: int) -> WorkspaceImage:
        return WorkspaceImage.from_dict(
            self._request("create", name=validate_image_name(name), size_bytes=validate_image_size(size_bytes))["image"]
        )

    def grow(self, name: str, size_bytes: int) -> WorkspaceImage:
        return WorkspaceImage.from_dict(
            self._request("grow", name=validate_image_name(name), size_bytes=validate_image_size(size_bytes))["image"]
        )

    def delete(self, name: str) -> None:
        self._request("delete", name=validate_image_name(name))

    def _request(self, action: str, **values: Any) -> dict[str, Any]:
        if self.socket_path is None:
            raise WorkspaceImageError("workspace image support is not configured")
        request = json.dumps({"action": action, **values}, separators=(",", ":")).encode() + b"\n"
        if len(request) > MAX_RPC_BYTES:
            raise WorkspaceImageError("workspace image request is too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(str(self.socket_path))
                client.sendall(request)
                response = bytearray()
                while b"\n" not in response:
                    chunk = client.recv(8192)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RPC_BYTES:
                        raise WorkspaceImageError("workspace image helper response is too large")
        except (OSError, TimeoutError) as exc:
            raise WorkspaceImageError(f"could not connect to workspace image helper: {exc}") from None
        try:
            payload = json.loads(bytes(response).split(b"\n", 1)[0])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkspaceImageError(f"workspace image helper returned invalid data: {exc}") from None
        if not isinstance(payload, dict):
            raise WorkspaceImageError("workspace image helper returned an invalid response")
        if not payload.get("ok"):
            raise WorkspaceImageError(str(payload.get("error") or "workspace image operation failed"))
        return payload


RunCommand = Callable[..., subprocess.CompletedProcess[str]]


class WorkspaceImageEngine:
    """Root-only, path-confined sparse image operations.

    All paths are derived from immutable service arguments and validated names;
    callers never supply a host path or arbitrary mount option.
    """

    def __init__(
        self,
        workspace_root: Path,
        image_dir: Path,
        service_uid: int,
        service_gid: int,
        *,
        runner: RunCommand = subprocess.run,
        require_root: bool = True,
    ) -> None:
        if require_root and os.geteuid() != 0:
            raise WorkspaceImageError("workspace image helper must run as root")
        self.workspace_root = self._safe_root(workspace_root, "Workspace Root")
        self.image_dir = self._safe_root(image_dir, "image directory")
        if self.workspace_root == self.image_dir or self.workspace_root in self.image_dir.parents or self.image_dir in self.workspace_root.parents:
            raise WorkspaceImageError("Workspace Root and image directory must not contain each other")
        self.service_uid = service_uid
        self.service_gid = service_gid
        self._runner = runner
        self._lock = threading.RLock()
        self._commands = {
            name: shutil.which(name) or f"/usr/sbin/{name}"
            for name in ("mkfs.ext4", "mount", "umount", "losetup", "resize2fs", "findmnt")
        }

    @staticmethod
    def _safe_root(path: Path, label: str) -> Path:
        if not path.is_absolute():
            raise WorkspaceImageError(f"{label} must be an absolute path")
        if path.is_symlink():
            raise WorkspaceImageError(f"{label} must not be a symbolic link")
        path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
        if resolved == Path("/"):
            raise WorkspaceImageError(f"{label} must not be the filesystem root")
        return resolved

    def mount_all(self) -> None:
        with self._lock:
            for image_path in sorted(self.image_dir.glob("*.img")):
                if image_path.is_symlink() or not image_path.is_file():
                    raise WorkspaceImageError(f"invalid image file: {image_path.name}")
                name = validate_image_name(image_path.stem)
                validate_image_size(image_path.stat().st_size)
                self._mount(name)

    def list(self) -> list[WorkspaceImage]:
        with self._lock:
            result = []
            for image_path in sorted(self.image_dir.glob("*.img")):
                if image_path.is_symlink() or not image_path.is_file():
                    continue
                try:
                    name = validate_image_name(image_path.stem)
                except WorkspaceImageError:
                    continue
                stat_result = image_path.stat()
                result.append(
                    WorkspaceImage(
                        name=name,
                        size_bytes=stat_result.st_size,
                        allocated_bytes=stat_result.st_blocks * 512,
                        mounted=self._mounted_loop(name) is not None,
                    )
                )
            return result

    def create(self, name: str, size_bytes: int) -> WorkspaceImage:
        name = validate_image_name(name)
        size_bytes = validate_image_size(size_bytes)
        image_path, mount_path = self._paths(name)
        with self._lock:
            if image_path.exists():
                raise WorkspaceImageError(f"image {name} already exists")
            if mount_path.exists():
                raise WorkspaceImageError(f"workspace directory {name} already exists and cannot be covered or hidden")
            fd = None
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(image_path, flags, 0o600)
                if os.geteuid() == 0:
                    os.fchown(fd, 0, 0)
                os.ftruncate(fd, size_bytes)
                os.fsync(fd)
                os.close(fd)
                fd = None
                self._run("mkfs.ext4", "-F", "-m", "0", str(image_path))
                mount_path.mkdir(mode=0o700)
                self._mount(name)
                os.chown(mount_path, self.service_uid, self.service_gid)
                os.chmod(mount_path, 0o700)
            except Exception:
                if fd is not None:
                    os.close(fd)
                if mount_path.exists():
                    self._run("umount", str(mount_path), check=False)
                try:
                    mount_path.rmdir()
                except OSError:
                    pass
                try:
                    image_path.unlink()
                except FileNotFoundError:
                    pass
                raise
            return self._get(name)

    def grow(self, name: str, size_bytes: int) -> WorkspaceImage:
        name = validate_image_name(name)
        size_bytes = validate_image_size(size_bytes)
        image_path, _ = self._paths(name)
        with self._lock:
            if not image_path.is_file() or image_path.is_symlink():
                raise WorkspaceImageError(f"image {name} does not exist")
            current = image_path.stat().st_size
            if size_bytes < current:
                raise WorkspaceImageError("images cannot be shrunk; the new size must not be smaller")
            loop = self._mounted_loop(name)
            if loop is None:
                self._mount(name)
                loop = self._mounted_loop(name)
            if loop is None:
                raise WorkspaceImageError("could not find the loop device for the image")
            if size_bytes > current:
                with image_path.open("r+b", buffering=0) as handle:
                    handle.truncate(size_bytes)
                    os.fsync(handle.fileno())
            self._run("losetup", "-c", loop)
            self._run("resize2fs", loop)
            return self._get(name)

    def delete(self, name: str) -> None:
        name = validate_image_name(name)
        image_path, mount_path = self._paths(name)
        with self._lock:
            if not image_path.is_file() or image_path.is_symlink():
                raise WorkspaceImageError(f"image {name} does not exist")
            if self._mounted_loop(name) is not None:
                self._run("umount", str(mount_path))
            image_path.unlink()
            try:
                mount_path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise WorkspaceImageError(f"image was deleted but its mount directory could not be removed: {exc}") from None

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if action == "list":
            return {"images": [asdict(item) for item in self.list()]}
        if action == "create":
            image = self.create(str(request.get("name", "")), int(request.get("size_bytes", 0)))
            return {"image": asdict(image)}
        if action == "grow":
            image = self.grow(str(request.get("name", "")), int(request.get("size_bytes", 0)))
            return {"image": asdict(image)}
        if action == "delete":
            self.delete(str(request.get("name", "")))
            return {}
        raise WorkspaceImageError("unknown workspace image operation")

    def _get(self, name: str) -> WorkspaceImage:
        return next(item for item in self.list() if item.name == name)

    def _paths(self, name: str) -> tuple[Path, Path]:
        safe_name = validate_image_name(name)
        return self.image_dir / f"{safe_name}.img", self.workspace_root / safe_name

    def _mount(self, name: str) -> None:
        image_path, mount_path = self._paths(name)
        if self._mounted_loop(name) is not None:
            return
        if mount_path.is_symlink():
            raise WorkspaceImageError(f"mount directory {name} must not be a symbolic link")
        if mount_path.exists():
            if not mount_path.is_dir():
                raise WorkspaceImageError(f"mount path {name} is not a directory")
            if any(mount_path.iterdir()):
                raise WorkspaceImageError(f"mount directory {name} is not empty; refusing to hide its contents")
        else:
            mount_path.mkdir(mode=0o700)
        self._run("mount", "-t", "ext4", "-o", "loop,nodev,nosuid,noatime", str(image_path), str(mount_path))
        if self._mounted_loop(name) is None:
            raise WorkspaceImageError(f"no loop device found after mounting image {name}")
        os.chown(mount_path, self.service_uid, self.service_gid)
        os.chmod(mount_path, 0o700)

    def _mounted_loop(self, name: str) -> str | None:
        image_path, mount_path = self._paths(name)
        if not mount_path.exists():
            return None
        found = self._run("findmnt", "-rn", "-o", "SOURCE,FSTYPE", "--mountpoint", str(mount_path), check=False)
        if found.returncode != 0 or not found.stdout.strip():
            return None
        pieces = found.stdout.strip().split()
        if len(pieces) < 2 or pieces[-1] != "ext4":
            raise WorkspaceImageError(f"{mount_path} is mounted but is not an ext4 image")
        loop = pieces[0].split("[", 1)[0]
        associated = self._run("losetup", "-j", str(image_path), "-n", "-O", "NAME", check=False)
        loops = {line.strip() for line in associated.stdout.splitlines() if line.strip()}
        if loop not in loops:
            raise WorkspaceImageError(f"{mount_path} is occupied by another device")
        return loop

    def _run(self, command: str, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(
                [self._commands[command], *arguments],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WorkspaceImageError(f"failed to run {command}: {exc}") from None
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise WorkspaceImageError(f"failed to run {command}: {detail}")
        return result


def peer_uid(connection: socket.socket) -> int | None:
    """Return Linux SO_PEERCRED uid; None on platforms without it."""
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", credentials)
    return uid

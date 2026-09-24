"""Privileged, path-confined rclone mount and workspace bind operations."""

from __future__ import annotations

import configparser
import io
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from openkapsel.workspace.workspace_images import WorkspaceImageError


_PROVIDER_ID_RE = re.compile(r"[A-Za-z0-9_-]{24}")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_KINDS = {
    "google_drive",
    "dropbox",
    "pcloud",
    "onedrive",
    "webdav",
    "s3",
    "sftp",
    "smb",
}
_MIN_RCLONE_VERSION = (1, 60, 0)
_RCLONE_VERSION_RE = re.compile(r"^rclone v(\d+)\.(\d+)\.(\d+)")
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


class HostStorageProviders:
    """Root helper implementation; callers provide IDs/settings, never host paths."""

    def __init__(
        self,
        workspace_root: Path,
        storage_root: Path,
        service_uid: int,
        service_gid: int,
        storage_uid: int,
        storage_gid: int,
        storage_home: Path,
        *,
        runner: RunCommand = subprocess.run,
    ) -> None:
        self.workspace_root = workspace_root.resolve(strict=True)
        self.storage_root = storage_root.resolve(strict=True)
        self.service_uid = int(service_uid)
        self.service_gid = int(service_gid)
        self.storage_uid = int(storage_uid)
        self.storage_gid = int(storage_gid)
        self.storage_home = storage_home.resolve(strict=True)
        self.run = runner
        self.rclone = shutil.which("rclone") or "/usr/bin/rclone"
        self.systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"
        self.systemd_run = shutil.which("systemd-run") or "/usr/bin/systemd-run"
        self.mount_command = shutil.which("mount") or "/usr/bin/mount"
        self.umount_command = shutil.which("umount") or "/usr/bin/umount"
        self.fusermount = shutil.which("fusermount3") or shutil.which("fusermount") or "/usr/bin/fusermount3"

    @staticmethod
    def _provider_id(value: Any) -> str:
        if not isinstance(value, str) or not _PROVIDER_ID_RE.fullmatch(value):
            raise WorkspaceImageError("invalid storage provider id")
        return value

    @staticmethod
    def _name(value: Any, label: str) -> str:
        if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
            raise WorkspaceImageError(f"invalid {label}")
        return value

    @staticmethod
    def _line(value: Any, label: str, *, maximum: int = 4096, allow_empty: bool = False) -> str:
        if not isinstance(value, str) or "\x00" in value or "\r" in value or "\n" in value or len(value) > maximum:
            raise WorkspaceImageError(f"{label} must be a single bounded line")
        if not allow_empty and not value:
            raise WorkspaceImageError(f"{label} must not be empty")
        return value

    @staticmethod
    def _port(value: Any, default: int) -> int:
        if value in (None, ""):
            return default
        try:
            port = int(value)
        except (TypeError, ValueError):
            raise WorkspaceImageError("port must be an integer") from None
        if not 1 <= port <= 65535:
            raise WorkspaceImageError("port must be between 1 and 65535")
        return port

    @staticmethod
    def _bool(value: Any, label: str, *, default: bool = False) -> bool:
        if value is None:
            return default
        if not isinstance(value, bool):
            raise WorkspaceImageError(f"{label} must be boolean")
        return value

    def _paths(self, provider_id: str) -> tuple[Path, Path, Path, Path]:
        provider_id = self._provider_id(provider_id)
        root = self.storage_root / provider_id
        return root, root / "mount", root / "cache", root / "rclone.conf"

    def _rc_runtime_name(self, provider_id: str) -> str:
        return f"openkapsel-storage-{self._provider_id(provider_id)}"

    def _rc_socket(self, provider_id: str) -> Path:
        return Path("/run") / self._rc_runtime_name(provider_id) / "rc.sock"

    def _unit(self, provider_id: str) -> str:
        return f"openkapsel-storage-{self._provider_id(provider_id)}.service"

    def _workspace_path(self, workspace: Any, name: Any) -> Path:
        workspace = self._name(workspace, "workspace")
        name = self._name(name, "storage mapping name")
        parent = self.workspace_root / workspace
        if parent.is_symlink() or not parent.is_dir() or parent.resolve().parent != self.workspace_root:
            raise WorkspaceImageError("storage mapping workspace must be an existing direct child")
        return parent / name

    def _ensure_provider_dirs(self, provider_id: str) -> tuple[Path, Path, Path, Path]:
        root, mount, cache, config = self._paths(provider_id)
        if root.is_symlink():
            raise WorkspaceImageError("storage provider root must not be a symbolic link")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.resolve(strict=True).parent != self.storage_root:
            raise WorkspaceImageError("storage provider root escaped the private storage directory")
        os.chown(root, self.storage_uid, self.storage_gid)
        os.chmod(root, 0o700)
        for path in (mount, cache):
            if path.is_symlink():
                raise WorkspaceImageError("storage provider directories must not be symbolic links")
            path.mkdir(mode=0o700, exist_ok=True)
            os.chown(path, self.storage_uid, self.storage_gid)
            os.chmod(path, 0o700)
        return root, mount, cache, config

    def _obscure(self, value: str) -> str:
        result = self.run(
            [self.rclone, "obscure", "-"],
            input=value + "\n", text=True, capture_output=True, timeout=10, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise WorkspaceImageError("rclone could not obscure the supplied password")
        return result.stdout.strip()

    @staticmethod
    def _oauth_token(value: Any, label: str) -> str:
        if not isinstance(value, str) or len(value) > 65536:
            raise WorkspaceImageError(f"{label} must be an rclone OAuth token JSON object")
        try:
            token = json.loads(value)
        except json.JSONDecodeError:
            raise WorkspaceImageError(f"{label} must be valid JSON") from None
        if not isinstance(token, dict) or not isinstance(token.get("access_token"), str):
            raise WorkspaceImageError(f"{label} must contain access_token")
        return json.dumps(token, ensure_ascii=False, separators=(",", ":"))

    def _write_private(self, path: Path, data: str, mode: int = 0o600) -> None:
        temporary = path.with_name("." + path.name + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, mode)
        try:
            os.fchown(fd, self.storage_uid, self.storage_gid)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def configure(self, provider_id: str, kind: Any, settings: Any) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        if kind not in _KINDS:
            raise WorkspaceImageError("unsupported storage provider kind")
        if not isinstance(settings, dict):
            raise WorkspaceImageError("storage provider settings must be an object")
        root, _mount, _cache, config_path = self._ensure_provider_dirs(provider_id)
        section: dict[str, str] = {}
        if kind == "google_drive":
            section["type"] = "drive"
            section["client_id"] = self._line(settings.get("client_id"), "Google client id", maximum=4096)
            section["client_secret"] = self._line(settings.get("client_secret"), "Google client secret", maximum=4096)
            section["scope"] = "drive"
            section["token"] = self._oauth_token(settings.get("token"), "Google token")
        elif kind == "dropbox":
            section["type"] = "dropbox"
            client_id = self._line(settings.get("client_id", ""), "Dropbox client id", maximum=4096, allow_empty=True)
            client_secret = self._line(settings.get("client_secret", ""), "Dropbox client secret", maximum=4096, allow_empty=True)
            if bool(client_id) != bool(client_secret):
                raise WorkspaceImageError("Dropbox client id and client secret must be supplied together")
            if client_id:
                section["client_id"] = client_id
                section["client_secret"] = client_secret
            section["token"] = self._oauth_token(settings.get("token"), "Dropbox token")
        elif kind == "pcloud":
            section["type"] = "pcloud"
            client_id = self._line(
                settings.get("client_id", ""),
                "pCloud client id",
                maximum=4096,
                allow_empty=True,
            )
            client_secret = self._line(
                settings.get("client_secret", ""),
                "pCloud client secret",
                maximum=4096,
                allow_empty=True,
            )
            if bool(client_id) != bool(client_secret):
                raise WorkspaceImageError(
                    "pCloud client id and client secret must be supplied together"
                )
            if client_id:
                section["client_id"] = client_id
                section["client_secret"] = client_secret
            hostname = self._line(
                settings.get("hostname", "api.pcloud.com"),
                "pCloud API hostname",
                maximum=256,
            )
            if hostname not in {"api.pcloud.com", "eapi.pcloud.com"}:
                raise WorkspaceImageError("pCloud API hostname must be api.pcloud.com or eapi.pcloud.com")
            section["hostname"] = hostname
            section["token"] = self._oauth_token(settings.get("token"), "pCloud token")
        elif kind == "onedrive":
            section["type"] = "onedrive"
            client_id = self._line(
                settings.get("client_id", ""),
                "OneDrive client id",
                maximum=4096,
                allow_empty=True,
            )
            client_secret = self._line(
                settings.get("client_secret", ""),
                "OneDrive client secret",
                maximum=4096,
                allow_empty=True,
            )
            if bool(client_id) != bool(client_secret):
                raise WorkspaceImageError(
                    "OneDrive client id and client secret must be supplied together"
                )
            if client_id:
                section["client_id"] = client_id
                section["client_secret"] = client_secret
            region = self._line(
                settings.get("region", "global"),
                "OneDrive cloud region",
                maximum=16,
            )
            if region not in {"global", "us", "de", "cn"}:
                raise WorkspaceImageError("unsupported OneDrive cloud region")
            drive_type = self._line(
                settings.get("drive_type"), "OneDrive drive type", maximum=64
            )
            if drive_type not in {"personal", "business", "documentLibrary"}:
                raise WorkspaceImageError("unsupported OneDrive drive type")
            section["region"] = region
            section["access_scopes"] = "Files.ReadWrite offline_access"
            section["drive_id"] = self._line(
                settings.get("drive_id"), "OneDrive drive id", maximum=4096
            )
            section["drive_type"] = drive_type
            section["token"] = self._oauth_token(settings.get("token"), "OneDrive token")
        elif kind == "webdav":
            section["type"] = "webdav"
            section["url"] = self._line(
                settings.get("url"), "WebDAV URL", maximum=4096
            )
            vendor = self._line(
                settings.get("vendor", "other"),
                "WebDAV vendor",
                maximum=64,
            )
            if vendor not in {
                "other",
                "nextcloud",
                "owncloud",
                "infinitescale",
                "fastmail",
                "rclone",
                "sharepoint",
                "sharepoint-ntlm",
            }:
                raise WorkspaceImageError("unsupported WebDAV vendor")
            section["vendor"] = vendor
            user = self._line(
                settings.get("user", ""),
                "WebDAV user",
                maximum=1024,
                allow_empty=True,
            )
            password = settings.get("password", "")
            if not isinstance(password, str) or len(password) > 65536:
                raise WorkspaceImageError("invalid WebDAV password")
            if bool(user) != bool(password):
                raise WorkspaceImageError("WebDAV user and password must be supplied together")
            if user:
                section["user"] = user
                section["pass"] = self._obscure(password)
        elif kind == "s3":
            section["type"] = "s3"
            section["provider"] = "Other"
            section["env_auth"] = "false"
            access_key = self._line(
                settings.get("access_key_id"),
                "S3 access key id",
                maximum=4096,
            )
            secret_key = self._line(
                settings.get("secret_access_key"),
                "S3 secret access key",
                maximum=65536,
            )
            section["access_key_id"] = access_key
            section["secret_access_key"] = secret_key
            region = self._line(
                settings.get("region", ""),
                "S3 region",
                maximum=256,
                allow_empty=True,
            )
            if region:
                section["region"] = region
            section["endpoint"] = self._line(
                settings.get("endpoint"),
                "S3 endpoint",
                maximum=4096,
            )
            section["force_path_style"] = (
                "true"
                if self._bool(
                    settings.get("force_path_style"),
                    "S3 force path style",
                    default=True,
                )
                else "false"
            )
            if self._bool(settings.get("v2_auth"), "S3 v2 auth", default=False):
                section["v2_auth"] = "true"
        elif kind == "sftp":
            section["type"] = "sftp"
            section["host"] = self._line(settings.get("host"), "SFTP host", maximum=1024)
            section["user"] = self._line(settings.get("user"), "SFTP user", maximum=256)
            section["port"] = str(self._port(settings.get("port"), 22))
            password = settings.get("password", "")
            key_pem = settings.get("private_key", "")
            if not isinstance(password, str) or not isinstance(key_pem, str) or len(password) > 65536 or len(key_pem) > 262144:
                raise WorkspaceImageError("invalid SFTP credential")
            if bool(password) == bool(key_pem):
                raise WorkspaceImageError("SFTP requires exactly one of password or private key")
            if password:
                section["pass"] = self._obscure(password)
            else:
                key_path = root / "id.pem"
                if "\x00" in key_pem or not key_pem.strip().startswith("-----BEGIN"):
                    raise WorkspaceImageError("SFTP private key must be PEM encoded")
                self._write_private(key_path, key_pem.rstrip() + "\n")
                section["key_file"] = str(key_path)
            known_hosts = settings.get("known_hosts")
            if not isinstance(known_hosts, str) or "\x00" in known_hosts or not known_hosts.strip() or len(known_hosts) > 65536:
                raise WorkspaceImageError("SFTP known_hosts entry is required")
            known_hosts_path = root / "known_hosts"
            self._write_private(known_hosts_path, known_hosts.rstrip() + "\n")
            section["known_hosts_file"] = str(known_hosts_path)
        else:
            section["type"] = "smb"
            section["host"] = self._line(settings.get("host"), "SMB host", maximum=1024)
            section["user"] = self._line(settings.get("user"), "SMB user", maximum=256)
            section["port"] = str(self._port(settings.get("port"), 445))
            domain = self._line(settings.get("domain", "WORKGROUP"), "SMB domain", maximum=256, allow_empty=True)
            if domain:
                section["domain"] = domain
            password = settings.get("password", "")
            if not isinstance(password, str) or len(password) > 65536:
                raise WorkspaceImageError("invalid SMB password")
            if password:
                section["pass"] = self._obscure(password)

        parser = configparser.RawConfigParser(interpolation=None)
        parser.optionxform = str
        parser["provider"] = section
        output = io.StringIO()
        parser.write(output)
        self._write_private(config_path, output.getvalue())
        return {"configured": True}

    @staticmethod
    def _rc_backend_error(result: subprocess.CompletedProcess[str]) -> str:
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if stdout:
            try:
                payload = json.loads(stdout)
            except (TypeError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, str) and error.strip():
                    return error.strip()[:1200]
                refreshed = payload.get("result")
                if isinstance(refreshed, dict):
                    for value in refreshed.values():
                        if isinstance(value, str) and value != "OK":
                            return value.strip()[:1200]
        if result.returncode != 0:
            detail = (stderr or stdout).strip()
            if detail:
                return detail[-1200:]
            return "rclone backend probe failed"
        return ""

    def _validate_mounted_backend(self, provider_id: str) -> None:
        socket_path = self._rc_socket(provider_id)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if socket_path.is_socket() and not socket_path.is_symlink():
                break
            time.sleep(0.05)
        else:
            raise WorkspaceImageError("rclone storage status socket did not become ready")

        result = self.run(
            [
                self.rclone,
                "rc",
                "--unix-socket",
                str(socket_path),
                "vfs/refresh",
                "recursive=false",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        error = self._rc_backend_error(result)
        if error:
            raise WorkspaceImageError(
                "storage provider backend validation failed: " + error
            )

    def mount(self, provider_id: str, remote_path: Any, writable: Any, cache_max_bytes: Any) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        remote_path = self._line(remote_path, "remote path", maximum=2048, allow_empty=True)
        if isinstance(cache_max_bytes, bool):
            raise WorkspaceImageError("invalid VFS cache size")
        try:
            cache_max_bytes = int(cache_max_bytes)
        except (TypeError, ValueError):
            raise WorkspaceImageError("invalid VFS cache size") from None
        if not 256 * 1024 * 1024 <= cache_max_bytes <= 1024 * 1024 * 1024 * 1024:
            raise WorkspaceImageError("VFS cache size is outside the supported range")
        root, mount, cache, config = self._paths(provider_id)
        unit = self._unit(provider_id)
        if os.path.ismount(mount):
            state = self.run(
                [self.systemctl, "is-active", unit],
                check=False, capture_output=True, text=True, timeout=5,
            )
            if state.returncode == 0 and state.stdout.strip() == "active":
                try:
                    self._validate_mounted_backend(provider_id)
                except WorkspaceImageError:
                    try:
                        self.unmount(provider_id)
                    except WorkspaceImageError:
                        pass
                    raise
                return {"mounted": True}
            self.unmount(provider_id)
        root, mount, cache, config = self._ensure_provider_dirs(provider_id)
        if not config.is_file() or config.is_symlink():
            raise WorkspaceImageError("storage provider credentials are not configured")
        if next(mount.iterdir(), None) is not None:
            raise WorkspaceImageError("storage provider mountpoint must be empty")
        self.run([self.systemctl, "stop", unit], check=False, capture_output=True, text=True, timeout=20)
        rc_socket = self._rc_socket(provider_id)
        if rc_socket.exists() or rc_socket.is_symlink():
            rc_socket.unlink()
        remote = "provider:" + remote_path
        argv = [
            self.systemd_run, "--quiet", "--collect", f"--unit={unit[:-8]}",
            "--uid", str(self.storage_uid), "--gid", str(self.storage_gid),
            "--property=PrivateMounts=no", "--property=Restart=on-failure", "--property=RestartSec=5s",
            f"--property=RuntimeDirectory={self._rc_runtime_name(provider_id)}",
            "--property=RuntimeDirectoryMode=0700",
            "--property=KillMode=mixed", f"--setenv=HOME={self.storage_home}",
            self.rclone, "mount", remote, str(mount), "--config", str(config), "--cache-dir", str(cache),
            "--rc", "--rc-no-auth", "--rc-addr", f"unix://{rc_socket}",
            "--vfs-cache-mode=writes", "--vfs-cache-max-size", f"{cache_max_bytes}B",
            "--vfs-cache-max-age=24h", "--dir-cache-time=5m", "--poll-interval=1m", "--buffer-size=16M",
            "--allow-other", "--default-permissions", "--umask=0077",
            "--uid", str(self.service_uid), "--gid", str(self.service_gid),
        ]
        if not bool(writable):
            argv.append("--read-only")
        result = self.run(argv, check=False, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            raise WorkspaceImageError("could not start rclone storage mount: " + (result.stderr or result.stdout)[-500:])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if os.path.ismount(mount):
                try:
                    self._validate_mounted_backend(provider_id)
                except WorkspaceImageError:
                    try:
                        self.unmount(provider_id)
                    except WorkspaceImageError:
                        pass
                    raise
                return {"mounted": True}
            state = self.run([self.systemctl, "is-active", unit], check=False, capture_output=True, text=True, timeout=5)
            if state.returncode not in (0, 3) and state.stdout.strip() not in {"activating", "active"}:
                break
            time.sleep(0.1)
        status = self.run([self.systemctl, "status", unit, "--no-pager", "-l"], check=False, capture_output=True, text=True, timeout=10)
        raise WorkspaceImageError("rclone storage mount did not become ready: " + (status.stdout or status.stderr)[-4000:])

    def unmount(self, provider_id: str) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        _root, mount, _cache, _config = self._paths(provider_id)
        unit = self._unit(provider_id)
        self.run([self.systemctl, "stop", unit], check=False, capture_output=True, text=True, timeout=30)
        if os.path.ismount(mount):
            self.run(
                [
                    self.systemd_run, "--quiet", "--wait", "--collect",
                    "--uid", str(self.storage_uid), "--gid", str(self.storage_gid),
                    "--property=PrivateMounts=no",
                    self.fusermount, "-uz", str(mount),
                ],
                check=False, capture_output=True, text=True, timeout=20,
            )
        if os.path.ismount(mount):
            raise WorkspaceImageError("storage provider mount remains attached")
        rc_socket = self._rc_socket(provider_id)
        if rc_socket.exists() or rc_socket.is_symlink():
            rc_socket.unlink()
        return {"mounted": False}

    def _rc_stats(self, provider_id: str) -> dict[str, Any]:
        socket_path = self._rc_socket(provider_id)
        if socket_path.is_symlink() or not socket_path.is_socket():
            raise WorkspaceImageError("rclone status socket is unavailable")
        result = self.run(
            [self.rclone, "rc", "--unix-socket", str(socket_path), "vfs/stats"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise WorkspaceImageError("rclone VFS status query failed")
        try:
            payload = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            raise WorkspaceImageError("rclone returned invalid VFS status") from None
        if not isinstance(payload, dict):
            raise WorkspaceImageError("rclone returned invalid VFS status")
        return payload

    @staticmethod
    def _cache_has_files(cache: Path) -> bool:
        if not cache.is_dir():
            return False
        for _root, _dirs, files in os.walk(cache):
            if files:
                return True
        return False

    def pending(self, provider_id: str) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        root, mount, cache, _config = self._paths(provider_id)
        if os.path.ismount(mount):
            try:
                stats = self._rc_stats(provider_id)
            except WorkspaceImageError as exc:
                return {
                    "pending": False,
                    "uncertain": True,
                    "uploads_queued": 0,
                    "uploads_in_progress": 0,
                    "cache_bytes": 0,
                    "reason": str(exc),
                }
            disk = stats.get("diskCache")
            if not isinstance(disk, dict):
                return {
                    "pending": False,
                    "uncertain": True,
                    "uploads_queued": 0,
                    "uploads_in_progress": 0,
                    "cache_bytes": 0,
                    "reason": "rclone did not report VFS disk cache state",
                }
            values = {}
            for key in ("uploadsQueued", "uploadsInProgress", "bytesUsed"):
                value = disk.get(key, 0)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    return {
                        "pending": False,
                        "uncertain": True,
                        "uploads_queued": 0,
                        "uploads_in_progress": 0,
                        "cache_bytes": 0,
                        "reason": "rclone returned invalid VFS disk cache counters",
                    }
                values[key] = value
            queued = values["uploadsQueued"]
            in_progress = values["uploadsInProgress"]
            return {
                "pending": bool(queued or in_progress),
                "uncertain": False,
                "uploads_queued": queued,
                "uploads_in_progress": in_progress,
                "cache_bytes": values["bytesUsed"],
                "reason": "",
            }
        if not root.exists() or not self._cache_has_files(cache):
            return {
                "pending": False,
                "uncertain": False,
                "uploads_queued": 0,
                "uploads_in_progress": 0,
                "cache_bytes": 0,
                "reason": "",
            }
        return {
            "pending": False,
            "uncertain": True,
            "uploads_queued": 0,
            "uploads_in_progress": 0,
            "cache_bytes": 0,
            "reason": "provider is offline while its local VFS cache still contains files",
        }

    @staticmethod
    def _same_mount(source: Path, target: Path) -> bool:
        try:
            return (
                os.path.ismount(source)
                and os.path.ismount(target)
                and os.stat(source).st_dev == os.stat(target).st_dev
            )
        except OSError:
            return False

    def bind(self, provider_id: str, workspace: Any, name: Any, writable: Any) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        _root, source, _cache, _config = self._paths(provider_id)
        if not os.path.ismount(source):
            raise WorkspaceImageError("storage provider is not mounted")
        target = self._workspace_path(workspace, name)
        if target.is_symlink():
            raise WorkspaceImageError("storage mapping path must not be a symbolic link")
        if os.path.ismount(target):
            if self._same_mount(source, target):
                return {"mapped": True}
            result = self.run(
                [self.umount_command, str(target)],
                check=False, capture_output=True, text=True, timeout=20,
            )
            if os.path.ismount(target):
                detail = result.stderr[-500:] if result.returncode != 0 else "mount remains attached"
                raise WorkspaceImageError("could not replace stale storage mapping: " + detail)
        target.mkdir(mode=0o700, exist_ok=True)
        os.chown(target, self.service_uid, self.service_gid)
        os.chmod(target, 0o700)
        if next(target.iterdir(), None) is not None:
            raise WorkspaceImageError("storage mapping path must be empty")
        result = self.run([self.mount_command, "--bind", str(source), str(target)], check=False, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise WorkspaceImageError("could not bind storage provider into workspace: " + result.stderr[-500:])
        if not bool(writable):
            result = self.run([self.mount_command, "-o", "remount,bind,ro", str(target)], check=False, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                self.run([self.umount_command, str(target)], check=False, capture_output=True, text=True, timeout=10)
                raise WorkspaceImageError("could not make storage mapping read-only: " + result.stderr[-500:])
        return {"mapped": True}

    def unbind(self, workspace: Any, name: Any, force: Any = False) -> dict[str, Any]:
        if not isinstance(force, bool):
            raise WorkspaceImageError("force must be a boolean")
        target = self._workspace_path(workspace, name)
        if os.path.ismount(target):
            command = [self.umount_command]
            if force:
                command.append("-l")
            command.append(str(target))
            result = self.run(command, check=False, capture_output=True, text=True, timeout=20)
            if result.returncode != 0 and os.path.ismount(target):
                raise WorkspaceImageError("could not unmount storage mapping: " + result.stderr[-500:])
        try:
            target.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            if not os.path.ismount(target):
                raise WorkspaceImageError("storage mapping directory is not empty") from None
        return {"mapped": False}

    def status(self, provider_id: str, mappings: Any = None) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        _root, mount, _cache, config = self._paths(provider_id)
        state = self.run([self.systemctl, "is-active", self._unit(provider_id)], check=False, capture_output=True, text=True, timeout=5)
        result: dict[str, Any] = {
            "configured": config.is_file() and not config.is_symlink(),
            "mounted": os.path.ismount(mount),
            "unit_active": state.stdout.strip() == "active",
        }
        mapped = {}
        if mappings is not None:
            if not isinstance(mappings, list) or len(mappings) > 256:
                raise WorkspaceImageError("invalid storage mapping status request")
            for item in mappings:
                if not isinstance(item, dict):
                    raise WorkspaceImageError("invalid storage mapping status request")
                mapping_id = self._provider_id(item.get("id"))
                target = self._workspace_path(item.get("workspace"), item.get("name"))
                mapped[mapping_id] = self._same_mount(mount, target)
        result["mappings"] = mapped
        return result

    def delete(self, provider_id: str) -> dict[str, Any]:
        provider_id = self._provider_id(provider_id)
        root, mount, _cache, _config = self._paths(provider_id)
        self.unmount(provider_id)
        if mount.exists() and os.path.ismount(mount):
            raise WorkspaceImageError("storage provider is still mounted")
        if root.exists():
            shutil.rmtree(root)
        return {"deleted": True}

    def probe(self) -> dict[str, Any]:
        rclone_present = Path(self.rclone).is_file()
        fusermount_present = Path(self.fusermount).is_file()
        version = None
        version_supported = False
        if rclone_present:
            result = self.run(
                [self.rclone, "version"],
                check=False, capture_output=True, text=True, timeout=10,
            )
            first_line = (result.stdout or "").splitlines()[0] if result.returncode == 0 and result.stdout else ""
            match = _RCLONE_VERSION_RE.match(first_line)
            if match:
                parsed = tuple(int(part) for part in match.groups())
                version = ".".join(str(part) for part in parsed)
                version_supported = parsed >= _MIN_RCLONE_VERSION
        available = rclone_present and fusermount_present and version_supported
        reason = ""
        if not rclone_present:
            reason = "rclone is not installed"
        elif not version_supported:
            reason = "rclone 1.60.0 or newer is required for SMB support"
        elif not fusermount_present:
            reason = "fusermount3 or fusermount is not installed"
        return {
            "available": available,
            "rclone": rclone_present,
            "rclone_version": version,
            "rclone_version_supported": version_supported,
            "minimum_rclone_version": "1.60.0",
            "fusermount": fusermount_present,
            "reason": reason,
        }

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if action == "storage_probe":
            return self.probe()
        provider_id = request.get("id")
        if action == "storage_configure":
            return self.configure(provider_id, request.get("kind"), request.get("settings"))
        if action == "storage_mount":
            return self.mount(provider_id, request.get("remote_path", ""), request.get("writable", False), request.get("cache_max_bytes"))
        if action == "storage_unmount":
            return self.unmount(provider_id)
        if action == "storage_bind":
            return self.bind(provider_id, request.get("workspace"), request.get("name"), request.get("writable", False))
        if action == "storage_unbind":
            return self.unbind(request.get("workspace"), request.get("name"), request.get("force", False))
        if action == "storage_status":
            return self.status(provider_id, request.get("mappings"))
        if action == "storage_pending":
            return self.pending(provider_id)
        if action == "storage_delete":
            return self.delete(provider_id)
        raise WorkspaceImageError("invalid storage provider action")

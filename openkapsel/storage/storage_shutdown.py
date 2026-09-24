"""Safely stop OpenKapsel storage mounts before an in-place upgrade.

This module intentionally uses only the Python standard library.  The installer
runs it from the *new source tree* before replacing /opt/openkapsel, so it must
not depend on the currently installed virtual environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


_PROVIDER_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_MAPPING_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_UNIT_RE = re.compile(r"openkapsel-storage-([A-Za-z0-9_-]{1,64})\.service")


class SafeShutdownError(RuntimeError):
    pass


@dataclass(frozen=True)
class Provider:
    id: str
    writable: bool


@dataclass(frozen=True)
class Mapping:
    provider_id: str
    workspace: str
    name: str


class SafeUpgradeShutdown:
    def __init__(
        self,
        *,
        db_path: Path = Path("/var/lib/openkapsel/storage-providers.sqlite3"),
        workspace_root: Path = Path("/var/lib/openkapsel/workspace"),
        storage_root: Path = Path("/var/lib/openkapsel-storage/providers"),
        main_service: str = "openkapsel.service",
        helper_service: str = "openkapsel-images.service",
        timeout_seconds: float = 300.0,
        poll_seconds: float = 1.0,
        force_recovery: bool = False,
        command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        output: Callable[[str], None] = print,
    ) -> None:
        self.db_path = db_path
        self.workspace_root = workspace_root
        self.storage_root = storage_root
        self.main_service = main_service
        self.helper_service = helper_service
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self.force_recovery = force_recovery
        self.command = command
        self.sleep = sleep
        self.monotonic = monotonic
        self.output = output

    def _run(self, argv: list[str], *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
        try:
            return self.command(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SafeShutdownError(f"could not run {argv[0]}: {exc}") from exc

    def _active(self, unit: str) -> bool:
        result = self._run(["systemctl", "is-active", "--quiet", unit], timeout=10)
        return result.returncode == 0

    def _stop_service(self, unit: str) -> None:
        result = self._run(["systemctl", "stop", unit], timeout=60)
        if result.returncode != 0 and self._active(unit):
            detail = (result.stderr or result.stdout).strip()
            raise SafeShutdownError(f"could not stop {unit}: {detail[-500:]}")
        if self._active(unit):
            raise SafeShutdownError(f"{unit} remains active after stop")

    @staticmethod
    def _provider_id(value: object) -> str:
        if not isinstance(value, str) or not _PROVIDER_ID_RE.fullmatch(value):
            raise SafeShutdownError("storage provider database contains an unsafe provider id")
        return value

    @staticmethod
    def _mapping_name(value: object, label: str) -> str:
        if not isinstance(value, str) or not _MAPPING_NAME_RE.fullmatch(value):
            raise SafeShutdownError(f"storage provider database contains an unsafe {label}")
        return value

    def _load_metadata(self) -> tuple[list[Provider], list[Mapping]]:
        if not self.db_path.exists():
            return [], []
        try:
            db = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error as exc:
            raise SafeShutdownError(f"could not open Storage Provider database: {exc}") from exc
        try:
            tables = {
                row[0]
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "storage_providers" not in tables:
                return [], []
            providers = [
                Provider(self._provider_id(row[0]), bool(row[1]))
                for row in db.execute(
                    "SELECT id,writable FROM storage_providers ORDER BY id"
                )
            ]
            mappings: list[Mapping] = []
            if "storage_provider_mappings" in tables:
                for provider_id, workspace, name in db.execute(
                    "SELECT provider_id,workspace,name "
                    "FROM storage_provider_mappings ORDER BY workspace,name"
                ):
                    mappings.append(
                        Mapping(
                            self._provider_id(provider_id),
                            self._mapping_name(workspace, "workspace name"),
                            self._mapping_name(name, "mapping name"),
                        )
                    )
            return providers, mappings
        except sqlite3.Error as exc:
            raise SafeShutdownError(f"could not read Storage Provider database: {exc}") from exc
        finally:
            db.close()

    def _listed_storage_units(self) -> dict[str, str]:
        result = self._run(
            [
                "systemctl",
                "list-units",
                "openkapsel-storage-*.service",
                "--all",
                "--no-legend",
                "--plain",
            ],
            timeout=15,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise SafeShutdownError(f"could not enumerate Storage Provider units: {detail[-500:]}")
        units: dict[str, str] = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            match = _UNIT_RE.fullmatch(fields[0])
            if match:
                units[match.group(1)] = fields[0]
        return units

    def _exact_mount(self, path: Path) -> bool:
        result = self._run(
            ["findmnt", "-rn", "-M", str(path), "-o", "TARGET"],
            timeout=10,
        )
        if result.returncode != 0:
            return False
        wanted = os.path.normpath(str(path))
        return any(os.path.normpath(line.strip()) == wanted for line in result.stdout.splitlines())

    @staticmethod
    def _cache_has_files(cache: Path) -> bool:
        if not cache.is_dir():
            return False
        for _root, _dirs, files in os.walk(cache):
            if files:
                return True
        return False

    def _rc_socket(self, provider_id: str) -> Path | None:
        candidates = (
            Path("/run") / f"openkapsel-storage-{provider_id}" / "rc.sock",
            self.storage_root / provider_id / "rc.sock",
        )
        for path in candidates:
            try:
                if stat.S_ISSOCK(path.stat().st_mode):
                    return path
            except FileNotFoundError:
                continue
            except OSError:
                continue
        return None

    def _rc_stats(self, provider_id: str) -> dict:
        socket_path = self._rc_socket(provider_id)
        if socket_path is None:
            raise SafeShutdownError("rclone RC socket is unavailable")
        result = self._run(
            ["rclone", "rc", "--unix-socket", str(socket_path), "vfs/stats"],
            timeout=15,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise SafeShutdownError(
                "rclone VFS status query failed" + (f": {detail[-300:]}" if detail else "")
            )
        try:
            payload = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise SafeShutdownError("rclone returned invalid VFS status") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("diskCache"), dict):
            raise SafeShutdownError("rclone did not report VFS disk cache state")
        return payload

    def _writable_state(self, provider: Provider) -> tuple[bool, bool, str]:
        """Return (safe, hard_failure, detail) for one writable provider."""
        mount = self.storage_root / provider.id / "mount"
        unit = f"openkapsel-storage-{provider.id}.service"
        online = self._active(unit) or self._exact_mount(mount)
        if not online:
            cache = self.storage_root / provider.id / "cache"
            if self._cache_has_files(cache):
                return (
                    False,
                    False,
                    "provider is offline while its VFS cache still contains files",
                )
            return True, False, "offline with empty cache"

        try:
            stats = self._rc_stats(provider.id)
        except SafeShutdownError as exc:
            return False, False, str(exc)
        disk = stats["diskCache"]
        values: dict[str, int] = {}
        for key in ("uploadsQueued", "uploadsInProgress", "erroredFiles"):
            value = disk.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return False, True, f"rclone returned invalid {key}"
            values[key] = value
        if values["erroredFiles"]:
            return (
                False,
                True,
                f"{values['erroredFiles']} cached file(s) are in an error state",
            )
        queued = values["uploadsQueued"]
        active = values["uploadsInProgress"]
        if queued or active:
            return False, False, f"{queued} queued, {active} uploading"
        return True, False, "write queue empty"

    def _wait_for_writes(self, providers: Iterable[Provider]) -> None:
        writable = [provider for provider in providers if provider.writable]
        if not writable:
            return
        if self.force_recovery:
            self.output(
                "warning: --force-recovery skips VFS write-drain safety checks"
            )
            return
        deadline = self.monotonic() + self.timeout_seconds
        last_message = ""
        while True:
            unsafe: list[str] = []
            for provider in writable:
                safe, hard_failure, detail = self._writable_state(provider)
                if hard_failure:
                    raise SafeShutdownError(
                        f"provider {provider.id} cannot be safely stopped: {detail}"
                    )
                if not safe:
                    unsafe.append(f"{provider.id}: {detail}")
            if not unsafe:
                self.output("Storage Provider write queues are drained.")
                return
            message = "; ".join(unsafe)
            if message != last_message:
                self.output("Waiting for Storage Provider writes: " + message)
                last_message = message
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise SafeShutdownError(
                    "timed out waiting for Storage Provider writes; "
                    "upgrade aborted without stopping provider mounts"
                )
            self.sleep(min(self.poll_seconds, remaining))

    def _mapping_path(self, mapping: Mapping) -> Path:
        target = self.workspace_root / mapping.workspace / mapping.name
        expected_parent = self.workspace_root / mapping.workspace
        if target.parent != expected_parent:
            raise SafeShutdownError("storage mapping path escaped the workspace root")
        return target

    def _unmount_mapping(self, mapping: Mapping) -> None:
        target = self._mapping_path(mapping)
        if not self._exact_mount(target):
            return
        result = self._run(["umount", str(target)], timeout=30)
        if result.returncode == 0 and not self._exact_mount(target):
            return
        if self.force_recovery:
            result = self._run(["umount", "-l", str(target)], timeout=30)
            if result.returncode == 0 and not self._exact_mount(target):
                return
        detail = (result.stderr or result.stdout).strip()
        raise SafeShutdownError(
            f"could not unmount storage mapping {mapping.workspace}/{mapping.name}: "
            f"{detail[-500:]}"
        )

    def _fuse_unmount(self, provider_id: str) -> None:
        mount = self.storage_root / provider_id / "mount"
        if not self._exact_mount(mount):
            return
        fusermount = shutil.which("fusermount3") or shutil.which("fusermount")
        if not fusermount:
            raise SafeShutdownError(
                f"provider {provider_id} remains mounted and fusermount is unavailable"
            )
        argv = [fusermount, "-u", str(mount)]
        result = self._run(argv, timeout=30)
        if result.returncode == 0 and not self._exact_mount(mount):
            return
        if self.force_recovery:
            result = self._run([fusermount, "-uz", str(mount)], timeout=30)
            if result.returncode == 0 and not self._exact_mount(mount):
                return
        detail = (result.stderr or result.stdout).strip()
        raise SafeShutdownError(
            f"provider {provider_id} FUSE mount remains attached: {detail[-500:]}"
        )

    def shutdown(self) -> None:
        self.output(f"Stopping {self.main_service} to block new storage activity...")
        self._stop_service(self.main_service)

        providers, mappings = self._load_metadata()
        units = self._listed_storage_units()
        known_ids = {provider.id for provider in providers}
        unknown_active = [
            provider_id
            for provider_id, unit in units.items()
            if provider_id not in known_ids and (
                self._active(unit)
                or self._exact_mount(self.storage_root / provider_id / "mount")
            )
        ]
        if unknown_active and not self.force_recovery:
            raise SafeShutdownError(
                "active OpenKapsel storage unit(s) are missing from the provider database: "
                + ", ".join(sorted(unknown_active))
                + "; rerun with --force-recovery only after verifying no writes are pending"
            )

        self._wait_for_writes(providers)

        for mapping in mappings:
            self._unmount_mapping(mapping)

        unit_ids = known_ids | set(units)
        for provider_id in sorted(unit_ids):
            unit = f"openkapsel-storage-{provider_id}.service"
            if self._active(unit):
                self.output(f"Stopping {unit}...")
            self._stop_service(unit)
            self._fuse_unmount(provider_id)

        self.output(f"Stopping {self.helper_service}...")
        self._stop_service(self.helper_service)
        self.output("OpenKapsel storage mounts are safely stopped for upgrade.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely stop OpenKapsel storage mounts before an upgrade."
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=300.0,
        help="maximum time to wait for writable VFS queues to drain (default: 300)",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=1.0,
        help="write-queue polling interval (default: 1)",
    )
    parser.add_argument(
        "--force-recovery",
        action="store_true",
        help="skip pending-write checks and permit lazy unmounts; recovery use only",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("/var/lib/openkapsel/storage-providers.sqlite3"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path("/var/lib/openkapsel/workspace"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--storage-root",
        type=Path,
        default=Path("/var/lib/openkapsel-storage/providers"),
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.timeout_seconds < 0 or args.poll_seconds <= 0:
        print("safe shutdown: timeout must be >= 0 and poll interval must be > 0", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("safe shutdown: run as root", file=sys.stderr)
        return 2
    shutdown = SafeUpgradeShutdown(
        db_path=args.db,
        workspace_root=args.workspace_root,
        storage_root=args.storage_root,
        timeout_seconds=args.timeout_seconds,
        poll_seconds=args.poll_seconds,
        force_recovery=args.force_recovery,
    )
    try:
        shutdown.shutdown()
    except SafeShutdownError as exc:
        print(f"safe shutdown: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

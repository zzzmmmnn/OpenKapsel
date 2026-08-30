"""Disk-backed retention for completed Shell task metadata and bounded output."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


TASK_ID_PATTERN = re.compile(r"\Atask_[A-Za-z0-9_-]{1,128}\Z")
TOKEN_KEY_PATTERN = re.compile(r"\A[0-9a-f]{32}\Z")
METADATA_FILE = "meta.json"
STDOUT_FILE = "stdout.bin"
STDERR_FILE = "stderr.bin"


class ArchivedOutput:
    """A request-local view of one archived bounded output stream."""

    def __init__(self, data: bytes, dropped: int):
        self._data = data
        self._dropped = dropped

    def snapshot(self) -> tuple[str, int]:
        return self._data.decode("utf-8", errors="replace"), self._dropped

    def read_from(self, offset: int, limit: int) -> dict[str, Any]:
        start = self._dropped
        end = start + len(self._data)
        gap = offset < start
        actual = min(max(offset, start), end)
        relative = actual - start
        chunk = self._data[relative : relative + limit]
        return {
            "data": chunk.decode("utf-8", errors="replace"),
            "data_base64": base64.b64encode(chunk).decode("ascii"),
            "encoding": "utf-8-replace",
            "offset": actual,
            "next_offset": actual + len(chunk),
            "available_end": end,
            "gap": gap,
        }


class ArchivedTask:
    """Completed task loaded transiently from disk for one API request."""

    def __init__(self, metadata: dict[str, Any], stdout: bytes, stderr: bytes):
        self.id = str(metadata["task_id"])
        self.status = "finished"
        self.command = str(metadata["command"])
        self.cwd = str(metadata["cwd"])
        self.exit_code = metadata.get("exit_code")
        self.started_at = str(metadata["started_at"])
        self.finished_at = str(metadata["finished_at"])
        self.timed_out = bool(metadata.get("timed_out", False))
        self.interrupted = bool(metadata.get("interrupted", False))
        self.force_killed = bool(metadata.get("force_killed", False))
        self.interactive = bool(metadata.get("interactive", False))
        self.error = metadata.get("error")
        self.sandboxed = bool(metadata.get("sandboxed", False))
        self.sandbox_backend = metadata.get("sandbox_backend")
        self.network_access = bool(metadata.get("network_access", False))
        self.resource_limited = bool(metadata.get("resource_limited", False))
        self.process = None
        self.stdout = ArchivedOutput(stdout, int(metadata.get("stdout_truncated_bytes", 0)))
        self.stderr = ArchivedOutput(stderr, int(metadata.get("stderr_truncated_bytes", 0)))
        self._lock = threading.Lock()

    def serialize(self) -> dict[str, Any]:
        stdout, stdout_dropped = self.stdout.snapshot()
        stderr, stderr_dropped = self.stderr.snapshot()
        return {
            "task_id": self.id,
            "status": self.status,
            "command": self.command,
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated_bytes": stdout_dropped,
            "stderr_truncated_bytes": stderr_dropped,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "timed_out": self.timed_out,
            "interrupted": self.interrupted,
            "force_killed": self.force_killed,
            "interactive": self.interactive,
            "stdin_open": False,
            "error": self.error,
            "sandboxed": self.sandboxed,
            "sandbox_backend": self.sandbox_backend,
            "network_access": self.network_access,
            "resource_limited": self.resource_limited,
        }

    def summary(self) -> dict[str, Any]:
        payload = self.serialize()
        payload.pop("stdout", None)
        payload.pop("stderr", None)
        return payload


class TaskHistoryStore:
    """Persist completed tasks by token hash with TTL and per-token caps."""

    def __init__(self, root: Path, *, retention_seconds: int, max_per_token: int):
        self.root = root
        self.retention_seconds = retention_seconds
        self.max_per_token = max_per_token
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.cleanup_all()
        self._thread = threading.Thread(
            target=self._cleanup_loop,
            name="task-history-cleanup",
            daemon=True,
        )
        self._thread.start()

    @staticmethod
    def token_key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def save(
        self,
        token: str,
        metadata: dict[str, Any],
        stdout: bytes,
        stderr: bytes,
    ) -> None:
        task_id = str(metadata.get("task_id", ""))
        if not TASK_ID_PATTERN.fullmatch(task_id):
            raise ValueError("invalid task id")
        token_dir = self.root / self.token_key(token)
        with self._lock:
            token_dir.mkdir(mode=0o700, exist_ok=True)
            os.chmod(token_dir, 0o700)
            temporary = Path(tempfile.mkdtemp(prefix=f".{task_id}.", dir=token_dir))
            os.chmod(temporary, 0o700)
            try:
                payload = dict(metadata)
                payload.update({"version": 1, "archived_at": time.time()})
                self._write_bytes(temporary / STDOUT_FILE, stdout)
                self._write_bytes(temporary / STDERR_FILE, stderr)
                self._write_json(temporary / METADATA_FILE, payload)
                destination = token_dir / task_id
                if destination.exists() or destination.is_symlink():
                    shutil.rmtree(destination, ignore_errors=True)
                os.replace(temporary, destination)
            finally:
                shutil.rmtree(temporary, ignore_errors=True)
            self._cleanup_token_locked(token_dir, time.time())

    def load(self, token: str, task_id: str) -> ArchivedTask | None:
        if not TASK_ID_PATTERN.fullmatch(task_id):
            return None
        token_dir = self.root / self.token_key(token)
        with self._lock:
            self._cleanup_token_locked(token_dir, time.time())
            directory = token_dir / task_id
            metadata = self._read_metadata(directory)
            if metadata is None:
                return None
            try:
                stdout = (directory / STDOUT_FILE).read_bytes()
                stderr = (directory / STDERR_FILE).read_bytes()
                return ArchivedTask(metadata, stdout, stderr)
            except (OSError, ValueError, TypeError, KeyError):
                return None

    def list(self, token: str) -> list[dict[str, Any]]:
        token_dir = self.root / self.token_key(token)
        with self._lock:
            self._cleanup_token_locked(token_dir, time.time())
            records: list[dict[str, Any]] = []
            for directory in self._task_directories(token_dir):
                metadata = self._read_metadata(directory)
                if metadata is None:
                    continue
                metadata = dict(metadata)
                metadata.pop("version", None)
                metadata.pop("archived_at", None)
                records.append(metadata)
            records.sort(key=lambda item: str(item.get("finished_at", "")), reverse=True)
            return records

    def cleanup_all(self) -> None:
        with self._lock:
            now = time.time()
            try:
                token_dirs = list(self.root.iterdir())
            except OSError:
                return
            for token_dir in token_dirs:
                if token_dir.is_symlink() or not token_dir.is_dir() or not TOKEN_KEY_PATTERN.fullmatch(token_dir.name):
                    continue
                self._cleanup_token_locked(token_dir, now)

    def _cleanup_loop(self) -> None:
        interval = min(60, max(1, self.retention_seconds // 4))
        while not self._stop.wait(interval):
            self.cleanup_all()

    def _cleanup_token_locked(self, token_dir: Path, now: float) -> None:
        if token_dir.is_symlink() or not token_dir.is_dir():
            return
        retained: list[tuple[float, Path]] = []
        for directory in self._task_directories(token_dir):
            metadata = self._read_metadata(directory)
            if metadata is None:
                shutil.rmtree(directory, ignore_errors=True)
                continue
            archived_at = metadata.get("archived_at")
            if isinstance(archived_at, bool) or not isinstance(archived_at, (int, float)):
                shutil.rmtree(directory, ignore_errors=True)
                continue
            timestamp = float(archived_at)
            if timestamp + self.retention_seconds <= now:
                shutil.rmtree(directory, ignore_errors=True)
                continue
            retained.append((timestamp, directory))
        retained.sort(key=lambda item: item[0], reverse=True)
        for _, directory in retained[self.max_per_token :]:
            shutil.rmtree(directory, ignore_errors=True)

    @staticmethod
    def _task_directories(token_dir: Path) -> list[Path]:
        try:
            return [
                item
                for item in token_dir.iterdir()
                if not item.is_symlink() and item.is_dir() and TASK_ID_PATTERN.fullmatch(item.name)
            ]
        except OSError:
            return []

    @staticmethod
    def _read_metadata(directory: Path) -> dict[str, Any] | None:
        if directory.is_symlink() or not directory.is_dir():
            return None
        try:
            payload = json.loads((directory / METADATA_FILE).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if (
            not isinstance(payload, dict)
            or payload.get("version") != 1
            or payload.get("task_id") != directory.name
            or payload.get("status") != "finished"
        ):
            return None
        return payload

    @staticmethod
    def _write_bytes(path: Path, data: bytes) -> None:
        with path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)

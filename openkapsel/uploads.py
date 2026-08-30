"""Persistent, token-bound resumable upload sessions."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import tempfile
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


class UploadError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


@dataclass(frozen=True)
class UploadRecord:
    upload_id: str
    owner_hash: str
    target_path: str
    temp_path: str
    temp_device: int
    temp_inode: int
    expected_size: int
    expected_sha256: str | None
    offset: int
    create_parents: bool
    created_at: str
    expires_at: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "UploadRecord":
        return cls(
            upload_id=str(payload["upload_id"]),
            owner_hash=str(payload["owner_hash"]),
            target_path=str(payload["target_path"]),
            temp_path=str(payload["temp_path"]),
            temp_device=int(payload["temp_device"]),
            temp_inode=int(payload["temp_inode"]),
            expected_size=int(payload["expected_size"]),
            expected_sha256=(
                str(payload["expected_sha256"]) if payload.get("expected_sha256") else None
            ),
            offset=int(payload.get("offset", 0)),
            create_parents=bool(payload.get("create_parents", False)),
            created_at=str(payload["created_at"]),
            expires_at=str(payload["expires_at"]),
        )

    def public(self, recommended_chunk_size: int) -> dict[str, Any]:
        return {
            "upload_id": self.upload_id,
            "path": self.target_path,
            "size": self.expected_size,
            "offset": self.offset,
            "complete": self.offset == self.expected_size,
            "sha256": self.expected_sha256,
            "recommended_chunk_size": recommended_chunk_size,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


class UploadRegistry:
    def __init__(
        self,
        state_dir: Path,
        *,
        ttl_seconds: int,
        max_file_bytes: int,
        max_incomplete_bytes: int,
        recommended_chunk_size: int,
    ):
        self.state_dir = state_dir.resolve()
        self.ttl_seconds = ttl_seconds
        self.max_file_bytes = max_file_bytes
        self.max_incomplete_bytes = max_incomplete_bytes
        self.recommended_chunk_size = recommended_chunk_size
        self._lock = threading.RLock()
        self._records: dict[str, UploadRecord] = {}
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self._load()

    @staticmethod
    def owner_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(
        self,
        *,
        token: str,
        target: Path,
        expected_size: int,
        expected_sha256: str | None,
        create_parents: bool,
    ) -> UploadRecord:
        if expected_size < 0:
            raise UploadError(400, "invalid_size", "size must be non-negative")
        if expected_size > self.max_file_bytes:
            raise UploadError(413, "file_too_large", "file exceeds the configured maximum size")
        if expected_sha256 is not None and not _valid_sha256(expected_sha256):
            raise UploadError(400, "invalid_sha256", "sha256 must be 64 hexadecimal characters")
        with self._lock:
            self._purge_expired_locked()
            reserved = sum(record.expected_size for record in self._records.values())
            if reserved + expected_size > self.max_incomplete_bytes:
                raise UploadError(507, "upload_quota_exceeded", "incomplete upload quota is exhausted")
            while True:
                upload_id = f"upload_{secrets.token_urlsafe(18)}"
                if upload_id not in self._records:
                    break
            target = target.resolve(strict=False)
            # Incomplete bytes live in the service-owned state directory, not in
            # a token-writable parent that can be renamed while an upload is active.
            temp_path = self.state_dir / f".{upload_id}.part"
            try:
                with temp_path.open("xb"):
                    pass
                os.chmod(temp_path, 0o600)
                temp_stat = temp_path.stat()
            except OSError as exc:
                raise UploadError(500, "upload_create_failed", f"cannot create upload file: {exc}") from None
            now = _utc_now()
            record = UploadRecord(
                upload_id=upload_id,
                owner_hash=self.owner_hash(token),
                target_path=str(target),
                temp_path=str(temp_path),
                temp_device=temp_stat.st_dev,
                temp_inode=temp_stat.st_ino,
                expected_size=expected_size,
                expected_sha256=expected_sha256.lower() if expected_sha256 else None,
                offset=0,
                create_parents=create_parents,
                created_at=_iso(now),
                expires_at=_iso(now + timedelta(seconds=self.ttl_seconds)),
            )
            self._records[upload_id] = record
            try:
                self._save_locked(record)
            except Exception:
                self._records.pop(upload_id, None)
                temp_path.unlink(missing_ok=True)
                raise
            return record

    def get(self, upload_id: str, token: str) -> UploadRecord:
        with self._lock:
            self._purge_expired_locked()
            record = self._records.get(upload_id)
            if record is None or not secrets.compare_digest(record.owner_hash, self.owner_hash(token)):
                raise UploadError(404, "upload_not_found", "upload does not exist")
            return record

    def append(self, upload_id: str, token: str, offset: int, stream: BinaryIO, length: int) -> UploadRecord:
        if length < 0:
            raise UploadError(400, "invalid_length", "Content-Length must be non-negative")
        with self._lock:
            record = self.get(upload_id, token)
            if offset != record.offset:
                raise UploadError(
                    409,
                    "upload_offset_mismatch",
                    "upload offset does not match",
                    {"expected": record.offset, "actual": offset},
                )
            if record.offset + length > record.expected_size:
                raise UploadError(413, "upload_too_large", "chunk exceeds the declared file size")
            temp_path = Path(record.temp_path)
            try:
                with self._open_temp(record, write=True) as handle:
                    handle.seek(record.offset)
                    remaining = length
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            handle.truncate(record.offset)
                            raise UploadError(400, "incomplete_body", "request body ended before Content-Length")
                        handle.write(chunk)
                        remaining -= len(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            except UploadError:
                raise
            except OSError as exc:
                raise UploadError(500, "upload_write_failed", f"cannot write upload chunk: {exc}") from None
            updated = UploadRecord(**{**asdict(record), "offset": record.offset + length})
            self._records[upload_id] = updated
            self._save_locked(updated)
            return updated

    def verify(self, upload_id: str, token: str) -> tuple[UploadRecord, str]:
        with self._lock:
            record = self.get(upload_id, token)
            if record.offset != record.expected_size:
                raise UploadError(
                    409,
                    "upload_incomplete",
                    "upload has not reached the declared size",
                    {"offset": record.offset, "size": record.expected_size},
                )
            digest = hashlib.sha256()
            try:
                with self._open_temp(record, write=False) as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            except OSError as exc:
                raise UploadError(500, "upload_read_failed", f"cannot verify upload: {exc}") from None
            actual = digest.hexdigest()
            if record.expected_sha256 is not None and not secrets.compare_digest(
                record.expected_sha256, actual
            ):
                raise UploadError(
                    422,
                    "checksum_mismatch",
                    "uploaded content does not match sha256",
                    {"expected": record.expected_sha256, "actual": actual},
                )
            return record, actual

    def finish(self, upload_id: str, token: str) -> None:
        with self._lock:
            record = self._records.get(upload_id)
            if record is None or not secrets.compare_digest(record.owner_hash, self.owner_hash(token)):
                raise UploadError(404, "upload_not_found", "upload does not exist")
            self._records.pop(upload_id, None)
            self._metadata_path(record.upload_id).unlink(missing_ok=True)

    def cancel(self, upload_id: str, token: str) -> UploadRecord:
        with self._lock:
            record = self.get(upload_id, token)
            self._remove_locked(record)
            return record

    def assert_temp_unchanged(self, upload_id: str, token: str) -> UploadRecord:
        with self._lock:
            record = self.get(upload_id, token)
            with self._open_temp(record, write=False):
                pass
            return record

    def copy_to(self, upload_id: str, token: str, destination: BinaryIO) -> UploadRecord:
        """Copy a verified upload into a caller-owned, safely opened file."""
        with self._lock:
            record = self.get(upload_id, token)
            if record.offset != record.expected_size:
                raise UploadError(
                    409,
                    "upload_incomplete",
                    "upload has not reached the declared size",
                    {"offset": record.offset, "size": record.expected_size},
                )
            copied = 0
            try:
                with self._open_temp(record, write=False) as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        destination.write(chunk)
                        copied += len(chunk)
            except UploadError:
                raise
            except OSError as exc:
                raise UploadError(500, "upload_read_failed", f"cannot copy upload: {exc}") from None
            if copied != record.expected_size:
                raise UploadError(409, "upload_temp_changed", "upload temporary file size changed")
            return record

    @staticmethod
    def _open_temp(record: UploadRecord, *, write: bool) -> BinaryIO:
        flags = os.O_RDWR if write else os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(record.temp_path, flags)
        except OSError as exc:
            raise UploadError(409, "upload_temp_changed", "upload temporary file changed") from exc
        try:
            current = os.fstat(descriptor)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_dev != record.temp_device
                or current.st_ino != record.temp_inode
            ):
                raise UploadError(409, "upload_temp_changed", "upload temporary file changed")
            return os.fdopen(descriptor, "r+b" if write else "rb")
        except Exception:
            os.close(descriptor)
            raise

    def _metadata_path(self, upload_id: str) -> Path:
        return self.state_dir / f"{upload_id}.json"

    def _save_locked(self, record: UploadRecord) -> None:
        destination = self._metadata_path(record.upload_id)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.state_dir,
                prefix=f".{record.upload_id}.",
                delete=False,
            ) as handle:
                temp_name = handle.name
                json.dump(asdict(record), handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, destination)
        finally:
            if temp_name is not None:
                Path(temp_name).unlink(missing_ok=True)

    def _load(self) -> None:
        with self._lock:
            for path in self.state_dir.glob("upload_*.json"):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    record = UploadRecord.from_dict(payload)
                    temp_path = Path(record.temp_path)
                    temp_stat = temp_path.lstat()
                    if (
                        self._metadata_path(record.upload_id) != path
                        or not stat.S_ISREG(temp_stat.st_mode)
                        or temp_stat.st_dev != record.temp_device
                        or temp_stat.st_ino != record.temp_inode
                        or record.offset < 0
                        or record.offset > record.expected_size
                        or temp_path.stat().st_size < record.offset
                    ):
                        raise ValueError("invalid upload metadata")
                    if temp_path.stat().st_size > record.offset:
                        with temp_path.open("r+b") as handle:
                            handle.truncate(record.offset)
                    self._records[record.upload_id] = record
                except Exception:
                    path.unlink(missing_ok=True)
            self._purge_expired_locked()

    def _purge_expired_locked(self) -> None:
        now = _utc_now()
        for record in tuple(self._records.values()):
            try:
                expiry = datetime.fromisoformat(record.expires_at)
            except (TypeError, ValueError):
                expiry = now
            if expiry <= now:
                self._remove_locked(record)

    def _remove_locked(self, record: UploadRecord) -> None:
        self._records.pop(record.upload_id, None)
        Path(record.temp_path).unlink(missing_ok=True)
        self._metadata_path(record.upload_id).unlink(missing_ok=True)


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)

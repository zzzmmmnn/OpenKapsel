#!/usr/bin/env python3
"""Upload one file with automatic direct/resumable selection and retries."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from openkapsel_http import (
    HttpResult,
    api_request,
    context_headers,
    decode_json_result,
    ensure_fresh_credentials,
    require_success,
)
from openkapsel_config import resolve_credentials


RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
ProgressCallback = Callable[[str | None, int], None]


@dataclass(frozen=True)
class UploadLimits:
    direct_bytes: int
    request_bytes: int
    chunk_bytes: int


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Upload one file to OpenKapsel with automatic resumable transfer"
    )
    result.add_argument("source", type=Path)
    result.add_argument("destination")
    result.add_argument("--base-url")
    result.add_argument("--control-token")
    result.add_argument("--env-file", help="credential file; defaults to nearest .openkapsel.env")
    result.add_argument("--plan-id", required=True, type=int)
    result.add_argument("--taskname", required=True)
    result.add_argument("--message", required=True)
    result.add_argument("--create-parents", action="store_true")
    result.add_argument(
        "--overwrite",
        action="store_true",
        help="recycle an existing destination before uploading",
    )
    result.add_argument("--force-resumable", action="store_true")
    result.add_argument("--resume-upload-id", help="resume an existing server upload session")
    result.add_argument("--retries", type=int, default=3)
    result.add_argument("--retry-delay", type=float, default=2.0)
    result.add_argument("--timeout", type=float, default=120.0)
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _error_code(result: HttpResult) -> str | None:
    try:
        payload = decode_json_result(result)
    except RuntimeError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("error"), dict):
        return None
    code = payload["error"].get("code")
    return str(code) if code is not None else None


class UploadClient:
    def __init__(
        self,
        *,
        base_url: str,
        control_token: str,
        plan_id: int,
        taskname: str,
        message: str,
        retries: int = 3,
        retry_delay: float = 2.0,
        timeout: float = 120.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if retries < 0:
            raise ValueError("retries must be non-negative")
        if retry_delay < 0:
            raise ValueError("retry-delay must be non-negative")
        self.base_url = base_url
        self.control_token = control_token
        self.plan_id = plan_id
        self.taskname = taskname
        self.message = message
        self.retries = retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.sleep = sleep
        self.last_request_retried = False

    def _context_payload(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            **payload,
            "plan_id": self.plan_id,
            "taskname": self.taskname,
            "message": self.message,
        }

    def _wait_before_retry(self, attempt: int, result: HttpResult | None = None) -> None:
        delay = self.retry_delay
        if result is not None:
            retry_after = result.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    pass
        print(
            f"retrying after {delay:g}s (attempt {attempt + 2}/{self.retries + 1})",
            file=sys.stderr,
        )
        self.sleep(delay)

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        retry: bool = True,
    ) -> HttpResult:
        attempts = self.retries + 1 if retry else 1
        self.last_request_retried = False
        for attempt in range(attempts):
            try:
                result = api_request(
                    method,
                    endpoint,
                    base_url=self.base_url,
                    control_token=self.control_token,
                    headers=headers,
                    query=query,
                    data=data,
                    timeout=self.timeout,
                )
            except (OSError, RuntimeError):
                if attempt + 1 >= attempts:
                    raise
                self.last_request_retried = True
                self._wait_before_retry(attempt)
                continue
            if result.status in RETRYABLE_STATUSES and attempt + 1 < attempts:
                self.last_request_retried = True
                self._wait_before_retry(attempt, result)
                continue
            return result
        raise RuntimeError("request retry loop ended unexpectedly")

    def json_request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, object] | None = None,
        *,
        mutation: bool = False,
        retry: bool = True,
    ) -> tuple[HttpResult, object]:
        headers: dict[str, str] = {}
        data = None
        if payload is not None:
            body = self._context_payload(payload) if mutation else payload
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif mutation:
            headers.update(context_headers(self.plan_id, self.taskname, self.message))
        result = self.request(
            method,
            endpoint,
            headers=headers,
            data=data,
            retry=retry,
        )
        require_success(result)
        return result, decode_json_result(result) if result.body else {}

    def discover_limits(self) -> UploadLimits:
        return self.upload_limits_from_discovery(self.discover_files())

    def discover_files(self) -> dict[str, object]:
        _result, payload = self.json_request("GET", "discovery/files")
        if not isinstance(payload, dict):
            raise RuntimeError("file Discovery response is not an object")
        return payload

    @staticmethod
    def upload_limits_from_discovery(payload: dict[str, object]) -> UploadLimits:
        if not isinstance(payload.get("limits"), dict):
            raise RuntimeError("file Discovery does not publish limits")
        limits = payload["limits"]
        direct = int(limits["max_direct_upload_bytes"])
        request = int(limits["max_request_body_bytes"])
        recommended = int(limits["recommended_upload_chunk_bytes"])
        return UploadLimits(
            direct_bytes=direct,
            request_bytes=request,
            chunk_bytes=max(1, min(recommended, request)),
        )

    @staticmethod
    def endpoint_available(payload: dict[str, object], name: str) -> bool:
        endpoints = payload.get("endpoints")
        if not isinstance(endpoints, dict):
            return False
        endpoint = endpoints.get(name)
        return isinstance(endpoint, dict) and endpoint.get("available") is True

    def manifest(
        self,
        items: list[dict[str, object]],
        *,
        include_sha256: bool = False,
    ) -> dict[str, object]:
        _result, payload = self.json_request(
            "POST",
            "fs/manifest",
            {"items": items, "include_sha256": include_sha256},
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise RuntimeError("file manifest response is not an object with items")
        return payload

    def ensure_directory(self, path: str) -> object:
        _result, payload = self.json_request(
            "POST",
            "fs/mkdir",
            {"path": path, "parents": True, "exist_ok": True},
            mutation=True,
        )
        return payload

    def recycle_existing(self, path: str) -> bool:
        payload = self._context_payload({"path": path})
        result = self.request(
            "POST",
            "fs/delete",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )
        if result.status == 404 and _error_code(result) in {"path_not_found", "not_found"}:
            return False
        require_success(result)
        return True

    def remote_matches(self, path: str, size: int, digest: str) -> bool:
        result = self.request(
            "GET",
            "fs/stat",
            query=(("path", path), ("fields", "type,size,sha256")),
        )
        if result.status in {401, 403, 404}:
            return False
        require_success(result)
        payload = decode_json_result(result)
        return bool(
            isinstance(payload, dict)
            and payload.get("type") == "file"
            and int(payload.get("size", -1)) == size
            and payload.get("sha256") == digest
        )

    def resume_status(
        self,
        upload_id: str,
        *,
        size: int,
        digest: str,
    ) -> int | None:
        result = self.request("GET", f"uploads/{upload_id}")
        if result.status == 404 and _error_code(result) == "upload_not_found":
            return None
        require_success(result)
        payload = decode_json_result(result)
        if not isinstance(payload, dict):
            raise RuntimeError("upload status response is not an object")
        if int(payload.get("size", -1)) != size or payload.get("sha256") != digest:
            raise RuntimeError("saved upload session does not match the local file")
        offset = int(payload.get("offset", -1))
        if offset < 0 or offset > size:
            raise RuntimeError("server returned an invalid upload offset")
        return offset

    def _append_chunk(
        self,
        upload_id: str,
        offset: int,
        chunk: bytes,
        *,
        total_size: int,
        digest: str,
    ) -> int:
        headers = {
            **context_headers(self.plan_id, self.taskname, self.message),
            "Content-Type": "application/octet-stream",
            "Upload-Offset": str(offset),
        }
        try:
            result = self.request(
                "PATCH",
                f"uploads/{upload_id}",
                headers=headers,
                data=chunk,
            )
        except (OSError, RuntimeError):
            current = self.resume_status(upload_id, size=total_size, digest=digest)
            if current is not None and offset < current <= offset + len(chunk):
                return current
            raise
        if result.status == 409 and _error_code(result) == "upload_offset_mismatch":
            payload = decode_json_result(result)
            expected = int(payload["error"]["details"]["expected"])
            if offset < expected <= offset + len(chunk):
                return expected
        require_success(result)
        payload = decode_json_result(result)
        if not isinstance(payload, dict):
            raise RuntimeError("upload chunk response is not an object")
        next_offset = int(payload.get("offset", -1))
        if next_offset != offset + len(chunk):
            raise RuntimeError(
                f"server returned unexpected offset {next_offset}; "
                f"expected {offset + len(chunk)}"
            )
        return next_offset

    def upload_file(
        self,
        source: Path,
        destination: str,
        *,
        limits: UploadLimits | None = None,
        digest: str | None = None,
        create_parents: bool = False,
        force_resumable: bool = False,
        overwrite: bool = False,
        resume_upload_id: str | None = None,
        allow_existing_match: bool = False,
        progress: ProgressCallback | None = None,
    ) -> object:
        if not source.is_file() or source.is_symlink():
            raise ValueError("source must be a regular non-symlink file")
        file_size = source.stat().st_size
        file_digest = digest or sha256_file(source)
        active_limits = limits or self.discover_limits()

        if allow_existing_match and self.remote_matches(
            destination, file_size, file_digest
        ):
            if progress is not None:
                progress(None, file_size)
            return {
                "path": destination,
                "created": True,
                "bytes_written": file_size,
                "sha256": file_digest,
                "recovered_after_interruption": True,
            }

        if resume_upload_id is None and file_size <= active_limits.direct_bytes and not force_resumable:
            if overwrite:
                self.recycle_existing(destination)
            if progress is not None:
                progress(None, 0)
            headers = {
                **context_headers(self.plan_id, self.taskname, self.message),
                "Content-Type": "application/octet-stream",
                "X-Content-SHA256": file_digest,
            }
            result = self.request(
                "PUT",
                "fs/content",
                query=(
                    ("path", destination),
                    ("create_parents", str(create_parents).lower()),
                ),
                headers=headers,
                data=source.read_bytes(),
            )
            if (
                result.status == 409
                and (allow_existing_match or self.last_request_retried)
                and self.remote_matches(destination, file_size, file_digest)
            ):
                payload: object = {
                    "path": destination,
                    "created": True,
                    "bytes_written": file_size,
                    "sha256": file_digest,
                    "recovered_after_interruption": True,
                }
            else:
                require_success(result)
                payload = decode_json_result(result)
            if progress is not None:
                progress(None, file_size)
            return payload

        upload_id = resume_upload_id
        offset: int | None = None
        if upload_id is not None:
            offset = self.resume_status(upload_id, size=file_size, digest=file_digest)
            if offset is None:
                if allow_existing_match and self.remote_matches(
                    destination, file_size, file_digest
                ):
                    if progress is not None:
                        progress(None, file_size)
                    return {
                        "path": destination,
                        "created": True,
                        "bytes_written": file_size,
                        "sha256": file_digest,
                        "recovered_after_interruption": True,
                    }
                upload_id = None

        if upload_id is None:
            if overwrite:
                self.recycle_existing(destination)
            _result, created = self.json_request(
                "POST",
                "uploads",
                {
                    "path": destination,
                    "size": file_size,
                    "sha256": file_digest,
                    "create_parents": create_parents,
                },
                mutation=True,
            )
            if not isinstance(created, dict) or not isinstance(created.get("upload_id"), str):
                raise RuntimeError("upload creation did not return upload_id")
            upload_id = created["upload_id"]
            offset = int(created.get("offset", 0))

        assert offset is not None
        if progress is not None:
            progress(upload_id, offset)
        print(
            f"upload_id={upload_id} size={file_size} "
            f"chunk_size={active_limits.chunk_bytes} offset={offset}",
            file=sys.stderr,
        )
        with source.open("rb") as handle:
            while offset < file_size:
                handle.seek(offset)
                chunk = handle.read(min(active_limits.chunk_bytes, file_size - offset))
                if not chunk:
                    raise RuntimeError("source ended before the declared size")
                offset = self._append_chunk(
                    upload_id,
                    offset,
                    chunk,
                    total_size=file_size,
                    digest=file_digest,
                )
                if progress is not None:
                    progress(upload_id, offset)
                print(f"uploaded {offset}/{file_size}", file=sys.stderr)

        try:
            _result, committed = self.json_request(
                "POST",
                f"uploads/{upload_id}/commit",
                None,
                mutation=True,
            )
        except RuntimeError:
            if (allow_existing_match or self.last_request_retried) and self.remote_matches(
                destination, file_size, file_digest
            ):
                committed = {
                    "path": destination,
                    "created": True,
                    "bytes_written": file_size,
                    "sha256": file_digest,
                    "recovered_after_interruption": True,
                }
            else:
                raise
        if progress is not None:
            progress(None, file_size)
        return committed


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        credentials = ensure_fresh_credentials(
            resolve_credentials(
                base_url=args.base_url,
                control_token=args.control_token,
                env_file=args.env_file,
            )
        )
        args.base_url = credentials.base_url
        args.control_token = credentials.control_token
        if not args.base_url:
            raise ValueError("set OPENKAPSEL_BASE_URL or pass --base-url")
        if not args.control_token:
            raise ValueError("set OPENKAPSEL_CONTROL_TOKEN or pass --control-token")
        client = UploadClient(
            base_url=args.base_url,
            control_token=args.control_token,
            plan_id=args.plan_id,
            taskname=args.taskname,
            message=args.message,
            retries=args.retries,
            retry_delay=args.retry_delay,
            timeout=args.timeout,
        )
        payload = client.upload_file(
            args.source,
            args.destination,
            create_parents=args.create_parents,
            force_resumable=args.force_resumable,
            overwrite=args.overwrite,
            resume_upload_id=args.resume_upload_id,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    except (KeyError, OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"openkapsel_upload.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

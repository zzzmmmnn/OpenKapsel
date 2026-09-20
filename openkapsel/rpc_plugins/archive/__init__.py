"""Safe, bounded archive browsing using Python standard-library readers."""

from __future__ import annotations

import base64
import datetime as _datetime
import errno
import mimetypes
import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from ...errors import ApiError


MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_READ_BYTES = 256 * 1024
MAX_ARCHIVE_OFFSET = 16 * 1024 * 1024


_STDLIB_ARCHIVE_FORMATS = frozenset({"zip", "tar", "gztar", "bztar", "xztar", "zstdtar"})


def supported_extensions() -> list[str]:
    values: set[str] = set()
    for name, extensions, _description in shutil.get_unpack_formats():
        if name in _STDLIB_ARCHIVE_FORMATS:
            values.update(extensions)
    return sorted(values, key=lambda value: (len(value), value))


def _member_name(value: str) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    while value.startswith("./"):
        value = value[2:]
    if not value:
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        return None
    if pure.parts and ":" in pure.parts[0]:
        return None
    return pure.as_posix().rstrip("/")


def _archive_kind(path: Path) -> str:
    lower = path.name.lower()
    if lower.endswith(".zip"):
        return "zip"
    for extension in supported_extensions():
        if extension != ".zip" and lower.endswith(extension):
            return "tar"
    raise ApiError(415, "archive_format_unsupported", "archive format is not supported by this Python runtime")


def _timestamp(value: float | int | None) -> str | None:
    if value is None:
        return None
    try:
        return _datetime.datetime.fromtimestamp(float(value), _datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _entry_type(mode: int | None, *, directory: bool, link: bool) -> str:
    if directory:
        return "directory"
    if link:
        return "link"
    if mode is not None and not stat.S_ISREG(mode):
        return "special"
    return "file"


def _direct_listing(entries: list[dict[str, Any]], prefix: str, offset: int, limit: int) -> dict[str, Any]:
    prefix = prefix.strip("/")
    if prefix and _member_name(prefix) != prefix:
        raise ApiError(400, "invalid_archive_path", "inner_path is invalid")
    base = prefix + "/" if prefix else ""
    children: dict[str, dict[str, Any]] = {}
    for entry in entries:
        name = entry["path"]
        if prefix:
            if name == prefix:
                continue
            if not name.startswith(base):
                continue
            remainder = name[len(base):]
        else:
            remainder = name
        if not remainder:
            continue
        head, sep, _tail = remainder.partition("/")
        child_path = base + head if base else head
        if sep:
            current = children.get(head)
            if current is None or current["type"] != "directory":
                children[head] = {
                    "name": head,
                    "path": child_path,
                    "type": "directory",
                    "size": None,
                    "compressed_size": None,
                    "modified_at": None,
                }
        else:
            item = dict(entry)
            item["name"] = head
            children[head] = item
    values = sorted(children.values(), key=lambda item: (item["type"] != "directory", item["name"].casefold(), item["name"]))
    total = len(values)
    return {
        "inner_path": prefix,
        "entries": values[offset:offset + limit],
        "total": total,
        "offset": offset,
        "limit": limit,
        "truncated": offset + limit < total,
    }


def _zip_entries(archive: zipfile.ZipFile) -> list[dict[str, Any]]:
    result = []
    for index, info in enumerate(archive.infolist()):
        if index >= MAX_ARCHIVE_ENTRIES:
            raise ApiError(413, "archive_entry_limit", "archive contains too many entries")
        name = _member_name(info.filename)
        if not name:
            continue
        mode = (info.external_attr >> 16) & 0xFFFF
        link = stat.S_ISLNK(mode)
        try:
            modified = _datetime.datetime(*info.date_time, tzinfo=_datetime.timezone.utc).isoformat()
        except (TypeError, ValueError):
            modified = None
        result.append({
            "path": name,
            "type": _entry_type(mode or None, directory=info.is_dir(), link=link),
            "size": info.file_size if not info.is_dir() else None,
            "compressed_size": info.compress_size if not info.is_dir() else None,
            "modified_at": modified,
        })
    return result


def _tar_entries(archive: tarfile.TarFile) -> list[dict[str, Any]]:
    result = []
    for index, member in enumerate(archive):
        if index >= MAX_ARCHIVE_ENTRIES:
            raise ApiError(413, "archive_entry_limit", "archive contains too many entries")
        name = _member_name(member.name)
        if not name:
            continue
        result.append({
            "path": name,
            "type": _entry_type(member.mode, directory=member.isdir(), link=member.issym() or member.islnk()),
            "size": member.size if member.isfile() else None,
            "compressed_size": None,
            "modified_at": _timestamp(member.mtime),
        })
    return result


def _open_guarded(access, path: Path):
    fd = access.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    handle = os.fdopen(fd, "rb")
    details = os.fstat(handle.fileno())
    if not stat.S_ISREG(details.st_mode):
        handle.close()
        raise ApiError(400, "archive_not_file", "archive path is not a regular file")
    return handle


def archive_list(access, path: Path, *, inner_path: str = "", offset: int = 0, limit: int = 200) -> dict[str, Any]:
    kind = _archive_kind(path)
    handle = _open_guarded(access, path)
    try:
        try:
            if kind == "zip":
                with zipfile.ZipFile(handle) as archive:
                    entries = _zip_entries(archive)
            else:
                with tarfile.open(fileobj=handle, mode="r:*") as archive:
                    entries = _tar_entries(archive)
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
            raise ApiError(422, "archive_invalid", "archive could not be read") from exc
    finally:
        handle.close()
    result = _direct_listing(entries, inner_path, offset, limit)
    result["format"] = kind
    result["supported_extensions"] = supported_extensions()
    return result


def _read_exact_prefix(stream, offset: int, limit: int) -> bytes:
    remaining = offset
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            return b""
        remaining -= len(chunk)
    return stream.read(limit)


def archive_read(access, path: Path, *, member: str, offset: int = 0, limit: int = 65536,
                 encoding: str = "utf-8") -> dict[str, Any]:
    normalized = _member_name(member)
    if normalized != member:
        raise ApiError(400, "invalid_archive_member", "member path is invalid")
    if offset < 0 or offset > MAX_ARCHIVE_OFFSET:
        raise ApiError(400, "invalid_archive_offset", "offset exceeds archive preview limit")
    if limit < 1 or limit > MAX_ARCHIVE_READ_BYTES:
        raise ApiError(400, "invalid_archive_limit", "limit exceeds archive preview limit")
    kind = _archive_kind(path)
    handle = _open_guarded(access, path)
    raw: bytes
    size: int
    try:
        try:
            if kind == "zip":
                with zipfile.ZipFile(handle) as archive:
                    info = next((item for item in archive.infolist() if _member_name(item.filename) == member), None)
                    if info is None:
                        raise KeyError(member)
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if info.is_dir() or stat.S_ISLNK(mode):
                        raise ApiError(400, "archive_member_not_file", "member is not a regular file")
                    size = info.file_size
                    with archive.open(info, "r") as stream:
                        raw = _read_exact_prefix(stream, offset, limit)
            else:
                with tarfile.open(fileobj=handle, mode="r:*") as archive:
                    info = next((item for item in archive if _member_name(item.name) == member), None)
                    if info is None:
                        raise KeyError(member)
                    if not info.isfile():
                        raise ApiError(400, "archive_member_not_file", "member is not a regular file")
                    size = info.size
                    stream = archive.extractfile(info)
                    if stream is None:
                        raise ApiError(422, "archive_member_unreadable", "archive member could not be opened")
                    with stream:
                        raw = _read_exact_prefix(stream, offset, limit)
        except KeyError:
            raise ApiError(404, "archive_member_not_found", "archive member does not exist") from None
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
            raise ApiError(422, "archive_invalid", "archive could not be read") from exc
    finally:
        handle.close()
    try:
        content = raw.decode(encoding, errors="strict")
    except LookupError:
        raise ApiError(400, "invalid_encoding", "unknown text encoding") from None
    except UnicodeDecodeError:
        content = None
    return {
        "member": member,
        "size": size,
        "offset": offset,
        "next_offset": offset + len(raw),
        "eof": offset + len(raw) >= size,
        "bytes_read": len(raw),
        "encoding": encoding,
        "content": content,
        "data_base64": base64.b64encode(raw).decode("ascii"),
        "content_type": mimetypes.guess_type(member)[0] or "application/octet-stream",
        "format": kind,
    }


class ArchiveRpcPlugin:
    family = "archive"
    version = 1
    operations = frozenset({"list", "read"})
    read_only = True

    def probe(self, config: dict[str, Any]):
        formats = supported_extensions()
        if not formats:
            return "unsupported", "runtime_missing", None
        return "available", None, {"extensions": formats}

    def dispatch(self, files, operation: str, args: dict[str, Any]):
        try:
            path = files.path(args.get("path", ""))
            if operation == "list":
                body = archive_list(
                    files.paths,
                    path,
                    inner_path=args.get("inner_path", ""),
                    offset=args.get("offset", 0),
                    limit=args.get("limit", 200),
                )
            elif operation == "read":
                body = archive_read(
                    files.paths,
                    path,
                    member=args.get("member", ""),
                    offset=args.get("offset", 0),
                    limit=args.get("limit", 65536),
                    encoding=args.get("encoding", "utf-8"),
                )
            else:
                raise OSError(errno.ENOSYS, "unsupported archive operation")
            return {"status": 200, "body": body}
        except ApiError as exc:
            return {
                "status": int(exc.status),
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                },
            }


plugin = ArchiveRpcPlugin()

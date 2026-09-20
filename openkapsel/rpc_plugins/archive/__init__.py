"""Safe, bounded archive browsing using Python standard-library readers."""

from __future__ import annotations

import base64
import datetime as _datetime
import errno
import mimetypes
import os
import secrets
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


def _zip_entry_type(info: zipfile.ZipInfo) -> str:
    if info.is_dir():
        return "directory"
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        return "link"
    file_type = stat.S_IFMT(mode)
    # ZIP creators often store only permission bits and omit S_IFREG.
    if file_type in {0, stat.S_IFREG}:
        return "file"
    return "special"


def _tar_entry_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    if member.issym() or member.islnk():
        return "link"
    if member.isfile():
        return "file"
    return "special"


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
        try:
            modified = _datetime.datetime(*info.date_time, tzinfo=_datetime.timezone.utc).isoformat()
        except (TypeError, ValueError):
            modified = None
        result.append({
            "path": name,
            "type": _zip_entry_type(info),
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
            "type": _tar_entry_type(member),
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


def supported_create_formats() -> list[str]:
    available = {name for name, _description in shutil.get_archive_formats()}
    return sorted(_STDLIB_ARCHIVE_FORMATS & available)


def _path_lstat(files, path: Path):
    if path == files.root:
        fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            return os.fstat(fd)
        finally:
            os.close(fd)
    parent_method = getattr(files.paths, "parent", None)
    if parent_method is not None:
        with parent_method(path) as parent:
            return parent.lstat()
    guard = getattr(files.paths, "guard", None)
    if guard is None:
        raise OSError(errno.ENOTSUP, "path metadata is unavailable")
    try:
        with guard(path, include_final=True):
            return path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None


def _directory_entries(files, path: Path):
    guard = getattr(files.paths, "guard", None)
    if guard is not None:
        with guard(path, include_final=True):
            with os.scandir(path) as items:
                return sorted(
                    ((item.name, item.stat(follow_symlinks=False)) for item in items),
                    key=lambda item: item[0],
                )
    fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with os.scandir(fd) as items:
            return sorted(
                ((item.name, item.stat(follow_symlinks=False)) for item in items),
                key=lambda item: item[0],
            )
    finally:
        os.close(fd)


def _walk_sources(files, source_values, *, skip_path: Path | None, task):
    if (
        not isinstance(source_values, list)
        or not source_values
        or len(source_values) > 100
        or any(not isinstance(value, str) or not value for value in source_values)
    ):
        raise ApiError(400, "invalid_archive_sources", "sources must be a non-empty array of at most 100 paths")
    seen = set()
    count = 0
    for source_value in source_values:
        source = files.path(source_value)
        relative = source.relative_to(files.root)
        if ".openkapsel" in relative.parts:
            raise ApiError(403, "reserved_path", "workspace internal paths cannot be archived")
        if skip_path is not None and source == skip_path:
            raise ApiError(400, "invalid_archive_sources", "destination cannot also be an archive source")
        root_arc = "" if source == files.root else relative.as_posix()
        stack = [(source, root_arc, _path_lstat(files, source))]
        while stack:
            task.check_cancelled()
            path, arcname, details = stack.pop()
            if details is None:
                raise ApiError(404, "archive_source_not_found", "archive source does not exist")
            if skip_path is not None and path == skip_path:
                continue
            if getattr(details, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(details.st_mode):
                raise ApiError(409, "archive_source_unsupported", "archive sources cannot contain links or reparse points")
            if stat.S_ISDIR(details.st_mode):
                if arcname:
                    if arcname in seen:
                        raise ApiError(409, "archive_duplicate_path", "archive sources overlap")
                    seen.add(arcname)
                    count += 1
                    if count > MAX_ARCHIVE_ENTRIES:
                        raise ApiError(413, "archive_entry_limit", "archive contains too many entries")
                    yield arcname, path, details
                children = _directory_entries(files, path)
                for name, child in reversed(children):
                    if name == ".openkapsel":
                        continue
                    child_path = path / name
                    child_arc = name if not arcname else arcname + "/" + name
                    stack.append((child_path, child_arc, child))
            elif stat.S_ISREG(details.st_mode):
                if not arcname:
                    raise ApiError(400, "invalid_archive_sources", "archive source path is invalid")
                if arcname in seen:
                    raise ApiError(409, "archive_duplicate_path", "archive sources overlap")
                seen.add(arcname)
                count += 1
                if count > MAX_ARCHIVE_ENTRIES:
                    raise ApiError(413, "archive_entry_limit", "archive contains too many entries")
                yield arcname, path, details
            else:
                raise ApiError(409, "archive_source_unsupported", "archive sources must contain only regular files and directories")


def _task_internal_root(files):
    root = files.root / ".openkapsel" / "rpc-tasks"
    files.paths.mkdir(root, parents=True, exist_ok=True)
    return root


def _remove_internal(files, path: Path):
    if not path.exists():
        return
    guard = getattr(files.paths, "guard", None)
    if guard is not None:
        with guard(path):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        with files.paths.parent(path) as parent:
            try:
                parent.unlink()
            except FileNotFoundError:
                pass


def _copy_safe_file(files, source: Path, target, task):
    fd = files.paths.open(source, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ApiError(409, "archive_source_unsupported", "archive source changed type")
        while chunk := stream.read(1024 * 1024):
            task.check_cancelled()
            target.write(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ApiError(409, "path_changed", "archive source changed while being read")


class _TaskReader:
    def __init__(self, files, path: Path, task):
        self.fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        self.stream = os.fdopen(self.fd, "rb")
        self.task = task
        self.before = os.fstat(self.fd)
        if not stat.S_ISREG(self.before.st_mode):
            self.stream.close()
            raise ApiError(409, "archive_source_unsupported", "archive source changed type")

    def read(self, size=-1):
        self.task.check_cancelled()
        return self.stream.read(size)

    def close(self):
        after = os.fstat(self.fd)
        self.stream.close()
        if (self.before.st_ino, self.before.st_size, self.before.st_mtime_ns) != (
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ApiError(409, "path_changed", "archive source changed while being read")


def _create_format(destination: Path, requested):
    formats = supported_create_formats()
    if requested is not None:
        if requested not in formats:
            raise ApiError(400, "archive_format_unsupported", "requested archive format is not available")
        return requested
    lower = destination.name.lower()
    matches = []
    for name, extensions, _description in shutil.get_unpack_formats():
        if name not in formats:
            continue
        for extension in extensions:
            if lower.endswith(extension):
                matches.append((len(extension), name))
    if not matches:
        raise ApiError(400, "archive_format_required", "format is required when destination suffix is ambiguous")
    return max(matches)[1]


def archive_create_task(files, args, task):
    destination = files.path(args.get("destination", ""))
    if destination == files.root or ".openkapsel" in destination.relative_to(files.root).parts:
        raise ApiError(400, "invalid_archive_destination", "destination must be an exported file path")
    if _path_lstat(files, destination.parent) is None:
        raise ApiError(404, "archive_destination_parent_missing", "destination parent directory does not exist")
    overwrite = args.get("overwrite", False)
    if not isinstance(overwrite, bool):
        raise ApiError(400, "invalid_request", "overwrite must be boolean")
    if _path_lstat(files, destination) is not None and not overwrite:
        raise ApiError(409, "archive_destination_exists", "destination already exists")
    format_name = _create_format(destination, args.get("format"))
    temporary = _task_internal_root(files) / (secrets.token_hex(12) + ".archive")
    fd = files.paths.open(temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR)
    entries = 0
    try:
        with os.fdopen(fd, "w+b") as raw:
            if format_name == "zip":
                with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                    for arcname, source, details in _walk_sources(
                        files,
                        args.get("sources"),
                        skip_path=destination,
                        task=task,
                    ):
                        task.check_cancelled()
                        entries += 1
                        info = zipfile.ZipInfo(arcname + ("/" if stat.S_ISDIR(details.st_mode) else ""))
                        info.create_system = 3
                        info.external_attr = (
                            (stat.S_IFDIR if stat.S_ISDIR(details.st_mode) else stat.S_IFREG)
                            | (details.st_mode & 0o777)
                        ) << 16
                        if stat.S_ISDIR(details.st_mode):
                            archive.writestr(info, b"")
                        else:
                            with archive.open(info, "w", force_zip64=True) as target:
                                _copy_safe_file(files, source, target, task)
                        if entries % 100 == 0:
                            task.write(f"archived {entries} entries\n")
            else:
                modes = {
                    "tar": "w",
                    "gztar": "w:gz",
                    "bztar": "w:bz2",
                    "xztar": "w:xz",
                    "zstdtar": "w:zst",
                }
                try:
                    archive = tarfile.open(fileobj=raw, mode=modes[format_name])
                except (tarfile.CompressionError, ValueError):
                    raise ApiError(415, "archive_format_unsupported", "archive format is unavailable at runtime") from None
                with archive:
                    for arcname, source, details in _walk_sources(
                        files,
                        args.get("sources"),
                        skip_path=destination,
                        task=task,
                    ):
                        task.check_cancelled()
                        entries += 1
                        info = tarfile.TarInfo(arcname)
                        info.mode = details.st_mode & 0o777
                        info.mtime = int(details.st_mtime)
                        if stat.S_ISDIR(details.st_mode):
                            info.type = tarfile.DIRTYPE
                            info.size = 0
                            archive.addfile(info)
                        else:
                            info.type = tarfile.REGTYPE
                            info.size = details.st_size
                            reader = _TaskReader(files, source, task)
                            try:
                                archive.addfile(info, reader)
                            finally:
                                reader.close()
                        if entries % 100 == 0:
                            task.write(f"archived {entries} entries\n")
            raw.flush()
            os.fsync(raw.fileno())
        task.check_cancelled()
        files.paths.rename(temporary, destination, overwrite=overwrite, create_parents=False)
        final_fd = files.paths.open(destination, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            size = os.fstat(final_fd).st_size
        finally:
            os.close(final_fd)
        task.write(f"archive complete: {entries} entries, {size} bytes\n")
        return {
            "destination": destination.relative_to(files.root).as_posix(),
            "format": format_name,
            "entries": entries,
            "size": size,
        }
    except Exception:
        _remove_internal(files, temporary)
        raise


def _safe_extract_target(temp_root: Path, member: str):
    normalized = _member_name(member)
    if not normalized:
        return None
    target = temp_root.joinpath(*PurePosixPath(normalized).parts)
    try:
        target.relative_to(temp_root)
    except ValueError:
        return None
    return target


def _write_extracted_stream(files, target: Path, source, task):
    files.paths.mkdir(target.parent, parents=True, exist_ok=True)
    fd = files.paths.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        with os.fdopen(fd, "wb") as output:
            while chunk := source.read(1024 * 1024):
                task.check_cancelled()
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            with files.paths.parent(target) as parent:
                parent.unlink()
        except Exception:
            pass
        raise


def archive_extract_task(files, args, task):
    archive_path = files.path(args.get("path", ""))
    destination = files.path(args.get("destination", ""))
    if destination == files.root or ".openkapsel" in destination.relative_to(files.root).parts:
        raise ApiError(400, "invalid_archive_destination", "destination must be a new exported directory")
    if _path_lstat(files, destination.parent) is None:
        raise ApiError(404, "archive_destination_parent_missing", "destination parent directory does not exist")
    if _path_lstat(files, destination) is not None:
        raise ApiError(409, "archive_destination_exists", "destination directory already exists")
    kind = _archive_kind(archive_path)
    temporary = _task_internal_root(files) / (secrets.token_hex(12) + ".extract")
    files.paths.mkdir(temporary, parents=False, exist_ok=False)
    entries = 0
    handle = _open_guarded(files.paths, archive_path)
    try:
        if kind == "zip":
            try:
                with zipfile.ZipFile(handle) as archive:
                    for info in archive.infolist():
                        task.check_cancelled()
                        if entries >= MAX_ARCHIVE_ENTRIES:
                            raise ApiError(413, "archive_entry_limit", "archive contains too many entries")
                        member = _member_name(info.filename)
                        if not member:
                            continue
                        target = _safe_extract_target(temporary, member)
                        if target is None:
                            raise ApiError(409, "archive_member_unsafe", "archive contains an unsafe member path")
                        entry_type = _zip_entry_type(info)
                        if entry_type == "directory":
                            files.paths.mkdir(target, parents=True, exist_ok=True)
                        elif entry_type == "file":
                            with archive.open(info, "r") as source:
                                _write_extracted_stream(files, target, source, task)
                        else:
                            raise ApiError(409, "archive_member_unsafe", "archive links and special members are not extracted")
                        entries += 1
                        if entries % 100 == 0:
                            task.write(f"extracted {entries} entries\n")
            except zipfile.BadZipFile as exc:
                raise ApiError(422, "archive_invalid", "archive could not be read") from exc
        else:
            try:
                with tarfile.open(fileobj=handle, mode="r:*") as archive:
                    for info in archive:
                        task.check_cancelled()
                        if entries >= MAX_ARCHIVE_ENTRIES:
                            raise ApiError(413, "archive_entry_limit", "archive contains too many entries")
                        member = _member_name(info.name)
                        if not member:
                            continue
                        target = _safe_extract_target(temporary, member)
                        if target is None:
                            raise ApiError(409, "archive_member_unsafe", "archive contains an unsafe member path")
                        if info.isdir():
                            files.paths.mkdir(target, parents=True, exist_ok=True)
                        elif info.isfile():
                            source = archive.extractfile(info)
                            if source is None:
                                raise ApiError(422, "archive_member_unreadable", "archive member could not be opened")
                            with source:
                                _write_extracted_stream(files, target, source, task)
                        else:
                            raise ApiError(409, "archive_member_unsafe", "archive links and special members are not extracted")
                        entries += 1
                        if entries % 100 == 0:
                            task.write(f"extracted {entries} entries\n")
            except tarfile.TarError as exc:
                raise ApiError(422, "archive_invalid", "archive could not be read") from exc
        task.check_cancelled()
        files.paths.rename(temporary, destination, overwrite=False, create_parents=False)
        task.write(f"extract complete: {entries} entries\n")
        return {
            "archive": archive_path.relative_to(files.root).as_posix(),
            "destination": destination.relative_to(files.root).as_posix(),
            "entries": entries,
        }
    except Exception:
        _remove_internal(files, temporary)
        raise
    finally:
        handle.close()


class ArchiveRpcPlugin:
    family = "archive"
    version = 1
    description = (
        "Safely browse ZIP and Python-standard-library tar archives without extracting "
        "members to the workspace."
    )
    operations = {
        "list": {
            "description": "List one archive directory with bounded pagination.",
            "execution": "sync",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1, "description": "Client-export-relative archive path."},
                    "inner_path": {"type": "string", "default": "", "description": "Archive-internal directory path."},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        "read": {
            "description": "Read a bounded regular-file member preview without extracting it.",
            "execution": "sync",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1, "description": "Client-export-relative archive path."},
                    "member": {"type": "string", "minLength": 1, "description": "Archive member path."},
                    "offset": {"type": "integer", "minimum": 0, "maximum": MAX_ARCHIVE_OFFSET, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ARCHIVE_READ_BYTES, "default": 65536},
                    "encoding": {"type": "string", "default": "utf-8"},
                },
                "required": ["path", "member"],
                "additionalProperties": False,
            },
        },
        "create": {
            "description": "Create an archive atomically from exported files/directories. Runs as a persistent client task.",
            "write": True,
            "execution": "task",
            "input_schema": {
                "type": "object",
                "properties": {
                    "destination": {"type": "string", "minLength": 1},
                    "sources": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                        "maxItems": 100,
                    },
                    "format": {
                        "type": "string",
                        "enum": ["zip", "tar", "gztar", "bztar", "xztar", "zstdtar"],
                    },
                    "overwrite": {"type": "boolean", "default": False},
                },
                "required": ["destination", "sources"],
                "additionalProperties": False,
            },
        },
        "extract": {
            "description": "Extract an archive atomically into a new directory. Links/special members are rejected. Runs as a persistent client task.",
            "write": True,
            "execution": "task",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "destination": {"type": "string", "minLength": 1},
                },
                "required": ["path", "destination"],
                "additionalProperties": False,
            },
        },
    }

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

    def dispatch_task(self, files, operation: str, args: dict[str, Any], task):
        try:
            if operation == "create":
                body = archive_create_task(files, args, task)
            elif operation == "extract":
                body = archive_extract_task(files, args, task)
            else:
                raise OSError(errno.ENOSYS, "unsupported Archive task operation")
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

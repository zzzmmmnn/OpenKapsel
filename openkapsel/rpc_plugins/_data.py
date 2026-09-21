"""Shared bounded validation and guarded I/O for data RPC plugins.

These helpers do not execute user code, open network connections, or use FUSE.
"""
from __future__ import annotations

import contextlib
import datetime
import errno
import hashlib
import json
import math
import os
import secrets
import stat
from collections.abc import Mapping

from ..errors import ApiError
from ..file_support import FileOperationSupportMixin

MAX_RESULT_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_NODES = 100_000


def fail(code, message, status=400, details=None):
    raise ApiError(status, code, message, details)


def validate(value, schema, name="args", depth=0):
    """Validate only the explicit JSON Schema subset used by these plugins."""
    if depth > MAX_DEPTH:
        fail("data_depth_limit", "request nesting exceeds the limit", 413)
    kind = schema.get("type")
    types = kind if isinstance(kind, list) else [kind] if kind else []
    checks = {"object": lambda: isinstance(value, dict), "array": lambda: isinstance(value, list),
              "string": lambda: isinstance(value, str), "integer": lambda: type(value) is int,
              "number": lambda: type(value) in (int, float) and (type(value) is int or math.isfinite(value)),
              "boolean": lambda: type(value) is bool, "null": lambda: value is None}
    if types and not any(checks[t]() for t in types):
        fail("invalid_data_arguments", f"{name} has an invalid type")
    if "enum" in schema and value not in schema["enum"]:
        fail("invalid_data_arguments", f"{name} is not an allowed value")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if any(k not in value for k in schema.get("required", [])):
            fail("invalid_data_arguments", f"{name} is missing required fields")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            fail("invalid_data_arguments", f"{name} contains unknown fields")
        for key, item in value.items():
            validate(item, properties.get(key, {}), f"{name}.{key}", depth + 1)
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", MAX_NODES):
            fail("invalid_data_arguments", f"{name} has too many or too few items")
        for item in value:
            validate(item, schema.get("items", {}), name + "[]", depth + 1)
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 4 * 1024 * 1024):
            fail("invalid_data_arguments", f"{name} has invalid length")
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            fail("invalid_data_arguments", "unpaired Unicode surrogates are not supported")
    elif type(value) in (int, float):
        if (type(value) is float and not math.isfinite(value)) or value < schema.get("minimum", -math.inf) or value > schema.get("maximum", math.inf):
            fail("invalid_data_arguments", f"{name} is outside the allowed range")


def object_schema(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def result(body):
    # Leave room for the broker envelope and task metadata/output. Checking the
    # ASCII wire representation matters for Chinese and other escaped text.
    raw = json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > MAX_RESULT_BYTES:
        fail("data_result_too_large", "select a smaller subtree, fewer rows/columns, or a smaller page", 413)
    return {"status": 200, "body": body}


def response(call):
    try:
        return result(call())
    except ApiError as exc:
        return {"status": int(exc.status), "error": {"code": exc.code, "message": exc.message, "details": exc.details}}
    except OSError as exc:
        if exc.errno == errno.ECANCELED:
            raise  # Preserve the task manager's cancellation classification.
        status, code = {errno.ENOENT: (404, "path_not_found"), errno.EACCES: (403, "path_access_denied"),
                        errno.EPERM: (403, "path_access_denied"), errno.EROFS: (403, "mapping_read_only"),
                        errno.EEXIST: (409, "path_exists")}.get(exc.errno, (409, "data_io_failed"))
        return {"status": status, "error": {"code": code, "message": "guarded data file access failed"}}


def export_path(files, value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        fail("invalid_data_path", "path must be a non-empty export-relative file path")
    path = files.path(value)
    if path == files.root or any(FileOperationSupportMixin._is_internal_transfer_name(p)
                                 for p in path.relative_to(files.root).parts):
        fail("reserved_path", "private, temporary and export-root paths are unavailable", 403)
    return path


def identity(details):
    return (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns)


def etag(details):
    return FileOperationSupportMixin._stat_etag(details)


class Snapshot:
    """One pinned regular file; metadata detects replacement or in-place edits."""
    def __init__(self, files, path, *, max_bytes=None):
        self.files, self.path = files, path
        fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        self.stream = os.fdopen(fd, "rb")
        try:
            self.stat = os.fstat(fd)
            if not stat.S_ISREG(self.stat.st_mode):
                fail("data_not_file", "path must identify a regular file")
            if max_bytes is not None and self.stat.st_size > max_bytes:
                fail("data_file_too_large", "file exceeds this format's parser limit", 413, {"max_bytes": max_bytes})
            self.etag = etag(self.stat)
        except BaseException:
            self.stream.close()
            raise

    def verify(self):
        if identity(os.fstat(self.stream.fileno())) != identity(self.stat):
            fail("data_source_changed", "file changed during the operation; discard this result", 409)
        try:
            fd = self.files.paths.open(self.path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            fail("data_source_changed", "file path changed during the operation", 409)
        try:
            if identity(os.fstat(fd)) != identity(self.stat):
                fail("data_source_changed", "file was replaced during the operation", 409)
        finally:
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()


def check_etag(expected, actual):
    if expected is not None and (expected == "*" or expected != actual):
        fail("etag_mismatch", "supply the exact current ETag from read/inspect; wildcard overwrite is not supported", 412)


def json_view(value):
    """Bounded JSON-compatible view; annotate dates and unsafe-size integers."""
    types, count = {}, 0
    active = set()

    def visit(item, pointer, depth):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            fail("data_structure_limit", "document has too many nodes or is nested too deeply", 413)
        if isinstance(item, (Mapping, list, tuple)):
            if id(item) in active:
                fail("data_cycle", "cyclic data is not supported", 422)
            active.add(id(item))
            try:
                if isinstance(item, Mapping):
                    if any(not isinstance(k, str) for k in item):
                        fail("data_key_type", "only string mapping keys are supported", 422)
                    if any(any(0xD800 <= ord(c) <= 0xDFFF for c in k) for k in item):
                        fail("data_unicode", "unpaired Unicode surrogates are not supported", 422)
                    return {str(k): visit(v, pointer + "/" + k.replace("~", "~0").replace("/", "~1"), depth + 1)
                            for k, v in item.items()}
                return [visit(v, pointer + "/" + str(i), depth + 1) for i, v in enumerate(item)]
            finally:
                active.remove(id(item))
        if isinstance(item, (datetime.datetime, datetime.date, datetime.time)):
            types[pointer] = type(item).__name__
            return item.isoformat()
        if isinstance(item, bool) or item is None:
            return item
        if isinstance(item, int):
            if abs(item) > 2**53 - 1:
                types[pointer] = "integer"
                return str(item)
            return int(item)
        if isinstance(item, float):
            if not math.isfinite(item):
                fail("data_nonfinite", "non-finite numbers cannot be represented safely by this RPC", 422)
            return float(item)
        if isinstance(item, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                fail("data_unicode", "unpaired Unicode surrogates are not supported", 422)
            return str(item)
        fail("data_value_type", "document contains an unsupported non-JSON value", 422)

    return visit(value, "", 0), types


def commit_text(files, path, content, expected, task, *, create_parents=False):
    """Create-only without an ETag; conditional replacement with an exact ETag.

The file lock serializes managed writers. Like the existing file API, ETags are
optimistic conflict detection, not a distributed CAS against hostile OS writers.
"""
    from ..client_file_api import ClientFileAPI
    if not files.writable:
        fail("mapping_read_only", "structured writes require a writable export", 403)
    with files.lock:
        task.check_cancelled()
        if expected is not None:
            with Snapshot(files, path) as current:
                check_etag(expected, current.etag)
            handler = ClientFileAPI(files, {})
            created, final = handler._atomic_write(path, content, expected_etag=expected,
                                                   create_parents=create_parents)
            return {"created": created, "etag": etag(final), "bytes_written": len(content.encode("utf-8"))}
        if create_parents:
            files.paths.mkdir(path.parent, parents=True, exist_ok=True)
        temp = path.with_name(f".{path.name}.openkapsel-put-{secrets.token_hex(12)}")
        try:
            fd = files.paths.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            task.check_cancelled()
            files._dispatch("rename", {"path": temp.relative_to(files.root).as_posix(),
                                       "destination": path.relative_to(files.root).as_posix(), "overwrite": False})
            with Snapshot(files, path) as final:
                return {"created": True, "etag": final.etag, "bytes_written": final.stat.st_size}
        finally:
            with contextlib.suppress(FileNotFoundError):
                files._dispatch("unlink", {"path": temp.relative_to(files.root).as_posix()})

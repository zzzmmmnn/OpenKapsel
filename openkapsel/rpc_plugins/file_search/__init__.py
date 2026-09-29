"""Cross-platform indexed filename search for server and mapping RPC execution."""

from __future__ import annotations

import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from openkapsel.files.file_support import FileOperationSupportMixin
from openkapsel.rpc_plugins._data import fail, object_schema, response, validate


MAX_QUERY_CHARS = 1024
MAX_RESULTS = 200
MAX_OFFSET = 10_000
SEARCH_TIMEOUT_SECONDS = 10.0

_SEARCH_SCHEMA = object_schema(
    {
        "query": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY_CHARS},
        "path": {"type": "string", "minLength": 1, "maxLength": 4096, "default": "."},
        "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET, "default": 0},
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_RESULTS, "default": 100},
        "case_sensitive": {"type": "boolean", "default": False},
    },
    ("query",),
)
_STATUS_SCHEMA = object_schema({})


def _platform_backend() -> tuple[str | None, str | None]:
    if os.name == "nt":
        return "everything_ipc", None
    if sys.platform == "darwin":
        executable = shutil.which("mdfind")
        return ("mdfind", executable) if executable else (None, None)
    if sys.platform.startswith("linux"):
        executable = shutil.which("plocate")
        return ("plocate", executable) if executable else (None, None)
    return None, None


def _backend_status() -> dict[str, Any]:
    backend, _executable = _platform_backend()
    if backend == "everything_ipc":
        from . import everything_ipc

        details = everything_ipc.status()
        return {"backend": backend, "available": bool(details["running"]), **details}
    if backend is not None:
        return {"backend": backend, "available": True}
    if sys.platform == "darwin":
        return {"backend": "mdfind", "available": False, "reason": "dependency_missing"}
    if sys.platform.startswith("linux"):
        return {"backend": "plocate", "available": False, "reason": "dependency_missing"}
    if os.name == "nt":
        return {"backend": "everything_ipc", "available": False, "reason": "service_unavailable"}
    return {"backend": None, "available": False, "reason": "platform_unsupported"}


def _scope(files, value: str) -> Path:
    path = files.path(value)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = files.paths.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            fail("file_search_scope_not_directory", "search path must identify a directory")
    finally:
        os.close(descriptor)
    return path


def _prefilter_term(query: str) -> str:
    tokens = re.findall(r"\w+", query, flags=re.UNICODE)
    return max(tokens, key=len) if tokens else query


def _plocate_pattern(value: str) -> str:
    result = []
    for char in value:
        if char in "\\*?[]":
            result.append("\\")
        result.append(char)
    return "".join(result)


def _nul_paths(command: list[str], backend: str) -> Iterator[str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        fail("file_search_failed", "indexed search could not open its output pipes", 503)

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    error = bytearray()
    deadline = time.monotonic() + SEARCH_TIMEOUT_SECONDS
    completed = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("file_search_timeout", "indexed search timed out; narrow the query or scope", 504)
            events = selector.select(min(0.1, remaining))
            if not events:
                continue
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    if len(error) < 8192:
                        error.extend(chunk[: 8192 - len(error)])
                    continue
                output.extend(chunk)
                while True:
                    split = output.find(0)
                    if split < 0:
                        break
                    raw = bytes(output[:split])
                    del output[: split + 1]
                    if raw:
                        yield os.fsdecode(raw)

        return_code = process.wait(timeout=1)
        completed = True
        if output:
            yield os.fsdecode(bytes(output))
        if return_code == 0:
            return
        if backend == "plocate" and return_code == 1 and not error.strip():
            return
        fail(
            "file_search_failed",
            f"{backend} indexed search failed",
            503,
            {"backend": backend, "exit_code": return_code},
        )
    finally:
        selector.close()
        if not completed and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        process.stdout.close()
        process.stderr.close()


def _backend_paths(scope: Path, query: str, case_sensitive: bool) -> tuple[str, Iterator[str]]:
    backend, executable = _platform_backend()
    if backend == "everything_ipc":
        from .everything_ipc import EverythingIpcError, query_paths

        def windows_paths():
            try:
                yield from query_paths(
                    str(scope),
                    query,
                    case_sensitive=case_sensitive,
                    timeout_seconds=SEARCH_TIMEOUT_SECONDS,
                )
            except EverythingIpcError as exc:
                fail(
                    "file_search_failed",
                    "Everything IPC search failed",
                    503,
                    {"backend": backend, "error": type(exc).__name__},
                )

        return backend, windows_paths()
    if backend == "mdfind" and executable:
        term = _prefilter_term(query)
        return backend, _nul_paths(
            [executable, "-0", "-onlyin", str(scope), "-name", term],
            backend,
        )
    if backend == "plocate" and executable:
        command = [executable, "-0", "-e"]
        if not case_sensitive:
            command.append("-i")
        command.extend(["--", _plocate_pattern(str(scope)), _plocate_pattern(query)])
        return backend, _nul_paths(command, backend)
    fail("file_search_unavailable", "no indexed filename-search backend is available", 503)


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def _candidate(files, scope: Path, raw: str, query: str, case_sensitive: bool):
    if not raw or _has_surrogate(raw):
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        return None
    candidate = candidate.resolve(strict=False)
    try:
        relative_scope = candidate.relative_to(scope)
        relative_root = candidate.relative_to(files.root)
    except ValueError:
        return None
    if not relative_scope.parts:
        return None

    name = candidate.name
    left = name if case_sensitive else name.casefold()
    right = query if case_sensitive else query.casefold()
    if right not in left:
        return None
    if ".openkapsel" in relative_root.parts:
        return None
    if any(
        FileOperationSupportMixin._is_internal_transfer_name(part)
        for part in relative_root.parts
    ):
        return None
    try:
        files.ensure_accessible_path(candidate)
        details = os.lstat(candidate)
    except OSError:
        return None
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if reparse and getattr(details, "st_file_attributes", 0) & reparse:
        return None
    if stat.S_ISREG(details.st_mode):
        kind = "file"
    elif stat.S_ISDIR(details.st_mode):
        kind = "directory"
    else:
        return None
    return {"path": relative_root.as_posix(), "type": kind}


def _search(files, args):
    query = args["query"]
    if "\x00" in query or "/" in query or "\\" in query:
        fail(
            "invalid_data_arguments",
            "query is a filename fragment and cannot contain path separators",
        )
    scope_arg = args.get("path", ".")
    scope = _scope(files, scope_arg)
    offset = args.get("offset", 0)
    limit = args.get("limit", 100)
    case_sensitive = args.get("case_sensitive", False)
    backend, paths = _backend_paths(scope, query, case_sensitive)

    accepted = []
    seen = set()
    try:
        for raw in paths:
            item = _candidate(files, scope, raw, query, case_sensitive)
            if item is None or item["path"] in seen:
                continue
            seen.add(item["path"])
            accepted.append(item)
            if len(accepted) >= offset + limit + 1:
                break
    finally:
        close = getattr(paths, "close", None)
        if callable(close):
            close()

    selected = accepted[offset : offset + limit]
    truncated = len(accepted) > offset + limit
    return {
        "backend": backend,
        "scope": scope_arg,
        "query": query,
        "case_sensitive": case_sensitive,
        "offset": offset,
        "limit": limit,
        "results": selected,
        "returned": len(selected),
        "truncated": truncated,
        "next_offset": offset + len(selected) if truncated else None,
    }


class FileSearchRpcPlugin:
    family = "file_search"
    version = 1
    default_enabled = True
    description = (
        "Read-only indexed filename search scoped to the selected export. "
        "Uses native Everything IPC on Windows, mdfind on macOS, and plocate on Linux."
    )
    operations = {
        "search": {
            "description": (
                "Find files/directories whose filename contains a literal query string. "
                "Results are export-relative and never escape the requested path scope."
            ),
            "write": False,
            "execution": "sync",
            "input_schema": _SEARCH_SCHEMA,
        },
        "status": {
            "description": "Report the local indexed-search backend and its current availability.",
            "write": False,
            "execution": "sync",
            "input_schema": _STATUS_SCHEMA,
        },
    }

    def probe(self, config):
        details = _backend_status()
        if details["available"]:
            return "available", None, details
        return "unsupported", details.get("reason", "backend_unavailable"), details

    def dispatch(self, files, operation, args):
        def run():
            if operation not in self.operations:
                fail("file_search_operation", "unsupported file-search operation")
            validate(args, self.operations[operation]["input_schema"])
            if operation == "status":
                return _backend_status()
            return _search(files, args)

        return response(run)


plugin = FileSearchRpcPlugin()

"""Cross-platform indexed filename search for server and mapping RPC execution."""

from __future__ import annotations

import fnmatch
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

from openkapsel.errors import ApiError
from openkapsel.files.file_support import FileOperationSupportMixin
from openkapsel.files.find_order import SORT_FIELDS, SORT_ORDERS, FILE_TYPES, TopResults, stat_item
from openkapsel.rpc_plugins._data import fail, object_schema, response, validate


MAX_QUERY_CHARS = 1024
MAX_RESULTS = 1000
MAX_OFFSET = 10_000
DEFAULT_SEARCH_TIMEOUT_SECONDS = 5.0
MAX_SEARCH_TIMEOUT_SECONDS = 60.0

_SEARCH_SCHEMA = object_schema(
    {
        "query": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY_CHARS},
        "path": {"type": "string", "minLength": 1, "maxLength": 4096, "default": "."},
        "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET, "default": 0},
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_RESULTS, "default": 50},
        "case_sensitive": {"type": "boolean", "default": False},
        "mode": {"type": "string", "enum": ["literal", "glob"], "default": "literal"},
        "sort_by": {"type": "string", "enum": list(SORT_FIELDS), "default": "path"},
        "sort_order": {"type": "string", "enum": list(SORT_ORDERS), "default": "asc"},
        "file_type": {"type": "string", "enum": list(FILE_TYPES), "default": "all"},
        "timeout_seconds": {
            "type": "number",
            "minimum": 0.1,
            "maximum": MAX_SEARCH_TIMEOUT_SECONDS,
            "default": DEFAULT_SEARCH_TIMEOUT_SECONDS,
        },
    },
    (),
)
_STATUS_SCHEMA = object_schema({})


def _platform_backend() -> tuple[str | None, str | None]:
    if os.name == "nt":
        return "everything_ipc", None
    if sys.platform == "darwin":
        executable = shutil.which("mdfind")
        return ("mdfind", executable) if executable else (None, None)
    if sys.platform.startswith("linux"):
        from openkapsel.files.filename_index import watcher_available
        return ("sqlite_watch", None) if watcher_available() else (None, None)
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
        return {"backend": "sqlite_watch", "available": False, "reason": "dependency_missing"}
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


def _spotlight_glob_pattern(pattern: str) -> str:
    """Broaden fnmatch-style Glob to Spotlight's '*' wildcard subset.

    '?' and bracket classes are replaced with '*', so Spotlight returns a
    superset; _candidate() applies the original Glob to every resulting name.
    Never treat user input as query expression syntax.
    """
    parts = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "[":
            end = i + 1
            if end < len(pattern) and pattern[end] == "!":
                end += 1
            if end < len(pattern) and pattern[end] == "]":
                end += 1
            end = pattern.find("]", end)
            if end >= 0:
                char = "*"
                i = end
        elif char == "?":
            char = "*"
        parts.append(char)
        i += 1
    return re.sub(r"\*+", "*", "".join(parts))


def _spotlight_glob_query(pattern: str) -> str:
    # Attribute predicates avoid the tokenizing/-name search syntax; flags
    # broaden case/diacritic matching before the exact Python name filter.
    widened = _spotlight_glob_pattern(pattern)
    escaped = widened.replace("\\", "\\\\").replace('"', '\\"')
    return f'kMDItemFSName == "{escaped}"cd'


def _nul_paths(command: list[str], backend: str, timeout_seconds: float) -> Iterator[str]:
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
    deadline = time.monotonic() + timeout_seconds
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


def _backend_paths(
    scope: Path,
    query: str,
    case_sensitive: bool,
    timeout_seconds: float,
    mode: str = "literal",
    sort_by: str = "path",
    sort_order: str = "asc",
    wanted: int | None = None,
) -> tuple[str, Iterator[str]]:
    backend, executable = _platform_backend()
    if backend == "everything_ipc":
        from .everything_ipc import EverythingIpcError, query_paths

        def windows_paths():
            try:
                yield from query_paths(
                    str(scope),
                    query,
                    case_sensitive=case_sensitive,
                    timeout_seconds=timeout_seconds,
                    sort_by=sort_by,
                    sort_order=sort_order,
                    mode=mode,
                    batch_size=min(256, max(1, wanted)) if wanted is not None else 256,
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
        if mode == "glob":
            command = [executable, "-0", "-onlyin", str(scope),
                       _spotlight_glob_query(query)]
        else:
            command = [executable, "-0", "-onlyin", str(scope),
                       "-name", _prefilter_term(query)]
        return backend, _nul_paths(command, backend, timeout_seconds)
    fail("file_search_unavailable", "no indexed filename-search backend is available", 503)


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def _candidate(files, scope: Path, raw: str, query: str, case_sensitive: bool, mode: str = "literal"):
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
    if not (fnmatch.fnmatchcase(left, right) if mode == "glob" else right in left):
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
    return stat_item(relative_root.as_posix(), kind, details)


def _spotlight_name_predicate(query: str, mode: str) -> str:
    if mode == "glob":
        return _spotlight_glob_query(query)
    # Spotlight's free-text -name is not combinable with metadata predicates.
    # An unquoted alphanumeric run is a safe superset of literal substring
    # matches; exact basename matching still happens in _candidate().
    tokens = re.findall(r"\w+", query, flags=re.UNICODE)
    term = max(tokens, key=len, default="")
    escaped = term.replace("\\", "\\\\").replace('"', '\\"')
    return f'kMDItemFSName == "*{escaped}*"cd'


def _search_spotlight_ordered(
    files, scope: Path, scope_arg: str, query: str, mode: str,
    *, case_sensitive: bool, sort_by: str, sort_order: str, file_type: str,
    offset: int, limit: int, timeout_seconds: float,
    executable: str,
):
    """Search disjoint, best-first Spotlight metadata ranges until Top N fits."""
    from .spotlight_adaptive import metadata_windows

    deadline = time.monotonic() + timeout_seconds
    ranked = TopResults(offset + limit, sort_by, sort_order)
    seen = set()
    name_predicate = _spotlight_name_predicate(query, mode)
    timed_out = False
    stopped_early = False
    for predicates, complete in metadata_windows(sort_by, sort_order):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        expression = " && ".join(
            [f"({name_predicate})", *(f"({part})" for part in predicates)]
        )
        paths = _nul_paths(
            [executable, "-0", "-onlyin", str(scope), expression],
            "mdfind", remaining,
        )
        try:
            try:
                for raw in paths:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    item = _candidate(files, scope, raw, query, case_sensitive, mode)
                    if (item is None or item["path"] in seen or
                            file_type not in {"all", item["type"]}):
                        continue
                    seen.add(item["path"])
                    ranked.add(item)
            except ApiError as exc:
                if exc.code != "file_search_timeout":
                    raise
                timed_out = True
        finally:
            close = getattr(paths, "close", None)
            if callable(close):
                close()

        if timed_out:
            break
        if ranked.seen >= offset + limit:
            # Entire metadata window was processed, so equal-primary-key
            # items are ranked with the same deterministic secondary path key.
            stopped_early = not complete
            break
        if complete:
            break

    selected = ranked.results()[offset : offset + limit]
    truncated = ranked.truncated or stopped_early or timed_out
    return {
        "backend": "mdfind",
        "scope": scope_arg, "query": query, "mode": mode,
        "sort_by": sort_by, "sort_order": sort_order, "file_type": file_type,
        "case_sensitive": case_sensitive, "offset": offset, "limit": limit,
        "timeout_seconds": timeout_seconds, "results": selected,
        "returned": len(selected), "truncated": truncated, "timed_out": timed_out,
        "next_offset": offset + len(selected) if truncated else None,
    }


def _search(files, args):
    query = args.get("query", "*")
    if "\x00" in query or "/" in query or "\\" in query:
        fail(
            "invalid_data_arguments",
            "query is a filename fragment and cannot contain path separators",
        )
    scope_arg = args.get("path", ".")
    scope = _scope(files, scope_arg)
    offset = args.get("offset", 0)
    limit = args.get("limit", 50)
    case_sensitive = args.get("case_sensitive", False)
    mode = "glob" if "query" not in args else args.get("mode", "literal")
    sort_by = args.get("sort_by", "path")
    sort_order = args.get("sort_order", "asc")
    file_type = args.get("file_type", "all")
    timeout_seconds = float(
        args.get("timeout_seconds", DEFAULT_SEARCH_TIMEOUT_SECONDS)
    )
    index = getattr(files, "filename_index", None)
    if index is not None and index.ready:
        indexed = index.search(
            scope, query, glob=mode == "glob", case_sensitive=case_sensitive,
            offset=offset, limit=limit, timeout_seconds=timeout_seconds,
            sort_by=sort_by, sort_order=sort_order, file_type=file_type,
            accept=lambda path, kind: _candidate(
                files, scope, str(path), query, case_sensitive, mode
            ),
        )
        if indexed is not None:
            return {
                **indexed, "scope": scope_arg, "query": query,
                "mode": mode, "case_sensitive": case_sensitive,
                "sort_by": sort_by, "sort_order": sort_order, "file_type": file_type,
                "offset": offset, "limit": limit,
                "timeout_seconds": timeout_seconds,
                "returned": len(indexed["results"]),
            }

    platform_backend = _platform_backend()[0]
    if mode == "glob" and platform_backend not in {"mdfind", "everything_ipc"}:
        fail("file_search_unavailable",
             "glob search requires a ready local index or platform search backend", 503)
    if platform_backend == "mdfind" and sort_by in {"modified", "size"}:
        _backend, executable = _platform_backend()
        if executable is not None:
            return _search_spotlight_ordered(
                files, scope, scope_arg, query, mode,
                case_sensitive=case_sensitive, sort_by=sort_by,
                sort_order=sort_order, file_type=file_type,
                offset=offset, limit=limit, timeout_seconds=timeout_seconds,
                executable=executable,
            )
    backend, paths = _backend_paths(
        scope, query, case_sensitive, timeout_seconds, mode=mode,
        sort_by=sort_by, sort_order=sort_order,
        wanted=offset + limit + 1,
    )

    ranked = TopResults(offset + limit, sort_by, sort_order)
    seen = set()
    timed_out = False
    try:
        try:
            for raw in paths:
                item = _candidate(files, scope, raw, query, case_sensitive, mode)
                if item is None or item["path"] in seen or file_type not in {"all", item["type"]}:
                    continue
                seen.add(item["path"])
                ranked.add(item)
                # QUERY2 sorts all native hits by size/mtime before paging.
                # Stop once we see a worse primary key beyond the requested
                # range, but drain equal-key ties to retain deterministic
                # secondary path ordering in our final Top N.
                wanted = offset + limit
                if (backend == "everything_ipc"
                        and sort_by in {"size", "modified"}
                        and ranked.seen > wanted):
                    boundary = ranked.results()[wanted - 1]
                    field = ("size_bytes" if sort_by == "size" else
                             "modified_utc_ns")
                    current_value = item.get(field)
                    boundary_value = boundary.get(field)
                    if (current_value is not None and
                            boundary_value is not None and
                            current_value != boundary_value):
                        break
        except ApiError as exc:
            if exc.code != "file_search_timeout":
                raise
            timed_out = True
    finally:
        close = getattr(paths, "close", None)
        if callable(close):
            close()

    selected = ranked.results()[offset : offset + limit]
    truncated = ranked.truncated or timed_out
    return {
        "backend": backend,
        "scope": scope_arg,
        "query": query,
        "mode": mode,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "file_type": file_type,
        "case_sensitive": case_sensitive,
        "offset": offset,
        "limit": limit,
        "timeout_seconds": timeout_seconds,
        "results": selected,
        "returned": len(selected),
        "truncated": truncated,
        "timed_out": timed_out,
        "next_offset": offset + len(selected) if truncated else None,
    }


class FileSearchRpcPlugin:
    family = "file_search"
    version = 1
    default_enabled = True
    description = (
        "Read-only indexed filename search scoped to the selected export. "
        "Uses native Everything IPC on Windows, mdfind on macOS, and SQLite/watchfiles on Linux."
    )
    operations = {
        "search": {
            "description": (
                "Search export-relative filenames; omit query to match all, or use "
                "mode=literal|glob (* ? []) for name matching. Sort by name/path/size/modified "
                "with sort_order=asc|desc, filter file_type, and set limit (default 50, "
                "maximum 1000) and offset. Results include byte size and UTC timestamps, "
                "stay within the selected export path and mark partial results on timeout."
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
                result = _backend_status()
                index = getattr(files, "filename_index", None)
                if index is not None:
                    result["ready"] = index.ready
                return result
            return _search(files, args)

        return response(run)


plugin = FileSearchRpcPlugin()

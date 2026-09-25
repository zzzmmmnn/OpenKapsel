"""Transactional bounded mutations and explicit large-file range I/O."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openkapsel.errors import ApiError
from openkapsel.files.text_encoding import decode_error, encode_text, text_encoding


SMALL_FILE_MAX_BYTES = 1 * 1024 * 1024
STANDARD_FILE_MAX_BYTES = 32 * 1024 * 1024
LARGE_FILE_WINDOW_MAX_BYTES = 256 * 1024
MUTATION_MAX_ITEMS = 1000
MUTATION_MAX_STAGED_BYTES = 256 * 1024 * 1024


def require_standard_file_size(details, *, operation: str = "this operation") -> None:
    if details.st_size > STANDARD_FILE_MAX_BYTES:
        raise ApiError(
            413,
            "large_file_api_required",
            f"{operation} is limited to files of at most {STANDARD_FILE_MAX_BYTES} bytes; "
            "use the explicit large-file range API",
            {
                "size": details.st_size,
                "standard_file_max_bytes": STANDARD_FILE_MAX_BYTES,
                "large_file_window_max_bytes": LARGE_FILE_WINDOW_MAX_BYTES,
            },
        )


def require_large_file_size(details) -> None:
    if details.st_size <= STANDARD_FILE_MAX_BYTES:
        raise ApiError(
            400,
            "large_file_required",
            "the large-file API is only for files larger than the standard 32 MiB limit",
            {
                "size": details.st_size,
                "standard_file_max_bytes": STANDARD_FILE_MAX_BYTES,
            },
        )


def _required_exact_etag(item: dict[str, Any], label: str) -> str:
    value = item.get("expected_etag")
    if not isinstance(value, str) or not value or value == "*" or any(c in value for c in "\r\n,"):
        raise ApiError(
            400,
            "invalid_request",
            f"{label}.expected_etag must be the exact ETag returned by a prior read; wildcard and null are not allowed",
        )
    return value


def _missing(handler, path: Path) -> bool:
    try:
        handler._file_stat(path)
    except ApiError as exc:
        if exc.code == "path_not_found":
            return True
        raise
    return False


def _read_regular_bytes(handler, path: Path, expected_etag: str) -> tuple[bytes, os.stat_result]:
    with handler._open_binary(path) as handle:
        before = handler._stream_stat(handle)
        if not stat.S_ISREG(before.st_mode):
            raise ApiError(400, "not_a_file", "mutation target is not a regular file")
        require_standard_file_size(before, operation="transactional mutation")
        handler._check_expected_etag(expected_etag, handler._path_etag(path, before))
        raw = handle.read(STANDARD_FILE_MAX_BYTES + 1)
        after = handler._stream_stat(handle)
    if handler._path_etag(path, before) != handler._path_etag(path, after):
        raise ApiError(409, "path_changed", "file changed while preparing the mutation")
    if len(raw) > STANDARD_FILE_MAX_BYTES:
        raise ApiError(413, "large_file_api_required", "file crossed the 32 MiB standard-file limit")
    current = handler._file_stat(path)
    handler._check_expected_etag(expected_etag, handler._path_etag(path, current))
    return raw, current


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\r\n|\r|\n", text))
    return starts


def _line_start_offset(starts: list[int], line: Any, item_index: int) -> tuple[int, int]:
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        raise ApiError(
            400,
            "invalid_line_range",
            f"items[{item_index}].start_line must be a non-negative integer",
        )
    if line >= len(starts):
        raise ApiError(
            400,
            "invalid_line_range",
            f"items[{item_index}].start_line is outside the file",
            {"item_index": item_index, "start_line": line, "line_count": len(starts)},
        )
    return starts[line], line


def _line_end_offset(
    text: str,
    starts: list[int],
    line: Any,
    item_index: int,
) -> tuple[int, int]:
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        raise ApiError(
            400,
            "invalid_line_range",
            f"items[{item_index}].end_line must be a non-negative integer",
        )
    if line >= len(starts):
        raise ApiError(
            400,
            "invalid_line_range",
            f"items[{item_index}].end_line is outside the file",
            {"item_index": item_index, "end_line": line, "line_count": len(starts)},
        )
    offset = starts[line + 1] if line + 1 < len(starts) else len(text)
    return offset, line


def _unique_text_marker(
    text: str,
    marker: Any,
    field: str,
    item_index: int,
) -> tuple[int, int]:
    if not isinstance(marker, str) or not marker:
        raise ApiError(
            400,
            "invalid_text_marker",
            f"items[{item_index}].{field} must be a non-empty string",
        )
    first = text.find(marker)
    if first < 0:
        raise ApiError(
            409,
            "text_marker_not_unique",
            f"items[{item_index}].{field} must occur exactly once in the full file; found 0 matches",
            {"item_index": item_index, "field": field, "matches": 0},
        )
    if text.find(marker, first + 1) >= 0:
        raise ApiError(
            409,
            "text_marker_not_unique",
            f"items[{item_index}].{field} must occur exactly once in the full file; found multiple matches",
            {"item_index": item_index, "field": field, "matches": "multiple"},
        )
    return first, first + len(marker)


def _text_window(
    text: str,
    item_index: int,
    *,
    start_line: Any = None,
    end_line: Any = None,
    start_text: Any = None,
    end_text: Any = None,
) -> tuple[int, int, dict[str, Any]]:
    if start_text is not None and start_line is not None:
        raise ApiError(
            400,
            "text_range_selector_conflict",
            f"items[{item_index}] cannot specify both start_line and start_text",
        )
    if end_text is not None and end_line is not None:
        raise ApiError(
            400,
            "text_range_selector_conflict",
            f"items[{item_index}] cannot specify both end_line and end_text",
        )

    starts = _line_starts(text)
    details: dict[str, Any] = {"item_index": item_index}

    if start_text is not None:
        _marker_start, range_start = _unique_text_marker(
            text, start_text, "start_text", item_index
        )
        details["start_selector"] = "text"
    else:
        resolved_start = 0 if start_line is None else start_line
        range_start, resolved_start = _line_start_offset(
            starts, resolved_start, item_index
        )
        details["start_selector"] = "line"
        details["start_line"] = resolved_start

    if end_text is not None:
        range_end, _marker_end = _unique_text_marker(
            text, end_text, "end_text", item_index
        )
        details["end_selector"] = "text"
    else:
        resolved_end = len(starts) - 1 if end_line is None else end_line
        range_end, resolved_end = _line_end_offset(
            text, starts, resolved_end, item_index
        )
        details["end_selector"] = "line"
        details["end_line"] = resolved_end

    if (
        details["start_selector"] == "line"
        and details["end_selector"] == "line"
        and details["end_line"] < details["start_line"]
    ):
        raise ApiError(
            400,
            "invalid_line_range",
            f"items[{item_index}] end_line must not be before start_line",
            details,
        )
    if range_start > range_end:
        raise ApiError(
            400,
            "invalid_text_range",
            f"items[{item_index}] resolved text range starts after it ends",
            {
                **details,
                "start_offset": range_start,
                "end_offset": range_end,
            },
        )
    return range_start, range_end, details


def _apply_text_replacements(
    text: str,
    replacements: Any,
    item_index: int,
    *,
    start_line: Any = None,
    end_line: Any = None,
    start_text: Any = None,
    end_text: Any = None,
) -> tuple[str, int]:
    if not isinstance(replacements, list) or not replacements:
        raise ApiError(400, "invalid_request", f"items[{item_index}].replacements must be a non-empty array")
    range_start, range_end, range_details = _text_window(
        text,
        item_index,
        start_line=start_line,
        end_line=end_line,
        start_text=start_text,
        end_text=end_text,
    )
    selected = text[range_start:range_end]
    spans: list[tuple[int, int, str, int]] = []
    total = 0
    for replacement_index, replacement in enumerate(replacements):
        if not isinstance(replacement, dict):
            raise ApiError(
                400,
                "invalid_request",
                f"items[{item_index}].replacements[{replacement_index}] must be an object",
            )
        old = replacement.get("old")
        new = replacement.get("new")
        expected_count = replacement.get("expected_count", 1)
        if not isinstance(old, str) or not old:
            raise ApiError(400, "invalid_request", "replacement old must be a non-empty string")
        if not isinstance(new, str):
            raise ApiError(400, "invalid_request", "replacement new must be a string")
        if isinstance(expected_count, bool) or not isinstance(expected_count, int) or expected_count < 1:
            raise ApiError(400, "invalid_request", "expected_count must be a positive integer")
        actual = selected.count(old)
        if actual != expected_count:
            raise ApiError(
                409,
                "match_count_mismatch",
                f"items[{item_index}].replacements[{replacement_index}] expected "
                f"{expected_count} exact match(es), found {actual}",
                {
                    "item_index": item_index,
                    "replacement_index": replacement_index,
                    "expected": expected_count,
                    "actual": actual,
                    **range_details,
                },
            )
        cursor = 0
        for _ in range(actual):
            position = selected.find(old, cursor)
            absolute = range_start + position
            spans.append((absolute, absolute + len(old), new, replacement_index))
            cursor = position + len(old)
        total += actual
    spans.sort(key=lambda value: (value[0], value[1], value[3]))
    for previous, current in zip(spans, spans[1:]):
        if current[0] < previous[1]:
            raise ApiError(
                400,
                "overlapping_replacements",
                "replacement source ranges must not overlap",
                {
                    "item_index": item_index,
                    "first_replacement_index": previous[3],
                    "second_replacement_index": current[3],
                },
            )
    chunks: list[str] = []
    cursor = 0
    for start, end, new, _index in spans:
        chunks.append(text[cursor:start])
        chunks.append(new)
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks), total


def _structured_format(path: Path, requested: Any) -> str:
    if requested is not None:
        if requested not in {"json", "yaml", "toml"}:
            raise ApiError(400, "invalid_request", "structured format must be json, yaml or toml")
        return requested
    value = {".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml"}.get(path.suffix.lower())
    if value is None:
        raise ApiError(400, "structured_format_required", "specify json, yaml or toml for this suffix")
    return value


def _apply_structured_patch(text: str, path: Path, item: dict[str, Any]) -> str:
    from openkapsel.rpc_plugins._data import json_view
    from openkapsel.rpc_plugins.structured import _apply, _equal, _parse

    operations = item.get("operations")
    if not isinstance(operations, list) or not operations or len(operations) > 100:
        raise ApiError(400, "invalid_request", "structured operations must contain between 1 and 100 entries")
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) - {"op", "path", "value"}:
            raise ApiError(400, "invalid_request", "structured operations contain an invalid entry")
        if operation.get("op") not in {"test", "add", "replace", "remove"}:
            raise ApiError(400, "invalid_request", "structured operation op is invalid")
        if not isinstance(operation.get("path"), str):
            raise ApiError(400, "invalid_request", "structured operation path must be a string")
    fmt = _structured_format(path, item.get("format"))
    doc, dump, aliases = _parse(text, fmt)
    if aliases:
        raise ApiError(
            409,
            "structured_yaml_alias_edit",
            "YAML aliases or merge keys require an explicit whole-document replacement",
        )
    edited = _apply(doc, operations)
    json_view(edited)
    if _equal(doc, edited):
        return text
    updated = dump(edited)
    if text.endswith(("\n", "\r")) and not updated.endswith("\n"):
        updated += "\n"
    if "\r\n" in text and "\n" not in text.replace("\r\n", ""):
        updated = updated.replace("\r\n", "\n").replace("\n", "\r\n")
    if text.startswith("\ufeff"):
        updated = "\ufeff" + updated
    _parse(updated, fmt)
    return updated


@dataclass
class MutationPlan:
    index: int
    requested_path: str
    path: Path
    operation: str
    expected_etag: str | None
    before_etag: str | None
    data: bytes
    mode: int
    stage: Path | None = None
    backup: Path | None = None
    replacements: int = 0
    changed: bool = True
    deleted: bool = False
    published: bool = False
    published_etag: str | None = None
    backed_up: bool = False
    recycle_id: str | None = None


def _stage_bytes(handler, plan: MutationPlan, transaction_id: str) -> None:
    stage = plan.path.with_name(
        f".{plan.path.name}.openkapsel-put-txn-{transaction_id}-{plan.index}"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    fd = handler._safe_path_access().open(stage, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(plan.data)
            stream.flush()
            os.fsync(stream.fileno())
            if hasattr(os, "fchmod"):
                try:
                    os.fchmod(stream.fileno(), plan.mode)
                except OSError:
                    pass
    finally:
        if fd >= 0:
            os.close(fd)
    plan.stage = stage
    if plan.expected_etag is not None:
        plan.backup = plan.path.with_name(
            f".{plan.path.name}.openkapsel-transfer-txn-{transaction_id}-{plan.index}"
        )


def _cleanup(path: Path | None) -> None:
    if path is None:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _plan_item(handler, item: Any, index: int) -> MutationPlan:
    if not isinstance(item, dict):
        raise ApiError(400, "invalid_request", f"items[{index}] must be an object")
    requested_path = item.get("path")
    operation = item.get("op")
    if not isinstance(requested_path, str) or not requested_path:
        raise ApiError(400, "invalid_request", f"items[{index}].path must be a non-empty string")
    if operation not in {"text.replace", "structured.patch", "file.create", "file.replace", "path.delete"}:
        raise ApiError(
            400,
            "invalid_request",
            f"items[{index}].op must be text.replace, structured.patch, file.create, file.replace or path.delete",
        )
    path = handler._resolve_path(requested_path, write=True)

    if operation == "file.create":
        if item.get("create_parents") not in {None, False}:
            raise ApiError(
                400,
                "invalid_request",
                "transactional file.create does not create parent directories; create them explicitly first",
            )
        if not _missing(handler, path):
            raise ApiError(409, "path_exists", f"items[{index}] create target already exists")
        content = item.get("content")
        if not isinstance(content, str):
            raise ApiError(400, "invalid_request", f"items[{index}].content must be a string")
        encoding = text_encoding(item.get("encoding", "utf-8"))
        data = encode_text(content, encoding)
        if len(data) > STANDARD_FILE_MAX_BYTES:
            raise ApiError(413, "large_file_api_required", "created standard files may not exceed 32 MiB")
        return MutationPlan(index, requested_path, path, operation, None, None, data, 0o600)

    expected_etag = _required_exact_etag(item, f"items[{index}]")
    if operation == "path.delete":
        try:
            path.relative_to(handler.token_scope_root)
        except ValueError:
            raise ApiError(
                403,
                "outside_delete_not_supported",
                "recoverable delete is only available inside the token workspace",
            ) from None
        if path == handler.token_scope_root:
            raise ApiError(403, "root_protected", "the workspace root cannot be deleted")
        storage_providers = getattr(handler.server, "storage_providers", None)
        if storage_providers is not None and storage_providers.is_mapping_root(path):
            raise ApiError(403, "storage_mapping_root_protected", "a Storage Provider mapping root cannot be deleted")
        details = handler._file_stat(path)
        if not (stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)):
            raise ApiError(400, "unsupported_path_type", "transactional delete supports regular files and directories")
        before_etag = handler._path_etag(path, details)
        handler._check_expected_etag(expected_etag, before_etag)
        return MutationPlan(
            index,
            requested_path,
            path,
            operation,
            expected_etag,
            before_etag,
            b"",
            details.st_mode & 0o777,
            deleted=True,
        )

    raw, details = _read_regular_bytes(handler, path, expected_etag)
    before_etag = handler._path_etag(path, details)
    mode = details.st_mode & 0o777

    if operation == "file.replace":
        content = item.get("content")
        if not isinstance(content, str):
            raise ApiError(400, "invalid_request", f"items[{index}].content must be a string")
        encoding = text_encoding(item.get("encoding", "utf-8"))
        data = encode_text(content, encoding)
        replacements = 0
    elif operation == "text.replace":
        encoding = text_encoding(item.get("encoding", "utf-8"))
        try:
            text = raw.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            raise decode_error(encoding) from None
        updated, replacements = _apply_text_replacements(
            text,
            item.get("replacements"),
            index,
            start_line=item.get("start_line"),
            end_line=item.get("end_line"),
            start_text=item.get("start_text"),
            end_text=item.get("end_text"),
        )
        data = encode_text(updated, encoding)
    else:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ApiError(415, "structured_encoding", "structured files must be UTF-8") from None
        updated = _apply_structured_patch(text, path, item)
        data = updated.encode("utf-8")
        replacements = len(item["operations"])

    if len(data) > STANDARD_FILE_MAX_BYTES:
        raise ApiError(
            413,
            "large_file_api_required",
            "transactional mutation cannot grow a standard file beyond 32 MiB",
        )
    return MutationPlan(
        index,
        requested_path,
        path,
        operation,
        expected_etag,
        before_etag,
        data,
        mode,
        replacements=replacements,
        changed=data != raw,
    )


def _revalidate(handler, plans: list[MutationPlan]) -> None:
    for plan in plans:
        if plan.expected_etag is None:
            if not _missing(handler, plan.path):
                raise ApiError(
                    409,
                    "mutation_precondition_failed",
                    "no files were changed because a create target now exists",
                    {"index": plan.index, "path": plan.requested_path, "reason": "path_exists"},
                )
            continue
        current = handler._file_stat(plan.path)
        current_etag = handler._path_etag(plan.path, current)
        if current_etag != plan.expected_etag:
            raise ApiError(
                409,
                "mutation_precondition_failed",
                "no files were changed because a source changed after preflight",
                {
                    "index": plan.index,
                    "path": plan.requested_path,
                    "reason": "etag_mismatch",
                    "expected_etag": plan.expected_etag,
                    "actual_etag": current_etag,
                },
            )


def _rollback(handler, plans: list[MutationPlan]) -> None:
    failures: list[str] = []
    paths = handler._safe_path_access()
    for plan in reversed(plans):
        try:
            if plan.deleted and plan.recycle_id is not None:
                handler._transaction_restore_recycle(plan.recycle_id)
                plan.recycle_id = None
                plan.published = False
                plan.backed_up = False
                continue
            if plan.published and plan.stage is not None:
                current = handler._file_stat(plan.path)
                current_etag = handler._path_etag(plan.path, current)
                if plan.published_etag is None or current_etag != plan.published_etag:
                    failures.append(plan.requested_path)
                    continue
                paths.rename(plan.path, plan.stage, overwrite=False, create_parents=False)
                plan.published = False
            if plan.backed_up and plan.backup is not None:
                paths.rename(plan.backup, plan.path, overwrite=False, create_parents=False)
                plan.backed_up = False
                plan.published = False
        except Exception:
            failures.append(plan.requested_path)
    if failures:
        raise ApiError(
            500,
            "mutation_rollback_failed",
            "transaction rollback refused to overwrite a concurrently changed path or could not restore an original; recovery artifacts were preserved",
            {"paths": sorted(set(failures))},
        )


def _transaction_domain(handler, path: Path) -> Path:
    """Return the authorized root defining one local transaction domain."""
    paths = handler._safe_path_access()
    anchor = getattr(paths, "anchor", None)
    if callable(anchor):
        root, _parts = anchor(path)
        return Path(root)
    root = getattr(paths, "root", None)
    if root is not None:
        try:
            path.relative_to(root)
        except ValueError:
            raise ApiError(
                409,
                "transaction_domain_mismatch",
                "transaction path is outside the active filesystem domain",
            ) from None
        return Path(root)
    return Path(handler.token_scope_root)


def execute_mutation(handler, body: dict[str, Any]) -> dict[str, Any]:
    items = body.get("items")
    if not isinstance(items, list) or not items:
        raise ApiError(400, "invalid_request", "items must be a non-empty array")
    if len(items) > min(MUTATION_MAX_ITEMS, handler.server.config.max_batch_file_operations):
        raise ApiError(400, "batch_too_large", "transaction contains too many file items")
    dry_run = body.get("dry_run", False)
    if not isinstance(dry_run, bool):
        raise ApiError(400, "invalid_request", "dry_run must be boolean")

    plans: list[MutationPlan] = []
    seen: set[Path] = set()
    transaction_domain: Path | None = None
    total_staged = 0
    transaction_id = secrets.token_hex(12)
    preserve_artifacts = False
    try:
        for index, item in enumerate(items):
            plan = _plan_item(handler, item, index)
            item_domain = _transaction_domain(handler, plan.path)
            if transaction_domain is None:
                transaction_domain = item_domain
            elif item_domain != transaction_domain:
                raise ApiError(
                    409,
                    "transaction_domain_mismatch",
                    "one mutation request cannot span multiple authorized filesystem roots",
                    {
                        "first_root": str(transaction_domain),
                        "conflicting_root": str(item_domain),
                    },
                )
            if plan.path in seen:
                raise ApiError(400, "duplicate_path", f"items[{index}] resolves to a duplicate path")
            for previous in plans:
                if (plan.deleted or previous.deleted) and (
                    plan.path in previous.path.parents or previous.path in plan.path.parents
                ):
                    raise ApiError(
                        400,
                        "overlapping_paths",
                        "transactional delete paths may not contain another mutation path",
                        {"first": previous.requested_path, "second": plan.requested_path},
                    )
            seen.add(plan.path)
            total_staged += len(plan.data)
            if total_staged > MUTATION_MAX_STAGED_BYTES:
                raise ApiError(
                    413,
                    "mutation_too_large",
                    "transaction after-images exceed the 256 MiB staging limit",
                    {"maximum": MUTATION_MAX_STAGED_BYTES, "actual": total_staged},
                )
            plans.append(plan)

        if dry_run:
            _revalidate(handler, plans)
            return {
                "committed": False,
                "dry_run": True,
                "items": [
                    {
                        "index": plan.index,
                        "path": plan.requested_path,
                        "op": plan.operation,
                        "changed": plan.changed,
                        "bytes_after": 0 if plan.deleted else len(plan.data),
                        **({"deleted": True} if plan.deleted else {}),
                        **({"replacements": plan.replacements} if plan.replacements else {}),
                    }
                    for plan in plans
                ],
                "total": len(plans),
            }

        for plan in plans:
            if plan.deleted:
                plan.backup = plan.path.with_name(
                    f".{plan.path.name}.openkapsel-transfer-txn-{transaction_id}-{plan.index}"
                )
            elif plan.changed or plan.expected_etag is None:
                _stage_bytes(handler, plan, transaction_id)

        _revalidate(handler, plans)
        paths = handler._safe_path_access()
        try:
            for plan in plans:
                if not plan.changed and plan.expected_etag is not None:
                    continue
                if plan.expected_etag is not None:
                    assert plan.backup is not None
                    paths.rename(plan.path, plan.backup, overwrite=False, create_parents=False)
                    plan.backed_up = True
                    backup_details = handler._file_stat(plan.backup)
                    backup_etag = handler._path_etag(plan.backup, backup_details)
                    if backup_etag != plan.expected_etag:
                        raise ApiError(
                            409,
                            "mutation_precondition_failed",
                            "source changed during commit; transaction was rolled back",
                            {"index": plan.index, "path": plan.requested_path},
                        )
                if plan.deleted:
                    plan.published = True
                    continue
                assert plan.stage is not None
                staged = handler._file_stat(plan.stage)
                staged_etag = handler._path_etag(plan.stage, staged)
                paths.rename(plan.stage, plan.path, overwrite=False, create_parents=False)
                plan.published = True
                plan.published_etag = staged_etag

            for plan in plans:
                if not plan.deleted:
                    continue
                assert plan.backup is not None
                recycled = handler._transaction_recycle(plan.backup, plan.path)
                recycle_id = recycled.get("recycle_id")
                if not isinstance(recycle_id, str) or not recycle_id:
                    raise ApiError(500, "invalid_recycle_result", "transactional delete did not return a recycle id")
                plan.recycle_id = recycle_id
                plan.backed_up = False
        except Exception:
            try:
                _rollback(handler, plans)
            except ApiError:
                preserve_artifacts = True
                raise
            raise

        results = []
        for plan in plans:
            if plan.deleted:
                results.append(
                    {
                        "index": plan.index,
                        "path": plan.requested_path,
                        "op": plan.operation,
                        "changed": True,
                        "deleted": True,
                        "recycled": True,
                        "recycle_id": plan.recycle_id,
                    }
                )
                continue
            final = handler._file_stat(plan.path)
            results.append(
                {
                    "index": plan.index,
                    "path": plan.requested_path,
                    "op": plan.operation,
                    "changed": plan.changed,
                    "etag": handler._path_etag(plan.path, final),
                    "size": final.st_size,
                    **({"replacements": plan.replacements} if plan.replacements else {}),
                }
            )
        return {
            "committed": True,
            "dry_run": False,
            "items": results,
            "total": len(results),
            "changed": sum(1 for item in results if item["changed"]),
            "transaction_scope": "single_backend_request",
        }
    finally:
        if not preserve_artifacts:
            for plan in plans:
                _cleanup(plan.stage)
                _cleanup(plan.backup)


def read_large_range(handler, body: dict[str, Any]) -> dict[str, Any]:
    requested = body.get("path")
    offset = body.get("offset")
    length = body.get("length")
    if not isinstance(requested, str) or not requested:
        raise ApiError(400, "invalid_request", "path must be a non-empty string")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ApiError(400, "invalid_request", "offset must be a non-negative integer")
    if (
        isinstance(length, bool)
        or not isinstance(length, int)
        or not 1 <= length <= LARGE_FILE_WINDOW_MAX_BYTES
    ):
        raise ApiError(
            400,
            "invalid_request",
            f"length must be between 1 and {LARGE_FILE_WINDOW_MAX_BYTES} bytes",
        )
    path = handler._resolve_path(requested)
    with handler._open_binary(path) as handle:
        before = handler._stream_stat(handle)
        if not stat.S_ISREG(before.st_mode):
            raise ApiError(400, "not_a_file", "path is not a regular file")
        require_large_file_size(before)
        if offset > before.st_size:
            raise ApiError(416, "invalid_offset", "offset is beyond the end of the file", {"size": before.st_size})
        handle.seek(offset)
        data = handle.read(length)
        after = handler._stream_stat(handle)
    if handler._path_etag(path, before) != handler._path_etag(path, after):
        raise ApiError(409, "path_changed", "large file changed during range read")
    current = handler._file_stat(path)
    if handler._path_etag(path, current) != handler._path_etag(path, before):
        raise ApiError(409, "path_changed", "large file path changed during range read")
    next_offset = offset + len(data)
    return {
        "path": requested,
        "offset": offset,
        "length": length,
        "bytes_read": len(data),
        "data_base64": base64.b64encode(data).decode("ascii"),
        "range_sha256": hashlib.sha256(data).hexdigest(),
        "etag": handler._path_etag(path, before),
        "size": before.st_size,
        "next_offset": next_offset,
        "eof": next_offset >= before.st_size,
    }


def replace_large_range(handler, body: dict[str, Any]) -> dict[str, Any]:
    requested = body.get("path")
    offset = body.get("offset")
    length = body.get("length")
    expected_sha256 = body.get("expected_range_sha256")
    expected_etag = _required_exact_etag(body, "request")
    encoded = body.get("data_base64")
    if not isinstance(requested, str) or not requested:
        raise ApiError(400, "invalid_request", "path must be a non-empty string")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ApiError(400, "invalid_request", "offset must be a non-negative integer")
    if (
        isinstance(length, bool)
        or not isinstance(length, int)
        or not 1 <= length <= LARGE_FILE_WINDOW_MAX_BYTES
    ):
        raise ApiError(
            400,
            "invalid_request",
            f"length must be between 1 and {LARGE_FILE_WINDOW_MAX_BYTES} bytes",
        )
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256)
    ):
        raise ApiError(400, "invalid_request", "expected_range_sha256 must be 64 hexadecimal characters")
    if not isinstance(encoded, str):
        raise ApiError(400, "invalid_request", "data_base64 must be a string")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(400, "invalid_base64", "data_base64 is not valid Base64") from None
    if len(data) != length:
        raise ApiError(
            400,
            "large_file_length_mismatch",
            "large-file replacement must contain exactly length bytes; file size changes are forbidden",
            {"length": length, "decoded_bytes": len(data)},
        )

    path = handler._resolve_path(requested, write=True)
    descriptor = handler._safe_open_descriptor(path, os.O_RDWR)
    old = b""
    try:
        with os.fdopen(descriptor, "r+b", buffering=0) as handle:
            descriptor = -1
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ApiError(400, "not_a_file", "path is not a regular file")
            require_large_file_size(before)
            handler._check_expected_etag(expected_etag, handler._path_etag(path, before))
            if offset + length > before.st_size:
                raise ApiError(
                    416,
                    "invalid_range",
                    "replacement range extends beyond the end of the file",
                    {"size": before.st_size, "offset": offset, "length": length},
                )
            handle.seek(offset)
            old = handle.read(length)
            actual_sha256 = hashlib.sha256(old).hexdigest()
            if actual_sha256.lower() != expected_sha256.lower():
                raise ApiError(
                    409,
                    "range_sha256_mismatch",
                    "large-file range changed since it was read; no bytes were written",
                    {
                        "expected_range_sha256": expected_sha256.lower(),
                        "actual_range_sha256": actual_sha256,
                    },
                )
            prewrite = os.fstat(handle.fileno())
            before_etag = handler._path_etag(path, before)
            if handler._path_etag(path, prewrite) != before_etag:
                raise ApiError(
                    409,
                    "path_changed",
                    "large file changed after its range was verified; no bytes were written",
                )
            current = handler._file_stat(path)
            if handler._path_etag(path, current) != before_etag:
                raise ApiError(
                    409,
                    "path_changed",
                    "large file path was replaced after its range was verified; no bytes were written",
                )
            try:
                handle.seek(offset)
                view = memoryview(data)
                written = 0
                while written < length:
                    count = handle.write(view[written:])
                    if not count:
                        raise OSError("short large-file write")
                    written += count
                handle.flush()
                os.fsync(handle.fileno())
                final = os.fstat(handle.fileno())
                if final.st_size != before.st_size:
                    raise OSError("large-file replacement changed file size")
                handle.seek(offset)
                verified = handle.read(length)
                if verified != data:
                    raise OSError("large-file replacement verification failed")
            except Exception:
                try:
                    handle.seek(offset)
                    view = memoryview(old)
                    restored = 0
                    while restored < length:
                        count = handle.write(view[restored:])
                        if not count:
                            raise OSError("short rollback write")
                        restored += count
                    handle.flush()
                    os.fsync(handle.fileno())
                except Exception as rollback_error:
                    raise ApiError(
                        500,
                        "large_file_rollback_failed",
                        "large-file range write failed and rollback could not be verified",
                    ) from rollback_error
                raise
            final = os.fstat(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return {
        "path": requested,
        "offset": offset,
        "length": length,
        "bytes_written": length,
        "range_sha256": hashlib.sha256(data).hexdigest(),
        "etag": handler._path_etag(path, final),
        "size": final.st_size,
    }

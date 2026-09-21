"""Guarded JSON/YAML/TOML reads and optimistic, atomic structured edits."""
from __future__ import annotations

import copy
import difflib
import importlib.util
import io
import json
import re
from collections.abc import Mapping, MutableSequence

from openkapsel.errors import ApiError
from .._data import (MAX_NODES, MAX_DEPTH, Snapshot, check_etag, commit_text, export_path,
                     fail, json_view, object_schema, response, validate)

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_PATCH_OPERATIONS = 100
FORMATS = ("json", "yaml", "toml")


def _installed(module):
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def _format(path, requested=None):
    if requested is not None:
        return requested
    fmt = {".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml"}.get(path.suffix.lower())
    if fmt is None:
        fail("structured_format_required", "specify json, yaml or toml for this suffix")
    return fmt


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("structured_duplicate_key", "duplicate JSON object keys are not accepted", 422)
        result[key] = value
    return result


def _parse(text, fmt):
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        fail("structured_size_limit", "configuration exceeds the 2 MiB document limit", 413)
    source = text.removeprefix("\ufeff")
    aliases = False
    try:
        if fmt == "json":
            def constant(_value):
                fail("data_nonfinite", "JSON NaN and Infinity are not accepted", 422)
            doc = json.loads(source, object_pairs_hook=_pairs, parse_constant=constant)
            indent_match = re.search(r"\n([ \t]+)\S", source)
            indent = indent_match.group(1) if indent_match else None
            def dump(value):
                return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=indent,
                                  separators=(",", ":") if indent is None else (",", ": "))
        elif fmt == "yaml":
            if not _installed("ruamel.yaml"):
                fail("structured_dependency_missing", "YAML needs the optional ruamel.yaml dependency", 415)
            from ruamel.yaml import YAML
            from ruamel.yaml.events import AliasEvent, CollectionStartEvent, CollectionEndEvent, ScalarEvent
            parser = YAML(typ="rt", pure=True)
            count = depth = alias_count = 0
            active_anchors = []
            safe_tags = {"tag:yaml.org,2002:" + k for k in ("str", "null", "bool", "int", "float", "seq", "map", "timestamp")}
            for event in parser.parse(source):
                count += 1
                if isinstance(event, CollectionStartEvent):
                    depth += 1
                    active_anchors.append(event.anchor)
                elif isinstance(event, CollectionEndEvent):
                    depth -= 1
                    active_anchors.pop()
                elif isinstance(event, AliasEvent):
                    if event.anchor in active_anchors:
                        fail("data_cycle", "cyclic YAML aliases are not supported", 422)
                    aliases = True
                    alias_count += 1
                if count > MAX_NODES or depth > MAX_DEPTH or alias_count > 64:
                    fail("structured_yaml_limit", "YAML event, nesting or alias limit exceeded", 413)
                tag = getattr(event, "tag", None)
                if tag is not None and tag not in safe_tags:
                    fail("structured_yaml_tag", "custom or executable YAML tags are not supported", 422)
                if isinstance(event, ScalarEvent) and event.value == "<<" and event.style is None:
                    aliases = True  # Merge-key edits need an explicit document replacement.
            parser = YAML(typ="rt", pure=True)
            parser.preserve_quotes = True
            parser.allow_duplicate_keys = False
            doc = parser.load(source)
            def dump(value):
                output = io.StringIO()
                parser.dump(value, output)
                return output.getvalue()
        else:
            if not _installed("tomlkit"):
                fail("structured_dependency_missing", "TOML needs the optional tomlkit dependency", 415)
            import tomlkit
            doc = tomlkit.parse(source)
            dump = tomlkit.dumps
        json_view(doc)  # Reject excessive/cyclic/non-JSON-shaped input before editing.
        return doc, dump, aliases
    except ApiError:
        raise
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        fail("structured_invalid", f"invalid or unsupported {fmt.upper()} document", 422,
             {"error_type": type(exc).__name__})
    except Exception as exc:
        # Parser exceptions can contain source text and host paths. Do not echo them.
        if type(exc).__module__.startswith(("ruamel.", "tomlkit.")):
            fail("structured_invalid", f"invalid or unsupported {fmt.upper()} document", 422,
                 {"error_type": type(exc).__name__})
        raise


def _tokens(pointer):
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        fail("structured_pointer_invalid", "use an RFC 6901 JSON Pointer, or the empty string for root")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _index(part, length, *, append=False):
    if part == "-" and append:
        return length
    if not re.fullmatch(r"0|[1-9][0-9]*", part) or len(part) > 10:
        fail("structured_pointer_invalid", "array indices must be nonnegative integers without leading zeros")
    value = int(part)
    if value >= length + int(append):
        fail("structured_pointer_missing", "array index is outside the selected value", 404)
    return value


def _at(doc, parts):
    for part in parts:
        if isinstance(doc, Mapping):
            if part not in doc:
                fail("structured_pointer_missing", "selected object key does not exist", 404)
            doc = doc[part]
        elif isinstance(doc, MutableSequence):
            doc = doc[_index(part, len(doc))]
        else:
            fail("structured_pointer_missing", "pointer traverses a scalar", 404)
    return doc


def _equal(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return left.keys() == right.keys() and all(_equal(left[k], right[k]) for k in left)
    if isinstance(left, MutableSequence) and isinstance(right, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    return left == right


def _apply(doc, operations):
    doc = copy.deepcopy(doc)
    for operation in operations:
        kind = operation["op"]
        parts = _tokens(operation["path"])
        if kind in {"test", "add", "replace"} and "value" not in operation:
            fail("structured_patch_invalid", "test/add/replace requires value")
        if kind == "remove" and "value" in operation:
            fail("structured_patch_invalid", "remove does not accept value")
        if kind == "test":
            if not _equal(_at(doc, parts), operation["value"]):
                fail("structured_test_failed", "patch test precondition failed; no changes were written", 409,
                     {"pointer": operation["path"]})
            continue
        if not parts:
            if kind == "remove":
                fail("structured_patch_root", "removing the entire document requires the recoverable file-delete API")
            doc = copy.deepcopy(operation["value"])
            continue
        parent = _at(doc, parts[:-1])
        key = parts[-1]
        value = copy.deepcopy(operation.get("value"))
        if isinstance(parent, Mapping):
            if kind != "add" and key not in parent:
                fail("structured_pointer_missing", "patch target does not exist", 404)
            if kind == "remove":
                del parent[key]
            else:
                parent[key] = value
        elif isinstance(parent, MutableSequence):
            index = _index(key, len(parent), append=kind == "add")
            if kind == "remove":
                del parent[index]
            elif kind == "add":
                parent.insert(index, value)
            else:
                parent[index] = value
        else:
            fail("structured_pointer_missing", "patch parent is not an object or array", 404)
    return doc


def _read_document(files, args):
    path = export_path(files, args["path"])
    fmt = _format(path, args.get("format"))
    with Snapshot(files, path, max_bytes=MAX_DOCUMENT_BYTES) as snap:
        check_etag(args.get("expected_etag"), snap.etag)
        raw = snap.stream.read(MAX_DOCUMENT_BYTES + 1)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("structured_encoding", "configuration files must be UTF-8 (optional BOM)", 415)
        doc, dump, aliases = _parse(text, fmt)
        snap.verify()
        return path, fmt, text, doc, dump, aliases, snap.etag


def _edited(files, args):
    path, fmt, text, doc, dump, aliases, current_etag = _read_document(files, args)
    if aliases:
        fail("structured_yaml_alias_edit", "use explicit write to replace YAML with aliases/merge keys; patch would change shared semantics", 409)
    try:
        edited = _apply(doc, args["operations"])
        json_view(edited)
        if _equal(doc, edited):
            updated = text
        else:
            updated = dump(edited)
            if text.endswith(("\n", "\r")) and not updated.endswith("\n"):
                updated += "\n"
            if "\r\n" in text and "\n" not in text.replace("\r\n", ""):
                updated = updated.replace("\r\n", "\n").replace("\n", "\r\n")
            if text.startswith("\ufeff"):
                updated = "\ufeff" + updated
            _parse(updated, fmt)  # TOML cannot encode null or a non-table root.
    except ApiError:
        raise
    except (ValueError, TypeError) as exc:
        fail("structured_value_unsupported", "patch value cannot be represented in the target format", 422,
             {"error_type": type(exc).__name__})
    return path, fmt, text, updated, current_etag


_PATH = {"path": {"type": "string", "minLength": 1, "maxLength": 4096},
         "format": {"type": "string", "enum": list(FORMATS)},
         "expected_etag": {"type": "string", "minLength": 1, "maxLength": 128}}
_PATCH = {**_PATH, "operations": {"type": "array", "minItems": 1, "maxItems": MAX_PATCH_OPERATIONS,
          "items": object_schema({"op": {"type": "string", "enum": ["test", "add", "replace", "remove"]},
                                  "path": {"type": "string", "maxLength": 4096}, "value": {}}, ("op", "path"))}}


class StructuredRpcPlugin:
    family = "structured"
    version = 1
    description = "Bounded JSON/YAML/TOML reads, validation, patch previews and conditional atomic writes. No executable tags, code or FUSE."
    operations = {
        "read": {"description": "Read a JSON Pointer subtree; paginate immediate object keys or array items. Native dates/large integers are annotated.",
                 "write": False, "execution": "sync", "input_schema": object_schema({**_PATH,
                 "pointer": {"type": "string", "maxLength": 4096, "default": ""},
                 "offset": {"type": "integer", "minimum": 0, "default": 0},
                 "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}}, ("path",))},
        "validate": {"description": "Validate UTF-8 document syntax, supported data types, duplicate keys and structural limits without changing it.",
                     "write": False, "execution": "sync", "input_schema": object_schema(_PATH, ("path",))},
        "preview": {"description": "Read-only bounded diff for test/add/replace/remove JSON Patch operations. Does not publish changes.",
                    "write": False, "execution": "sync", "input_schema": object_schema(_PATCH, ("path", "operations"))},
        "write": {"description": "Validate and atomically write UTF-8 source content. No ETag means create-only; replacement requires exact expected_etag. Runs as task.",
                  "write": True, "execution": "task", "input_schema": object_schema({**_PATH,
                  "content": {"type": "string", "maxLength": MAX_DOCUMENT_BYTES},
                  "create_parents": {"type": "boolean", "default": False}}, ("path", "content"))},
        "patch": {"description": "Apply test/add/replace/remove JSON Patch operations with an exact ETag, preserving YAML/TOML comments where supported. Atomic task.",
                  "write": True, "execution": "task", "input_schema": object_schema(_PATCH, ("path", "operations", "expected_etag"))},
    }

    def probe(self, config):
        available = ["json"] + (["yaml"] if _installed("ruamel.yaml") else []) + (["toml"] if _installed("tomlkit") else [])
        return "available", None, {"formats": available, "max_document_bytes": MAX_DOCUMENT_BYTES,
                "max_patch_operations": MAX_PATCH_OPERATIONS, "write_precondition": "exact_etag_or_create_only",
                "patch_operations": ["test", "add", "replace", "remove"]}

    def dispatch(self, files, operation, args):
        def run():
            if operation not in {"read", "validate", "preview"}:
                fail("structured_operation", "operation requires task execution")
            validate(args, self.operations[operation]["input_schema"])
            if operation == "preview":
                _path, fmt, text, updated, tag = _edited(files, args)
                chunks, length, truncated = [], 0, False
                for line in difflib.unified_diff(text.splitlines(True), updated.splitlines(True),
                                                 fromfile="before", tofile="after", n=2):
                    if length + len(line) > 32768:
                        truncated = True
                        break
                    chunks.append(line)
                    length += len(line)
                return {"path": args["path"], "format": fmt, "etag": tag, "changed": text != updated,
                        "diff": "".join(chunks), "diff_truncated": truncated,
                        "formatting": "JSON may be reformatted; YAML indentation may be normalized; TOML trivia is preserved."}
            _path, fmt, _text, doc, _dump, aliases, tag = _read_document(files, args)
            base = {"path": args["path"], "format": fmt, "etag": tag, "yaml_aliases": aliases}
            if operation == "validate":
                return dict(base, valid=True)
            selected = _at(doc, _tokens(args.get("pointer", "")))
            offset, limit = args.get("offset", 0), args.get("limit", 100)
            if isinstance(selected, Mapping):
                keys = list(selected)
                total = len(keys)
                selected = {key: selected[key] for key in keys[offset:offset + limit]}
                kind = "object"
            elif isinstance(selected, MutableSequence):
                total = len(selected)
                selected = list(selected[offset:offset + limit])
                kind = "array"
            else:
                if offset:
                    fail("structured_offset", "scalar reads do not accept a nonzero offset")
                total, kind = 1, "scalar"
            value, native_types = json_view(selected)
            return dict(base, pointer=args.get("pointer", ""), value=value, type=kind, native_types=native_types,
                        offset=offset, total=total, next_offset=min(total, offset + limit),
                        truncated=offset + limit < total)
        return response(run)

    def dispatch_task(self, files, operation, args, task):
        def run():
            if operation not in {"write", "patch"}:
                fail("structured_operation", "operation is not a write task")
            validate(args, self.operations[operation]["input_schema"])
            if not files.writable:
                fail("mapping_read_only", "structured writes require a writable export", 403)
            task.check_cancelled()
            if operation == "write":
                path = export_path(files, args["path"])
                fmt = _format(path, args.get("format"))
                text = args["content"]
                _parse(text, fmt)
                tag = args.get("expected_etag")
            else:
                path, fmt, old, text, tag = _edited(files, args)
                if old == text:
                    task.check_cancelled()
                    with Snapshot(files, path) as snap:
                        check_etag(tag, snap.etag)
                    return {"path": args["path"], "format": fmt, "etag": tag, "changed": False, "created": False}
            task.check_cancelled()
            outcome = commit_text(files, path, text, tag, task, create_parents=args.get("create_parents", False))
            task.write("structured document published\n")
            return dict(outcome, path=args["path"], format=fmt, changed=True)
        return response(run)


plugin = StructuredRpcPlugin()

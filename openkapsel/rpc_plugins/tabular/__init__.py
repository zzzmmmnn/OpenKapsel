"""Read-only CSV/Excel RPC with bounded pages and asynchronous segment scans."""
from __future__ import annotations

import contextlib
import csv
import decimal
import json
import time
import zipfile

from openkapsel.errors import ApiError
from .._data import (MAX_RESULT_BYTES, Snapshot, check_etag, export_path, fail,
                     object_schema, response, validate)
from .csv_stream import CSVStream, CSV_SCHEMA, MAX_CSV_BYTES, MAX_COLUMNS, csv_options
from .excel import ExcelStream, EXCEL_SCHEMA, MAX_EXCEL_BYTES, available_formats

_COLUMN = {"type": ["integer", "string"], "minimum": 0, "maximum": MAX_COLUMNS - 1, "minLength": 1, "maxLength": 512}
_WHERE = {"type": "array", "maxItems": 32, "items": object_schema({
    "column": _COLUMN,
    "op": {"type": "string", "enum": ["eq", "ne", "contains", "starts_with", "gt", "ge", "lt", "le", "is_empty", "not_empty"]},
    "value": {"type": ["string", "number", "boolean", "null"], "maxLength": 1024},
}, ("column", "op"))}
_BASE = {"path": {"type": "string", "minLength": 1, "maxLength": 4096},
         "format": {"type": "string", "enum": ["csv", "xlsx", "xlsm", "xls"]},
         "csv": CSV_SCHEMA, "excel": EXCEL_SCHEMA,
         "expected_etag": {"type": "string", "minLength": 1, "maxLength": 128}}
_READ = {**_BASE, "cursor": {"type": "string", "minLength": 1, "maxLength": 2048},
         "columns": {"type": "array", "minItems": 1, "maxItems": 256, "items": _COLUMN},
         "where": _WHERE,
         "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
         "max_result_bytes": {"type": "integer", "minimum": 1024, "maximum": 128 * 1024, "default": 64 * 1024},
         "scan_rows": {"type": "integer", "minimum": 1, "maximum": 100000, "default": 100000},
         "scan_bytes": {"type": "integer", "minimum": 1024, "maximum": 64 * 1024 * 1024, "default": 16 * 1024 * 1024},
         "time_budget_seconds": {"type": "number", "minimum": 0.01, "maximum": 30, "default": 5}}
_SCAN = {**_BASE, "cursor": _READ["cursor"], "where": _WHERE,
         "mode": {"type": "string", "enum": ["count", "aggregate"], "default": "count"},
         "group_by": {"type": "array", "maxItems": 4, "items": _COLUMN},
         "metrics": {"type": "array", "minItems": 1, "maxItems": 8, "items": object_schema({
             "op": {"type": "string", "enum": ["count", "sum", "min", "max", "mean"]},
             "column": _COLUMN, "name": {"type": "string", "minLength": 1, "maxLength": 64},
         }, ("op", "name"))},
         "max_groups": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
         "scan_rows": {"type": "integer", "minimum": 1, "maximum": 10**12, "default": 10**9},
         "scan_bytes": {"type": "integer", "minimum": 1024, "maximum": MAX_CSV_BYTES, "default": 512 * 1024 * 1024},
         "time_budget_seconds": {"type": "number", "minimum": 0.01, "maximum": 3600, "default": 300}}


def _format(path, args):
    fmt = args.get("format") or path.suffix.lower().lstrip(".")
    if fmt == "tsv":
        fmt = "csv"
    if fmt not in {"csv", "xlsx", "xlsm", "xls"}:
        fail("tabular_format_unsupported", "supported formats are CSV/TSV, XLSX/XLSM and XLS; specify format if needed", 415)
    if fmt == "csv" and args.get("excel"):
        fail("tabular_options", "excel options do not apply to CSV")
    if fmt != "csv" and args.get("csv"):
        fail("tabular_options", "csv options do not apply to Excel")
    return fmt


@contextlib.contextmanager
def _open(files, args, task=None):
    path = export_path(files, args["path"])
    fmt = _format(path, args)
    with Snapshot(files, path, max_bytes=MAX_CSV_BYTES if fmt == "csv" else MAX_EXCEL_BYTES) as snap:
        check_etag(args.get("expected_etag"), snap.etag)
        try:
            if fmt == "csv":
                options = dict(args.get("csv", {}))
                if path.suffix.lower() == ".tsv" and "delimiter" not in options:
                    options["delimiter"] = "\t"
                stream = CSVStream(snap, csv_options(options), cursor=args.get("cursor"), task=task)
            else:
                stream = ExcelStream(snap, fmt, args.get("excel", {}), cursor=args.get("cursor"), task=task)
            with stream:
                yield fmt, snap, stream
                snap.verify()
        except ApiError:
            raise
        except (zipfile.BadZipFile, EOFError, UnicodeDecodeError, decimal.InvalidOperation, ValueError, KeyError):
            fail("tabular_invalid", "invalid or unsupported tabular file contents", 422)
        except Exception as exc:
            if type(exc).__module__.startswith(("openpyxl.", "xlrd.", "defusedxml.", "xml.", "lxml.")):
                fail("excel_invalid", "invalid or unsafe Excel workbook", 422, {"error_type": type(exc).__name__})
            raise


def _column(value, names):
    if type(value) is int:
        if not 0 <= value < len(names):
            fail("tabular_column_missing", "column index is outside the header", 404)
        return value
    matches = [i for i, name in enumerate(names) if name == value]
    if len(matches) != 1:
        fail("tabular_column_ambiguous", "column name must match exactly once; use a zero-based index for duplicate names", 400)
    return matches[0]


def _columns(values, names):
    selected = list(range(len(names))) if values is None else [_column(v, names) for v in values]
    if len(set(selected)) != len(selected):
        fail("tabular_column_duplicate", "selected columns must be distinct")
    return selected


def _number(value):
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text or len(text) > 256:
        return None
    try:
        number = decimal.Decimal(text)
        if not number.is_finite() or abs(number.adjusted()) > 128 or len(number.as_tuple().digits) > 128:
            return None
        return number
    except decimal.InvalidOperation:
        return None


def _predicates(specs, names):
    prepared = []
    for spec in specs:
        index, op = _column(spec["column"], names), spec["op"]
        if op not in {"is_empty", "not_empty"} and "value" not in spec:
            fail("tabular_filter_value", "this filter requires value")
        value = spec.get("value")
        if op in {"contains", "starts_with"} and not isinstance(value, str):
            fail("tabular_filter_value", "text comparison requires a string")
        numeric = op in {"gt", "ge", "lt", "le"} or (op in {"eq", "ne"} and type(value) in (int, float))
        if numeric:
            value = _number(value)
            if value is None:
                fail("tabular_filter_number", "numeric comparison requires a finite bounded number")
        prepared.append((index, op, value, numeric))

    def matches(row):
        for index, op, value, numeric in prepared:
            cell = row[index] if index < len(row) else None
            if op in {"is_empty", "not_empty"}:
                okay = cell is None or cell == ""
                if (op == "is_empty") != okay:
                    return False
                continue
            if numeric:
                cell = _number(cell)
                if cell is None:
                    return False
            elif cell is not None and value is not None and not isinstance(value, bool):
                cell = str(cell)
            if op == "eq":
                okay = cell == value and (not isinstance(value, bool) or type(cell) is bool)
            elif op == "ne":
                okay = cell != value or (isinstance(value, bool) and type(cell) is not bool)
            elif op == "contains":
                okay = cell is not None and value in cell
            elif op == "starts_with":
                okay = cell is not None and cell.startswith(value)
            elif op == "gt":
                okay = cell > value
            elif op == "ge":
                okay = cell >= value
            elif op == "lt":
                okay = cell < value
            else:
                okay = cell <= value
            if not okay:
                return False
        return True
    return matches


def _metadata(args, fmt, snap, stream, selected):
    body = {"path": args["path"], "format": fmt, "etag": snap.etag,
            "file_size_bytes": snap.stat.st_size, "column_count": len(stream.names),
            "columns": [{"index": i, "name": stream.names[i]} for i in selected],
            "row_number_kind": "data_record" if fmt == "csv" else "worksheet",
            "cursor_access": "seek" if fmt == "csv" else "worksheet_rescan"}
    if fmt == "csv":
        body["csv"] = stream.options
        body["total_rows"] = None  # Exact counts require an explicit scan.
    else:
        body.update(sheets=stream.sheets, value_mode=stream.options["value_mode"], formulas_recalculated=False)
    return body


def _read(files, args):
    deadline = time.monotonic() + args.get("time_budget_seconds", 5)
    with _open(files, args) as (fmt, snap, stream):
        selected = _columns(args.get("columns"), stream.names)
        matches = _predicates(args.get("where", []), stream.names)
        rows, numbers, ragged = [], [], 0
        count = output_bytes = 0
        start = stream.row
        hint = stream.byte_hint() if fmt == "csv" else 0
        reason = "eof"
        while True:
            if time.monotonic() >= deadline:
                reason = "time_budget"
                break
            if count >= args.get("scan_rows", 100000):
                reason = "scan_rows"
                break
            if fmt == "csv" and stream.byte_hint() - hint >= args.get("scan_bytes", 16 * 1024 * 1024):
                reason = "scan_bytes"
                break
            checkpoint = stream.checkpoint()
            row = stream.next_row()
            if row is None:
                break
            count += 1
            is_ragged = len(row) != len(stream.names)
            if not matches(row):
                ragged += is_ragged
                continue
            chosen = row if args.get("columns") is None else [row[i] if i < len(row) else None for i in selected]
            size = len(json.dumps(chosen, ensure_ascii=True, allow_nan=False).encode()) + 32
            if size + output_bytes > args.get("max_result_bytes", 64 * 1024):
                stream.restore(checkpoint)
                count -= 1
                if not rows:
                    fail("tabular_row_too_large", "one selected row exceeds the output budget; select fewer columns or raise max_result_bytes", 413)
                reason = "result_budget"
                break
            ragged += is_ragged
            rows.append(chosen)
            numbers.append(stream.row)
            output_bytes += size
            if len(rows) >= args.get("limit", 100):
                reason = "row_limit"
                break
        eof = stream.at_eof()
        body = _metadata(args, fmt, snap, stream, selected)
        body.update(rows=rows, row_numbers=numbers, rows_scanned=count, start_row_exclusive=start,
                    ragged_rows=ragged, eof=eof, truncated=not eof, stop_reason="eof" if eof else reason,
                    next_cursor=None if eof else stream.cursor())
        if fmt == "csv":
            body["approx_bytes_scanned"] = max(0, stream.byte_hint() - hint)
        return body


def _inspect(files, args):
    # Only a bounded header and sample are read, never COUNT(*) or a full hash.
    with _open(files, args) as (fmt, snap, stream):
        offset, limit = args.get("column_offset", 0), args.get("column_limit", 100)
        selected = list(range(len(stream.names)))[offset:offset + limit]
        body = _metadata(args, fmt, snap, stream, selected)
        rows, size = [], 0
        for _ in range(args.get("sample_rows", 10)):
            row = stream.next_row()
            if row is None:
                break
            chosen = [row[i] if i < len(row) else None for i in selected]
            encoded = len(json.dumps(chosen, ensure_ascii=True, allow_nan=False).encode())
            if size + encoded > 64 * 1024:
                break
            rows.append(chosen)
            size += encoded
        body.update(sample=rows, sample_is_not_full_scan=True,
                    column_offset=offset, columns_truncated=offset + limit < len(stream.names))
        return body


def _scan(files, args, task):
    mode = args.get("mode", "count")
    if mode == "count" and (args.get("metrics") or args.get("group_by")):
        fail("tabular_scan_mode", "metrics/group_by require mode=aggregate")
    if mode == "aggregate" and not args.get("metrics"):
        fail("tabular_scan_metrics", "aggregate mode requires at least one named metric")
    deadline = time.monotonic() + args.get("time_budget_seconds", 300)
    last_progress = time.monotonic()
    with _open(files, args, task) as (fmt, snap, stream):
        filters = _predicates(args.get("where", []), stream.names)
        grouping = _columns(args.get("group_by", []), stream.names)
        metrics = []
        for metric in args.get("metrics", []):
            if metric["op"] != "count" and "column" not in metric:
                fail("tabular_metric_column", "numeric metrics require a column")
            metrics.append((metric["name"], metric["op"], _column(metric["column"], stream.names) if "column" in metric else None))
        if len({m[0] for m in metrics}) != len(metrics):
            fail("tabular_metric_name", "metric names must be distinct")
        groups = {}
        scanned = matched = ragged = 0
        start_row = stream.row
        hint = stream.byte_hint() if fmt == "csv" else 0
        reason = "eof"
        with decimal.localcontext() as ctx:
            # Accepted values span adjusted exponents -128..128 with up to
            # 128 digits, hence coefficient exponents down to -255. Include
            # that full span plus the 10**12 row-count budget so cancellation
            # cannot silently lose small contributions to a very large sum.
            ctx.prec = 416
            while True:
                task.check_cancelled()
                if time.monotonic() >= deadline:
                    reason = "time_budget"
                    break
                if scanned >= args.get("scan_rows", 10**9):
                    reason = "scan_rows"
                    break
                if fmt == "csv" and stream.byte_hint() - hint >= args.get("scan_bytes", 512 * 1024 * 1024):
                    reason = "scan_bytes"
                    break
                row = stream.next_row()
                if row is None:
                    break
                scanned += 1
                ragged += len(row) != len(stream.names)
                if filters(row):
                    matched += 1
                    if mode == "aggregate":
                        key_values = [row[i] if i < len(row) else None for i in grouping]
                        key = json.dumps(key_values, ensure_ascii=True, allow_nan=False)
                        if len(key) > 2048:
                            fail("tabular_group_key_limit", "grouping key exceeds 2048 bytes", 413)
                        if key not in groups:
                            if len(groups) >= args.get("max_groups", 100):
                                fail("tabular_group_limit", "too many distinct groups; narrow filters or reduce grouping columns", 413)
                            groups[key] = {"key": key_values, "rows": 0,
                                           "metrics": {name: {"value": None, "count": 0, "missing": 0, "invalid": 0} for name, _, _ in metrics}}
                        group = groups[key]
                        group["rows"] += 1
                        for name, op, index in metrics:
                            state = group["metrics"][name]
                            cell = row[index] if index is not None and index < len(row) else None
                            if op == "count":
                                state["count"] += index is None or cell not in (None, "")
                                continue
                            if cell in (None, ""):
                                state["missing"] += 1
                                continue
                            number = _number(cell)
                            if number is None:
                                state["invalid"] += 1
                                continue
                            state["count"] += 1
                            previous = state["value"]
                            if previous is None:
                                state["value"] = number
                            elif op in {"sum", "mean"}:
                                state["value"] += number
                            elif op == "min":
                                state["value"] = min(previous, number)
                            else:
                                state["value"] = max(previous, number)
                if scanned % 1024 == 0 and time.monotonic() - last_progress >= 5:
                    snap.verify()
                    # Progress is diagnostic, not a saved aggregate checkpoint.
                    task.write(json.dumps({"event": "scan_progress", "rows_scanned": scanned, "matched_rows": matched,
                                           "approx_byte_position": stream.byte_hint() if fmt == "csv" else None}) + "\n")
                    last_progress = time.monotonic()
            for group in groups.values():
                for name, op, _ in metrics:
                    state = group["metrics"][name]
                    if op == "count":
                        state["value"] = state["count"]
                    elif state["value"] is not None:
                        if op == "mean":
                            # Return the sum as well so segment means can be merged correctly.
                            state["sum"] = str(state["value"])
                            with decimal.localcontext() as average:
                                average.prec = 40
                                state["value"] = str(state["value"] / state["count"])
                        else:
                            state["value"] = str(state["value"])
        task.check_cancelled()
        eof = stream.at_eof()
        body = {"path": args["path"], "format": fmt, "etag": snap.etag, "mode": mode,
                "result_scope": "segment", "start_row_exclusive": start_row, "end_row_inclusive": stream.row,
                "rows_scanned": scanned, "matched_rows": matched, "ragged_rows": ragged,
                "complete": eof, "stop_reason": "eof" if eof else reason,
                "next_cursor": None if eof else stream.cursor(),
                "group_by": [{"index": i, "name": stream.names[i]} for i in grouping], "groups": list(groups.values())}
        if fmt == "csv":
            body["approx_bytes_scanned"] = max(0, stream.byte_hint() - hint)
        else:
            body.update(value_mode=stream.options["value_mode"], formulas_recalculated=False)
        return body


class TabularRpcPlugin:
    family = "tabular"
    version = 1
    description = "Read-only CSV/Excel inspection and pages; CSV supports 2-10 GiB files via streaming seek cursors. Bounded count/aggregate scans run as cancellable tasks."
    operations = {
        "inspect": {"description": "Inspect columns/workbook sheets and a small sample. CSV row count is unknown until explicitly scanned.",
                    "write": False, "execution": "sync", "input_schema": object_schema({**_BASE,
                    "sample_rows": {"type": "integer", "minimum": 0, "maximum": 100, "default": 10},
                    "column_offset": {"type": "integer", "minimum": 0, "maximum": MAX_COLUMNS, "default": 0},
                    "column_limit": {"type": "integer", "minimum": 1, "maximum": 256, "default": 100}}, ("path",))},
        "read": {"description": "Read a bounded row page with projection/AND filters. Resume next_cursor; no deep row offsets for CSV. Empty rows plus cursor is not EOF.",
                 "write": False, "execution": "sync", "input_schema": object_schema(_READ, ("path",))},
        "scan": {"description": "Count/filter or aggregate one bounded input segment as a read-only task. Defaults to 512 MiB. Resume next_cursor and merge segment results; cancellation requires restarting the interrupted segment.",
                 "write": False, "execution": "task", "input_schema": object_schema(_SCAN, ("path",))},
    }

    def probe(self, config):
        return "available", None, {"formats": ["csv", "tsv", *available_formats()], "max_csv_bytes": MAX_CSV_BYTES,
                "max_excel_bytes": MAX_EXCEL_BYTES, "max_result_bytes": MAX_RESULT_BYTES,
                "csv_field_chars": csv.field_size_limit(), "cursor_lifetime_seconds": 86400,
                "csv_cursor": "file-bound seek; survives reconnect, not client process restart",
                "excel_cursor": "worksheet rescan; not constant-time random access",
                "writes": False, "formula_recalculation": False}

    def dispatch(self, files, operation, args):
        def run():
            if operation not in {"inspect", "read"}:
                fail("tabular_operation", "scan must use task execution")
            validate(args, self.operations[operation]["input_schema"])
            return _inspect(files, args) if operation == "inspect" else _read(files, args)
        return response(run)

    def dispatch_task(self, files, operation, args, task):
        def run():
            if operation != "scan":
                fail("tabular_operation", "only scan uses task execution")
            validate(args, self.operations[operation]["input_schema"])
            return _scan(files, args, task)
        return response(run)


plugin = TabularRpcPlugin()

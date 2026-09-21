"""Streaming CSV records and authenticated, file-bound seek checkpoints.

No row-offset rescans, dataframe, persistent index, or client-side file mutation.
Positions are opaque TextIOWrapper cookies, not guessed physical line offsets.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import secrets
import time

from .._data import fail, identity, object_schema, validate

MAX_CSV_BYTES = 64 * 1024**3
MAX_RECORD_CHARS = 1024 * 1024
MAX_COLUMNS = 4096
MAX_HEADER_CHARS = 32768
CURSOR_TTL_SECONDS = 24 * 3600
_CURSOR_KEY = secrets.token_bytes(32)
CSV_SCHEMA = object_schema({
    "encoding": {"type": "string", "enum": ["utf-8", "utf-8-sig", "ascii", "iso8859-1", "cp1252", "gbk", "gb18030", "big5", "shift_jis"], "default": "utf-8-sig"},
    "delimiter": {"type": "string", "minLength": 1, "maxLength": 1, "default": ","},
    "quotechar": {"type": "string", "minLength": 1, "maxLength": 1, "default": "\""},
    "escapechar": {"type": ["string", "null"], "minLength": 1, "maxLength": 1},
    "doublequote": {"type": "boolean", "default": True},
    "skipinitialspace": {"type": "boolean", "default": False},
    "header": {"type": "boolean", "default": True},
})


def csv_options(raw):
    validate(raw, CSV_SCHEMA, "csv")
    values = {"encoding": "utf-8-sig", "delimiter": ",", "quotechar": '\"',
              "escapechar": None, "doublequote": True, "skipinitialspace": False, "header": True}
    values.update(raw)
    if any(c in ("\r", "\n", "\x00") for c in (values["delimiter"], values["quotechar"], values["escapechar"])):
        fail("csv_dialect_invalid", "CSV dialect characters cannot be line breaks or NUL")
    if values["delimiter"] == values["quotechar"]:
        fail("csv_dialect_invalid", "delimiter and quotechar must differ")
    return values


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _encode_cursor(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    signature = hmac.new(_CURSOR_KEY, raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + signature).decode().rstrip("=")


def _decode_cursor(token):
    if not isinstance(token, str) or not 1 <= len(token) <= 2048:
        fail("tabular_cursor_invalid", "invalid continuation cursor")
    try:
        packed = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        raw, signature = packed[:-32], packed[-32:]
        if len(signature) != 32 or not hmac.compare_digest(signature, hmac.new(_CURSOR_KEY, raw, hashlib.sha256).digest()):
            raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("v") != 1 or not isinstance(value.get("expires"), (int, float)):
            raise ValueError()
        if time.time() > value["expires"]:
            fail("tabular_cursor_expired", "cursor expired; restart the read or scan", 409)
        return value
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        fail("tabular_cursor_invalid", "cursor was modified or belongs to an earlier client process", 409)


class _Lines:
    def __init__(self, text, task):
        self.text, self.task = text, task
        self.record_chars = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.task is not None:
            self.task.check_cancelled()
        # readline rather than TextIOWrapper.__next__ keeps tell() available.
        line = self.text.readline(MAX_RECORD_CHARS - self.record_chars + 1)
        if not line:
            raise StopIteration
        self.record_chars += len(line)
        if self.record_chars > MAX_RECORD_CHARS:
            fail("csv_record_limit", "one logical CSV record exceeds 1 MiB of decoded characters", 413)
        return line


class CSVStream:
    def __init__(self, snapshot, options, *, cursor=None, task=None):
        self.snapshot, self.options, self.task = snapshot, options, task
        self.row = 0
        self.ended = False
        self.scope = _digest(str(snapshot.path))
        self.version = _digest(identity(snapshot.stat))
        self.dialect = _digest(options)
        self.text = io.TextIOWrapper(snapshot.stream, encoding=options["encoding"], errors="strict", newline="")
        self.lines = _Lines(self.text, task)
        self.reader = csv.reader(self.lines, delimiter=options["delimiter"], quotechar=options["quotechar"],
                                 escapechar=options["escapechar"], doublequote=options["doublequote"],
                                 skipinitialspace=options["skipinitialspace"], strict=True)
        try:
            first = self._header()
            if first is None:
                self.names = []
                self.ended = True
            elif options["header"]:
                if sum(map(len, first)) > MAX_HEADER_CHARS:
                    fail("csv_header_limit", "CSV header exceeds 32768 characters", 413)
                self.names = first
            else:
                self.names = [f"column_{i + 1}" for i in range(len(first))]
                self.text.seek(0)
            if cursor is not None:
                state = _decode_cursor(cursor)
                if state.get("scope") != self.scope or state.get("dialect") != self.dialect:
                    fail("tabular_cursor_mismatch", "cursor belongs to a different file or CSV dialect", 409)
                if state.get("identity") != self.version:
                    fail("data_source_changed", "CSV changed since the cursor was issued; restart instead of resuming", 409)
                self.text.seek(int(state["position"]))
                self.row = state["row"]
                self.ended = False
            self.start_byte_hint = self.byte_hint()
        except BaseException:
            self.close()
            raise

    def _header(self):
        chars = 0
        while True:
            row = self._parse_row()
            chars += self.lines.record_chars
            if chars > MAX_RECORD_CHARS:
                fail("csv_header_limit", "CSV header search exceeds the bounded prefix", 413)
            if row is None or row:
                return row

    def _parse_row(self):
        self.lines.record_chars = 0
        try:
            row = next(self.reader)
        except StopIteration:
            return None
        except UnicodeDecodeError:
            fail("csv_encoding", "CSV is not valid in the requested encoding; specify csv.encoding", 415)
        except csv.Error:
            fail("csv_invalid", "malformed CSV or field exceeds the runtime field-size limit", 422,
                 {"max_field_chars": csv.field_size_limit(), "data_row": self.row + 1})
        if len(row) > MAX_COLUMNS:
            fail("csv_column_limit", "CSV record exceeds 4096 columns", 413)
        return row

    def next_row(self):
        if self.ended:
            return None
        row = self._parse_row()
        if row is None:
            self.ended = True
            return None
        self.row += 1
        # Keep blank and ragged rows explicit; do not silently drop data.
        return row

    def checkpoint(self):
        return self.text.tell(), self.row

    def restore(self, checkpoint):
        position, self.row = checkpoint
        self.text.seek(position)
        self.ended = False

    def byte_hint(self):
        # Buffered read-ahead makes this a progress estimate, never a seek key.
        return min(self.snapshot.stat.st_size, self.snapshot.stream.tell())

    def at_eof(self):
        if self.ended:
            return True
        position = self.text.tell()
        try:
            char = self.text.read(1)
        except UnicodeDecodeError:
            fail("csv_encoding", "CSV contains invalid encoded data", 415)
        self.text.seek(position)
        self.ended = not char
        return self.ended

    def cursor(self):
        return _encode_cursor({"v": 1, "scope": self.scope, "identity": self.version,
                               "dialect": self.dialect, "position": str(self.text.tell()), "row": self.row,
                               "expires": int(time.time()) + CURSOR_TTL_SECONDS})

    def close(self):
        if self.text is not None:
            try:
                self.text.detach()
            except ValueError:
                pass
            self.text = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

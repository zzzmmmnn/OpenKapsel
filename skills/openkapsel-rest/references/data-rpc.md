# Structured configuration and read-only tables

These are client RPC extensions, not Shell commands or server filesystem mounts.
Call `GET /mappings` first. Inspect `capabilities.rpc.structured` and
`capabilities.rpc.tabular`, including their `operation_specs`, `write`,
`execution`, and `details.formats`. Use the generic RPC endpoint/tools; no new
DSH/OpenCode typed tool is required.

All `args.path` values are relative to the selected client's exported directory,
NOT the server workspace. For mapping `laptop` and file `laptop/config/app.yaml`,
pass `args.path: "config/app.yaml"`. No absolute paths, traversal, symlinks,
Windows reparse points, `.openkapsel`, or internal transfer filenames are allowed.
Ordinary file APIs remain the right interface for byte-exact/binary transfers.

## Availability and permissions

JSON and CSV/TSV need only the Python standard library. YAML needs `ruamel.yaml`,
TOML needs `tomlkit`, XLSX/XLSM needs `openpyxl` plus `defusedxml`, and legacy XLS
needs `xlrd`. Missing optional libraries remove the corresponding format from
`details.formats`; an attempted unsupported format returns an explicit error.
The client may independently disable `rpc.structured` or `rpc.tabular`.

`structured.read`, `validate`, and `preview` are read-only synchronous operations.
`structured.write` and `patch` are write tasks: require a writable mapping, token
write permission, control authorization, and ordinary Plan/Context fields.
`tabular.inspect` and `read` are read-only synchronous operations. `tabular.scan`
is a **read-only task**: it does not require write/Shell/`allow_exec`, but it still
uses the client's task concurrency and deadline limits. It never modifies the
CSV/workbook or creates an index or sidecar beside it.

## JSON, YAML and TOML

### Read and validate

```json
{
  "args": {
    "path": "config/app.yaml",
    "pointer": "/limits",
    "offset": 0,
    "limit": 100
  }
}
```

Send this to `POST /mappings/<id>/rpc/structured/read`. `pointer` is an RFC 6901
JSON Pointer; the empty string selects the document root. Escape `/` as `~1` and
`~` as `~0` within a key. `offset` and `limit` paginate the selected object's
immediate keys or array items, not arbitrary text. Use `next_offset`, `total`,
and `truncated`; select a narrower pointer when nested content exceeds the
response budget. Values use JSON-compatible representations. Native date/time
values and integers beyond JavaScript's exact integer range are returned as
strings with `native_types` annotations relative to the returned value.

`structured.validate` accepts `path`, optional `format` and `expected_etag`.
It validates syntax, supported types, duplicate keys, nesting and size limits.
It is NOT validation against a caller-supplied JSON Schema.

Configuration input is UTF-8 with an optional BOM. The source file is bounded to
2 MiB, nesting to 64 levels and the parsed view to 100000 nodes. Filename suffix
selects JSON/YAML/TOML unless an explicit `format` is supplied. Duplicate keys,
non-finite numbers, non-string mapping keys, executable/custom YAML tags and
recursive aliases are rejected.

### Preview and patch

```json
{
  "args": {
    "path": "config/app.yaml",
    "expected_etag": "<exact ETag from structured.read>",
    "operations": [
      {"op": "test", "path": "/limits/max_tasks", "value": 2},
      {"op": "replace", "path": "/limits/max_tasks", "value": 4}
    ]
  },
  "plan_id": 123,
  "taskname": "config",
  "message": "Increase the configured task limit"
}
```

Use `structured.preview` first with only the `args` object to obtain a bounded
unified diff without writing. Send the same patch to `structured.patch` with
write authorization and Context to publish it. An exact `expected_etag` is
required by `patch`; `*` is not allowed. The supported JSON Patch subset is
`test`, `add`, `replace`, and `remove` (up to 100 operations). Arrays accept `-`
for append with `add`. `copy`, `move`, and removal of the entire document root are not implemented; use the recoverable file-delete API for whole files. All operations are
validated against an in-memory copy before publication. A failed `test`, invalid
value or stale ETag leaves the original file unchanged.

YAML/TOML patches preserve comments and supported quoting/trivia. YAML indentation
or alignment may normalize; JSON may be reformatted. Use the preview rather
than assuming byte-identical formatting. YAML documents with aliases or merge
keys may be read, but patch/preview rejects them because changing an aliased
subtree could change shared semantics. Replace such a document explicitly with
`write`. TOML cannot represent JSON null or an arbitrary non-table root.

### Write/create

`structured.write` accepts `path`, `content` (UTF-8 source text), optional
`format`, `create_parents`, and `expected_etag`. The content is parsed and checked
before writing. **Omitting ETag means create-only**; replacing an existing file
requires its exact current ETag. Publication uses a same-filesystem temporary
file and atomic replacement. ETags detect ordinary concurrent edits but do not
provide a distributed compare-and-swap against uncooperative OS-level writers.

Writes return HTTP 202 with a unified client task ID. Read `/tasks/<id>` until
finished and inspect `result` or `error`. Do not replay an uncertain task start.
The existing 1 MiB RPC message limit still applies, even though files being read
or patched may be up to 2 MiB. Use a small patch rather than transferring a large
replacement string in one RPC.

## CSV/TSV and Excel inspection

`tabular.inspect` takes `path`, optional `format`, parser options `csv`/`excel`,
`sample_rows` (default 10, maximum 100), and `column_offset`/`column_limit`.
It returns file size, ETag, column metadata and a bounded sample. For Excel it
also returns worksheet names and producer-reported dimensions when available.

**CSV inspection does not count rows or hash the entire file.** `total_rows` is
null; an exact count requires `scan`. Preview is a prefix sample, not a uniform
random sample and not proof that later records are valid.

CSV defaults to UTF-8 with optional BOM, comma delimiter, double quotes, and a
header. `.tsv` defaults to tab. Supply explicit `csv.encoding`, `delimiter`,
`quotechar`, `escapechar`, `doublequote`, `skipinitialspace`, or `header:false`
when needed. Only uncompressed CSV is supported. No delimiter/encoding guessing or lossy decoding is performed.
The advertised encodings include common single/multibyte CSV encodings such as
UTF-8, GBK, GB18030 and CP1252; UTF-16 CSV is not supported in this revision.

The first nonblank logical record is the header. Data row numbers exclude that
header and count logical records, not physical lines. Blank/ragged data records
are retained and reported, not silently discarded. Duplicate header names require
zero-based numeric column selectors. CSV values remain strings, including
leading zeros and formula-like text; no formulas are executed.

## Large CSV pages: use cursors, not deep offsets

```json
{
  "args": {
    "path": "data/events.csv",
    "columns": ["time", "status", "message"],
    "where": [{"column": "status", "op": "eq", "value": "error"}],
    "limit": 100,
    "scan_bytes": 16777216,
    "max_result_bytes": 65536
  }
}
```

Send to `POST /mappings/<id>/rpc/tabular/read`. For the next request, retain the
same parser/filter options and add the returned `next_cursor` to `args`.
Column selectors may be unique names or zero-based indices. Filters are ANDed;
supported comparisons are `eq`, `ne`, `contains`, `starts_with`, `gt`, `ge`, `lt`,
`le`, `is_empty`, and `not_empty`. Ordered comparisons are numeric and reject
non-numeric filter operands; malformed/non-numeric cells do not match them.
There is no executable expression, arbitrary SQL, regex or implicit sorting.

`read` defaults to 100 returned rows, at most 100000 scanned rows, approximately
16 MiB scanned input and a 5-second cooperative time budget. Limits are independent:
a selective filter can scan its entire budget and return **zero rows with a
non-null cursor**. Check `eof`, `next_cursor`, `truncated`, and `stop_reason`.
Do not interpret an empty page as EOF. A record that exceeds the output budget
is not silently consumed: select fewer columns or raise the permitted result
budget. `row_numbers` preserves each returned record's source position.

CSV cursors are authenticated and tied to the export path, file identity and
parser dialect. They store an opaque seek checkpoint at a complete logical
record boundary, including records containing quoted newlines. Each continuation
reads only a bounded header and seeks to that checkpoint; it does not repeatedly
scan from the beginning. Positions are serialized without JavaScript integer
precision loss, including offsets beyond 2/4 GiB. No caller-chosen byte offsets
or arbitrary deep row offsets are accepted.

File replacement, append or in-place changes invalidate a cursor. Cursors expire
after 24 hours and survive provider reconnects in the same client process, but
not a client process restart. They do not pin a snapshot indefinitely. Preserve
previous cursors to revisit already-observed page boundaries. Queries/filters
are not encoded as authorization in the cursor; retain the same query when
combining consecutive results.

## Asynchronous count and aggregation

```json
{
  "args": {
    "path": "data/events.csv",
    "mode": "aggregate",
    "group_by": ["status"],
    "metrics": [
      {"name": "rows", "op": "count"},
      {"name": "total_bytes", "op": "sum", "column": "bytes"},
      {"name": "average_ms", "op": "mean", "column": "elapsed_ms"}
    ],
    "scan_bytes": 536870912,
    "time_budget_seconds": 300
  },
  "timeout_seconds": 330
}
```

Send to `POST /mappings/<id>/rpc/tabular/scan`; no mutation Context is required.
`mode: "count"` with only `path` counts logical data records. `where` filters may
be used in either mode. The endpoint returns HTTP 202 immediately. Poll the
unified task through `/tasks/<id>` or `/tasks/<id>/output`; scan progress is
bounded diagnostic output. Interrupt/kill requests use the usual authorized
task-control interfaces. The task's outer `timeout_seconds` must fit the client's
configured `limits.max_seconds`; choose it above the cooperative segment budget.

A scan defaults to **one 512 MiB segment**, not an unbounded all-file operation.
It returns `result_scope: "segment"`, `start_row_exclusive`, `end_row_inclusive`,
`rows_scanned`, `matched_rows`, `complete`, and `next_cursor`. `complete=true`
means the scan reached EOF from its starting cursor, NOT that this individual
result includes earlier segments. Resume with the returned cursor and combine
completed segment results. Increase `scan_bytes` deliberately for a full scan
when local throughput and deadlines allow it.

Supported metrics are count/sum/min/max/mean, with up to 4 group keys, 8 named
metrics, and an explicit group-count cap (default 100, maximum 200). Excess
cardinality is an error, not silent truncation or unbounded RAM use. Numeric
aggregate results are decimal strings; missing and invalid counts are reported.
Mean results include `sum` and `count` so segment means can be combined as
`sum(segment sums) / sum(segment counts)`, not an unweighted average of means.
Counts can be added, minima/maxima merged, and sums added by identical group keys.
Do not merge overlapping segments or results with different source ETags.

Cancellation does not publish a partial aggregate checkpoint. Restart that
interrupted segment from its input cursor; retain earlier completed segment
results. Progress lines are not durable aggregate results. Neither scanning nor
pagination creates a database or persistent index.

## Limits and Excel-specific behavior

CSV file size is permitted up to 64 GiB; 2–10 GiB does not increase memory usage
in proportion to file size. Per-record decoded text is bounded to 1 MiB, column
count to 4096, and each field to the Python runtime's advertised CSV field limit
(normally 131072 characters). One row, one header, or the response can hit its
own limit even when the file size is otherwise supported. Input byte/time budgets
are cooperative at record boundaries, with bounded read-ahead.

Excel inputs are separately bounded to 64 MiB compressed/source bytes; OOXML
parts and total expanded size have additional limits. This is **not** a promise
to open a 10 GiB Excel workbook. `.xlsx`/`.xlsm` use read-only worksheet iteration;
`.xls` uses a bounded read-only legacy reader. `.xlsb` is not supported.

`excel.sheet` selects a worksheet, `header_row` is 1-based (0 means no header),
and `start_row` selects an initial physical worksheet row. For subsequent pages
omit `start_row` and pass the cursor. Excel cursor continuation may rescan the
compressed worksheet prefix; it does not have CSV's constant-seek behavior.
An exact-size last Excel page can require one final empty page to confirm EOF.

`excel.value_mode` is `cached` (default) or `formula`. Cached values can be stale
or absent; they are **not recalculated results**. Formula mode returns formula
source for XLSX/XLSM. Legacy XLS supports cached values only. Macros, formulas,
external links and application code are never executed. The response explicitly
states `formulas_recalculated:false`. Table reading and scans never save a
workbook or modify its styles/data.

All data RPC results are bounded to 256 KiB of encoded JSON, below the existing
1 MiB wire limit. Reduce columns, subtree size, group cardinality or page budgets
when necessary. File metadata is checked before/after reads and at scan progress
boundaries; a changed source fails rather than returning an allegedly consistent
mixed-version result. This is optimistic change detection, not a transactional
snapshot against hostile external writers.

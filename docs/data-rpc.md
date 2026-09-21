# Structured and tabular client RPC

[Client setup](client-mappings.md) | [Complete API contract and examples](../skills/openkapsel-rest/references/data-rpc.md)

## Scope

Two built-in, self-described families extend client RPC without FUSE or arbitrary
Shell execution:

| Family | Synchronous reads | Task operations |
| --- | --- | --- |
| `structured` | read, validate, preview | write, patch (write-authorized) |
| `tabular` | inspect, read | scan (read-only) |

JSON and CSV/TSV operate with standard-library dependencies. Optional parsers are
loaded only when their formats are used. `GET /mappings` reports the actual
supported format list, schemas and limits. Both generic REST/MCP RPC and the
existing DSH/OpenCode `kapsel_rpc` bridge use those schemas directly.

## Install on a source-based client

Minimal parser-only installation into the client's own environment:

```sh
python -m pip install 'ruamel.yaml>=0.18.6,<0.19' 'tomlkit>=0.13,<1' \
  'openpyxl>=3.1.5,<4' 'defusedxml>=0.7.1,<1' 'xlrd>=2.0.1,<3'
```

A full editable project installation may instead include the new optional extra:

```sh
python -m pip install -e '.[client,data-rpc]'
```

The full package retains its existing server/scientific dependencies. A client
that only needs JSON/CSV does not need the parser extra. Restart an upgraded
mapping client to publish its new capabilities. No credentials or mapping IDs
need to change. Families can be disabled independently:

```json
{"rpc": {"git": true, "archive": true, "structured": true, "tabular": true}}
```

These parser dependencies and new features are source-tree changes; no package
publication or service deployment is implied by this document.

## Large CSV design

Inspection reads only a bounded header/sample. Pagination uses authenticated
TextIOWrapper seek cookies at complete logical CSV-record boundaries. It never
implements a large row offset by repeatedly skipping the prefix. Cookies are
serialized as strings so positions beyond 2/4 GiB remain exact through JSON/JS.
Cursors bind path, file identity, dialect and expiry, but are not a persistent
index or an authorization credential. A process restart invalidates them;
network reconnects do not.

Filtering returns bounded pages. Exact count/aggregation is an asynchronous
read-only task with cooperative byte/row/time budgets. The default scan segment
is 512 MiB; callers retain and combine completed segment results, then resume
from `next_cursor`. Cancellation restarts the interrupted segment, not the whole
file. No unbounded dataframe, global sort or group dictionary is constructed.
Numeric aggregates are bounded Decimal calculations and expose invalid/missing
counts. RPC task lists now omit large result bodies and expose
`result_available`; retrieve each result through task GET/output instead.

CSV permits files up to 64 GiB, but also bounds field, logical-record, header,
column, response, scan and grouping sizes. The complete contract documents the
independent limits. Excel has a separate 64 MiB input limit and archive/XML
budgets; it is not the multi-gigabyte path. XLSX/XLSM rows are read lazily;
legacy XLS is parsed from a bounded input buffer. Excel continuation may rescan
worksheet XML. Formulas/macros are never evaluated and external links are not
followed.

## Validation record

Local validation on September 21, 2026:

- Native macOS Python 3.14 full suite: 289 tests, 286 passed and 3 Windows-native
  handle/process tests skipped. All YAML, TOML, XLSX and XLS tests ran with the
  optional parsers supplied through an isolated dependency directory.
- DSH bridge: 18 tests passed. OpenCode bridge: 18 passed and one optional real
  OpenCode runtime integration test skipped.
- All three working trees passed `git diff --check`; bundled skill copies match
  the primary source. New plugin sources pass Python 3.10 grammar parsing; this
  is not a Python 3.10 runtime validation.
- No GitHub Actions run, package release, deployment or service restart has been
  performed for these uncommitted changes. Linux and Windows execution of the
  new data-family tests remains for the configured CI matrix.

The dense CSV benchmark ran in fresh native macOS Python processes:

| CSV data size | Logical data records | Scan segments | Count-scan time | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| 2 GiB | 524,288 | 5 | 13.598 s | 28.95 MiB |
| 10 GiB | 2,621,440 | 21 | 69.671 s | 28.95 MiB |

Each file additionally contains an 8-byte header. The files were fully written,
not sparse; each record was 4096 bytes with two ASCII fields. Scans verified exact
record counts and contiguous segment row boundaries. Header/sample inspection
was approximately 0.001 seconds in this test. Temporary files were removed.

These numbers measure local parser/count throughput, not network speed, cold-cache
performance, arbitrary narrow-row CSV performance or grouped-query throughput.
RSS excludes the operating system's filesystem cache. Separate sparse fixtures
exercise authenticated seek positions above 2 and 10 GiB without reading holes;
those tests are offset correctness tests, not full-file throughput benchmarks.

Reproduce the opt-in dense benchmark (requires at least 12 GiB free temporary
disk for the default sizes):

```sh
python tests/benchmark_tabular_csv.py --gib 2 10
```

Ordinary regression suites do not generate dense multi-gigabyte files. The CI
matrix installs the optional parsers and runs the new reader/editor tests on
Linux, macOS and Windows, plus the full server suite on Python 3.10 and 3.14.

## Parser references

- ruamel.yaml round-trip details: https://yaml.dev/doc/ruamel.yaml/detail/
- TOMLKit formatting-preserving parser: https://tomlkit.readthedocs.io/en/latest/
- openpyxl read-only mode and worksheet dimensions: https://openpyxl.readthedocs.io/en/stable/optimized.html
- Python CSV newline and field-limit semantics: https://docs.python.org/3/library/csv.html

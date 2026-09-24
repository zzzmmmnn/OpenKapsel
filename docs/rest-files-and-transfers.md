# REST files, transfers, and sharing

[Back to README](../README.md)

Workspace endpoints are relative to `<url_base_path>/w/<READ_TOKEN>`. State-changing operations require the matching Bearer control token and mutation context.

## Endpoint overview

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Compact Workspace Discovery |
| `GET` | `/discovery/<section>` | Focused or complete Discovery |
| `GET/POST` | `/context` | Query Context or create a Plan or Note |
| `GET` | `/context/plans/<id>/tree` | Read a Plan subtree and attached entries |
| `PATCH` | `/context/plans/<id>` | Update Plan content, status, parent, and debrief |
| `GET/POST` | `/memory`, `/memory/project` | Query, create, or read project Memory |
| `GET/PATCH/DELETE` | `/memory/<id>` | Read, revise, or archive Memory |
| `GET` | `/fs/list`, `/fs/tree`, `/fs/search` | List, recursively inspect, or search files |
| `GET` | `/fs/read`, `/fs/stat` | Read explicitly encoded text or selected metadata |
| `GET` | `/git/status`, `/git/diff`, `/git/diff_stat`, `/git/log`, `/git/show`, `/git/ls_files` | Read-only Git snapshot inspection; see [Git options](shell-and-mcp.md#git-inspection) |
| `POST` | `/fs/manifest` | Batch synchronization preflight or recursive metadata manifest |
| `POST` | `/fs/read_many` | Read multiple small text files in one request |
| `GET/HEAD/PUT` | `/fs/content` | Stream or atomically upload raw bytes |
| `POST` | `/fs/mutate` | Transactionally create, replace, exact-edit, structured-edit, or recycle one or more paths |
| `POST` | `/fs/large/read`, `/fs/large/replace` | Bounded large-file inspection and equal-length guarded replacement |
| `POST` | `/fs/mkdir`, `/fs/move` | Create directories or move/rename paths |
| `GET/POST` | `/recycle/list`, `/recycle/restore` | List and restore recycled paths |
| `POST` | `/uploads` | Start a resumable upload |
| `GET/HEAD/PATCH` | `/uploads/<id>` | Inspect or append upload bytes |
| `POST/DELETE` | `/uploads/<id>/commit`, `/uploads/<id>` | Commit or cancel an upload |
| `POST` | `/shell/exec` | Start an asynchronous Shell task |
| `GET` | `/tasks`, `/tasks/<id>` | List tasks or inspect task state |
| `GET` | `/tasks/<id>/output`, `/tasks/<id>/stream` | Incremental or SSE output |
| `POST` | `/tasks/<id>/stdin` | Write or close interactive stdin |
| `POST` | `/tasks/<id>/interrupt`, `/tasks/<id>/kill` | Graceful or forced termination |
| `GET` | `/sandbox/processes` | List token cgroup processes and usage |
| `POST/GET/DELETE` | `/shares`, `/shares/<id>` | Create, inspect, or delete a share |
| `POST` | `/shares/<id>/import` | Import a share into the Workspace |
| `POST` | `/mcp` | Stateless Streamable HTTP MCP |

Discovery contains the complete request schemas, permissions, configured size limits, and stable error codes.

## Mutation context

Create a root Plan before changing project state:

```bash
BASE='https://ws.example.com/kapsel/w/<READ_TOKEN>'
AUTH='Authorization: Bearer <CONTROL_TOKEN>'

PLAN_ID=$(curl -fsS -X POST "$BASE/context" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"type":"plan","taskname":"release","content":"Prepare the release."}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -fsS -X POST "$BASE/fs/mutate" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"items\":[{\"op\":\"file.create\",\"path\":\"release.txt\",\"content\":\"ready\"}],\"plan_id\":$PLAN_ID,\"taskname\":\"release\",\"message\":\"Write release marker\"}"
```

JSON mutations carry `plan_id`, `taskname`, and `message` in the body. Raw-byte upload, upload commit or cancel, stdin, interrupt, and kill requests use:

- `OpenKapsel-Plan-Id`
- `OpenKapsel-Taskname`
- `OpenKapsel-Message`

## Metadata, search, and trees

`POST /fs/read_many` accepts `{"paths":["src/main.py","README.md"],"limit":65536,"max_total_chars":262144}`.
`limit` caps characters per file; `max_total_chars` caps their combined content.
Both are bounded by `max_read_chars`, and paths by `max_batch_file_operations`.
Results preserve input order with per-item `status`, `content`, `etag`, `length`,
`truncated`, and `next_offset`, or an `error`. Partial failures return HTTP 207.
When the shared budget is exhausted, remaining items report `read_budget_exhausted`.
Use `/fs/read?path=...&offset=<next_offset>` to continue a truncated file.
This endpoint is read-only despite using POST; it needs no control token or Plan.

Search accepts repeated `include` and `exclude` glob query parameters, for example
`/fs/search?path=src&query=TODO&include=*.py&include=*.js&exclude=node_modules`.
Patterns without `/` match basenames; others match POSIX paths relative to the
search root. Matching is case-sensitive regardless of the content-search flag;
`*` spans `/` (Python fnmatch semantics). Exclude wins, and matching directories
are pruned. Include only filters files, allowing traversal to matching descendants.
Each group accepts at most 64 patterns, each at most 512 characters.

`POST /fs/manifest` additionally accepts
`{"recursive":true,"path":"src","depth":8,"include_sha256":true}` instead of `items`.
It returns a flat `items` list containing the root and descendants with
`path`, `name`, `type`, `size`, and `modified_at`, plus optional `sha256`
(null for non-files). Depth 0 returns only the root, depth 1 includes direct children.
Traversal is bounded by `max_recursion_depth` and `max_tree_nodes`; `truncated`
reports the node limit, while the requested depth intentionally bounds traversal.
Internal storage is omitted and symlinks are not followed. Hashes are computed
on demand; this is not a transactional snapshot across files.

All three operations execute locally on an updated mapping client when the request
targets one mapping, using a single RPC. Large RPC responses may return HTTP 413;
reduce batch size, character budgets, or traversal depth.

`fs/stat` can return selected fields: `type`, `size`, `created_at`, `modified_at`, `changed_at`, `etag`, `content_type`, and `sha256`. SHA-256 is calculated only when requested. On platforms without birth time, `created_at` is `null`; inode change time remains separate.

`fs/search` supports literal or regular-expression matching, case sensitivity, recursion depth, and bounded results. Binary, non-UTF-8, oversized, private, and symlinked content is skipped. `fs/tree` uses the same depth model and a total node limit.

`fs/manifest` classifies bounded path sets as `missing`, `same`, `conflict`, or `exists`, calculating hashes only when requested.

## Transactional mutations

`POST /fs/mutate` is the ordinary file mutation protocol. One request may contain up to the configured batch limit of items and supports:

- `file.create`: create-only text content; the destination must not exist.
- `file.replace`: replace an existing standard-size text file; exact `expected_etag` is required.
- `text.replace`: apply one or more exact replacement rules to the original text; exact `expected_etag` and exact match counts are required.
- `structured.patch`: apply guarded JSON/YAML/TOML `test`, `add`, `replace`, and `remove` operations; exact `expected_etag` is required.
- `path.delete`: recoverably recycle an existing file or directory; exact `expected_etag` is required. Content size is irrelevant, so large files may be recycled this way.

All items are preflighted before publication. A request may operate only inside one filesystem domain: one workspace, one mapped client export, or one administrator-granted filesystem root. It never splits a transaction across backends. Ordinary commit failures roll back already-published items; if rollback would overwrite content changed concurrently by another writer, OpenKapsel fails closed and preserves recovery artifacts.

`path.delete` is workspace-local because recycle metadata and restoration belong to that workspace. It rejects the workspace root, Storage Provider mapping roots, duplicate paths, and parent/child overlap with another item. Successful deletes return a `recycle_id` and can be restored through `/recycle/restore`.

This is request-level transactionality, not a durable database transaction: v1 does not provide a write-ahead log or guarantee crash recovery across a process or operating-system crash.

### Text encoding and line endings

Text APIs default to UTF-8 independently of the host locale. `encoding` is a query parameter for `fs/read`, a body field for `fs/read_many`, and an item field for content operations in `fs/mutate`. Supported codecs: `utf-8`, `utf-8-sig`, `utf-16-le`, `utf-16-be`, `ascii`, `iso8859-1` (alias `latin-1`), `cp1252`, `gbk`, `gb18030`, `big5`, and `shift_jis`. MCP text tools expose the same parameter. Search remains UTF-8-only; binary download/upload preserves arbitrary bytes.

There is no encoding detection, locale fallback, or lossy replacement. Invalid input bytes return 415; unsupported codecs or unrepresentable output return 400 without replacing the target. Batch encoding failures are detected before any file is published. Specify the existing encoding for edits. For BOM handling, `utf-8-sig` consumes/emits the UTF-8 BOM; ordinary `utf-8` preserves it as U+FEFF. UTF-16 requires explicit endian and preserves any BOM as U+FEFF; include that character to create a new BOM-bearing UTF-16 file.

Reads preserve LF (`\n`), CRLF (`\r\n`), CR (`\r`), and mixed endings. Character offsets count both characters of CRLF. Writes encode the supplied text literally, even on Windows; use `\r\n` explicitly to create CRLF files. Replacements match exact line endings and preserve all untouched text; replacement text controls its own endings. `byte_offset` remains UTF-8-only; use character offsets for other codecs. Client-local text reads require file API v3 (client 1.59.0+). Transactional mutation requires file API v4; RPC-first servers fail closed rather than degrading `fs/mutate` into older write calls.

## Recycle and overwrite policy

File API deletion moves paths into workspace-local private recycle storage under `.openkapsel`. If that storage was removed, OpenKapsel recreates it safely before moving the path. Restore operations return an item to its prior location.

Uploads only create new files. Direct, resumable, and MCP uploads all reject an existing destination. To replace a binary file, first obtain its exact ETag with `/fs/stat`, then call `/fs/mutate` with a `path.delete` item so the previous version enters private recycle storage, and finally upload the replacement.

Full Shell deletion is direct and is not recoverable through the recycle API.

## Large-file transfer

Direct `PUT /fs/content` streams raw bytes and is intended for content within `max_direct_upload_bytes`. It does not Base64-encode or load the whole file into Python memory.

For larger files:

1. Create an upload with final path, expected size, and optional SHA-256.
2. Append `application/octet-stream` chunks in order using `Upload-Offset`.
3. Inspect the current offset after interruption.
4. Commit the upload.

Offset conflicts return the server offset. State survives service restarts. Commit rechecks permission, destination absence, size, and optional SHA-256, then atomically publishes without replacement. Temporary quotas, chunk recommendations, concurrency, and TTL are configured and published in Discovery.

Downloads support GET, HEAD, ETag, and one HTTP Range. MCP can return authenticated transfer URLs so large bytes remain outside JSON and AI context.

## Temporary cross-workspace sharing

A source token can copy exactly one file or directory into the service share store and receive a random `share_id`. Workspace Root, host-path grants, symlinks, and `.openkapsel` cannot be shared.

Anyone holding the ID can inspect the immutable share without a Workspace token. A destination token imports it with its own credentials and mutation context. Import requires a new destination and never overwrites.

Shares expire after 24 hours by default. At most ten are retained; creating another evicts the oldest. Creators may delete their shares early. Invalid, expired, evicted, and deleted IDs all return `404 share_not_found`.

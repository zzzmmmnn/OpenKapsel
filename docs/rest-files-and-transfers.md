# REST files and transfers

[Back to README](../README.md)

Workspace endpoints are relative to `<url_base_path>/w/<READ_TOKEN>`. State-changing operations require the matching Bearer control token and mutation context.

## Endpoint overview

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Compact Workspace Discovery |
| `GET` | `/discovery/<section>` | Focused or complete Discovery |
| `GET/POST` | `/context` | Query Context or create a Plan or Note |
| `GET` | `/context/plans/<id>/tree` | Read a Plan subtree and attached entries |
| `PATCH` | `/context/plans/<id>` | Update Plan content or status using `expected_revision` (completion includes a debrief; parentage is immutable) |
| `GET/POST` | `/memory` | Query or create Memory |
| `GET` | `/memory/project` | Read project Memory |
| `GET/PATCH/DELETE` | `/memory/<id>` | Read, revise, or archive Memory |
| `GET` | `/fs/query/list`, `/fs/query/tree`, `/fs/query/find`, `/fs/query/grep` | List, recursively inspect, find by name, or grep file contents |
| `GET` | `/fs/query/stat` | Read selected metadata |
| `POST` | `/rpc/git/<operation>` | Generic Git reads/writes for the server workspace; use mapping RPC for mapped repositories |
| `POST` | `/fs/query/manifest` | Batch synchronization preflight or recursive metadata manifest |
| `POST` | `/fs/read/files` | Read one or more text files in one request |
| `GET/HEAD/PUT` | `/fs/content` | Stream or atomically upload raw bytes |
| `POST` | `/fs/write/mutate` | Transactionally create, replace, exact-edit, structured-edit, or recycle one or more paths |
| `POST` | `/fs/read/large`, `/fs/write/replace_large` | Bounded large-file inspection and equal-length guarded replacement |
| `POST` | `/fs/write/mkdir`, `/fs/write/move` | Create directories or move/rename paths |
| `GET/POST` | `/recycle/list`, `/recycle/restore` | List and restore recycled paths |
| `POST` | `/upload/create` | Start a resumable upload |
| `GET/HEAD` | `/upload/status/<id>` | Inspect upload status |
| `PATCH` | `/upload/chunk/<id>` | Append upload bytes |
| `POST` | `/upload/commit/<id>`, `/upload/cancel/<id>` | Commit or cancel an upload |
| `POST` | `/shell/exec` | Start an asynchronous Shell task |
| `GET` | `/task/list`, `/task/get/<id>` | List tasks or inspect task state |
| `GET` | `/task/output/<id>`, `/task/stream/<id>` | Incremental or SSE output |
| `POST` | `/task/stdin/<id>` | Write or close interactive stdin |
| `POST/DELETE` | `/task/interrupt/<id>`, `/task/<id>` | Graceful interrupt or forced termination |
| `GET` | `/sandbox/processes` | List token cgroup processes and usage |
| `POST` | `/mcp` | Stateless Streamable HTTP MCP |

Discovery contains the complete request schemas, permissions, configured size limits, and stable error codes.

## Temporary File API approval

Use this when a Token needs time-limited read or write access through the
existing File API, without changing its permanent read/write permission flags.
Passwords and grants belong to the **individual Token** (stable app_id), not
to all Tokens using the same server directory.

First make a command-free approval request:

```json
{"access":"write","target":"server","writer_nonce":"@Ab12@",
 "plan_id":123,"taskname":"files","message":"Request File API write access"}
```

Send it to `POST /files/approval/request` with the Token's Bearer control
credential. `access` is `read` or `write`. `target` is `server` or an exact
authorized Mapping ID (not `auto`). The API returns HTTP 200 with
`status=approval_required` and `approval_url` (or `status=granted`).
The user approves in the browser using that Token's Workspace password.
MCP uses `capability_call` family `files`, operation `request_approval`,
with `access`, `target` and `writer_nonce` inside `args`; Plan Context stays
outside `args`.

After approval, explicitly include `approved=true`, `target`, the
Conversation `writer_nonce` and its in-progress `plan_id` **on every**
File API operation. For example:

```json
{"paths":["notes.txt"],"approved":true,"target":"server",
 "writer_nonce":"@Ab12@","plan_id":123}
```

Send this to `POST /fs/read/files`. For GET file query/content endpoints
supply `approved=true&target=server&writer_nonce=...&plan_id=...` as query
parameters; raw PUT may instead supply the Plan ID in
`OpenKapsel-Plan-Id` and the approval options in its query string.
Supported operations include file list/stat/find/grep/tree/manifest,
text/binary/large reads, guarded mutation, mkdir, move, direct content PUT
and guarded large replacement. The corresponding MCP File tools accept the
same opt-in arguments. Approval for `files.read` never grants `files.write`
and vice versa. Without `approved=true` the original permission flags apply.

**External directory approval:** To access an absolute directory outside the
Token Workspace, add `"path":"/Users"` to the File approval request and
set `target` to the **specific Mapping ID** hosting that directory (or
`server` for a directory on the Server). The initial API response and
approval URL **do not check directory existence or reveal canonical paths**.
The browser first shows the requested path and prompts for that Token's
Workspace password. **Only after the correct password** does the Server
resolve the real path locally, or call the Mapping Client's private read-only
`resolve_path` RPC. A second browser page then shows both the original path
and the emphasized **actual authorized directory**. The user must explicitly
confirm that actual directory before any grant is issued; a missing directory
fails only after password verification. Confirmation is tied to the browser
that provided the password, and immediately rechecks the original symlink
before granting access. The grant binds to the canonical directory; File RPC
checks aliases again and operates through descriptor-anchored paths to prevent
symlink substitution. Unauthenticated requests cannot distinguish whether
an unapproved directory exists or discover where an alias points.
Approved File operation paths containing `..` are rejected before normalization. Approval covers only that directory and descendants for
this Token, Conversation, target and read/write mode. An unscoped read/write
grant never permits access outside the configured roots. For example, after
approving `access=read,target=<Mapping ID>,path=/Users`, call
`fs_list(path="/Users", approved=true, target="<Mapping ID>", writer_nonce=...,
plan_id=...)`. After the broad File approval grant is approved, direct File operations
with `approved=true` return the same generic `path_unavailable` result for
missing, inaccessible and unapproved external paths, without revealing a
symlink destination. Before broad approval, all those operations request the
same unscoped files.read/write approval, regardless of the path. Use the separate
`files/approval/request` action with `path` to initiate approval; the user
enters the Workspace password before seeing the real directory. For a file or
file symlink rather than a directory, pass `scope_is_directory=false` with
its absolute path; approval covers the resolved **parent directory**, not the
lexical alias's parent. An internal symlink needs no extra directory approval
once the broad files.read/write capability is granted. A broad filesystem
root such as `/` cannot be approved. Mapping Clients must
advertise `file_stream.external_root_file_api=true` and
`file_stream.external_realpath=true`; older Clients reject
external File API approvals/operations with `mapping_client_upgrade_required` rather
than silently accessing the normal export.

**Security boundaries:** Four path modes are `rw`, `ro`, `protect`
and `deny`. For File API and sandboxed Shell, absolute `deny` at any
ancestor cannot be overridden by a child rule or File Approval.
A separately approved unsandboxed Shell is outside these path restrictions.
User-facing File API and File Approval reject reserved `.openkapsel` and `.openkapsel-*` components regardless of letter case, including mixed-case aliases. Cross-root transfers use narrowly validated, random temporary stage names through the internal low-level transport only; those stages remain hidden from public File APIs and directory listings.

Archive RPC `extract` applies an uncompressed output quota of **512 MiB per
operation** and **256 MiB per individual member**, in addition to the 100,000
entry limit. ZIP members are checked using their declared sizes before any
member is extracted; ZIP and TAR streaming writes also count actual output
bytes. Exceeding either size limit returns `413 archive_extracted_size_limit`
and removes the incomplete temporary extraction directory.
 Other modes use deepest path priority with
same-path `deny > protect > ro > rw`. A `protect` rule denies ordinary reads
and writes but a separately confirmed `files.read`/`files.write` grant
for the protected directory itself or a more precise canonical child may
unlock only that subtree. Approving an ancestor never unlocks a nested
`protect`; independently approved child scopes are preserved. A
`files.write` grant elevates ordinary `ro` only within its scope.
Approved operations require matching Token, Conversation, target,
in-progress Plan, and `approved=true`. Absolute `deny`, Mapping write
protection, private Client configuration/metadata and OS permissions
cannot be bypassed. Deleting/moving an ancestor cannot indirectly remove
unapproved protected or denied descendants. File approval never grants
Shell/Git/Archive RPC or uploads.

File requests spanning multiple targets cannot borrow another target's grant.
Approval URLs last thirty minutes; grants default to ten minutes and are
scoped to the Token, Conversation, target and capability.

## Mutation context

Create a root Plan before changing project state:

```bash
BASE='https://ws.example.com/kapsel/w/<READ_TOKEN>'
AUTH='Authorization: Bearer <CONTROL_TOKEN>'

PLAN_ID=$(curl -fsS -X POST "$BASE/context" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"type":"plan","taskname":"release","content":"Prepare the release."}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -fsS -X POST "$BASE/fs/write/mutate" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"items\":[{\"op\":\"file.create\",\"path\":\"release.txt\",\"content\":\"ready\"}],\"plan_id\":$PLAN_ID,\"taskname\":\"release\",\"message\":\"Write release marker\"}"
```

JSON mutations carry `plan_id`, `taskname`, and `message` in the body. Raw-byte upload, upload commit or cancel, stdin, interrupt, and kill requests use:

- `OpenKapsel-Plan-Id`
- `OpenKapsel-Taskname`
- `OpenKapsel-Message`

## Metadata, find, grep, and trees

`POST /fs/read/files` accepts `{"paths":["src/main.py","README.md"],"limit":65536,"max_total_chars":262144}`.
`limit` caps characters per file; `max_total_chars` caps their combined content.
Both are bounded by `max_read_chars`, and paths by `max_batch_file_operations`.
Results preserve input order with per-item `status`, `content`, `etag`, `length`,
`truncated`, and `next_offset`, or an `error`. Partial failures return HTTP 207.
When the shared budget is exhausted, remaining items report `read_budget_exhausted`.
Use `POST /fs/read/files` again with the same one-item `paths` array and `offset=<next_offset>` to continue a truncated file.
This endpoint is read-only despite using POST; it needs no control token or Plan.

Content grep accepts repeated `include` and `exclude` glob query parameters, for example
`/fs/query/grep?path=src&query=TODO&include=*.py&include=*.js&exclude=node_modules`.
Patterns without `/` match basenames; others match POSIX paths relative to the
grep root. Glob matching is case-sensitive regardless of the content-grep flag;
`*` spans `/` (Python fnmatch semantics). Exclude wins, and matching directories
are pruned. Include only filters files, allowing traversal to matching descendants.
Each group accepts at most 64 patterns, each at most 512 characters.

`POST /fs/query/manifest` additionally accepts
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

`GET /fs/query/stat` can return selected fields: `type`, `size`, `created_at`, `modified_at`, `changed_at`, `etag`, `content_type`, and `sha256`. SHA-256 is calculated only when requested. On platforms without birth time, `created_at` is `null`; inode change time remains separate.

`GET /fs/query/grep` supports literal or regular-expression matching, case sensitivity, recursion depth, and bounded results. Binary, non-UTF-8, oversized, private, and symlinked content is skipped. `GET /fs/query/tree` uses the same depth model and a total node limit.

`POST /fs/query/manifest` classifies bounded path sets as `missing`, `same`, `conflict`, or `exists`, calculating hashes only when requested.

## Transactional mutations

`POST /fs/write/mutate` is the ordinary file mutation protocol. One request may contain up to the configured batch limit of items and supports:

- `file.create`: create-only text content; the destination must not exist.
- `file.replace`: replace an existing standard-size text file; exact `expected_etag` is required.
- `text.replace`: apply one or more exact replacement rules; exact `expected_etag` and exact match counts are required. Range boundaries may use zero-based inclusive `start_line` / `end_line`, or full-file-unique `start_text` / `end_text` markers that may span multiple lines. Text markers are inclusive: the range starts at the first character of `start_text` and ends immediately after the final character of `end_text`, so either marker may be part of the replaced text. A text marker and line selector cannot both define the same side. With no start selector the range begins at line 0; with no end selector it runs through EOF. On a count mismatch the 409 error includes the first mismatch as `expected` / `actual` plus `match_counts[]` for every replacement rule, so the failed preflight also reports the observed counts without changing the file.
- `text.insert_before` / `text.insert_after`: preserve an exact `match` anchor and insert `content` immediately before or after every matched occurrence. They use the same optional range selectors, require exact `expected_etag`, and require `expected_count` (default 1) to match the observed anchor count. Count mismatch errors include `actual` and `match_counts[]` and do not modify the file.
- `structured.patch`: apply guarded JSON/YAML/TOML `test`, `add`, `replace`, and `remove` operations; exact `expected_etag` is required.
- `path.delete`: recoverably recycle an existing file or directory; exact `expected_etag` is required. Content size is irrelevant, so large files may be recycled this way.

All items are preflighted before publication. A request may operate only inside one filesystem domain: one server workspace, one mapped client export, one Storage Provider mount, or one administrator-granted filesystem root. It never splits a transaction across backends. Ordinary commit failures roll back already-published items; if rollback would overwrite content changed concurrently by another writer, OpenKapsel fails closed and preserves recovery artifacts.

`path.delete` is backend-local: server files go to the server bin, mapped client files to the client bin, and Storage Provider files to that provider mount in .openkapsel/recycle. The delete response includes root for mapped clients and Storage Providers; use the same root selector with recycle_list, recycle_restore and recycle_purge. Each backend restores within its own filesystem. It rejects the workspace root, Storage Provider mapping roots, duplicate paths, and parent/child overlap with another item. Successful deletes return a `recycle_id` and can be restored through `/recycle/restore`.

This is request-level transactionality, not a durable database transaction: v1 does not provide a write-ahead log or guarantee crash recovery across a process or operating-system crash.

### Text encoding and line endings

Text APIs default to UTF-8 independently of the host locale. `encoding` is a request body field for `POST /fs/read/files` (applied to every listed path) and an item field for content operations in `POST /fs/write/mutate`. Supported codecs: `utf-8`, `utf-8-sig`, `utf-16-le`, `utf-16-be`, `ascii`, `iso8859-1` (alias `latin-1`), `cp1252`, `gbk`, `gb18030`, `big5`, and `shift_jis`. MCP text tools expose the same parameter. Search remains UTF-8-only; binary download/upload preserves arbitrary bytes.

There is no encoding detection, locale fallback, or lossy replacement. Invalid input bytes return 415; unsupported codecs or unrepresentable output return 400 without replacing the target. Batch encoding failures are detected before any file is published. Specify the existing encoding for edits. For BOM handling, `utf-8-sig` consumes/emits the UTF-8 BOM; ordinary `utf-8` preserves it as U+FEFF. UTF-16 requires explicit endian and preserves any BOM as U+FEFF; include that character to create a new BOM-bearing UTF-16 file.

Reads preserve LF (`\n`), CRLF (`\r\n`), CR (`\r`), and mixed endings. Character offsets count both characters of CRLF. Writes encode the supplied text literally, even on Windows; use `\r\n` explicitly to create CRLF files. Replacements match exact line endings and preserve all untouched text; replacement text controls its own endings. `POST /fs/read/files` offsets and limits count characters for every codec; byte-addressed access uses the explicit offset/length windows of `POST /fs/read/large`, raw `/fs/content` HTTP Range requests, and upload offsets. Client-local text reads require file API v3 (client 1.59.0+). Transactional mutation requires file API v4; RPC-first servers fail closed rather than degrading `POST /fs/write/mutate` into older write calls.

## Recycle and overwrite policy

File API deletion moves paths into workspace-local private recycle storage under `.openkapsel`. If that storage was removed, OpenKapsel recreates it safely before moving the path. Restore operations return an item to its prior location.

Uploads only create new files. Direct, resumable, and MCP uploads all reject an existing destination. To replace a binary file, first obtain its exact ETag with `/fs/query/stat`, then call `/fs/write/mutate` with a `path.delete` item so the previous version enters private recycle storage, and finally upload the replacement.

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

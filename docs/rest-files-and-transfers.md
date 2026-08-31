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
| `GET` | `/fs/read`, `/fs/stat` | Read UTF-8 text or selected metadata |
| `POST` | `/fs/manifest` | Batch synchronization preflight |
| `GET/HEAD/PUT` | `/fs/content` | Stream or atomically upload raw bytes |
| `POST` | `/fs/write`, `/fs/replace`, `/fs/replace/batch` | Write or perform exact UTF-8 replacements |
| `POST` | `/fs/mkdir`, `/fs/move`, `/fs/delete` | Create, move, rename, or recycle paths |
| `POST` | `/fs/delete/batch` | Preflight and recycle multiple paths |
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

curl -fsS -X POST "$BASE/fs/write" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"path\":\"release.txt\",\"content\":\"ready\",\"plan_id\":$PLAN_ID,\"taskname\":\"release\",\"message\":\"Write release marker\"}"
```

JSON mutations carry `plan_id`, `taskname`, and `message` in the body. Raw-byte upload, upload commit or cancel, stdin, interrupt, and kill requests use:

- `OpenKapsel-Plan-Id`
- `OpenKapsel-Taskname`
- `OpenKapsel-Message`

## Metadata, search, and trees

`fs/stat` can return selected fields: `type`, `size`, `created_at`, `modified_at`, `changed_at`, `etag`, `content_type`, and `sha256`. SHA-256 is calculated only when requested. On platforms without birth time, `created_at` is `null`; inode change time remains separate.

`fs/search` supports literal or regular-expression matching, case sensitivity, recursion depth, and bounded results. Binary, non-UTF-8, oversized, private, and symlinked content is skipped. `fs/tree` uses the same depth model and a total node limit.

`fs/manifest` classifies bounded path sets as `missing`, `same`, `conflict`, or `exists`, calculating hashes only when requested.

## Conditional and batch edits

`fs/write` and `fs/replace` accept conditional ETags. `expected_etag: "*"` requires an existing path. A mismatch returns `412 etag_mismatch` without modifying the target.

`fs/replace/batch` performs replace-only edits across existing UTF-8 files. It supports multiple exact replacement rules in one file. Rules match the original text, source ranges must not overlap, and every file is preflighted before publication. Match, permission, size, ETag, and overlap errors therefore make no requested change. A race after preflight may return per-file `207 Multi-Status` results.

`fs/delete/batch` rejects duplicate and parent/child-overlapping paths and preflights every item before recycling. Its maximum item count is `max_batch_file_operations`.

## Recycle and overwrite policy

File API deletion moves paths into the workspace-local `.recycle` directory. If that directory was removed, OpenKapsel recreates it safely before moving the path. Restore operations return an item to its prior location.

Uploads only create new files. Direct, resumable, and MCP uploads all reject an existing destination. To replace a binary file, first call `fs/delete` so the previous version enters `.recycle`, then upload the replacement.

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

A source token can copy exactly one file or directory into the service share store and receive a random `share_id`. Workspace Root, host-path grants, symlinks, `.recycle`, `.sql`, and `.context` cannot be shared.

Anyone holding the ID can inspect the immutable share without a Workspace token. A destination token imports it with its own credentials and mutation context. Import requires a new destination and never overwrites.

Shares expire after 24 hours by default. At most ten are retained; creating another evicts the oldest. Creators may delete their shares early. Invalid, expired, evicted, and deleted IDs all return `404 share_not_found`.


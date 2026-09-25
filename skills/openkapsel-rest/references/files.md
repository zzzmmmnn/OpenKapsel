# Files, recycle, and binary transfer

Read `GET /discovery/files` first when server-specific limits or availability matter.

For parsed configuration edits or table queries, use the optional [structured/tabular RPC families](data-rpc.md) instead of reading an entire binary or multi-gigabyte CSV through text APIs.

## Read operations

All paths are workspace-relative unless they are absolute paths inside the workspace or an administrator-granted extra path. Symlink escapes are rejected. `.openkapsel` is private.

| Method | Path | Inputs and result |
|---|---|---|
| `GET` | `/fs/list` | `path=.` plus `offset=0`, `limit=1000`; immediate children |
| `GET` | `/fs/read` | required `path`; `offset` or UTF-8-only `byte_offset`; `limit`; optional `encoding`, default UTF-8 |
| `GET` | `/fs/stat` | required `path`; optional comma-separated `fields` |
| `POST` | `/fs/manifest` | bounded `items` with `path` plus optional expected `size`/`sha256`; returns per-file synchronization status |
| `POST` | `/fs/read_many` | read several small text files with optional `encoding`, per-file errors and bounded total content |
| `GET` | `/fs/search` | `path=.`, required `query`, `depth`, `max_results`, `regex`, `case_sensitive` |
| `GET` | `/fs/tree` | `path=.`, `depth=2`; nested tree bounded by published node/depth limits |
| `GET|HEAD` | `/fs/content` | required `path`; raw bytes, ETag, Last-Modified, single HTTP Range support |

`fs/stat` fields are `type`, `size`, `created_at`, `modified_at`, `changed_at`, `etag`, `content_type`, and `sha256`. SHA-256 is computed only when requested. For `fs/content`, use `Range: bytes=<start>-<end>` or `If-None-Match: <etag>` where useful.

`POST /fs/manifest` accepts `{"items":[{"path":"...","size":123,"sha256":"..."}],"include_sha256":false}`. An item with expectations returns `same`, `conflict`, or `missing`; one without expectations returns `exists` or `missing`. It computes SHA-256 only when an expected hash is supplied or `include_sha256` is true. Split requests at `limits.max_batch_file_operations`.

For a recursive inventory, use `{"recursive":true,"path":"src","depth":8,"include_sha256":true}` instead of `items`. The flat response includes the root, file/directory metadata and optional hashes, bounded by `max_tree_nodes`. Depth 0 includes only root; check `truncated` for the node cap. It is not a transactional snapshot.

Prefer `POST /fs/read_many` with `{"paths":["src/main.py","README.md"],"limit":65536,"max_total_chars":262144}` when reading several small source files. Limits count characters (per-file and aggregate), bounded by `max_read_chars`; paths are bounded by `max_batch_file_operations`. Check each item's `status` (HTTP 207 means partial errors). Continue truncated content with `fs/read` using `offset=next_offset`; retry remaining paths separately on `read_budget_exhausted`. It is read-only and requires no mutation context.

Search supports repeated `include`/`exclude` query parameters, e.g. `include=*.py&exclude=node_modules`. Slash-free patterns match basenames; slash-containing patterns match root-relative POSIX paths, with case-sensitive Python fnmatch semantics (`*` spans `/`). Excludes win and prune matching directories; includes only filter files. Each group allows 64 patterns of up to 512 characters.

For a single mapping, these operations run client-locally in one RPC with an
updated client. RPC-first servers do not fall back to FUSE. Reduce batch size,
text budget or depth on 413, or use binary transfer for large payloads.

Workspace-root listing merges virtual mapping registrations without requiring
providers to be online or mounted. Search, tree and recursive manifests delegate
visited mapping subtrees while preserving global depth/result/node limits.
Inspect `unavailable_mappings`, `truncated` and unavailable nodes: an incomplete
result does not mean no matching files exist. Mixed-backend batches retain their
per-item results and preflight rules; they do not require native mounts. Binary
and mixed-root access need current client `file_stream` metadata; see
[mappings.md](mappings.md) for upgrade and reconnect behavior.

Search skips binary, non-UTF-8, oversized, private, and symlinked content. Depth `0` means only the named root; consult Discovery for the maximum.

Text reads and transactional content mutations default to UTF-8 regardless of OS locale. Pass `encoding` in the read/read_many request or on each relevant `fs/mutate` item for other codecs: utf-8-sig, utf-16-le, utf-16-be, ascii, iso8859-1, cp1252, gbk, gb18030, big5, shift_jis. No automatic detection or lossy conversion: decode errors are 415, unrepresentable output is 400 and leaves files unchanged. UTF-16 uses explicit endian; its BOM remains U+FEFF. utf-8-sig consumes/emits the BOM. LF/CRLF/CR are preserved literally; exact replacement must include the original line endings, and new text controls its own endings. Character offsets count both CRLF characters. byte_offset is UTF-8-only; use binary APIs for byte-exact arbitrary formats. Client-local text reads need file API v3; transactional mutation needs file API v4.

## Text and path mutations

These require the matching Bearer token, write permission, and JSON Context fields.

| Method | Path | JSON-specific fields |
|---|---|---|
| `POST` | `/fs/mutate` | transactional `items` using `file.create`, `file.replace`, `text.replace`, `structured.patch`, or recoverable `path.delete`; every existing path requires exact `expected_etag` |
| `POST` | `/fs/large/read` | large files only (>32 MiB): required byte `offset` and bounded `length`; returns Base64, ETag and range SHA-256 |
| `POST` | `/fs/large/replace` | large files only: exact ETag + range SHA-256 + equal-length Base64 replacement; file size cannot change |
| `POST` | `/fs/mkdir` | `path`, optional `parents`, optional `exist_ok` |
| `POST` | `/fs/move` | `source`, `destination`, optional `overwrite=false`, optional `create_parents=false` |
| `POST` | `/recycle/restore` | `recycle_id`; restores only when the original destination is absent |

`fs/mutate` is the single ordinary mutation protocol. Every existing target must carry the exact ETag observed by the preceding stat/read/search; wildcard ETags are rejected. `file.create` is create-only. `text.replace` evaluates exact replacement rules only inside its selected range and requires the declared occurrence count there. `text.insert_before` / `text.insert_after` preserve an exact `match` anchor and insert `content` immediately before/after each occurrence, with `expected_count` defaulting to 1. All three text operations share the same range selectors: each boundary can use a zero-based inclusive line selector or a full-file-unique `start_text` / `end_text` marker that may contain multiple lines. Text marker bounds are inclusive: the range starts at the first character of `start_text` and ends immediately after the final character of `end_text`. Text and line selectors are mutually exclusive on the same side. If omitted, the start defaults to line 0 and the end to EOF. A `match_count_mismatch` error includes `expected`, `actual`, and `match_counts[]`; for multi-rule `text.replace`, `match_counts[]` reports every rule's observed count before anything is published, giving the caller dry-run-like preflight information. `structured.patch` supports guarded JSON/YAML/TOML edits. `path.delete` recycles files or directories and can include large files because it does not inspect their content.

For one logical AI edit, put all affected paths in one request. All items are parsed and preflighted before publication, and content after-images are staged before the first destination is published. One request is restricted to one filesystem domain/mapped client. An ordinary commit error rolls back already-published items. If an external writer changes a just-published path during rollback, OpenKapsel refuses to overwrite that newer content and preserves hidden recovery artifacts instead. This first version is request-transactional; it does not claim crash-journal recovery across a process or OS crash.

`path.delete` rejects duplicate/overlapping targets and parent-child overlap with other mutation items. It is recoverable only inside the token workspace; use the returned `recycle_id` with `/recycle/restore`. The workspace root and Storage Provider mapping roots are protected.

Ordinary content inspection and mutation are capped at **32 MiB per file**. Search also skips larger content, and whole-file SHA-256 metadata operations reject it. Files above 32 MiB must use `fs/large/read`: provide an explicit byte `offset` and `length` (maximum 256 KiB). The response binds the range to an exact file ETag and `range_sha256`. To change that range, call `fs/large/replace` with those two preconditions and exactly `length` replacement bytes in Base64. The server rechecks both before writing and rejects any request that would change total file size. Raw download/upload endpoints remain transfer mechanisms for opaque files; do not use them as a substitute for AI content inspection/mutation.

Deletion is recoverable and recreates private recycle storage safely if a full Shell command removed it. The workspace root cannot be deleted. Full Shell deletion does not use the recycle mechanism.

Batch deletion rejects duplicate paths and parent/child overlaps. It validates every path before the first recycle move, so ordinary precondition failures change none of the requested paths. A race after preflight can produce `207 Multi-Status`; inspect every item and retry only failures after checking current state.

`GET /recycle/list?offset=0&limit=1000` lists recoverable items. It is available only for a child workspace where recycle is enabled.

## Direct binary upload

`PUT /fs/content?path=<encoded-path>&create_parents=false` accepts raw `application/octet-stream` bytes. Include:

- `Content-Length`
- optional `X-Content-SHA256`
- all three `OpenKapsel-*` Context headers

It is atomic and create-only. It never overwrites. If the destination exists, stat it for an exact ETag, then use `fs/mutate` with `path.delete` so the prior version enters private recycle storage before uploading the new file. Use this route only up to `limits.max_direct_upload_bytes`.

## Resumable upload

1. `POST /uploads` with `path`, `size`, optional `sha256`, optional `create_parents`, and JSON Context fields. Save `upload_id` and current `offset`.
2. `GET|HEAD /uploads/<upload_id>` to recover status/offset after interruption.
3. `PATCH /uploads/<upload_id>` with raw bytes, `Upload-Offset`, `Content-Type: application/octet-stream`, and all three `OpenKapsel-*` Context headers.
4. `POST /uploads/<upload_id>/commit` with the three Context headers.
5. `DELETE /uploads/<upload_id>` with the three Context headers to cancel.

Chunks are strictly ordered. Use `limits.recommended_upload_chunk_bytes`; do not exceed the server request-body limit. Commit rechecks permission, destination absence, final size, and optional SHA-256 before atomic publication.

The bundled single-file uploader implements this selection and sequence, including bounded retries:

```bash
python3 scripts/openkapsel_upload.py ./artifact.zip releases/artifact.zip \
  --plan-id 42 --taskname release --message 'Upload the release artifact'
```

The server never overwrites through an upload request. Passing `--overwrite` explicitly makes the helper stat the existing destination, recycle it through transactional `fs/mutate path.delete`, and then start a create-only upload. Without that flag an existing destination is reported as a failure.

## Multiple files and directory trees

`openkapsel_upload_tree.py` accepts one or more files/directories and places each source basename below `--destination`. It creates the complete remote directory tree, preserves empty directories, skips symlinks, and automatically chooses direct or resumable transfer for every file:

```bash
python3 scripts/openkapsel_upload_tree.py ./site ./assets/logo.svg \
  --destination releases/candidate \
  --exclude .git --exclude '*.tmp' --exclude-from .uploadignore \
  --plan-id 42 --taskname release --message 'Upload the release tree'
```

Repeat `--include` or `--exclude` for multiple globs. Patterns are evaluated against POSIX paths relative to each directory source. An exclude pattern without `/` matches any path component, so `--exclude node_modules` prunes every such directory before scanning or hashing. An include pattern without `/` matches file basenames. `--exclude-from` accepts one pattern per line with blank lines and `#` comments ignored. The helper's own `.openkapsel-upload-state` directory is always excluded.

The batch helper first uses `/fs/manifest` when the server advertises it, splitting at the published batch limit. Matching remote files are skipped, differing files fail unless `--overwrite` is explicit, and older servers fall back to the original per-file behavior. It writes a mode-`0600` state file after scanning, upload-session creation, and every accepted chunk. It contains local paths, file metadata, SHA-256 values, upload IDs, and offsets, but never stores either token or the workspace URL. Rerun the same command to query each saved upload session and resume from the server's authoritative offset. The default state path is `.openkapsel-upload-state/<batch-key>.json`; use `--state-file` to choose another path and `--keep-state` to retain a completed manifest.

Transient transport failures and HTTP `408`, `425`, `429`, and selected `5xx` responses are retried. Configure the bounded retry count with `--retries` and the sleep interval with `--retry-delay`; numeric `Retry-After` values are honored when longer. Files continue independently after ordinary failures, and the final JSON summary reports completed, resumed, filtered, skipped-symlink, and failed entries. A process interruption leaves the state file intact. `--overwrite` remains opt-in and recycles each existing file before replacement.

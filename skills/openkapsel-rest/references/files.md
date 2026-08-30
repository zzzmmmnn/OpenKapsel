# Files, recycle, and binary transfer

Read `GET /discovery/files` first when server-specific limits or availability matter.

## Read operations

All paths are workspace-relative unless they are absolute paths inside the workspace or an administrator-granted extra path. Symlink escapes are rejected. `.recycle`, `.sql`, and `.context` are private.

| Method | Path | Inputs and result |
|---|---|---|
| `GET` | `/fs/list` | `path=.` plus `offset=0`, `limit=1000`; immediate children |
| `GET` | `/fs/read` | required `path`; `offset` or efficient `byte_offset`; `limit`; UTF-8 text only |
| `GET` | `/fs/stat` | required `path`; optional comma-separated `fields` |
| `POST` | `/fs/manifest` | bounded `items` with `path` plus optional expected `size`/`sha256`; returns per-file synchronization status |
| `GET` | `/fs/search` | `path=.`, required `query`, `depth`, `max_results`, `regex`, `case_sensitive` |
| `GET` | `/fs/tree` | `path=.`, `depth=2`; nested tree bounded by published node/depth limits |
| `GET|HEAD` | `/fs/content` | required `path`; raw bytes, ETag, Last-Modified, single HTTP Range support |

`fs/stat` fields are `type`, `size`, `created_at`, `modified_at`, `changed_at`, `etag`, `content_type`, and `sha256`. SHA-256 is computed only when requested. For `fs/content`, use `Range: bytes=<start>-<end>` or `If-None-Match: <etag>` where useful.

`POST /fs/manifest` accepts `{"items":[{"path":"...","size":123,"sha256":"..."}],"include_sha256":false}`. An item with expectations returns `same`, `conflict`, or `missing`; one without expectations returns `exists` or `missing`. It computes SHA-256 only when an expected hash is supplied or `include_sha256` is true. Split requests at `limits.max_batch_file_operations`.

Search skips binary, non-UTF-8, oversized, private, and symlinked content. Depth `0` means only the named root; consult Discovery for the maximum.

## Text and path mutations

These require the matching Bearer token, write permission, and JSON Context fields.

| Method | Path | JSON-specific fields |
|---|---|---|
| `POST` | `/fs/write` | `path`, `content`, optional `create_parents`, optional `expected_etag` |
| `POST` | `/fs/replace` | `path`, `old`, `new`, optional `expected_matches` or `replace_all`, optional `expected_etag` |
| `POST` | `/fs/replace/batch` | replace-only `items`; each file has one or more exact `replacements` and optional `expected_etag` |
| `POST` | `/fs/mkdir` | `path`, optional `parents`, optional `exist_ok` |
| `POST` | `/fs/move` | `source`, `destination`, optional `overwrite=false`, optional `create_parents=false` |
| `POST` | `/fs/delete` | `path`; moves it into the workspace-local recycle bin |
| `POST` | `/fs/delete/batch` | `paths`; preflights and recycles multiple independent paths |
| `POST` | `/recycle/restore` | `recycle_id`; restores only when the original destination is absent |

`fs/replace` requires `old` to occur exactly once by default. Use `expected_matches` or `replace_all` only when intentional. Use an ETag from `fs/stat` or `fs/content` to prevent lost updates. `expected_etag: "*"` requires the destination to exist.

`fs/replace/batch` accepts this shape:

```json
{
  "items": [
    {
      "path": "src/example.py",
      "expected_etag": "<optional ETag>",
      "replacements": [
        {"old": "exact original text", "new": "replacement", "expected_matches": 1}
      ]
    }
  ],
  "plan_id": 42,
  "taskname": "refactor",
  "message": "Update related call sites"
}
```

Every rule is located against that file's original text, and every matched occurrence is replaced. Rules may therefore modify several independent places in one file without earlier replacements changing later match targets. Source ranges must not overlap. The server validates every file, match count, range, permission, size, and optional ETag before publishing the first file; it also uses each observed ETag internally when publishing. Ordinary validation failures modify nothing. A post-preflight race can return `207 Multi-Status` with per-file results. The configured batch limit bounds file items, replacement rules, and total matched replacements.

Deletion is recoverable and recreates `.recycle` safely if a Shell command removed it. The workspace root cannot be deleted. Full Shell deletion does not use the recycle mechanism.

Batch deletion rejects duplicate paths and parent/child overlaps. It validates every path before the first recycle move, so ordinary precondition failures change none of the requested paths. A race after preflight can produce `207 Multi-Status`; inspect every item and retry only failures after checking current state.

`GET /recycle/list?offset=0&limit=1000` lists recoverable items. It is available only for a child workspace where recycle is enabled.

## Direct binary upload

`PUT /fs/content?path=<encoded-path>&create_parents=false` accepts raw `application/octet-stream` bytes. Include:

- `Content-Length`
- optional `X-Content-SHA256`
- all three `OpenKapsel-*` Context headers

It is atomic and create-only. It never overwrites. If the destination exists, call `fs/delete` first so the prior version enters `.recycle`, then upload the new file. Use this route only up to `limits.max_direct_upload_bytes`.

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

The server never overwrites through an upload request. Passing `--overwrite` explicitly makes the helper call `fs/delete` first, preserving the old destination in `.recycle`, and then starts a create-only upload. Without that flag an existing destination is reported as a failure.

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

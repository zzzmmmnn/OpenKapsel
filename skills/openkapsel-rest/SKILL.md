---
name: openkapsel-rest
description: Operate an OpenKapsel workspace through its REST, raw-transfer, sharing, preview, and FastAPI HTTP surfaces. Use when a task provides an OpenKapsel workspace URL or asks to inspect files, modify a workspace, manage Context or Memory, run or schedule Shell tasks, transfer data, share content, or test a workspace web app; this skill covers neither MCP nor administrator operations.
---

# OpenKapsel REST

Use the smallest relevant reference instead of loading the complete API contract.

This skill may be installed from the public `skills.openkapsel_rest` descriptor in any OpenKapsel Discovery response. The descriptor exposes a token-free manifest, entrypoint, deterministic ZIP archive, and SHA-256. The same files can be read remotely without installation.

## Required inputs

For workspace operations, obtain:

- `workspace_url`: the read-only capability URL ending in `/w/<READ_TOKEN>`.
- `control_token`: the matching privileged token when the task needs Context, Memory, writes, uploads, Shell, task control, or authenticated capability discovery.

Treat both as credentials. Do not print them, place them in source-controlled files, or send the control token to preview, share-inspection, or application-defined URLs.

From the local controlling project directory, initialize the directory-scoped configuration once:

```bash
python3 <openkapsel-rest-skill-directory>/scripts/openkapsel_config.py init \
  'https://host.example/kapsel/w/<READ_TOKEN>' '<CONTROL_TOKEN>'
```

Invoke the script by its actual installed path while keeping the process working directory at the controlling project. `init` writes `.openkapsel.env` in that current directory with mode `0600` and does not echo either credential. It is idempotent for the same pair and refuses to replace different existing credentials unless `--force` is explicit. Exclude the file from version control. The helpers search from the current directory upward through the nearest Git repository, so changing project directories selects a different OpenKapsel workspace. Never upload or copy this file into the controlled workspace; the tree uploader excludes it automatically.

Explicit `--base-url`, `--control-token`, and `--env-file` options remain available. The original `OPENKAPSEL_BASE_URL` and `OPENKAPSEL_CONTROL_TOKEN` process environment variables remain fallback inputs when no directory file supplies them.

For directory-scoped credentials, the helpers cache the published expiration in the file. When less than two days remain, they call the conditional renewal endpoint, atomically replace the workspace URL and control token, and store the new three-day expiration. Renewal leaves the preview token unchanged. If credentials already expired, administrator renewal is required.

## Operating rules

1. Fetch `GET /` once. Add the matching Bearer token when privileged capability availability matters. Runtime Discovery is authoritative for permissions, limits, URLs, and version differences.
2. Load only the relevant Discovery section and matching reference below. Avoid `discovery/full` unless auditing compatibility across the entire server.
3. Before changing workspace state, query for a suitable active root Plan or create one. Every ordinary modifying endpoint requires `plan_id`, `taskname`, and `message`. Configure persistent Shell variables or POSIX initialization through `/env`, not the local credential file.
4. Keep `taskname` stable for one task and messages brief. Ordinary reads should omit Context fields unless recording the read is genuinely useful.
5. Use ETags for concurrent text or Memory updates. For several exact edits in one or more files, prefer the replace-only batch endpoint so every rule is checked against original text before publication. Binary destinations are create-only: recycle an existing file before uploading its replacement.
6. On completion, update the Plan with a debrief and explicit `memory_actions`, using `[]` when nothing deserves long-term retention.

JSON mutations carry `plan_id`, `taskname`, and `message` in the top-level object. Raw-byte requests and bodyless mutations carry `OpenKapsel-Plan-Id`, `OpenKapsel-Taskname`, and `OpenKapsel-Message` headers. Context Plan/Note endpoints and Memory endpoints have their own documented metadata shapes.

## Route to the needed reference

- For credentials, Discovery, errors, request helpers, and raw transfer aliases, read [references/api-basics.md](references/api-basics.md).
- For file listing, reading, metadata, search, trees, text edits, recycle, direct binary transfer, and resumable uploads, read [references/files.md](references/files.md).
- For operation history, hierarchical Plans, Notes, mutation attribution, and Plan completion, read [references/context.md](references/context.md).
- For durable project knowledge, revision checks, tags, paths, and Memory actions, read [references/memory.md](references/memory.md).
- For persistent Shell environments, tasks, output polling or SSE, interactive stdin, interruption, force-kill, and process inspection, read [references/shell.md](references/shell.md).
- For persistent once, interval, or six-field cron Shell schedules and their run history, read [references/schedules.md](references/schedules.md).
- For static preview and workspace FastAPI applications, read [references/web-and-apps.md](references/web-and-apps.md).
- For temporary cross-workspace transfer by share ID, read [references/sharing.md](references/sharing.md).
- For a compact inventory of every non-MCP HTTP surface, read [references/endpoint-index.md](references/endpoint-index.md).

## Helpers

Use `scripts/openkapsel_http.py` for authenticated JSON, raw, and streaming HTTP requests. It injects Context into JSON bodies or headers when the three Context options are supplied.

Use `scripts/openkapsel_upload.py` for one local file. It reads the server's published limits, calculates SHA-256, automatically chooses direct or resumable upload, and retries transient failures with a configurable sleep interval. Its optional `--overwrite` is explicit and first recycles the existing destination; the upload request itself never overwrites.

Use `scripts/openkapsel_upload_tree.py` for multiple files or directories. It creates remote directories, skips hidden entries unless explicitly selected, supports include/exclude filters, uses native manifest preflight when advertised, chooses the transfer method independently for every file, and keeps a credential-free local state file so rerunning the same command resumes an interrupted batch. The helper resolves the target from `.openkapsel.env`, explicit options, or legacy environment variables; this skill contains no server address.

Do not infer authorization from possession of the URL token. A URL token remains read-only; the matching control token only unlocks permissions enabled on that token record.

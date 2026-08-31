# REST basics

## URL and authentication model

Normalize `workspace_url` by removing its trailing slash. Workspace endpoints are relative to it.

- The read token embedded in `workspace_url` authenticates read-only file and Discovery access.
- Send `Authorization: Bearer <CONTROL_TOKEN>` for privileged Discovery, Context, Memory, mutations, uploads, sharing changes, Shell, and task control.
- The Bearer token must belong to the same record as the URL token. Missing/invalid credentials normally return `401`; a valid control token bound to another workspace URL returns `403`.
- A preview token is independent. Never substitute it for either workspace credential.
- `GET <workspace_url>/` never echoes the control token.

Use the control token only on the workspace origin or a documented control-authenticated `/transfer/...` URL. Do not forward it to a static preview URL, public share URL, or workspace application's own route.

## Directory-scoped configuration and renewal

Initialize a controlling project from its directory:

```bash
python3 <openkapsel-rest-skill-directory>/scripts/openkapsel_config.py init \
  'https://host.example/kapsel/w/<READ_TOKEN>' '<CONTROL_TOKEN>'
```

Invoke the installed script by its actual path while keeping the working directory at the controlling project. The command writes `.openkapsel.env` in that current directory with mode `0600`, returns only its path/action/mode, is idempotent for identical credentials, and requires `--force` to replace a different existing configuration. Exclude it from version control and do not place it in or upload it to the controlled workspace. The bundled helpers first use explicit CLI values, then the nearest `.openkapsel.env`, then the legacy process environment. `OPENKAPSEL_ENV_FILE` or `--env-file` selects a non-default file. The helpers do not Shell-source this file; they parse only the documented keys without expansion.

Directory-scoped helpers discover and cache `OPENKAPSEL_CREDENTIALS_EXPIRES_AT`. With less than 172800 seconds remaining they send `POST credentials/renew` using the current URL and Bearer token. A successful response returns `read_token`, `control_token`, `workspace_url`, and `credentials_expires_at`; the helper atomically updates the file before continuing the original operation. Both old workspace credentials become invalid immediately, the replacements expire three days after the renewal request, and the preview token does not change. A `409 credentials_renewal_not_due` means at least two days remain. Expired credentials require administrator renewal.

## Discovery

| Method | Relative path | Purpose |
|---|---|---|
| `GET` | `/` | Compact capability index and links |
| `GET` | `/discovery/files` | File, recycle, and binary transfer contract |
| `GET` | `/discovery/context` | Context and Plan contract |
| `GET` | `/discovery/memory` | Long-term Memory contract |
| `GET` | `/discovery/shell` | Shell, task, process, and resource limits |
| `GET` | `/discovery/web` | Preview, FastAPI, libraries, and database runtime |
| `GET` | `/discovery/sharing` | Temporary share contract |
| `GET` | `/discovery/full` | Complete compatibility document; load only when necessary |

Send `Accept: application/json`. Supplying the Bearer token changes capability fields from redacted/read-only to the privileges actually available.

Every Discovery response also contains `skills.openkapsel_rest`. Its `manifest_url`, `entrypoint_url`, and `archive_url` are public, contain no workspace credential, and require no Authorization header. To install, download `archive_url`, verify it against `archive_sha256`, and extract the single `openkapsel-rest` directory into the AI client's skill directory. An agent that cannot install may read `entrypoint_url` and its linked files directly.

## Context on requests

Ordinary JSON mutation:

```json
{
  "path": "src/app.py",
  "content": "...",
  "plan_id": 42,
  "taskname": "fix-preview",
  "message": "Update the preview handler"
}
```

Raw or bodyless mutation:

```http
OpenKapsel-Plan-Id: 42
OpenKapsel-Taskname: fix-preview
OpenKapsel-Message: Upload the rebuilt asset
```

`taskname` is at most 32 characters and an operation `message` is at most 200 characters. A read may optionally include `plan_id`, `taskname`, and `message` as query parameters; omit all three for ordinary reads. `taskname` and `message` must be supplied together when recording a read.

## Request helper

Examples from the skill directory:

```bash
python3 scripts/openkapsel_http.py GET discovery/files

python3 scripts/openkapsel_http.py GET fs/stat \
  --query path=src/app.py --query fields=type,size,etag,sha256

python3 scripts/openkapsel_http.py POST fs/mkdir \
  --json '{"path":"build","parents":true,"exist_ok":true}' \
  --plan-id 42 --taskname build --message 'Create the build directory'
```

The helper uses the nearest `.openkapsel.env` by default and falls back to `OPENKAPSEL_BASE_URL` and `OPENKAPSEL_CONTROL_TOKEN`. Relative paths receive the Bearer token when it is present. Absolute URLs receive no Bearer token unless `--auth control` is explicit.

Use `--output FILE` for binary downloads, `--include-headers` to inspect response headers, `--data-file FILE` for raw request bodies, and `--header 'Name: value'` for protocol-specific headers.

## Control-only raw transfer aliases

The server also accepts these routes under the service base, without a URL token:

- `GET|HEAD|PUT <service-base>/transfer/fs/content?...`
- `GET|HEAD|PATCH|DELETE <service-base>/transfer/uploads/<upload_id>`
- `POST <service-base>/transfer/uploads/<upload_id>/commit`

They require the Bearer control token, which selects the token record. There is no control-only alias for creating an upload session; create it through `<workspace_url>/uploads` first. Prefer the canonical workspace routes unless a returned transfer URL specifically uses `/transfer`.

## Errors and retries

Errors are JSON and use non-2xx status codes:

```json
{"error":{"code":"stable_code","message":"human message","details":{}}}
```

- Do not retry `400`, `401`, `403`, `404`, `409`, or `412` unchanged.
- Honor `Retry-After` on `429`.
- On upload offset conflict, use the returned current offset rather than restarting blindly.
- On ETag or revision conflict, re-read the resource, reconcile, and retry with the new validator.
- Treat an ambiguous network failure after a mutation as unknown outcome; inspect state before repeating it.

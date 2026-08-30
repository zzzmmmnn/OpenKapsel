# OpenKapsel

OpenKapsel is Python 3 remote-workspace infrastructure for AI clients. It exposes token-scoped files, Shell tasks, previews, application backends, Context, Memory, sharing, and MCP without trying to be an online IDE. A configured Workspace Root contains direct child workspaces; every token is bound to one child workspace or one mounted workspace image.

The read-only URL token, control token, and browser preview token are independent credentials. File mutation, uploads, Shell, task control, Context, Memory, and MCP require the matching control token. Static browser preview uses a separate preview origin and never exposes either Workspace credential.

The main service uses the Python standard library. Workspace FastAPI applications use the bundled web, database, scientific-computing, plotting, cryptography, and XML runtime described below. Python 3.10 or later is required. Restricted Shell supports Bubblewrap and Podman on Linux; aggregate process, memory, and CPU limits use cgroup v2 and systemd delegation.

## Production installation

The supported production layout is:

- read-only application files: `/opt/openkapsel`
- configuration and token registry: `/var/lib/openkapsel`
- Workspace Root: `/var/lib/openkapsel/workspace`
- temporary cross-workspace shares: `/var/lib/openkapsel/shares`
- ephemeral token-scoped network proxies: `/var/lib/openkapsel/network-proxies`
- system service user: `openkapsel`, with no interactive login
- TLS and public routing: an existing Caddy instance

The installer has been tested on Ubuntu 24.04 with Bubblewrap 0.9.0.

### New installation

Run from the project directory:

```bash
sudo ./install.sh
```

The installer creates an eight-character random administrator name and a sixteen-character random password on first installation. They are printed once. Existing credentials are preserved during upgrades.

The installer installs Python, venv, Bubblewrap, RootlessKit, slirp4netns, uidmap, ACL tools, Git, curl, e2fsprogs, util-linux, CA certificates, Fontconfig, DejaVu fonts, Noto fonts including Noto CJK, and the Python runtime dependencies. To install and enable the Podman backend as well:

```bash
sudo ./install.sh --with-podman
```

Use `--no-package-install` when system packages are already present. Use `--no-start` to generate and validate the installation without starting services.

Edit `/var/lib/openkapsel/config.json` after installation, then restart:

```bash
sudo systemctl restart openkapsel
sudo systemctl status openkapsel openkapsel-images
```

### Migration from an older directory layout

If an older installation stores code, state, and `workspace` in one directory:

```bash
sudo ./install.sh --migrate-from /path/to/old/openkapsel
```

The installer preserves administrator settings and token data, rewrites managed paths, and moves the old Workspace only when the new destination is absent or empty. Old code and state remain available for rollback. Back up configuration, tokens, and workspaces before migration.

### Granting paths outside Workspace Root

An additional host path must be authorized at three layers: host permissions, systemd filesystem policy, and the individual token.

```bash
sudo ./install.sh \
  --grant-ro /srv/reference \
  --grant-rw /var/www/site
```

The installer grants ACL access only to `openkapsel` and writes a systemd drop-in. Add the same normalized absolute path to a token in the administration console and choose read-only or writable access. Restricted Shell mounts only that token's workspace and explicit path grants. It cannot see other token workspaces, OpenKapsel configuration, or token data.

Re-running the installer without `--grant-ro` or `--grant-rw` preserves existing host grants. Supplying either option replaces the complete grant list. An existing `/opt/openkapsel` is retained as a UTC-stamped `.previous.*` directory; `/var/lib/openkapsel` is never overwritten.

### Caddy routing

Merge routes into the existing Caddyfile. Keep the `/agent` prefix for the API site and forward the preview origin without rewriting its root path:

```caddyfile
ws.example.com {
    handle /agent/* {
        reverse_proxy 127.0.0.1:8765
    }
}

preview.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

Validate and reload using the command appropriate for the existing Caddy installation. Do not start a second Caddy process on the same ports.

OpenKapsel does not terminate TLS. Production mode requires HTTPS as indicated by `public_base_url` and `preview_base_url`; Caddy supplies HSTS and forwarding headers.

### Installation checks

```bash
systemctl is-active openkapsel openkapsel-images
curl -I https://ws.example.com/agent/admin
curl -I https://preview.example.com/
```

Open `https://ws.example.com/agent/admin`, sign in, and create a token. Start additional path grants as read-only and enable writes only when required.

## Development mode

```bash
cp config.example.json config.json
python3 set_password.py --config config.json
python3 -m openkapsel --config config.json
```

`set_password.py` interactively sets and confirms the password. Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and an independent random sixteen-byte salt:

```text
pbkdf2_sha256$600000$<random-salt>$<derived-digest>
```

Generate a random administrator name and password with:

```bash
python3 set_password.py --config config.json --generate-username --generate
```

Credentials are printed once. Configuration updates are atomic and use mode `0600`. Legacy fixed-salt SHA-256 credentials remain accepted and migrate to PBKDF2 after a successful login.

See `config.example.json` for every setting. Important groups include:

- `workspace_root`, `listen_host`, `listen_port`, and `url_base_path`
- `public_base_url` and `preview_base_url`
- `token_data_file`, `upload_state_dir`, and `share_dir`, which must remain outside Workspace Root
- upload, file, batch-operation, search, task, and share size or concurrency limits
- `sandbox_default_backend`, Bubblewrap and Podman paths, and cgroup settings
- the optional workspace-image helper socket

Relative paths resolve from the configuration file directory. The service listens on HTTP only; TLS belongs to the reverse proxy.

## Authentication and Discovery

The canonical Workspace URL is:

```text
https://ws.example.com/agent/w/<READ_TOKEN>/
```

The URL token always grants read-only access. Mutating and privileged requests add:

```http
Authorization: Bearer <CONTROL_TOKEN>
```

The control token must belong to the same token record as the URL token. A missing or invalid control token returns `401`; using a valid control token from another record returns `403`. Discovery never echoes the control token. The read and control credentials share a short expiration, defaulting to three days, while the workspace lifetime remains the longer administrator-selected period. Discovery publishes both credential expiration timestamps.

The root URL returns a compact Discovery index containing authentication rules, capability summaries, key limits, a short workflow, and links to focused documents:

- `./discovery/files`
- `./discovery/context`
- `./discovery/memory`
- `./discovery/shell`
- `./discovery/web`
- `./discovery/sharing`
- `./discovery/full`

The `full` section retains the complete compatibility document. The same URL token and optional matching Bearer token apply to every section. Browser requests preferring HTML receive a readable page; API clients receive JSON. Invalid tokens and paths preserve their real non-2xx status.

### OpenKapsel REST skill

`skills/openkapsel-rest` is a portable AI-agent skill for the non-MCP workspace HTTP surface. Its short `SKILL.md` routes an agent to focused references for files, Context, Memory, Shell, preview/FastAPI applications, and sharing, so routine work does not need to load `discovery/full`. Administrator operations are intentionally excluded. Runtime focused Discovery remains authoritative for the deployed token's permissions and limits.

The skill also includes standard-library request and upload helpers. It is server-agnostic: the target workspace URL is supplied at runtime and no deployment address is embedded in the skill. Running the installed `scripts/openkapsel_config.py init <workspace-url> <control-token>` by its absolute Skill path while the working directory is a local controlling project creates a mode-`0600` `.openkapsel.env` there without echoing credentials; identical initialization is idempotent and replacing a different configuration requires `--force`. Helpers resolve the nearest file from the current directory, while explicit arguments and the original process environment variables remain supported. The helpers cache credential expiration and, when less than two days remain, use the conditional self-renewal endpoint to atomically rotate both workspace credentials for another three days and rewrite the file. Directory uploads skip hidden files and directories by default; explicitly named hidden sources or matching `--include` rules opt them in, while `.openkapsel.env` is always excluded. The single-file helper automatically chooses direct or resumable transfer and performs bounded transient-error retries. The batch helper accepts multiple files and directory trees, creates directories, applies include/exclude filters, uses native manifest preflight when available, selects the transfer method per file, and resumes interrupted batches from a credential-free local state file. Upload requests remain create-only; an explicit helper overwrite option first moves the prior file to `.recycle`. Every Discovery response advertises `skills.openkapsel_rest` with public, token-free manifest, entrypoint, archive, and SHA-256 fields. An AI can read the linked files remotely or verify and install the ZIP into its own skills directory. The server exposes these files at `<url_base_path>/skills/openkapsel-rest`; no Workspace, control, or preview credential appears in those URLs.

Install the source copy locally by copying `skills/openkapsel-rest` into the AI client's skills directory. Production installation places the served copy at `/opt/openkapsel/skills/openkapsel-rest`; it is not mounted into restricted Shell or FastAPI workers.

MCP `workspace_info` defaults to the compact index and accepts `section` with `main`, `files`, `context`, `memory`, `shell`, `web`, `sharing`, or `full`. MCP `tools/list` remains authoritative for tool schemas.

## Administration and token permissions

The administration console is at `<url_base_path>/admin`. Its twelve-hour session cookie is `HttpOnly` and `SameSite=Strict`; it is also `Secure` behind HTTPS. All forms use CSRF protection. Repeated login failures are rate-limited in memory by source address.

The single-page console has responsive tabs for tokens, workspace images, and password changes. Token entries are collapsed by default and show only name, state, workspace, workspace lifetime, and a permission summary. Expanding an entry reveals credentials, renewal/rotation controls, and advanced permissions. Administrator renewal replaces both the read URL token and control token atomically and sets their shared expiration to 1–30 days from renewal time (three days by default). A control-authenticated workspace may also call `POST credentials/renew` only when less than two days remain; self-renewal always rotates both credentials for three more days and returns the replacement read token, control token, full workspace URL, and expiration. The preview token and workspace lifetime do not change.

Each token controls:

- workspace lifetime: 1, 7, 30, 91, 365, or 730 days, or no expiration
- read/control credential lifetime: three days initially; administrator renewal accepts 1–30 days
- regular direct-child directory or mounted ext4 workspace image
- read and write permissions
- independent Web preview permission
- network mode: disabled, allowed domains only, or full network
- no Shell, restricted Shell, or full Shell
- Bubblewrap, Podman, or the configured automatic restricted-Shell backend
- process/thread, aggregate memory, and aggregate CPU limits
- additional absolute host paths, each read-only or writable

New restricted tokens default to 64 workload processes/threads, 256 MiB aggregate memory, and 100% CPU, where 100% equals one logical core. These values are per-token settings, not global configuration constants. Bubblewrap adds a fixed allowance of 16 PIDs to its cgroup limit for namespace launchers, the proxy relay, and other sandbox infrastructure; Podman continues to enforce the configured process value directly.

Allowed-domain mode accepts exact hosts such as `github.com` and explicit suffix rules such as `.githubusercontent.com`. New-token forms are prefilled from `default_network_domains`, covering GitHub and GitHub Packages, PyPI, npm, Yarn, Node.js releases, GitLab, Bitbucket, Codeberg, Gitee, and SourceHut. Administrators can replace the list per token. This mode supports HTTP, HTTPS, WebSocket, and HTTPS Git operations, including ordinary `git clone`, package installation, and release downloads whose redirect targets are also allowed. Browser preview requests do not use this Shell/API-worker allowlist; external preview scripts remain governed separately by the preview Content Security Policy. SSH clone URLs, the unauthenticated Git protocol, UDP/QUIC, direct IP destinations, private addresses, and non-80/443 ports are blocked.

Full Shell runs directly as the OpenKapsel service user. It can access every path and network resource available to that user; token path grants and network modes do not constrain it. Full Shell is intentionally not a sandbox boundary.

Renewing read/control credentials invalidates both prior credentials but leaves the preview token, workspace, and settings unchanged. Individual control, URL, and preview rotation controls remain available for targeted revocation; individual rotation does not extend the credential expiration.

Deleting a token does not delete its workspace. Multiple tokens may reference the same regular workspace or workspace image. A workspace image cannot be deleted while any token references it; the error identifies the records using it.

### Workspace images and capacity

The privileged `openkapsel-images` helper manages sparse ext4 image files. `name.img` mounts at the same-named child directory under Workspace Root. New images default to 256 MiB. They can be expanded but not shrunk.

Image deletion is permanent and is allowed only when no token references the image. The regular-directory mode remains supported on platforms without the helper.

Workspace image capacity is published in Discovery. The quota is enforced by the mounted filesystem rather than application bookkeeping, so Shell subprocesses cannot write beyond it.

### Sandbox backends

Restricted Shell uses a pluggable backend:

- Bubblewrap provides mount, user, network, and PID namespaces.
- Podman uses a rootless container runtime and the same token path grants.
- `auto` resolves to the configured default and never falls back to full Shell.

The administration console enumerates images installed in the rootless Podman storage owned by the `openkapsel` service account. Each token can select a distinct `Podman · <image>` entry; the selected image is persisted with that token. `podman_image` remains the backward-compatible default for older Podman tokens and for `auto` when Podman is the configured default. Removing a selected image does not silently substitute another image: the token keeps its selection and Shell launch reports that the image is unavailable. Podman runs with `--pull=never`, so restricted Shell requests cannot trigger implicit image downloads.

Only the read-only venv required by FastAPI workers is mounted from `/opt/openkapsel`; the complete application directory is not exposed. Restricted processes receive a private PID namespace and cannot inspect host `/proc` or other workspaces.

Full-network restricted tasks use RootlessKit/slirp4netns or the Podman rootless network and block host loopback. Disabled and allowed-domain modes both give the sandbox a network namespace without direct external connectivity. Allowed-domain mode mounts only a private Unix socket for that Token and runs a loopback HTTP proxy relay inside the namespace; OpenKapsel resolves and connects to approved public destinations on the other side. Merely ignoring proxy environment variables or connecting directly to an IP therefore does not bypass the policy. Each Shell task and FastAPI worker receives a separate proxy instance carrying that Token's current rules.

The proxy does not decrypt TLS. HTTPS `CONNECT` targets are checked by hostname and port, while certificate validation remains end-to-end between the sandboxed client and destination. Redirects cause a new proxy request and are checked again. An allowed service can still expose user-controlled content on its own approved origin, so prefer exact domains and add suffix rules only where required.

Bubblewrap uses the host Git and curl installed by `install.sh`. A Podman Shell uses only tools present in its token-selected image; choose an image containing Git or curl when those commands are required. Pull images as the `openkapsel` account so they appear in the administration console, for example:

```bash
sudo -u openkapsel env HOME=/var/lib/openkapsel/home XDG_RUNTIME_DIR=/var/lib/openkapsel/run \
  podman pull docker.io/library/python:3.14-slim-trixie
```

The included `containers/python-3.14-git/Containerfile` builds a Python 3.14
image with Git, curl, wget, and CA certificates. Build it directly into the
service account's rootless image store:

```bash
cd /opt/openkapsel
sudo -u openkapsel env HOME=/var/lib/openkapsel/home XDG_RUNTIME_DIR=/var/lib/openkapsel/run \
  podman --cgroup-manager=cgroupfs build --pull=never --network=slirp4netns \
  --tag localhost/openkapsel-python:3.14-git containers/python-3.14-git
```

After the build completes, `Podman · localhost/openkapsel-python:3.14-git`
appears automatically in the token sandbox selector.

## REST API overview

Workspace endpoints are relative to `<url_base_path>/w/<READ_TOKEN>`. All state-changing operations require the matching Bearer control token and valid `plan_id`, `taskname`, and `message` context.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Compact Workspace Discovery |
| `GET` | `/discovery/<section>` | Focused or complete Discovery |
| `GET/POST` | `/context` | Query Context or create a Plan/Note |
| `GET` | `/context/plans/<id>/tree` | Read a Plan subtree and attached entries |
| `PATCH` | `/context/plans/<id>` | Update Plan content, status, parent, and debrief |
| `PATCH` | `/context/notes/<id>` | Replace a Note with a new record |
| `GET` | `/memory`, `/memory/project` | Query Memory or read project Memory |
| `POST` | `/memory` | Create Memory |
| `GET/PATCH/DELETE` | `/memory/<id>` | Read, revise, or archive Memory |
| `GET` | `/memory/<id>/revisions` | List Memory revisions |
| `GET` | `/fs/list`, `/fs/tree`, `/fs/search` | List, recursively inspect, or search files |
| `GET` | `/fs/read`, `/fs/stat` | Read UTF-8 text or selected metadata |
| `POST` | `/fs/manifest` | Batch file status and synchronization preflight |
| `GET/HEAD/PUT` | `/fs/content` | Stream or atomically upload raw bytes |
| `POST` | `/fs/write`, `/fs/replace`, `/fs/replace/batch` | Atomically write or perform exact UTF-8 replacements |
| `POST` | `/fs/mkdir`, `/fs/move`, `/fs/delete` | Create, move/rename, or recycle paths |
| `POST` | `/fs/delete/batch` | Preflight and recycle multiple independent paths |
| `GET/POST` | `/recycle/list`, `/recycle/restore` | List and restore recycled paths |
| `POST` | `/uploads` | Start a resumable upload |
| `GET/HEAD/PATCH` | `/uploads/<id>` | Inspect or append upload data |
| `POST/DELETE` | `/uploads/<id>/commit` or `/uploads/<id>` | Commit or cancel an upload |
| `POST` | `/shell/exec` | Start an asynchronous Shell task |
| `GET` | `/tasks`, `/tasks/<id>` | List tasks or read task state |
| `GET` | `/tasks/<id>/output`, `/tasks/<id>/stream` | Incremental or SSE task output |
| `POST` | `/tasks/<id>/stdin` | Write or close interactive stdin |
| `POST` | `/tasks/<id>/interrupt`, `/tasks/<id>/kill` | Graceful or forced termination |
| `GET` | `/sandbox/processes` | List token cgroup processes and usage |
| `POST/GET/DELETE` | `/shares`, `/shares/<id>` | Create, inspect, or delete temporary shares |
| `POST` | `/shares/<id>/import` | Import a share into this workspace |
| `POST` | `/mcp` | Stateless Streamable HTTP MCP |

`fs/stat` accepts `type,size,created_at,modified_at,changed_at,etag,content_type,sha256`. SHA-256 is calculated only when requested. On platforms without birth time, `created_at` is `null` and `created_at_available` is false; inode change time is reported separately.

`fs/search` supports literal or regular-expression matching, case sensitivity, recursion depth, and bounded results. Binary, non-UTF-8, oversized, private, and symlinked content is skipped. `fs/tree` uses the same depth semantics and a total node limit.

`fs/write` and `fs/replace` accept conditional ETags. `expected_etag: "*"` requires an existing destination. A mismatch returns `412 etag_mismatch` and preserves the target.

`fs/replace/batch` performs replace-only edits across one or more existing UTF-8 files, with multiple exact replacement rules per file. Every rule matches the original file text, all source ranges must be non-overlapping, and all files are preflighted before the first publication. Match, permission, size, overlap, and supplied ETag errors therefore modify no files. Publication uses the observed ETags even when the caller omitted them; a post-preflight race can return per-file `207 Multi-Status` results.

Binary uploads only create new files and never overwrite an existing path. To
replace a file, first delete it through `fs/delete` so the old version is retained
in `.recycle`, then upload the replacement. Direct, resumable, and MCP uploads all
enforce this rule.

Deletion through the file API moves paths into the workspace-local `.recycle`. If `.recycle` was removed, the service recreates it safely before the move. Full Shell deletion is direct and not recoverable through this API.

`fs/manifest` reports `missing`, `same`, `conflict`, or `exists` for a bounded set of paths and calculates hashes only when requested. `fs/delete/batch` rejects duplicates and parent/child overlaps, preflights every path before changing any requested item, and reports a post-preflight race with per-item `207 Multi-Status` results. The shared maximum item count is `max_batch_file_operations` in configuration and Discovery.

### Mutation context

Create a root Plan before changing state:

```bash
BASE='https://ws.example.com/agent/w/<READ_TOKEN>'
AUTH='Authorization: Bearer <CONTROL_TOKEN>'

PLAN_ID=$(curl -fsS -X POST "$BASE/context" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"type":"plan","taskname":"release","content":"Prepare and verify the release."}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -X POST "$BASE/fs/write" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"path\":\"release.txt\",\"content\":\"ready\",\"plan_id\":$PLAN_ID,\"taskname\":\"release\",\"message\":\"Write the release marker\"}"
```

JSON mutations carry `plan_id`, `taskname`, and `message` in the object. Raw-byte uploads, upload commit/cancel, stdin, interrupt, and kill use `OpenKapsel-Plan-Id`, `OpenKapsel-Taskname`, and `OpenKapsel-Message` headers.

### Resumable large-file transfer

Create an upload with the final path, size, and optional SHA-256. The destination must not exist. Append raw `application/octet-stream` bytes in order with `Upload-Offset`, then commit. Offset conflicts return the current server offset. Upload state survives service restarts.

REST raw-byte transfer does not use Base64 or load a complete file into Python memory. Direct `PUT /fs/content` is for files within the configured direct-body limit. Larger files use resumable uploads. MCP returns authenticated raw transfer URLs so large data stays outside JSON and AI context.

Commit rechecks path permission, destination absence, final size, and optional SHA-256 before atomically publishing without replacement. Temporary upload totals, file limits, concurrency, chunk recommendations, and TTL are configured and published in Discovery.

### Temporary cross-workspace sharing

A source token can copy exactly one file or directory into the service-level share store and receive a random `share_id`. The source cannot share Workspace Root, additional host paths, symbolic links, or `.recycle`, `.sql`, and `.context` private content.

Anyone holding the ID can inspect the immutable share without a Workspace token. A destination token imports it using its own read URL, control token, and mutation context. The source credential is never required or disclosed. Import requires a new destination path and never overwrites.

Shares expire after 24 hours by default. The service retains at most ten; creating another evicts the oldest. A creator may delete its share early. Invalid, expired, evicted, and deleted IDs all return `404 share_not_found`.

## Web preview and FastAPI applications

A token with read and preview permissions receives an independent URL:

```text
https://preview.example.com/<PREVIEW_TOKEN>/path/to/index.html
```

Directories resolve `index.html`. Static preview uses a dedicated origin, `Referrer-Policy: no-referrer`, restrictive CSP and permissions policy, no permissive CORS response, and browser script support without exposing Workspace credentials.

Any directory named `api` delegates that application subtree to FastAPI. The entrypoint is the parent application's `api/app.py`; nested applications are independent. Example:

```text
workspace/
  site-a/
    index.html
    api/app.py
  site-b/
    index.html
    api/app.py
```

The application is a normal FastAPI module:

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"ok": True}
```

OpenKapsel returns `404` for FastAPI's default `/docs`, `/redoc`, and
`/openapi.json` routes so an application schema is not anonymously exposed.
Applications that intentionally publish documentation should use a different,
explicit route and apply their own authentication policy.

Supported application libraries are published at `capabilities.web_app_api.available_libraries` in `discovery/web` and MCP `workspace_info(section="web")`:

- `fastapi`: ASGI application, routing, requests, and responses
- `sqlalchemy`: portable ORM, Core, schema, and transaction APIs
- `python-multipart`: `UploadFile`, `File`, and `Form` multipart parsing
- `jinja2`: server-side HTML and text templates
- `httpx`: synchronous and asynchronous HTTP clients; outbound requests still require token network permission
- `numpy`: multidimensional arrays and numerical computing
- `numba`: JIT compilation for numerical Python code
- `pandas`: data frames, tabular data, and time-series tools
- `matplotlib`: non-interactive plotting; DejaVu and Noto fonts are installed on production hosts
- `scipy`: scientific algorithms, optimization, statistics, and signal processing
- `cryptography`: high-level cryptographic recipes and low-level primitives
- `lxml`: XML and HTML parsing, validation, and XPath support
- `pillow`: image decoding, encoding, resizing, format conversion, and transformation
- `pyyaml`: YAML parsing and serialization; prefer `yaml.safe_load` for untrusted input
- `beautifulsoup4`: fault-tolerant HTML and XML document traversal, using `lxml` when requested

Uvicorn is installed as Worker infrastructure rather than an application-facing contract. Transitive packages such as Pydantic, Starlette, and AnyIO are not promised as independent stable runtime libraries.

Numba installs `llvmlite` as a dependency. Supported pip wheels bundle the LLVM components required by Numba, so a separate system LLVM toolchain is not installed. Building Numba or llvmlite from source is outside the supported installer path.

These application libraries are installed in `/opt/openkapsel/venv` and are available to FastAPI Workers. This does not promise the same packages inside every restricted Shell backend: Bubblewrap Shell sees host system tools, while Podman Shell sees packages contained in its configured image.

OpenKapsel does not provide application users, login, CAPTCHA, cookies, sessions, CSRF, or roles. Each application implements its own business authentication.

### Managed database runtime

Application code imports:

```python
from openkapsel_runtime import database
```

`database.engine("main")` returns a cached SQLAlchemy Engine for the Worker lifetime. `database.session("main")` is a transaction context manager: normal exit commits and closes; exceptions roll back, close, and are re-raised.

Database IDs contain 1-64 ASCII letters, digits, underscores, or hyphens. Applications should use SQLAlchemy ORM, Core, schema, and transaction APIs. They must not construct storage paths or depend on backend-specific SQL. The current implementation uses private workspace storage, but Discovery intentionally publishes only the portable SQLAlchemy contract.

Database storage is under the application's private `.sql` area and is unavailable through file APIs, static preview, restricted Shell, or other applications. Missing private directories are recreated automatically for older workspaces.

Workers run in an isolated PID namespace and see only the application workspace plus the read-only runtime venv. The complete `/opt/openkapsel` tree, host `/proc`, token registry, configuration, other workspaces, `.context`, and raw database files are not mounted.

## Shell tasks and streaming I/O

`POST /shell/exec` creates an asynchronous task and returns `task_id`. The default limits are eight concurrent tasks per token and sixteen globally; both are configurable. Each task has a maximum runtime, one hour by default.

Interactive tasks accept stdin. Output can be read by byte cursor, waited on for up to thirty seconds, or streamed with SSE `output` and `done` events. `interrupt` sends SIGTERM to the process group and escalates after the grace period; `kill` sends SIGKILL immediately.

Finished task output is persisted to disk rather than retained indefinitely in memory. Each token keeps a bounded number of completed records, four by default, with configurable retention. The process endpoint lists the restricted token's cgroup PIDs, command, memory, CPU, and OOM counters.

## Workspace Context

Each workspace owns `.context/context.sqlite3`. Context is an append-oriented operation history, not a session that must be opened or closed. IDs are auto-incrementing integers.

Types:

- `operation`: automatically recorded REST or MCP work with `running`, `succeeded`, or `failed` status
- `plan`: AI-authored work hierarchy with `in_progress`, `completed`, or `cancelled` status
- `note`: AI-authored finding attached to a Plan

A root Plan has `plan_id: null`. A Sub Plan references its parent. Operations and Notes reference their owning Plan. Plan parent cycles and self-parenting are rejected. Plan updates preserve the ID; Note replacement creates a new ID and deletes the old row atomically.

New `taskname` values are limited to 32 Unicode characters. Operation messages are limited to 200 characters; Plan and Note content can contain up to 32,768 characters. `actor_id` is a SHA-256 pseudonymous identifier derived from the URL token, allowing multiple tokens sharing one workspace to be distinguished without storing the raw token.

Every state-changing REST or MCP operation requires a valid Plan plus `taskname` and `message`. Reads are not recorded when context is omitted. To record a read, supply `taskname` and `message` together; `plan_id` is optional but recommended.

Creating a Plan through REST or MCP returns `unfinished_root_plans`, containing up to twenty previously existing `in_progress` root Plan summaries. Sub Plans and the newly created Plan are excluded. `unfinished_root_plans_total` and `unfinished_root_plans_truncated` describe the complete result. Each `content_preview` is limited to 256 characters.

Plan completion requires a debrief with `summary`, `outcome`, and `memory_actions`. Context stores only filtered result metadata and never records file bodies, Shell commands, stdin, stdout, stderr, tokens, or Authorization headers.

Queries support integer ID, text, type, status, taskname, actor, normalized operation path, direct Plan ID, root-only filtering, and cursors. Results are newest first and limited to 200. The Plan tree endpoint returns flat depth-annotated Plans and attached entries so clients can rebuild the hierarchy.

Each workspace retains up to 100,000 Context entries. Overflow removes the oldest Operations and Notes in batches while retaining referenced Plans. `.context` is private from file APIs, preview, FastAPI workers, and restricted Shell. Full Shell is outside the sandbox boundary and can still alter workspace-private files.

## Project Memory

Long-lived Memory uses the separate `.context/memory.sqlite3`. It stores cross-task overview, architecture, conventions, decisions, and known issues without counting toward Context retention.

Memory categories are `overview`, `architecture`, `convention`, `decision`, and `known_issue`. Records have a title, up to 32,768 characters of content, optional stable key, up to 32 indexed tags, up to 64 workspace-relative paths, status, severity, and revision.

Tags provide exact relevance signals. Paths use overlap semantics: `frontend/auth` matches `frontend/auth/login.js`. Known issues can be `open`, `resolved`, or `wontfix`, with `high`, `medium`, or `low` severity.

Create a Plan before writing Memory. Updates and archive operations require the current revision to prevent silent multi-agent overwrites. REST accepts the response ETag through `If-Match` or `expected_revision` in JSON.

Plan creation can include `scope_paths` and `memory_tags`; `related_memory` ranks summaries by path overlap, exact tags, text relevance, and open-issue severity. Read full content by `memory_id` only when needed.

Completing a Plan can execute up to twenty ordered `memory_actions`:

| Action | Required fields | Purpose |
|---|---|---|
| `create` | `action, category, title, content` | Create revision 1 |
| `update` | `action, memory_id, expected_revision` plus a changed field | Conditional revision |
| `resolve` | `action, memory_id, expected_revision` | Resolve a known issue |
| `archive` | `action, memory_id, expected_revision` | Soft archive with history |

An empty array explicitly retains no long-lived Memory. Discovery and MCP reuse the same discriminated JSON Schema for actions. All REST and MCP Memory responses consistently use `memory_id`.

## MCP

Each read-only Workspace URL has a Streamable HTTP MCP endpoint:

```text
https://ws.example.com/agent/w/<READ_TOKEN>/mcp
```

It is stateless JSON-RPC. The negotiated protocol is `2025-11-25`, with compatibility for `2025-03-26` and `2025-06-18`. Every request requires the matching Bearer control token. MCP has no anonymous read-only mode and no required session ID. Use `POST /mcp`; `GET /mcp` returns `405`.

Tool families include:

- Discovery: `workspace_info`
- Context: `query_context`, `add_context`, `get_plan_tree`, `update_plan`, `replace_note`
- Memory: `query_memory`, `get_memory`, `get_project_memory`, `add_memory`, `update_memory`, `archive_memory`
- files: listing, reading, metadata, binary chunks, search, tree, writes, replacements, directory creation, move, recycle, and restore
- large transfer: `prepare_download`, upload session creation, chunks, status, commit, and abort
- preview: `get_web_preview_url`
- Shell: run, list, status, incremental output, stdin, interrupt, kill, and sandbox process listing
- sharing: create, inspect, import, and delete temporary shares

MCP binary chunks use Base64 and are intentionally bounded. Large downloads and uploads return full `/transfer/...` URLs that contain no URL, control, or preview token. The client reuses its Bearer header. Downloads support GET, HEAD, ETag, and a single HTTP Range. Upload transfer URLs support offset inspection, raw PATCH, commit, and cancel.

Requests with `Origin` are checked against the configured public origin to mitigate DNS rebinding.

## Security model

- The URL token is read-only; mutation and MCP require a separate matching control token.
- URL and control tokens share a short expiration; an administrator may renew at any time, while conditional self-renewal is available only with less than two days remaining. Preview remains valid until its workspace expires or is disabled.
- Preview uses an independent rotatable credential on a dedicated origin.
- Invalid capability URLs return 404 to reduce token enumeration.
- Paths are normalized and constrained to the token workspace or explicit grants.
- Symlink escapes are rejected.
- `.recycle`, `.sql`, and `.context` are private reserved directories.
- Restricted Shell uses namespaces, explicit mounts, token-scoped network modes, and per-token cgroups.
- FastAPI workers use a private PID namespace and a minimal read-only runtime mount.
- Restricted Shell task output redacts sandbox-launcher command lines while preserving application stderr.
- The service runs as non-root; only the workspace-image helper is privileged.
- Passwords use PBKDF2-HMAC-SHA256; sessions use secure cookie and CSRF controls.
- Security headers include HSTS behind HTTPS, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, restrictive CSP, and no precise public package version.
- Errors use stable non-2xx status codes and structured JSON.

Full Shell is the explicit exception: it has all permissions of the `openkapsel` operating-system user and is not contained by token mounts or network flags.

## Project layout

```text
openkapsel/
  admin_handlers.py       administration request handling
  admin_ui.py             dependency-free administration HTML
  context_store.py        per-workspace Context database
  discovery.py            Discovery document construction
  discovery_sections.py   focused Discovery metadata
  mcp.py                  MCP schemas and constants
  mcp_handlers.py         MCP transport adapters
  memory_store.py         project Memory database
  network_proxy.py        token-scoped HTTP/HTTPS egress policy
  proxy_relay.py          sandbox loopback-to-Unix proxy relay
  routes.py               route registry
  sandbox_backends.py     Bubblewrap and Podman backends
  server.py               HTTP server and shared orchestration
  skill_handlers.py       public dynamic REST skill packaging and downloads
  tasks.py                asynchronous Shell tasks
  tokens.py               token records and path grants
  uploads.py              resumable uploads
  workspace_images.py     image client and privileged manager
skills/openkapsel-rest/      progressive REST skill and request/upload helpers
containers/                reproducible optional Podman image recipes
install.sh                production installer
set_password.py           offline administrator credential tool
```

## Tests

Run the complete suite from the project venv:

```bash
.venv/bin/python -m unittest discover -s tests
```

The suite covers routing, authorization, files, binary transfer, resumable uploads, Shell tasks, sandbox isolation, Context, Memory, workspace images, sharing, FastAPI applications, MCP schemas, and administration flows.

## Current boundaries

- OpenKapsel is an AI workspace service, not a multi-user IDE.
- Application authentication belongs to each FastAPI application.
- Workspace images currently support expansion but not shrinking.
- Restricted sandbox features require Linux; regular-directory and full-Shell modes remain available elsewhere.
- Full Shell is deliberately powerful and must be granted only to trusted tokens.

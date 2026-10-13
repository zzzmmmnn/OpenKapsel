# Authentication and administration

[Back to README](../README.md)

## Workspace credentials

The canonical Workspace URL is:

```text
https://ws.example.com/kapsel/w/<READ_TOKEN>/
```

The URL token is always read-only. Mutating and privileged requests add:

```http
Authorization: Bearer <CONTROL_TOKEN>
```

The control token must belong to the same record as the URL token. A missing or invalid control token returns `401`; a valid token from a different record returns `403`. Discovery never echoes the control token.

For constrained clients that can only issue `GET` requests to the exact Workspace root URL, Discovery advertises a query-route fallback and an HMAC-signed GET envelope. Load `GET <workspace_url>/discovery/transport` for the authoritative wire contract; the REST Skill mirrors it in `references/request-transport.md`.

Read and control credentials share a short expiration, initially three days. The administrator-selected workspace lifetime is separate and usually longer. The independent preview token remains valid until preview is disabled, it is rotated, or the workspace expires.

## Discovery

The Workspace root returns a compact Discovery index with authentication rules, capability summaries, current limits, a short workflow, and links to:

- `./discovery/files`
- `./discovery/context`
- `./discovery/memory`
- `./discovery/paths`
- `./discovery/rpc`
- `./discovery/network`
- `./discovery/shell`
- `./discovery/schedules`
- `./discovery/web`
- `./discovery/sharing`
- `./discovery/full`

The `full` section is the compatibility document. The same URL token and optional matching Bearer token apply to each section. Browser requests preferring HTML receive a readable page; API clients receive JSON. Invalid tokens and paths keep their real non-2xx status.

Runtime Discovery is authoritative for token permissions and configured limits.

## Administration console

The console is at `<url_base_path>/admin`. Its twelve-hour session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` behind HTTPS. Forms use CSRF protection. Repeated failed logins are rate-limited by source address.

MCP clients are managed on separate **Static MCP** and **OAuth connections** pages, grouped by project directory. Both support editing comments. [Static MCP connections](static-mcp-connections.md) provide copyable client JSON containing an independent Bearer secret and editable expiration (30/91/182/365/730 days; default 365). Project token cards expose REST and preview credentials.

The single-page console has responsive views for tokens, workspace images, static MCP connections, OAuth connections, and administrator password changes. Token cards are collapsed by default. Expanding one reveals credentials, renewal and rotation controls, paths, sandbox settings, and advanced permissions. [OAuth connections](oauth-connections.md) provide stable, independently revocable remote MCP access. Once authenticated, OAuth and Static MCP connections may explicitly export or renew the linked configuration's REST workspace URL/control token for cross-platform handoff; ordinary MCP responses continue to redact those secrets.

Each token controls:

- workspace lifetime: 1, 7, 30, 91, 365, or 730 days, or no expiration
- read/control renewal lifetime: 1–30 days; default three days
- a regular child directory or mounted ext4 workspace image
- read and write permissions
- independent preview permission
- network mode: disabled, allowed domains, or full network
- Shell mode: none, restricted, or full
- independent scheduled-task permission; Shell permission is also required
- restricted backend: automatic, Bubblewrap, or one installed Podman image
- process/thread, aggregate memory, and aggregate CPU limits
- additional absolute host paths, each read-only or writable

New restricted tokens default to 64 workload processes/threads, 256 MiB aggregate memory, and 100% CPU, where 100% is one logical core. Bubblewrap adds 16 infrastructure PIDs when creating its cgroup; Podman enforces the configured value directly.

## OAuth owner consent

OAuth approval uses an independent authorization page with the current control token for the exact linked configuration or its configured Workspace Password. It never creates a backend session or grants administration privileges. The client receives independent OAuth credentials, not the control token. See [OAuth consent and migration](oauth-connections.md).

## Renewal and rotation

Administrator renewal replaces the read and control tokens atomically and sets their shared expiration to 1–30 days from renewal time. The default is three days.

A control-authenticated Workspace can call `POST credential/renew` only when less than two days remain. Self-renewal always rotates both credentials for another three days and returns the new read token, control token, full Workspace URL, and expiration.

The preview token and workspace lifetime do not change during renewal. Individual URL, control, and preview rotation controls remain available for targeted revocation; rotating one credential does not extend expiration.

Deleting a token does not delete its workspace. Multiple records may reference the same regular workspace or image.

## Workspace images

The privileged `openkapsel-images` helper creates sparse ext4 files. `name.img` mounts at the same-named child directory under Workspace Root.

- Default capacity is 256 MiB.
- Images may be expanded but not shrunk.
- Capacity is published in Discovery.
- The mounted filesystem enforces capacity, including writes made by Shell subprocesses.
- Deletion is permanent and is refused while any token references the image; the error identifies those records.

Regular-directory mode remains available when the image helper is not installed.


## Temporary capability grants

In Administration → Token management, expand a Token. **Credentials**
and **Workspace password** are separate settings tabs. Use the Workspace
password tab to set or reset that Token's approval password, or generate a
**temporary password setup URL** to share with its user. A recipient holding
that URL needs no administrator login or old password: they enter and confirm
the new password twice (6–1024 characters). Each URL is single-use, valid for
15 minutes, and stored in server memory only. Generating a replacement URL
invalidates the earlier unused link for the same Token; changing/deleting or
reassigning the Token revokes its links. Successful setup invalidates the
link and existing temporary approvals/grants for that Token. Only an
authenticated administrator with a valid CSRF token can create such a URL.
Treat it as a secret bearer credential and share it securely.

**Each Token is its own
Workspace for passwords and temporary grants**: even two Tokens pointing at the
same filesystem directory have independent passwords. The stable Token
`app_id` is the internal password and grant identity, so rotating Read/Control
credentials does not reset this password. Deleting the Token deletes its
password; changing its directory or disabling it revokes that Token's grants.
The password is separate from the administrator login. The legacy
`/admin/capabilities` page remains available for inspecting and revoking
active per-Token grants. Existing passwords previously stored under the shared
directory are **not** assigned to Tokens during upgrade; set each Token's
password explicitly. Workspace approval passwords accept 6–1024 characters,
while the separate administrator login password still requires at least 12.
Passwords use salted PBKDF2 hashes, and resetting a Token's password revokes
only that Token's pending approvals and grants.
Password forms require HTTPS; local loopback HTTP is supported for development.

AI may proactively request `shell.elevated` using REST `POST
/shell/elevation/request` or MCP `shell.request_elevation` without starting a
command. Supply the explicit target (`server` or Mapping ID), the owning
Conversation's `writer_nonce`, and the in-progress `plan_id` with mutation
Context. The response is `status=approval_required` with `approval_url`, or
`status=granted` if already approved. Later Shell commands must still request
`elevated=true`. Alternatively, an ordinary elevated Shell invocation can
request a grant and return `capability_approval_required` when not approved.
The user opens that URL,
checks workspace/conversation/target/capability, enters the Workspace Password,
and chooses 1–1440 minutes (default 10). AI retries after approval; the page never
executes a command.

Approvals are browser-cookie/CSRF-bound, script-free, single use, and valid for
five minutes. Five incorrect passwords exhaust one URL. Shared workspace/address
attempt budgets prevent newly requested URLs resetting password budgets. Audit
logs contain the workspace, conversation, capability and target, never passwords
or approval IDs. Context history also excludes writer nonces and approval URLs.

Grants are independent per workspace, Conversation, target (server or Mapping ID)
and capability. Only password hashes persist; Server restart clears approvals and
grants. Expiry/revocation blocks new elevated jobs while running jobs remain
queryable/controllable. `files.write` is reserved and has no execution integration.

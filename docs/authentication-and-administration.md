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

Read and control credentials share a short expiration, initially three days. The administrator-selected workspace lifetime is separate and usually longer. The independent preview token remains valid until preview is disabled, it is rotated, or the workspace expires.

## Discovery

The Workspace root returns a compact Discovery index with authentication rules, capability summaries, current limits, a short workflow, and links to:

- `./discovery/files`
- `./discovery/context`
- `./discovery/memory`
- `./discovery/shell`
- `./discovery/web`
- `./discovery/sharing`
- `./discovery/full`

The `full` section is the compatibility document. The same URL token and optional matching Bearer token apply to each section. Browser requests preferring HTML receive a readable page; API clients receive JSON. Invalid tokens and paths keep their real non-2xx status.

Runtime Discovery is authoritative for token permissions and configured limits.

## Administration console

The console is at `<url_base_path>/admin`. Its twelve-hour session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` behind HTTPS. Forms use CSRF protection. Repeated failed logins are rate-limited by source address.

The single-page console has responsive views for tokens, workspace images, and administrator password changes. Token cards are collapsed by default. Expanding one reveals credentials, renewal and rotation controls, paths, sandbox settings, and advanced permissions.

Each token controls:

- workspace lifetime: 1, 7, 30, 91, 365, or 730 days, or no expiration
- read/control renewal lifetime: 1–30 days; default three days
- a regular child directory or mounted ext4 workspace image
- read and write permissions
- independent preview permission
- network mode: disabled, allowed domains, or full network
- Shell mode: none, restricted, or full
- restricted backend: automatic, Bubblewrap, or one installed Podman image
- process/thread, aggregate memory, and aggregate CPU limits
- additional absolute host paths, each read-only or writable

New restricted tokens default to 64 workload processes/threads, 256 MiB aggregate memory, and 100% CPU, where 100% is one logical core. Bubblewrap adds 16 infrastructure PIDs when creating its cgroup; Podman enforces the configured value directly.

## Renewal and rotation

Administrator renewal replaces the read and control tokens atomically and sets their shared expiration to 1–30 days from renewal time. The default is three days.

A control-authenticated Workspace can call `POST credentials/renew` only when less than two days remain. Self-renewal always rotates both credentials for another three days and returns the new read token, control token, full Workspace URL, and expiration.

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


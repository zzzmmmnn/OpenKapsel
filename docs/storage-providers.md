# Storage Providers

OpenKapsel can expose remote storage inside a workspace without synchronizing the
whole remote into the server first. Storage Providers are server-managed rclone
mounts. Version 1 supports:

- Google Drive
- Dropbox
- SFTP
- SMB

A Storage Provider is separate from a client mapping. The provider is mounted
under a private server path first, and an administrator can then bind that
mounted filesystem into one or more workspaces under a chosen directory name.

## Data flow and local disk usage

The provider layout is intentionally two-stage:

```text
remote storage
    │
    │ rclone mount
    ▼
/var/lib/openkapsel/storage-providers/<provider-id>/mount
    │
    │ root-owned bind mount
    ▼
/var/lib/openkapsel/workspace/<workspace>/<mapping-name>
```

`rclone mount` is a virtual filesystem. Creating a provider for a 1 TiB drive
does **not** download 1 TiB to the OpenKapsel server. Directory metadata is
listed on demand and file contents are fetched when applications read them.
OpenKapsel uses `--vfs-cache-mode=writes`: reads stream from the remote while
writes are staged through the local VFS cache before upload.

Each provider has a private cache directory and an independent VFS cache target.
The default is 1 GiB; Administration accepts 1-1024 GiB. Rclone treats
`--vfs-cache-max-size` as a soft quota: it is enforced on cache-poll cycles and
open files cannot be evicted, so active writes can temporarily exceed the target.
Cached data is not the authoritative copy of the remote. A 1 GiB cache target
does not cap the size of files that can be read: in `writes` mode read-only files
stream directly from the remote. A write larger than the cache target can also
temporarily exceed the target because open files cannot be evicted.

Before deleting a provider, OpenKapsel queries that mount's private rclone RC Unix
socket for VFS upload counters. If uploads are queued or in progress, normal
deletion stops and Administration shows a warning. If the provider is offline
and a non-empty local VFS cache remains, synchronization cannot be proven and
normal deletion also stops. Only an explicit **Force delete** discards the local
cache and disconnects the provider. Neither normal nor forced deletion asks
rclone to delete remote files.

## Security boundary

Provider credentials do not live in the Workspace Root. They are written under
`/var/lib/openkapsel/storage-providers/<provider-id>/` and owned by the separate
non-login `openkapsel-storage` account with mode 0700/0600. The main
`openkapsel` service account cannot read the rclone configuration directly.
The root mount helper owns the narrow operations required to configure, mount,
unmount and bind providers.

Administration accepts credentials as write-only form fields. Provider list and
status responses contain public metadata only; OAuth tokens, passwords, private
keys and generated rclone configuration are never returned through the Files,
REST or MCP interfaces.

For SFTP, OpenKapsel requires a pinned `known_hosts` entry. Passwords are passed
to `rclone obscure` over stdin before being written to rclone configuration.
Private keys and `known_hosts` are stored as separate 0600 files.

## Installation

The standard Debian/Ubuntu installer installs `rclone`, creates the dedicated
`openkapsel-storage` account, and enables FUSE `user_allow_other`. Storage
Providers require rclone 1.60.0 or newer because SMB support was added in rclone
1.60. On hosts where `--no-package-install` is used, install a compatible rclone
and FUSE before creating a Storage Provider. Missing or older rclone disables the
Storage Providers panel capability without disabling the core OpenKapsel service.

Check capability from Administration → **Storage Providers**. Provider creation
is disabled when the privileged helper cannot find both rclone and fusermount.

## Google Drive

Google Drive uses an rclone `drive` remote. Create a Google OAuth **Web
application**, add the exact **OAuth redirect URI** shown by OpenKapsel
Administration, then enter its client ID and client secret and click **Connect
Google Drive**. The browser is redirected to Google and then back to OpenKapsel;
the returned access and refresh tokens are written directly into the provider's
private rclone configuration.

The authorization request uses offline access so rclone can refresh credentials
without another browser login. Pending browser authorization state and the
client secret are kept only in server memory for up to 10 minutes and are bound
to the administrator session.

For recovery or headless setup, **Advanced: paste rclone OAuth token JSON** keeps
the original manual flow available:

```bash
rclone authorize drive <client-id> <client-secret>
```

The optional **Remote path** selects a subdirectory. Leave it empty to expose the
remote root.

## Dropbox

Dropbox uses an rclone `dropbox` remote. Create a Dropbox application, add the
exact **OAuth redirect URI** shown by Administration, enter its app key and app
secret, then click **Connect Dropbox**. OpenKapsel requests offline token access
so rclone receives a refresh token for unattended mounts.

Manual token JSON remains available under **Advanced**. A token generated with
rclone's shared Dropbox application may still be pasted with blank client
fields; browser OAuth through OpenKapsel requires your own Dropbox app key and
secret.

## SFTP

SFTP requires:

- host and port (default 22)
- user
- exactly one of password or PEM private key
- a `known_hosts` entry for the server key

The **Remote path** is interpreted relative to the configured SFTP remote root.
OpenKapsel never enables rclone's insecure SFTP host-key behavior implicitly.

## SMB

SMB requires host, user, password (unless the server intentionally permits the
configured account without one), port (default 445), and domain/workgroup
(default `WORKGROUP`). The **Remote path** normally starts with the share name,
for example:

```text
Engineering/projects
```

## Workspace mappings

Creating a provider mounts the remote internally but does not automatically make
it visible to every workspace. In Administration → **Storage Providers**, choose
an existing workspace and a directory name such as `drive` or `assets`.
OpenKapsel then creates a bind mount at:

```text
<workspace>/drive
```

The mapping name must not collide with an existing directory, client mapping or
another Storage Provider mapping. The mapping root itself cannot be moved or
deleted through workspace file APIs; remove it from Administration instead.
Files below the mapping use the normal OpenKapsel file APIs and inherit the
provider's read-only/writable policy.

A single provider may be bound into multiple workspaces. All bindings share the
same rclone mount and the same bounded provider cache.

## Lifecycle

Enabled providers are reconciled when the server starts. The rclone process runs
as `openkapsel-storage` in its own transient systemd service with restart-on-
failure. Each process exposes rclone's control API only through a Unix socket
inside that provider's private 0700 directory; OpenKapsel uses it for VFS upload
status, not as a network-facing API. Disabling a provider removes its workspace
bind mounts and stops the rclone mount; re-enabling it mounts the remote and
restores configured workspace bindings.

If a provider cannot connect, its workspace mapping is not silently replaced by
an empty local directory. Administration reports the provider as unavailable and
**Reconcile mount** can retry after credentials or connectivity are repaired.

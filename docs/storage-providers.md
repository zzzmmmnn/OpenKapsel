# Storage Providers

OpenKapsel can expose remote storage inside a workspace without synchronizing the
whole remote into the server first. Storage Providers are server-managed rclone
mounts. The built-in provider types are:

- Google Drive
- Dropbox
- pCloud
- Microsoft OneDrive
- WebDAV
- S3 Compatible
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
/var/lib/openkapsel-storage/providers/<provider-id>/mount
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
`/var/lib/openkapsel-storage/providers/<provider-id>/` and owned by the separate
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
and FUSE before creating a Storage Provider. Install OpenSSH client tools
(`ssh-keyscan`) as well to use SFTP host-key detection; manual verified
`known_hosts` entry remains available without it. Missing or older rclone
disables the Storage Providers panel capability without disabling the core
OpenKapsel service.

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

Before authorizing a custom Dropbox app, open its **Permissions** tab and enable
the file scopes required by rclone. Directory listing requires
`files.metadata.read`; rclone's normal read/write setup also uses
`files.metadata.write`, `files.content.read`, `files.content.write`, and
sharing permissions. Changing the app permissions does not retroactively expand
an already-issued token, so re-authorize or replace credentials after changing
the scopes.

Manual token JSON remains available under **Advanced**. A token generated with
rclone's shared Dropbox application may still be pasted with blank client
fields; browser OAuth through OpenKapsel requires your own Dropbox app key and
secret.

## pCloud

pCloud uses rclone's `pcloud` backend. Create a pCloud application, register
the exact **OAuth redirect URI** displayed in Administration, enter the app
client ID and secret, then click **Connect pCloud**.

pCloud accounts can live in the US or EU data region. During browser OAuth,
pCloud returns the API hostname with the authorization callback; OpenKapsel
validates it and pins the provider to either `api.pcloud.com` (US) or
`eapi.pcloud.com` (EU). This avoids a valid EU token being used against the
US API endpoint.

pCloud access tokens are non-expiring, so their rclone token JSON does not need
a refresh token. Manual rclone token JSON remains available under **Advanced**.
For a manual token, choose the matching pCloud data region. Client ID and secret
may both be left blank when the token was created with rclone's shared pCloud
application; custom credentials must always be supplied as a pair.

The optional **Remote path** selects a directory below the pCloud root.

## Microsoft OneDrive

Microsoft OneDrive uses rclone's `onedrive` backend. Register a Microsoft
Entra application with the exact **OAuth redirect URI** shown by OpenKapsel and
create a client secret. The browser flow requests delegated
`Files.ReadWrite offline_access` permissions.

This first implementation connects the signed-in user's **default OneDrive**.
After the OAuth token exchange, OpenKapsel calls Microsoft Graph `/me/drive`
and records the returned drive ID and drive type for rclone automatically. It
does not browse or choose arbitrary SharePoint sites. The same narrow
`Files.ReadWrite offline_access` scope is written to rclone's
`access_scopes` setting so later refreshes do not expand the consent scope.

Administration supports Microsoft's global cloud, US Government, China, and
the legacy Germany region. The application registration must exist in the
matching Microsoft cloud.

Manual rclone token JSON remains available under **Advanced**. Manual setup also
requires the target drive ID and drive type (`personal`, `business`, or
`documentLibrary`). Client ID and secret may both be left blank for a token
created with rclone's shared Microsoft application; custom credentials must be
supplied as a pair.

The optional **Remote path** selects a directory below the selected drive.

## WebDAV

WebDAV uses rclone's `webdav` backend. Supply the full WebDAV endpoint URL and
choose the closest vendor preset. OpenKapsel currently exposes:

- standard/other WebDAV
- Nextcloud
- ownCloud
- ownCloud Infinite Scale
- Fastmail Files
- SharePoint Online
- SharePoint with NTLM authentication
- `rclone serve webdav`

For authenticated endpoints, user and password/app-password must be supplied
together. The password is passed to `rclone obscure` over stdin before the
private rclone configuration is written. Both fields may be left empty only
for an endpoint that intentionally permits anonymous WebDAV access.

The optional **Remote path** is relative to the configured WebDAV endpoint.

## S3 Compatible

S3 Compatible uses rclone's generic `s3` backend with `provider = Other`.
Supply the S3 API endpoint, access key ID, secret access key, and an optional
region. Provider credentials remain in the provider's private 0600 rclone
configuration and are not returned through OpenKapsel APIs.

For S3, **Remote path** normally begins with the bucket name:

```text
bucket-name
bucket-name/prefix
```

**Force path-style URLs** is enabled by default because it has the broadest
compatibility with generic S3 implementations. It can be disabled for services
that require virtual-host-style bucket addressing. **Use legacy S3 v2
signatures** is an Advanced compatibility option and should be enabled only for
old S3-compatible servers that do not support v4 signing.

For **Backblaze B2**, use a separately created B2 Application Key: its
`keyID` is the S3 **Access key ID** and its `applicationKey` is the
**Secret access key**. Backblaze's master application key is not accepted by the
S3-compatible API. Set **Region** to the region embedded in the endpoint (for
example `us-west-004` for
`s3.us-west-004.backblazeb2.com`), put the bucket name in **Remote path**, and
leave legacy S3 v2 signatures disabled because B2's S3-compatible API uses v4
signing. A bucket-restricted key that must list the account's bucket root also
needs Backblaze's **Allow List All Bucket Names** capability; using the bucket
name directly in Remote path avoids an unnecessary account-root listing.

This generic provider is intended for S3-compatible services such as private
MinIO/Ceph deployments and public object-storage services that expose the S3
API. Provider-specific tuning can be added later without changing workspace
mapping semantics.

## SFTP

SFTP requires:

- host and port (default 22)
- user
- exactly one of password or PEM private key
- a pinned SSH host key

Administration provides **Detect SSH host key**. Detection runs from the
non-root OpenKapsel server and performs only SSH host-key discovery; it does not
authenticate and does not send the SFTP password or private key. The detected
public keys are written into the `known_hosts` field and their SHA256
fingerprints are shown to the administrator.

Detection is **not** proof of server identity. Verify the displayed fingerprint
through an independent channel (for example with the SFTP server administrator)
before checking the trust confirmation and saving the provider. OpenKapsel will
not save new SFTP credentials unless that confirmation is checked.

For a non-default port, the saved entry uses OpenSSH's bracketed form, for
example:

```text
[files.example.com]:2222 ssh-ed25519 AAAA...
```

**Advanced: known_hosts entry** remains available for environments where
automatic detection is unavailable or where a verified entry is supplied
out-of-band. OpenKapsel never enables rclone's insecure SFTP host-key behavior
implicitly. If the remote server later presents a different key, the pinned key
causes the mount to fail closed until an administrator verifies and explicitly
saves the replacement key.

The **Remote path** is interpreted relative to the configured SFTP remote root.

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
as `openkapsel-storage` in its own transient `openkapsel-storage-<provider-id>.service`
unit with restart-on-failure. Each process exposes rclone's control API only
through `/run/openkapsel-storage-<provider-id>/rc.sock`; the systemd
`RuntimeDirectory` lifecycle removes the socket when the unit stops, avoiding a
stale provider-local socket across restarts. The socket is local-only and is used
for VFS upload status, not as a network-facing API.

A crash of the main `openkapsel.service` does not tear down a healthy provider
mount. On restart, OpenKapsel reuses a live rclone/FUSE unit and an existing
workspace bind when they still match the provider database. If the privileged
helper is restarting at the same time, startup waits briefly for its Unix socket
and retries transient reconcile failures. A stale FUSE mount or stale bind is
detached and rebuilt instead of being treated as a healthy provider. This keeps
queued rclone uploads alive across a main-process crash while still repairing
orphaned resources.

Normal upgrades take a different path: `install.sh` runs
`scripts/openkapsel-safe-shutdown` before replacing code. It stops the main API
first, waits for writable VFS queues to drain, unmounts recorded workspace binds,
stops provider units, verifies FUSE detachment, and stops the privileged helper
last. If write safety cannot be established, the upgrade aborts rather than
forcing an unmount. See [installation.md](installation.md) for the manual command
and the explicit `--force-recovery` exception.

Disabling a provider removes its workspace bind mounts and stops the rclone
mount; re-enabling it mounts the remote and restores configured workspace
bindings. If a provider cannot connect, its workspace mapping is not silently
replaced by an empty local directory. Administration reports the provider as
unavailable and **Reconcile mount** can retry after credentials or connectivity
are repaired.

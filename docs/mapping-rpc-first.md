# RPC-first mappings

[Client setup and RPC plugins](client-mappings.md) | [README](../README.md)

## Lifecycle

A mapping registration, its provider WebSocket session, and its native filesystem
view have independent lifetimes. Creating a mapping reserves its child directory
name without spawning a process. Connecting a provider enables RPC, still without
FUSE. File APIs use RPC even when a native view happens to exist.

A server Shell task or FastAPI application that needs native filesystem access
acquires a reference-counted mount lease. The first consumer mounts the mapping;
subsequent consumers reuse the same per-mapping FUSE worker. The last release
starts the idle timeout. Unmounting or reaping that worker does not disconnect
the provider or stop client-side RPC tasks.

The broker socket and its worker machinery are initialized only when a native
mount is requested. RPC-only operation does not require `/dev/fuse`. Server-side
native views still require Linux, FUSE userspace support and the existing mount
helper/namespace configuration. This is not a promise that every unrelated
OpenKapsel server feature runs on every operating system.

## Configuration

```json
{
  "mappings_enabled": true,
  "mapping_fuse_enabled": true,
  "max_active_mapping_mounts": 16,
  "mapping_mount_idle_seconds": 30
}
```

`mapping_fuse_enabled=true` permits lazy native mounts; it does not enable eager
mounting. Set it to `false` for a strictly RPC-only deployment. File APIs and
client execution remain available; server operations requiring native mapping
access fail explicitly instead of falling back to client execution.

`max_active_mapping_mounts` limits active native mounts, including idle cached
mounts until reaped. Its range is 1-256. It is not a configuration-count or
provider-connection limit. The former global limit of 16 registrations is removed.
Normal HTTP/WebSocket, RPC concurrency, task and memory limits still apply.
`mapping_mount_idle_seconds` accepts 0-3600 seconds; zero requests immediate
unmount after the last lease is released.

`GET /mappings` exposes `online`, `mounted`, `mount_references`, and
`native_mounts_enabled`. Busy mappings cannot be renamed, deleted or have their
administrative properties changed until native consumers stop. Offline or
unmounted roots never turn into writable ordinary server directories.

## File operations that do not mount

Same-mapping file operations retain their coarse-grained client RPC path. The
shared local/RPC backend also supports workspace-root listing/traversal, mixed
read/manifest/replace/delete batches, binary download and Range/HEAD responses,
MCP binary chunks/download preparation, static Web Preview, binary uploads,
resumable upload publication, cross-root copies/moves, and share snapshots/imports.
Git and Archive operations within a mapping continue to use client RPC plugins.

Copies place their temporary data in the destination filesystem. A cross-root
move verifies the destination before recycling its source; it is not atomic.
Cancellation leaves resumable partial transfer data in that destination. Direct
uploads stream to a destination-side temporary file. Resumable uploads retain
the existing bounded server spool until commit and stream it to the provider;
the successful commit removes that spool. Shares remain immutable server-owned
snapshots, so they necessarily consume the configured server share quota.

A server Git snapshot cannot span virtual mapping roots: it returns
`git_mapping_boundary`. Inspect a repository wholly within one backend, use the
mapping's Git plugin, or run an explicitly authorized server Shell command with
native mapping dependencies. Shell semantics are not silently substituted for
read-authorized Git inspection.

Core file RPC is always enabled; `rpc.file` is no longer a client setting (remove
the key from older configurations). Read/write permissions still apply. File RPC
never falls back to FUSE for old clients, legacy disabled capabilities, unsupported
operations or large requests. Unsupported capabilities produce an explicit
403/409 error; oversized requests produce 413. Use smaller batches or binary
transfer rather than relying on a native fallback. Requests already dispatched
are never automatically retried after a timeout, disconnect, or an oversized
response reporting that a mutation may have completed.

## Server commands

`target=auto` still executes a mapped cwd on its client. That path does not mount
anything on the server. A server-target command automatically acquires the
mapping containing its cwd. Declare additional dependencies by mapping name or
ID when a command starts outside a mapping or accesses other mappings:

```json
{
  "command": "python laptop/project/main.py",
  "target": "server",
  "cwd": ".",
  "mount_mappings": ["laptop"],
  "plan_id": 123,
  "taskname": "build",
  "message": "Run the project using the server runtime"
}
```

The server does not parse shell source to guess file dependencies. The
`mount_mappings` field is server-only and is rejected for client execution.
Scheduled commands share the server launch path and acquire their cwd mapping;
this revision does not add an extra mapping-dependency field to schedule records.

Mounts are prepared before strict cwd resolution and before sandbox creation.
Bubblewrap and Podman explicitly expose leased roots and mask undeclared roots
with a read-only inaccessible view. Full Shell is intentionally unsandboxed and
cannot provide per-task namespace masking; declare every native dependency and
do not rely on another task's mount.

A native task retains leases until its managed process group has ended. Timeout,
interrupt and kill still apply. Deliberately detached processes that leave the
managed process group are outside this lifecycle contract; run native consumers
in the foreground. If cleanup cannot establish that a managed process group has
exited, its lease is retained rather than unmounting beneath a live consumer.

## FastAPI applications

An application located under a mapping automatically leases its containing
mapping. Other dependencies can be declared in the application's
`api/mappings.json` file:

```json
{"mount_mappings": ["datasets", "assets"]}
```

The manifest must contain only that field and is limited to 16 KiB. Names/IDs are
resolved within the application's token workspace. Route discovery and manifest
reading use RPC; mounting happens only when an authorized request needs a real
API worker. Dependencies are ready before constructing the worker's sandbox.

Leases belong to the API worker, not an individual HTTP connection. Ordinary
requests and SSE connections do not release the worker's mounts. Reused workers
retain one set of leases; worker stop/restart or idle reclamation releases them.
Provider generation changes invalidate the worker fingerprint so a replacement
worker receives current dependencies.

Mapped applications keep their private layout and SQL data below the server's
`mapping-app-state/<worker-key>` state directory, not in the client's forbidden
`.openkapsel` directory. The source application subtree is exposed without
implicitly granting the entire containing export. Static HTML/JavaScript/media
preview remains an RPC operation and does not start either an API worker or FUSE.

## Upgrade and failure handling

Upgrade both server and clients. File family version 3 is unchanged, but binary
and mixed-root paths additionally need descriptor metadata: clients advertise
`file_stream.version=1`, `descriptor_stat=true`, and `directory_details=true`.
The `search_prefix=true` feature supports workspace-root-relative glob filtering
inside delegated searches. Root `fs/list` uses virtual registration metadata
without contacting providers. Root search, tree, and recursive manifest queries
delegate each visited mapping subtree as one coarse RPC (with remaining depth
and global result/node limits); remote files are not streamed back for searching
or hashing. Search marks incomplete provider results with `unavailable_mappings`
and `truncated=true`; tree/manifest expose unavailable mapping nodes explicitly.
The server validates device/inode identity and nanosecond timestamps and rejects
clients missing required stream metadata rather than using native fallback.
Legacy capability advertisements remain accepted for operations they implement.

In-progress streams and transfer operations are bound to one provider generation.
A reconnect invalidates old handles; it never redirects an uncertain write to a
new provider. Resume a transfer only after checking its reported state and source
identity. Transfer and upload records bind destination/source mapping IDs so a
renamed or replaced registration cannot silently redirect a later commit.

Existing pending mapped uploads without a recorded mapping identity must be
restarted. Existing configuration and credentials remain valid. Administrative
changes that disconnect a provider remain explicit; ordinary idle mount cleanup
does not rotate credentials or close the RPC session.

## Validation

Validation performed on September 21, 2026:

- Native macOS regression suite: 259 tests, 256 passed and 3 platform-specific
  tests skipped. Compilation checks passed.
- Isolated Linux Podman container with no `/dev/fuse` and no network: 67 mapping,
  file, Shell-routing and API-worker tests passed using a source snapshot and
  temporary pure-Python test dependencies.
- Configuration and English-project checks after documentation/discovery updates:
  4 tests passed. `git diff --check` passed.

`tests/test_mapping_rpc_first.py` exercises file APIs with `mount()` forbidden,
including root traversal, binary transfer, static preview, cross-root copy/move,
mixed-batch preflight, shares, provider generation fencing and private-path
containment. It separately checks mount leases, rollback, native dependency
selection, API-worker lifetime, and unavailable-mount failure before process
launch. Existing mapping, file, Shell, API-worker, upload and safety tests remain
part of the regression suite.

Native client validation was extended on September 22, 2026: both the native
macOS and native Windows client test suites were exercised locally without known
failures, including the Windows filesystem provider and native task/process paths.

Real native Linux FUSE mounting and host-helper namespace propagation still
require deployment checks. Passing mocked mount-lifecycle tests or running RPC
tests on Linux without `/dev/fuse` does not establish those native Linux mount
results. No service restart or deployment is part of this source-tree refactor.

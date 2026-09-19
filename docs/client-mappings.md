# Client mappings and execution

[Back to README](../README.md)

## Direction and storage

A Python client exports a local directory to a Linux OpenKapsel server over an outbound WebSocket connection. FUSE makes it appear below a workspace. No client FUSE driver, inbound client port, directory synchronization, or full server-side copy is required.

Each mapping is independently registered for one workspace and a single child directory name. Multiple mappings may share a workspace. All caller permissions still apply. Provider tokens are independent of the rotating REST tokens and are stored hashed by the server. Editing or rotating a mapping disconnects the provider. Only one active provider is accepted per mapping.

Mapped content consumes client storage, not the workspace image quota. Server API transfer-size limits still apply. Offline access fails rather than falling back to a local backing directory. Files already cached/opened by application code are not a substitute for reconnecting; old provider handles become stale on reconnection.

## Server setup

Install the declared Python dependencies and Linux FUSE userspace support (`libfuse2` or the distribution's `libfuse2t64`, plus `fuse3` providing `fusermount`). The service unit allows `/dev/fuse`; do not run the main service as root or enable `allow_other`.

Set `"mappings_enabled": true` in the server configuration and restart the service. The default is false. The existing reverse proxy must forward WebSocket upgrades on the normal application prefix. Caddy's normal `reverse_proxy` handles this; no separate client-facing port is needed.

Open **Administration → Client mappings**, choose the workspace, directory name, writable state, and optional client execution permission. Save the generated client configuration: the provider token is shown only once. The name must not already exist. Up to 16 mappings are supported.

Expand an existing mapping to edit its directory name. Renaming changes only the server mountpoint: the mapping ID, provider credential, client root and recycle store remain unchanged. The provider disconnects and can reconnect with its existing configuration. Stop active transfers/tasks first; open handles and running sandboxes may still refer to the old mount. Existing destination names are never overwritten.

Under the server state directory, `mappings.sqlite3` holds registrations and `file-transfers` holds resumable transfer metadata. `mapping-run` next to Workspace Root holds private broker IPC. With the installed image helper, fixed-command transient `openkapsel-mapping-<id>.service` units run FUSE as the non-root service account in the host mount namespace. This makes mappings visible to both the service and rootless Podman's persistent namespace. The helper accepts only mapping IDs and relative workspace/directory names, not arbitrary commands or mount options. Without a helper, development-mode mounts stay in the server's own namespace; persistent Podman namespaces may not see them.

## Python client installation

The client requires Python 3.10+. To avoid installing scientific and web-server libraries on a client-only machine, run from a source checkout:

```sh
python3 -m venv .venv-client
.venv-client/bin/python -m pip install 'websocket-client>=1.8,<2' 'python-socks>=2.7,<3'
.venv-client/bin/python -m openkapsel.client --config /path/to/client.json
```

On Windows use `python` and `.venv-client\Scripts\python.exe`. A full package installation can instead use the `client` extra and the `openkapsel-client` command.

Keep the configuration outside the exported directory and source control. On POSIX systems use mode `0600`:

```json
{
  "url": "wss://host.example/kapsel/mapping-connect/<MAPPING_ID>",
  "token": "<MAPPING_TOKEN>",
  "root": "/path/to/local/project",
  "writable": true,
  "allow_exec": false,
  "sandbox": true,
  "proxy": "socks5://127.0.0.1:1080"
}
```

Supported proxy schemes are `http`, `socks4`, `socks4a`, `socks5`, and `socks5h`. Use the `a`/`h` variants for proxy-side DNS. Optional proxy credentials use URL userinfo. TLS verification remains enabled; a proxy connection failure never falls back to direct access. Use `--once` to disable automatic reconnection during diagnostics.

If local DNS returns a proxy's synthetic address (for example an address from `198.18.0.0/15`), use `socks5h` instead of `socks5`; this still uses SOCKS5, but sends the hostname to the proxy for resolution.

## Files, recycling, and transfers

Use normal file APIs, server Shell, and backend filesystem operations for mapped paths. `GET /mappings` reports online state, writable state, and client capabilities. Mapping roots cannot be moved or deleted through file APIs; detach them through administration.

Updated clients advertise `capabilities.file_api` with version `2` and a list of
supported operations. The server automatically sends one complete file operation
over the existing WebSocket when all its paths belong to the same mapping. The
client performs filesystem work locally and returns the normal REST response.
For example, SHA-256 calculation sends back the digest rather than transferring
the file to the server, and directory listing returns metadata in one RPC.

The fast path supports list, stat/hash, text read (including byte offsets), tree,
search, text write, replace, mkdir, same-mapping move, recoverable delete, and
same-mapping manifest/replace/delete batches, multi-file text reads, glob-filtered
search, and recursive manifests with optional SHA256. The latter three require
version 2; older clients retain the FUSE fallback. REST and MCP callers keep their
existing endpoints, request fields, permissions, and Context attribution. Server
Shell and application filesystem access still use FUSE. Binary streaming,
resumable uploads, cross-root transfers, and batches spanning multiple storage
roots retain their existing paths.

Upgrade and reconnect the client to enable this optimization. An older client,
an oversized request, or a server limit above the client operation ceiling uses
the existing FUSE path, decided before an RPC is sent. RPC messages are bounded
to 1 MiB. An oversized response returns `mapping_response_too_large` (413): use
a smaller page, read limit, tree depth, or batch. A timeout or disconnection after
dispatch is never automatically replayed; check the affected paths before
retrying a mutation whose result is unknown. The same applies to an oversized
response reporting `mutation_may_have_completed: true`. Client-side path guards, protected
internal directories, and both mapping and local write restrictions still apply.

Git inspection uses the separate `capabilities.git_api` version `1` capability.
The six `/git/*` inspection endpoints execute on the mapped client, using its
existing task sandbox and concurrency limits. Both client and mapping must enable
execution; caller and mapping must be writable. Git must be installed in the host
or sandbox image. Git does not use the file API fallback: unsupported clients
return an upgrade-required error. See [Git inspection](shell-and-mcp.md#git-inspection)
for parameters, bounded output, and asynchronous task polling.

API deletion moves files to `.openkapsel/recycle` on the client. Recycle list/restore use `root=.` for the ordinary workspace or the mapping directory name for a client recycle store. Raw Shell deletion is still direct deletion. Symlinks, Windows reparse points, and special files are not exported in this version. POSIX `chmod` is unsupported on Windows; filesystem case sensitivity remains that of the client. Full distributed file-lock semantics are not promised.

`POST /fs/copy` starts a verified, resumable copy. `fs/move` between different roots uses verified copy followed by source recycling. Both return 202 with a transfer ID; poll `/fs/transfers/<id>` and use POST `/cancel` or `/resume` with mutation Context. A move is not atomic. `copied_source_retained` means the destination exists but the source still needs attention. Publication never silently overwrites an existing destination. Cancellation retains partial data on the destination for resumption, so it still consumes client/destination space.

## Client execution policy

Execution requires server caller Shell/write permissions, a writable mapping with client execution enabled, and client-local `allow_exec: true`. Sandbox defaults to true. The initial sandbox backend is Podman; it must be installed and its VM started where required. The image is configurable using `image`; default `docker.io/library/python:3.14-slim-trixie`. Network defaults off for sandboxed tasks (`network: true` enables it). Podman defaults are two concurrent tasks, 600 seconds, 256 MB memory, 64 processes, and one CPU per task.

To run native macOS/Windows tasks before native sandbox adapters are implemented, explicitly set `"sandbox": false`. This mode also works on Linux. It grants the task the client's OS-account permissions: `cwd`, mapping read/write configuration, and `network: false` do not confine an unsandboxed process. The client warns at startup. No missing sandbox ever causes automatic fallback to this mode.

Client tasks use argv arrays and export-relative working directories. Output is combined stdout/stderr, capped at 2 MB per task, and retrieved incrementally as base64. Stdin accepts bounded chunks. Interrupt and force-kill are supported; native POSIX tasks use process groups and Windows uses process-tree termination. These are lifecycle controls, not sandbox boundaries, and deliberately detached native processes are outside the guarantee. Active tasks are terminated when the provider session closes. Completed tasks are retained in memory for at most one hour and four tasks per provider session; reconnect starts a new session.

Podman on macOS/Windows runs Linux workloads, not native platform tests. Linux Bubblewrap and native macOS/Windows sandbox adapters remain follow-up backends; this version does not claim they are implemented.

Local task limits can be set in `limits`: `max_tasks` (1–16), `max_seconds` (1–86400), `memory_mb`, `processes`, and `cpus`. CPU/memory/process limits are container controls; native unsandboxed mode only enforces concurrency, output bounds, and task deadlines. Client execution currently offers Podman or explicit native execution; additional sandbox backends can be added independently of the mapping transport.

`POST /recycle/purge` removes one selected recycle entry permanently. It requires the root selector, entry ID, normal mutation Context, and `confirm: true`.

## Validation status

Validated with a Linux server and a native macOS client over a SOCKS5 proxy: REST read/write/rename, client-local recycle/restore, cross-root copy/move, Podman Shell access, client stdin/output/interrupt/kill, offline errors, and reconnect after service restart. A 300 MiB sparse client file was visible without consuming that size in the server workspace image; this is not a large-file throughput benchmark.

Automated tests cover path containment, credential separation, CSRF, generation fencing, bounded tasks, transfer resume, and the fixed unprivileged mount launcher. Windows-specific tests are included in the client CI matrix but have not yet been validated on a real Windows installation. In particular, verify reparse-point containment, developer-tool compatibility, and process-tree cleanup before production use. Native Linux client execution, client-side Podman execution, and project backend access require additional deployment validation.

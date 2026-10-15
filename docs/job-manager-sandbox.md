# Shared Job Manager sandbox (experimental)

The Manager accepts an optional `sandbox` **JSON string** on `task_start`.
When omitted, or when set to `{"type":"current_user"}`, the job executes
under the Manager's current OS user exactly as before. An invalid or unavailable
requested sandbox **fails closed**; it is never silently replaced with native
execution. This is an internal Manager IPC contract, not a public REST parameter.

## Modes

- `bubblewrap`: Linux only; uses the existing Server Bubblewrap backend,
  isolated filesystem/PID/network namespaces, and the Server's `DomainProxy`
  and Unix-socket relay for domain-filtered egress.
- `seatbelt`: macOS only; uses `/usr/bin/sandbox-exec` with a deny-by-default
  filesystem and network profile. For domain-filtered egress the Manager runs
  a private per-job `DomainProxy` on a **pinned random IPv4 loopback port**.
  The sandbox may connect only to that port; the proxy validates domain names,
  destination ports, DNS answers and public addresses. A restricted program
  cannot initiate arbitrary TCP connections merely by ignoring `HTTP_PROXY`.
- `srt_windows`: legacy Windows Sandbox Runtime backend. **Temporarily disabled** for Mapping Shell: literal-only filesystem commands run inside the Client's guarded file interpreter, and all other commands require explicit Shell approval and run as the Client OS user without isolation.
  0.0.79+ (Node.js 22.12+). SRT's Rust `srt-win.exe` uses a dedicated
  `srt-sandbox` account, SID-restricted WFP egress filter and NTFS ACLs.
  First run requires `npm install -g @anthropic-ai/sandbox-runtime` and an
  approved `srt windows-install`. The Manager writes an independent private
  SRT settings JSON and invokes the globally installed Node entrypoint.
  `none` and `domain_allowlist` work with SRT's proxy; `full` currently
  **fails closed** because this SRT version cannot express an unrestricted
  Windows egress policy. The shared sandbox account SID means directory
  grants across concurrently running Windows Jobs may overlap; these Jobs
  intentionally remain parallel in this initial implementation.

Example JSON **value of the `sandbox` string**:

```json
{
  "type": "seatbelt",
  "root": "/absolute/workspace",
  "writable": false,
  "network_mode": "domain_allowlist",
  "allowed_domains": ["github.com", ".githubusercontent.com"],
  "allowed_paths": [{"path": "/absolute/reference", "access": "ro"},
                    {"path": "/absolute/output", "access": "rw"}],
  "hidden_paths": ["/absolute/workspace/private",
                   "/absolute/output/.openkapsel"]
}
```

`root` is required and must be an existing directory, not `/`; `cwd` must
lie inside it. `allowed_paths` grants up to 32 existing absolute directories
with `access: "rw"` or `"ro"` (alias `"r"`). `hidden_paths` masks up
to 32 existing files/directories beneath `root` **or a permitted extra
directory**. Manager IPC intentionally does not accept old `read_only`
entries. Denies take precedence over all grants, and read-only ancestors
take precedence over descendant rw grants. `writable` is the implicit
workspace root access. Directory denies mask contents on Bubblewrap/Podman;
file denies are read-only /dev/null bind mounts. Seatbelt and SRT apply
read/write denies. Existing direct-child `.openkapsel` directories and
Client configuration are automatically hidden by Client policy generation.
For Client configuration see `docs/client-mappings.md` (`job_sandbox`
automatically derives `type`, `root`, and `writable` and forwards the
Manager's JSON **string** for every Shell invocation). The Manager's own state, job output,
and IPC files may not be mounted as workspace or as an extra grant.

`network_mode` is `none` (default), `full`, or `domain_allowlist`.
`allowed_domains` must be nonempty only with `domain_allowlist`, and uses the
same normalization and suffix-match rules as Server Shell. The proxy is
restricted to HTTP port 80 and HTTPS port 443, not arbitrary raw TCP protocols.
If the requested backend or proxy cannot launch, the job is rejected.

## Server Token path access and legacy compatibility

In **Administration → Tokens → Additional accessible directories**, the
access selector now offers **Writable**, **Read only**, and **Deny access**.
Deny entries can refer to an existing regular file or directory below the
Token workspace or a separately granted extra directory. Under an existing
read/write root, add a narrower rule such as
`/data/project/.openkapsel` with **Deny access**; the other files remain
readable/writable. Rules compose regardless of order using **deny > ro > rw**.
The short alias `r` is normalized to `ro` in programmatic rules.

Server Token records retain backwards compatibility: persisted entries with
`read_only: true/false` are accepted on load as `ro/rw`, and existing Admin
form mode values `ro/rw` still work. New Token JSON is serialized with
`access`; Discovery continues to report `read_only` as well as `access`
for existing integrations. Server File API read/write/list and restricted
Shell enforce the same deny rules. Existing direct-child `.openkapsel`
subdirectories below extra granted directories are automatically hidden;
within the token workspace, the existing recursive metadata hide continues.
An explicit deny is incompatible with `shell_mode=full` because an unrestricted
host Shell could bypass it: set Shell permission to Restricted (or None).

Podman overlays directories with `--tmpfs` and individual files with a
read-only `/dev/null` bind after permitted mounts. Bubblewrap does the
same. These backends generally show a masked empty view rather than hiding
the pathname itself; they prevent reading or modifying the host contents.

## Job Manager IPC security (Linux/macOS/Windows)

The shared Manager authenticates IPC using a private 32-byte key stored in
`job-manager/ipc.key` (mode 0600 on POSIX). Each connection uses
`multiprocessing.connection` challenge-response authentication; random
Mapping identifiers and Unix socket owner permissions alone are not credentials.
The Manager state directory and IPC key are not sandbox-mounted.

On macOS with Xcode selected, Seatbelt also permits **read-only** access
to the trusted selected `/Applications/Xcode*.app` bundle. Apple's
`/usr/bin/python3` shim needs `Contents/Developer/usr/lib/libxcrun.dylib`;
`xcodebuild` also requires sibling
`Contents/SharedFrameworks/DVTSystemPrerequisites.framework` (and other Xcode
frameworks), so granting only `Contents/Developer` is insufficient.
The selected developer directory (or explicit `DEVELOPER_DIR`) is verified
against the system Xcode installation layout after resolving symlinks.
This **does not** grant all of `/Applications`, other applications or
arbitrary user-selected paths.

On macOS, `/usr/bin/python3` can be an Apple `xcrun` shim rather than an
installed Python interpreter. Some Xcode installations (including GitHub's
Xcode 26.6 runner) do not supply the requested `python3` tool, even when
Seatbelt allows every Xcode library. Launch a real installed interpreter
(e.g. the Python executable in the Client's virtual environment), rather
than relying on the shim. Seatbelt additionally allows writes **only** to
`/dev/null` among host device files so ordinary tool stderr redirection
continues to work without granting arbitrary filesystem writes.

On Linux, Bubblewrap creates private `/tmp`, `/var/tmp` and `/run`
mounts. If a broad explicitly allowed directory could otherwise include the
Manager socket, the socket parent directory is additionally masked. On macOS,
Seatbelt explicitly denies reading the IPC credential and accessing the socket
directory, and **denies all outbound AF_UNIX sockets**, including
`network_mode=full`; HTTP/S domain proxies use TCP loopback instead.
The Manager state directory is otherwise outside the sandbox's readable roots,
except for the specific per-Job temporary directory (used by `TMPDIR`).
These restrictions complement IPC authentication: a sandboxed process sharing
the Manager's UID must never obtain Manager command access.

**Upgrade note:** stop a previously running, keyless Job Manager using the
previous version of OpenKapsel before upgrading the Client. New Clients detect
an old Unix-domain Manager without `ipc.key` and fail with an explicit error
rather than hanging during an incompatible authentication handshake. Do not
delete or reset `ipc.key` while a Manager is running.

## Platform boundaries

Seatbelt has **no Linux-style PID namespace** and this feature does not
provide per-job cgroup resource quotas. Its system read-only runtime paths
and global pathname metadata permission are not equivalent to an empty Linux
mount namespace. It uses a legacy macOS `sandbox-exec` interface which may
differ on future macOS releases. Only explicitly requested restricted jobs
have been changed; the existing Client Shell/Podman configuration and the
Manager's current-user default remain unchanged.

The macOS integration tests execute real Seatbelt profiles and check denied
filesystem and network access, proxy policy, output and cleanup. Windows
adapter tests exercise settings translation, dependency refusal and cleanup,
but native Windows isolation is not yet verified on a provisioned host. Linux CI
executes real Bubblewrap isolation under
`OPENKAPSEL_REAL_SANDBOX_TESTS=1`, rather than treating mocks as isolation.

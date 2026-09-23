# SSH RPC

[Client setup](client-mappings.md) | [REST Skill reference](../skills/openkapsel-rest/references/ssh-rpc.md)

The built-in `ssh` RPC family gives a mapping client controlled SSH/SFTP access without exposing SSH passwords or private keys to the OpenKapsel server. It uses Paramiko on the client and keeps authenticated SSH transports alive for short bursts of related operations.

## Installation

Install the normal client dependencies plus the SSH extra:

```sh
python -m pip install -e '.[client,ssh-rpc]'
```

If `rpc.ssh` is enabled but Paramiko is missing, the client advertises the family as `unsupported` with reason `dependency_missing`. If no SSH profiles are configured, it advertises `unsupported` with reason `not_configured`.

## Client configuration

SSH profiles belong only in the mapping client configuration. Keep that file outside the exported mapping root and outside source control.

```json
{
  "url": "wss://host.example/kapsel/mapping-connect/<MAPPING_ID>",
  "token": "<MAPPING_TOKEN>",
  "root": "/path/to/local/project",
  "writable": true,
  "rpc": {
    "ssh": true
  },
  "ssh": {
    "idle_seconds": 60,
    "connect_timeout_seconds": 15,
    "max_connections": 8,
    "max_channels_per_connection": 8,
    "known_hosts": "/home/me/.ssh/known_hosts",
    "profiles": {
      "prod": {
        "host": "10.0.0.10",
        "port": 22,
        "username": "deploy",
        "key_filename": "/home/me/.ssh/id_ed25519",
        "host_key_policy": "strict"
      },
      "lab": {
        "host": "192.168.10.44",
        "username": "atp",
        "password": "<LOCAL-ONLY-PASSWORD>",
        "host_key_sha256": "SHA256:<43-character-base64-digest>"
      }
    }
  }
}
```

A profile must have at least one authentication source: `password`, `key_filename`, `allow_agent=true`, or `look_for_keys=true`. A private-key `passphrase` is also client-local. None of these secret values appear in capabilities, RPC inputs, RPC results, or task output unless a remote command itself prints them.

The supported pool settings are:

- `idle_seconds`: 10–3600, default 60.
- `connect_timeout_seconds`: 1–120, default 15.
- `max_connections`: 1–32, default 8.
- `max_channels_per_connection`: 1–64, default 8.

## Host-key policy

The default `host_key_policy` is `strict`. The client loads system host keys and an optional configured `known_hosts` file. A profile may additionally pin an OpenSSH-style `SHA256:...` host-key fingerprint.

If a strict connection sees an unknown key, the RPC fails with `ssh_host_key_unknown` and returns only the key type and SHA-256 fingerprint needed for an out-of-band verification/pinning decision. A changed or mismatched key fails with `ssh_host_key_mismatch`.

`host_key_policy: "accept-new"` is available only when the operator explicitly wants first-use trust. It accepts an unknown key for that client process; it does not silently rewrite the configured `known_hosts` file.

## Connection lifecycle

An operation can select SSH in exactly one of two ways:

```json
{"profile": "prod", "...": "..."}
```

creates a new connection, while:

```json
{"connection_id": "ssh_...", "...": "..."}
```

requires that exact existing connection.

Every successful connection-using result includes the opaque `connection_id` and profile name. For synchronous operations the ID is returned directly. For task operations (`exec`, `upload`, `download`) the first call returns the ordinary OpenKapsel task ID immediately; after the task finishes, its task `result` contains the SSH `connection_id`.

Connections belong to the long-lived mapping client runtime. Normal provider WebSocket disconnect/reconnect does not discard them. Client process exit/reload/restart closes them, and old IDs then cease to exist.

The idle timeout starts only when the connection has no active operation/channel. A long-running command or transfer may exceed 60 seconds without being closed. When the last operation finishes, the idle timer starts or resets. A new operation on the ID resets it again when that operation completes.

Expired, lost, and explicitly closed IDs are distinct:

- `ssh_connection_expired`: normal idle timeout.
- `ssh_connection_lost`: underlying SSH transport is no longer active.
- `ssh_connection_closed`: caller explicitly closed it.
- `ssh_connection_not_found`: the current client process has never seen the ID (including after process restart).

An explicit ID is never silently replaced by a new connection. To reconnect, the caller must deliberately make a new request with `profile` and no `connection_id`.

Use `close` when work is complete instead of waiting for idle expiry. A busy connection cannot be explicitly closed until its active operations finish.

## Operations

All SSH operations advertise `write=true`, including remote reads. This is intentional: using client-local SSH credentials is privileged external access. The caller therefore needs the matching control credential, token write permission, a mapping configured writable in Administration, and normal Plan Context.

| Operation | Execution | Purpose |
| --- | --- | --- |
| `profiles` | sync | List profile names and non-secret host/user/auth metadata. |
| `status` | sync | Verify one exact connection ID and refresh its activity. |
| `close` | sync | Explicitly close an idle connection. |
| `stat` | sync | SFTP `lstat` by default, optional followed-symlink stat. |
| `listdir` | sync | Bounded directory page, max 200 returned entries. |
| `read` | sync | Read up to 128 KiB at a byte offset; Base64 plus UTF-8 when decodable. |
| `exec` | task | Execute one remote command on a fresh SSH channel. |
| `upload` | task | Guarded local mapping file to remote SFTP path. |
| `download` | task | Remote SFTP file to guarded local mapping path. |

Transport reuse does **not** create a persistent shell process. Each `exec` opens a new SSH channel. Commands such as `cd` or `export` do not affect the next `exec`; combine dependent shell commands into one command or explicitly encode their environment/path.

`exec` writes both stdout and stderr into the ordinary bounded RPC task output stream and returns `remote_exit_code`, `stdout_bytes`, and `stderr_bytes` in the task result. `pty=true` requests a PTY for commands that require one; this version does not expose an interactive persistent SSH shell or RPC-task stdin.

## Failure and replay rules

Remote command execution is not automatically replayed. If the transport dies after the command was dispatched, the task returns `ssh_execution_uncertain` with `command_may_have_completed=true`. The caller must inspect remote state or deliberately establish a new connection before deciding whether to run the command again.

Interrupting or killing an OpenKapsel SSH task closes its local SSH channel, but SSH does not guarantee that an already started remote process was terminated. Treat cancellation after dispatch as remote-state-sensitive and verify the server before repeating a non-idempotent command.

The same principle applies to a task start whose OpenKapsel mapping response is lost: query/list the candidate client task first. Do not create a second task blindly.

## SFTP publication

`upload` reads only a guarded regular file inside the mapping. It uploads to a random temporary file beside the remote destination and publishes only after the complete source snapshot still matches.

By default the final remote destination must not exist. `overwrite=true` requires the server's atomic POSIX rename extension; if unavailable, the RPC returns `ssh_atomic_replace_unsupported` instead of falling back to delete-then-rename.

`download` writes a random temporary file inside the guarded mapping, fsyncs it, and atomically renames it into the requested local destination only after the remote read completes. By default the local destination must not exist; `overwrite=true` is explicit. Cancellation/failure removes the local temporary file.

Transfers use task cancellation checks between bounded chunks. A transport loss during upload is reported as uncertain rather than automatically retried. A transport loss during download leaves the final local destination unpublished.

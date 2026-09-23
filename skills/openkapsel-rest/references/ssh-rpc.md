# SSH RPC

SSH is a privileged client RPC family. Inspect `GET /mappings` and require `capabilities.rpc.ssh.state == "available"` before use. Paramiko must be installed on the mapping client and the client's private configuration must contain at least one `ssh.profiles` entry.

Every SSH operation advertises `write=true`, including remote reads, because the operation consumes client-local SSH credentials. Send the matching control token and normal `plan_id`, `taskname`, and `message`; the mapping must also be writable. SSH passwords, key passphrases and private-key contents are never RPC arguments.

## Connection selection

For the first operation, pass a configured profile:

```json
{"profile":"prod","command":"uname -a"}
```

A successful result contains an opaque `connection_id`. Reuse it on later operations and omit `profile`:

```json
{"connection_id":"ssh_...","command":"uptime"}
```

Never send both fields and never invent an ID. Explicit IDs are strict: expired/lost/closed IDs fail and are not silently reconnected. To establish a replacement connection, deliberately call again with `profile`.

The default idle timeout is 60 seconds after the last active SSH/SFTP operation finishes. Active commands/transfers prevent expiry. Provider WebSocket reconnects preserve the pool while the mapping client process remains alive; client restart/reload does not.

For task operations the initial HTTP response contains the OpenKapsel task ID, not a newly created SSH connection ID. Poll the task. Its completed `result.connection_id` is the ID to reuse.

## Operations

- `profiles` (sync): no args. Returns only non-secret profile metadata.
- `status` (sync): `{"connection_id":"ssh_..."}`.
- `close` (sync): explicitly closes an idle exact connection.
- `stat` (sync): profile or ID + `path`; optional `follow_symlinks`.
- `listdir` (sync): profile or ID + `path`; optional `offset`, `limit<=200`.
- `read` (sync): profile or ID + `path`; optional byte `offset`, `limit<=131072`. Returns Base64 and UTF-8 text when valid.
- `exec` (task): profile or ID + `command`; optional `pty`. Task output combines stdout/stderr; task result contains `remote_exit_code`.
- `upload` (task): profile or ID + mapping-relative `local_path` + remote `remote_path`; optional `overwrite`.
- `download` (task): profile or ID + remote `remote_path` + mapping-relative `local_path`; optional `overwrite`, `create_parents`.

Example REST task start:

```http
POST /mappings/<id>/rpc/ssh/exec
Authorization: Bearer <CONTROL_TOKEN>
Content-Type: application/json

{
  "args": {"profile":"prod","command":"hostname; uptime"},
  "plan_id": 123,
  "taskname": "deploy-check",
  "message": "Check the remote host before deployment"
}
```

Use the generic MCP `rpc` tool equivalently with family `ssh` and the advertised operation schema.

## Critical errors

- `ssh_host_key_unknown`: strict trust rejected a new key; verify and pin the returned SHA-256 fingerprint out of band.
- `ssh_host_key_mismatch`: pinned/known key changed.
- `ssh_authentication_failed`: client-local credentials did not authenticate.
- `ssh_connection_expired`: idle timeout.
- `ssh_connection_lost`: transport died.
- `ssh_connection_closed`: explicit close.
- `ssh_connection_not_found`: ID does not belong to the current client process.
- `ssh_execution_uncertain`: transport failed after command dispatch. Do **not** replay automatically.
- Task interruption closes the local SSH channel but does not prove an already started remote process stopped; verify remote state before replaying.
- `ssh_transfer_uncertain`: upload transport failed at a point where remote state needs inspection.
- `ssh_atomic_replace_unsupported`: overwrite requested but remote SFTP lacks atomic POSIX rename.

Each `exec` uses a new SSH channel, not a persistent shell process. Reusing a transport does not preserve shell `cd`, variables, aliases, or process state between commands.

Uploads stage beside the remote destination. Non-overwrite publication requires the destination to be absent; overwrite requires atomic POSIX rename. Downloads stage inside the guarded mapping and atomically publish the local destination after complete transfer and fsync.

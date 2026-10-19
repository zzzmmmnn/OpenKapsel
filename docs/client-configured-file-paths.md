# Client-configured external File access

Client `job_sandbox.paths` is shared policy for Shell and normal File operations.
An explicit external `ro`/(`r`) scope allows reads without browser approval;
`rw` also allows writes. This is ordinary configured access, not temporary full
Client approval. No grant or password exchange is created.

For example, on Windows:

```json
{
  "job_sandbox": {
    "paths": [
      {"path": "C:/Users/me/xwechat_files/", "access": "ro"}
    ]
  }
}
```

For an external File API path, explicitly select the Mapping so it is not
interpreted as a Server path:

```json
{
  "target": "moe",
  "paths": ["C:/Users/me/xwechat_files/received/log.txt"]
}
```

This example is an ordinary `fs_read_files` request: do not set `approved=true`.
Mutation requests still require their normal Plan context and Token/Mapping write
permission. A configured `ro` path remains read-only.

The simple Windows PowerShell file-command interpreter also uses configured
external scopes, for example `Get-Content -LiteralPath 'C:/Users/me/xwechat_files/received/log.txt'`.
Complex commands still use the normal Shell approval flow.

The Client advertises `configured_file_paths=true`; both Server and Client must be
updated for this routing. Old Clients receive no new implicit scope; explicit
ordinary targets return an upgrade-required error instead of falling back to
Server paths. Their existing explicit File approval flow remains available. The configuration is interpreted on the Client host, including
Windows drive letters, case behavior, filename checks and reparse-point guards.

Canonical destination checks prevent a configured path from opening unconfigured
symlink targets. Explicit lexical deny/protect rules remain effective. Pattern rules
alone do not open external roots. Exact-file rules do not open siblings or the parent
directory. Client configuration, hidden runtime state, Token restrictions and OS
permissions remain enforced.

File approval requests for already configured permitted scopes return
`status=granted` without an approval URL. A separate explicit approval is still
required when attempting to elevate a protected scope.

Mixed literal file/directory rules retain their own trailing-slash type, independent
of configuration order. Previously the final loop item's directory flag could be
reused incorrectly for earlier entries.

## Validation

- Full local suite: 1022 tests in 270.584 seconds, OK (13 skipped).
- The final old-Client no-fallback guard was verified afterward with 43 related
  tests, OK (2 skipped).
- Nine new configured-scope tests cover Chinese/space paths, normal File API,
  streams, ro/rw, single-file boundaries, denied/protected/config paths, alias
  destinations, safe Windows file commands and real HTTP/WebSocket routing.
- Existing browser grant-merge coverage remains intact using explicit protected
  scopes, followed by a ro scope to verify independent write elevation.
- Portable tests are included in the Linux/macOS/Windows Client CI matrix.
  Native Windows execution still requires that CI or a Windows host update;
  local development validation ran on macOS.

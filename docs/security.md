# Security model

[Back to README](../README.md)

## Attacker definition

OpenKapsel treats remote clients, AI agents, request payloads, workspace files,
and workspace-executed code as potentially hostile. An attacker is assumed to
know the source code, public URLs, endpoint shapes, and non-secret deployment
details. They may bypass Discovery and the REST Skill, construct arbitrary and
malformed requests, open concurrent or slow connections, and—when they possess
a restricted control credential—run arbitrary Shell syntax, interpreters, and
scripts. Security must therefore come from credential checks, path validation,
process isolation, and resource limits rather than from model cooperation or
endpoint obscurity.

The relevant attacker profiles are:

| Profile | Assumed capability | Boundary OpenKapsel is expected to preserve |
|---|---|---|
| Anonymous network client | Can reach public API, preview, and application routes but initially has no valid credential | Cannot enumerate valid capabilities, enter administration, or use Workspace read/mutation surfaces; behavior intentionally exposed by a project application remains that application's responsibility |
| Read-token holder | Can issue every read operation authorized by that Workspace URL | Cannot mutate the workspace, invoke Shell/MCP, obtain the control token, or cross into another token scope |
| OAuth client or connection-URL holder | Can discover metadata and request registration; a successfully authorized client possesses connection-scoped access/refresh credentials | A URL or registration alone cannot grant access; matching control-token or configured Workspace Password owner consent, PKCE and exact callback/resource binding are required. An authorized client remains within its linked configuration's current permissions and pinned workspace |
| Restricted control-token holder or compromised AI client | Has the matching Workspace URL and control token and can deliberately send arbitrary mutation and Shell requests | Is confined to that token's workspace and explicit path/network grants, resource limits, and permitted capabilities; cannot reach service-private state or other workspaces |
| Preview visitor or application user | Can load published assets, execute project JavaScript in their browser, and call public project application routes | A preview credential does not become a read/control credential; the application worker remains isolated from service-private state and other workspaces |
| Malicious workspace program | Runs inside restricted Shell or an application worker and may attempt interpreter-based escapes, process spawning, filesystem traversal, network pivoting, or resource exhaustion | Remains inside the corresponding mount, namespace, network, process, memory, CPU, and task limits |

Possession of a credential authorizes everything that credential explicitly
grants. In particular, workspace content is not confidential from a read-token
holder, and workspace integrity is not protected from a matching control-token
holder with write permission. Two token records intentionally pointing to the
same workspace are in the same data-isolation domain; OpenKapsel distinguishes
their actors and permissions but does not isolate their shared files from one
another.

Security goals include preventing cross-workspace and host-filesystem access,
protecting token and administrator secrets, preventing a restricted process
from escaping its granted network and resource policy, rejecting ambiguous or
malformed protocol input safely, and bounding application-level denial of
service where configured limits apply.

## Credential boundaries

- The URL token is read-only.
- REST mutations require a separate matching control token. MCP connections require their own static credential or owner-approved OAuth access token and cannot authorize ordinary REST requests. Both inherit the linked workspace configuration's current permissions and validity; REST credential renewal does not revoke them.
- URL and control credentials share a short expiration and rotate together.
- Conditional self-renewal works only when less than two days remain.
- Browser preview uses an independent rotatable credential on a dedicated origin.
- Invalid capability URLs return `404` to reduce enumeration.
- OAuth grants and Static MCP credentials are independent of read/control renewal. An authenticated MCP connection may explicitly export the linked configuration's REST workspace URL/control token or rotate that REST pair inside the normal renewal window; this is an intentional delegation capability, not an administration login. Deleting a connection revokes its MCP credential; disabling/deleting the linked token configuration or changing its directory blocks access. Full Shell remains trusted even when invoked through OAuth.
- OAuth client names are unverified registration metadata. Control-token holders must inspect the displayed workspace, permissions and return address before approving a connection. The authorization server does not fetch client-supplied metadata URLs in this version.
- Discovery never returns the control token unless the request already supplies that matching credential where required.

## Filesystem boundaries

- Paths are normalized and constrained to the token workspace or explicit grants.
- Each additional path independently selects read-only or writable access.
- Symlink escapes are rejected.
- Named path rules are literal, not regular expressions: `/scope/data/` covers that directory and descendants, `/scope/config` covers exactly one file; `*/.git/` covers any directory component named `.git`, regardless of its parent, and `*/.gitconfig` matches that filename. The only wildcard syntax is the initial `*/`. When absolute and prefix-ignored rules match the **same directory**, the more restrictive `deny > protect > ro > rw` applies to that directory and all descendants. Deeper explicit rules may control their own subtree, except under an explicit absolute deny.
- Defaults protect `.git` directories and metadata pointer files, `.config/`, `.ssh/`, `.gitconfig`, `.gitattributes`, and `.gitmodules`; `*/.openkapsel/` is denied by default. Administrators may explicitly override a default at the matching path, including `.openkapsel/` (which risks exposing service metadata). The separate transport-staging paths and Client configuration secrets remain restricted.
- Existing restricted-Shell profiles mask named protected paths discovered at launch. Static mount masks **cannot** guarantee protection against new hidden directories or atomically renamed/symlinked object-store paths after launch; writable native Git object storage may still suffer the documented `alternates`/fanout TOCTOU cross-Workspace disclosure until Git subprocesses receive a complete filesystem isolation boundary. Do not rely on pattern rules alone to prevent this attack.
- Deleting through the API moves data to workspace-local recycle storage.
- Application workers cannot read raw databases, Context, Memory, tokens, configuration, or another workspace.
- Workspace image capacity is enforced by its mounted ext4 filesystem.

## Process and network boundaries

- Restricted Shell uses namespaces, explicit mounts, token-scoped network modes, and per-token cgroups.
- Application workers use private PID and network namespaces and a minimal read-only runtime mount.
- Domain-restricted networking has no direct external route and relies on one token-scoped proxy.
- Plain HTTP proxy framing rejects request-smuggling ambiguity.
- Restricted Shell stderr redacts sandbox-launcher command lines while retaining application errors.
- HTTP, SSE, and restricted-proxy connections have global and per-scope limits.
- The main service runs as non-root; only the workspace-image helper is privileged.

Full Shell is the explicit exception. It has all filesystem and network privileges of the `openkapsel` operating-system user and is not contained by token mounts or network settings.

## Web and administration protections

- Administrator passwords use PBKDF2-HMAC-SHA256.
- Administration uses rate-limited login, a secure session cookie, and CSRF tokens.
- Administrator login, OAuth consent and capability approval rate-limit keys use the actual TCP peer, never client-provided `X-Forwarded-For`, `Forwarded` or `X-Real-IP`. A local HTTP caller can forge these headers even when its socket peer is loopback. When traffic enters through a same-host TLS reverse proxy, backend requests therefore share the proxy's rate-limit bucket; configure additional per-client ingress limits on that trusted proxy and restrict direct backend access.
- Workspace Password hashes are held in a SQLite database created with `0600` permissions; on startup the store also repairs older databases that were created with broader permissions. These passwords can approve privileged capabilities and must never be readable by other system users.
- Password-setup and capability approval browser URLs are bearer credentials. Their ticket path and query string are redacted from HTTP access/error logs, including when `--verbose` is enabled. Log redaction does not remove previously written log records; restrict log access and revoke any exposed live setup links.
- Git read and write RPCs validate repository metadata and pin the local Git configuration to a private per-invocation snapshot using `GIT_COMMON_DIR`. Git subprocesses cannot execute executable filter or redirect settings swapped into the worktree's `.git/config` after validation. Git's real object, reference and index storage remains in use; configured host/user Git settings are still operator-controlled. If safe isolation cannot be established, the RPC fails closed.
- OAuth consent is separate: exact configuration control-token or Workspace Password verification, a signed browser/request/permission proof, Origin checks, bounded POST budgets, script-free pages and a 303 callback. Admin sessions do not authorize this flow; controls never enter its cookie or callback.
- A stolen control token can delegate OAuth access for its own configuration. Routine control rotation does not revoke grants; revoke affected OAuth connections as part of compromise recovery.
- Production requires HTTPS. OpenKapsel itself serves plain HTTP: bind it to a loopback address and terminate TLS at an HTTPS reverse proxy. A non-loopback HTTP listener emits a startup security warning; directly accessing its port can expose admin passwords and Bearer tokens even if a public reverse proxy uses HTTPS. Restrict direct listener access with network controls if loopback binding is not possible.
- Responses include HSTS behind HTTPS, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and restrictive CSP where applicable.
- Preview does not send permissive CORS headers.
- FastAPI default documentation and schema routes return `404`.
- Public responses do not expose the precise package version.
- Errors use stable non-2xx status codes and structured JSON.

## Trust assumptions

OpenKapsel isolates Workspace infrastructure, not application business logic. A project FastAPI application is responsible for its own users, authorization, password reset, cookies, sessions, CSRF, abuse controls, and data model.

Allowed public domains can host user-controlled content. Prefer exact domains over broad suffixes. The network proxy does not inspect encrypted HTTPS content; it limits destinations, while TLS certificate validation remains end-to-end.

The host administrator, the `root` account, the reverse proxy, the operating
system kernel, and the selected Bubblewrap or Podman runtime are trusted. An
attacker who compromises those components, administrator credentials, the
`openkapsel` service account, or the installed runtime/dependencies is outside
the isolation guarantee. Full Shell tokens are also explicitly trusted: as
stated above, Full Shell deliberately runs with all privileges of the service
account and is not confined by token path or network settings.

OpenKapsel's connection, task, process, CPU, memory, and workspace-image limits
reduce service-level resource abuse; they are not a complete volumetric DDoS or
host-capacity defense. Public ingress rate limiting, firewalling, monitoring,
backups, host disk reservation, and dependency patching remain deployment
responsibilities.


Temporary `shell.unsandboxed` grants deliberately permit execution without a sandbox
as the selected target's OS user. A `deny` path rule protects File API and ordinary
sandboxed Shell access, but is not a host-level barrier: an explicitly approved
unsandboxed Shell may access those paths when OS permissions allow. The Shell's
initial working directory still passes normal checks. The approval
page requires the workspace's password plus browser/request CSRF proof, has bounded attempts, and exposes the
exact Conversation and target being approved. Grants cannot be transferred
between conversations, workspaces, targets or capabilities. Only salted password
hashes persist; pending URLs and grants are memory-only. Approval and OAuth
consent are independent, and neither grants administrator access.

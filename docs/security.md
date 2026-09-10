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
| OAuth client or connection-URL holder | Can discover metadata and request registration; a successfully authorized client possesses connection-scoped access/refresh credentials | A URL or registration alone cannot grant access; administrator approval, PKCE and exact callback/resource binding are required. An authorized client remains within its linked configuration's current permissions and pinned workspace |
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
- REST mutations require a separate matching control token. MCP connections require their own static credential or administrator-approved OAuth access token and cannot authorize ordinary REST requests. Both inherit the linked workspace configuration's current permissions and validity; REST credential renewal does not revoke them.
- URL and control credentials share a short expiration and rotate together.
- Conditional self-renewal works only when less than two days remain.
- Browser preview uses an independent rotatable credential on a dedicated origin.
- Invalid capability URLs return `404` to reduce enumeration.
- OAuth grants are independent of read/control renewal. Deleting a connection revokes its credentials; disabling/deleting the linked token configuration or changing its directory blocks access. Full Shell remains trusted even when invoked through OAuth.
- OAuth client names are unverified registration metadata. Administrators must inspect the displayed workspace, permissions and return address before approving a connection. The authorization server does not fetch client-supplied metadata URLs in this version.
- Discovery never returns the control token unless the request already supplies that matching credential where required.

## Filesystem boundaries

- Paths are normalized and constrained to the token workspace or explicit grants.
- Each additional path independently selects read-only or writable access.
- Symlink escapes are rejected.
- `.openkapsel` is the single private reserved directory for recycle, databases, Context, Memory, and Shell environments.
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
- Production requires HTTPS.
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

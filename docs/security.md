# Security model

[Back to README](../README.md)

## Credential boundaries

- The URL token is read-only.
- Mutation and MCP require a separate matching control token.
- URL and control credentials share a short expiration and rotate together.
- Conditional self-renewal works only when less than two days remain.
- Browser preview uses an independent rotatable credential on a dedicated origin.
- Invalid capability URLs return `404` to reduce enumeration.
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

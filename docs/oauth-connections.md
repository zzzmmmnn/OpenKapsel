# OAuth connections for remote MCP

[Back to README](../README.md)

## Connect a client

1. In Administration, select **OAuth connections**.
2. Choose an active child-workspace token configuration and enter a comment, such as `personal client`.
3. Copy the generated MCP URL into the remote client's connector configuration:

   `https://ws.example.com/kapsel/connect/<CONNECTION_ID>/mcp`

4. The client discovers OAuth metadata, registers itself, and opens OpenKapsel's independent authorization page. No administrator sign-in is required.
5. Check the workspace, exact configuration, permissions and callback address. The page also discloses that this MCP client may export or rotate the linked REST workspace URL/control token. Paste that configuration's current control token into the password-style field and select **Verify and authorize**. Client names are self-reported, not verified platform identities.
6. After the client exchanges the authorization code, the connection appears as **Authenticated**.

The URL is a stable identifier, not an access credential. Registration alone cannot claim it. Approval by the matching control-token holder locks the connection to one client ID; only that client can subsequently reauthorize. A client that discards its registration must use a newly created connection. Each successful reauthorization replaces the previous grant. The original URL continues serving MCP requests after binding.

The dashboard shows the comment, pinned workspace, creation/authorization timestamps, latest authenticated use, registered client and callback addresses. Last-use writes are coalesced to once per minute. **Delete connection** removes its registration, outstanding requests and access/refresh credentials immediately; it does not delete files or terminate already-running Shell tasks.

Connections are grouped by project directory. Edit a connection's comment or select another active child-workspace configuration without changing its URL, client registration, or existing access/refresh grant. The new workspace and permissions apply on the next request. Clients without OAuth support can use independently expiring [static MCP connections](static-mcp-connections.md).

## Permissions and lifetime

Connections refer to the stable `app_id` of a token configuration and pin its workspace directory. Current permissions, workspace expiry, sandbox and network policies remain authoritative on every call. Disabling/deleting the configuration or changing its directory blocks the connection. Read/control credential expiration and renewal do not invalidate OAuth credentials.

The `openkapsel` scope grants the linked configuration's enabled MCP capabilities, without administration access. Configure a separate token record if a client needs a different permission set, even when both records reference the same directory. Permission changes to a linked record also change the connection's effective permissions.\n\nAn authenticated OAuth MCP connection is also a portable delegation entry point for that configuration. `get_workspace_credentials` returns the current REST `workspace_url`, `control_token`, and credential expiration without rotating anything. `renew_workspace_credentials` uses the same final-two-day self-renewal rule as REST `POST /credentials/renew`: it atomically rotates the URL/read token and control token, invalidates the previous REST pair immediately, and leaves the OAuth access/refresh grant unchanged. Expired REST credentials still cannot self-renew; an administrator must renew them. Ordinary MCP Discovery and `workspace_info` describe this capability but continue to redact the actual REST credentials.

Access tokens expire after one hour. Refresh tokens rotate on every use, with a fixed grant lifetime of 30 days. Reusing a consumed refresh token revokes that entire grant, including its access tokens. After grant expiry, the same registered client can ask a current matching control-token holder to authorize again. Clients must persist a refresh response before retrying; a lost rotation response may require reauthorization.

OAuth credentials work only on the connection's MCP endpoint and the connection-scoped raw transfer URLs returned by MCP tools. Other REST endpoints require their normal read/control credentials. Use tools for task polling, Context, Memory and other operations instead of following REST examples. `workspace_info` identifies the OAuth mode and masks underlying capability credentials.

## Control-token consent boundary

Only the **current valid control token of the exact linked app_id and workspace**
can approve. Another configuration is rejected even when it points to the same
physical directory. Read tokens, preview tokens, expired/rotated controls and
controls belonging to disabled/expired configurations cannot approve. The page
never creates an administrator session; an existing admin cookie does not bypass
the control-token requirement. Connection creation/edit/deletion remains an
administrator operation.

The token is sent only in an HTTPS form POST to OpenKapsel's configured service
origin. It is never put in the authorization URL, OAuth state, callback, consent
cookie, rendered form value or OAuth database. The OAuth client gets an
authorization code, not the control token. The browser callback uses **303**, not
a method-preserving 307/308. Do not enable request-body logging at a proxy or APM
layer for consent/token endpoints. The existing private TokenStore is unchanged.

A short-lived HttpOnly/SameSite=Lax cookie has no access privileges. On HTTPS its
name is `__Host-openkapsel_oauth` with Secure and Path=/; development HTTP uses
`openkapsel_oauth`. The signed form proof binds that cookie, the exact request and
the displayed configuration/permissions, and expires within ten minutes. Multiple
forms in one browser may coexist. A service restart invalidates open form proofs;
reload the page. Missing/foreign CSRF or Origin fails closed. Pages contain no
scripts or external resources, use no-store/no-referrer, and forbid framing.
Cancel also checks CSRF but does not require a token.

Consent POST budgets are separate from administrator login: at most 10 attempts
per address and 5 per authorization request in a 60-second window. A concurrent
reservation counts before credential verification; both failures and successes
consume budget. Excess requests return 429 with Retry-After. Limiter storage is
bounded to 4096 active keys; full capacity fails closed until a window expires.
The reverse proxy and its forwarded-address handling must remain trusted.

Normal control-token rotation/expiration does not revoke existing OAuth grants.
**After suspected control-token compromise, rotate it and revoke affected OAuth
connections too.** OAuth permissions still follow the linked configuration, so
disabling that configuration blocks further MCP calls and refresh requests.

Pending authorizations and codes are pinned to their original configuration.
Administrative reassignment discards those pending requests, while the existing
explicit reassignment behavior for already-issued grants remains unchanged.
If permissions change after the consent page was displayed, reload and review
before approving. The first upgrade adds owner-binding columns and discards only
pre-upgrade pending handshakes/codes, not issued access/refresh credentials.
Legacy GET `/admin/oauth/approve?request=...` links redirect to the independent
page when still valid; old POST approval forms are rejected, never forwarded.

OAuth authorization-server metadata publishes the implementation-specific
`openkapsel_consent` object. Authenticated MCP `workspace_info` publishes the same
object at `authentication.consent`. Standard endpoints, PKCE and client token
exchange remain unchanged. REST Discovery remains focused on REST/Skill access.

## Protocol

Supported: authorization code flow with mandatory PKCE S256, exact registered redirect-URI matching, resource/audience binding and dynamic client registration (DCR). Token-endpoint authentication methods: `none`, `client_secret_basic` and `client_secret_post`. HTTPS redirects and HTTP loopback IP redirects are accepted. Client ID Metadata Documents (CIMD) are not implemented or advertised in this version. Platform-specific interoperability requires testing with the actual connector.

Each connection is an independent issuer:

| Endpoint | Purpose |
|---|---|
| `/kapsel/connect/<id>/mcp` | Streamable HTTP MCP; missing credentials return 401 with a resource metadata challenge |
| `/kapsel/oauth/<id>/resource` | Additional protected resource metadata endpoint |
| `/.well-known/oauth-protected-resource/kapsel/connect/<id>/mcp` | Standard resource metadata discovery; also referenced by the 401 challenge |
| `/.well-known/oauth-authorization-server/kapsel/oauth/<id>` | Authorization server metadata |
| `/kapsel/oauth/<id>/register` | Dynamic client registration |
| `/kapsel/oauth/<id>/authorize` | Starts an owner-consent request |
| `/kapsel/oauth/<id>/consent` | Independent browser GET/form POST; verifies a matching control token |
| `/kapsel/oauth/<id>/token` | Authorization-code exchange and refresh |

Clients must supply `resource` equal to the exact MCP URL in authorization and token requests. Access tokens are opaque and bound to one connection. Authorization codes expire after two minutes and are consumed atomically. Browser authorization requests expire after ten minutes. Public registration is capped at 32 pending clients per connection; authorization requests are capped at 64 per connection. Expired pending records are pruned during registration and token requests. Bound registration remains until deletion.

## Installation and proxy

Set a fixed HTTPS `public_base_url`. HTTP is accepted only for loopback development. Administrator login is needed to manage connections, not to approve them or use existing connections; those routes keep working when the admin console is disabled. The issuer uses this configured origin, never the request's Host header. No additional Python dependencies are required.

In addition to the normal `/kapsel/*` proxy, forward these metadata paths to the same server without stripping their prefixes:

```caddyfile
@kapsel_oauth_metadata path /.well-known/oauth-authorization-server/kapsel/oauth/* /.well-known/oauth-protected-resource/kapsel/connect/*
handle @kapsel_oauth_metadata {
    reverse_proxy 127.0.0.1:8765
}
```

Keep this matcher on the API origin, not the independent preview origin. Adjust `kapsel` if `url_base_path` differs. Do not modify Caddy's process management or TLS configuration.

The registry is stored as `oauth.sqlite3` alongside the upload state directory, normally `/var/lib/openkapsel/oauth.sqlite3`. It is outside workspaces and restricted sandbox mounts. Access tokens, refresh tokens, authorization codes and client secrets are stored as SHA-256 digests. These are random high-entropy credentials, not human passwords. Back up this database with other private service state; it contains registration details and authorization records. Deleting it invalidates every OAuth connection.

## Verification

`python3 -m unittest tests.test_oauth tests.test_oauth_control_consent tests.test_static_mcp -v` exercises the complete browser/control-token flow, exact owner matching, CSRF/cookie/origin checks, stale permissions, migration, pending-owner reassignment, concurrent approval, budgets, DCR, PKCE, callback/resource binding, refresh rotation/replay, credential renewal, transfer handoff and separate administrator management. Testing with each target client is a separate acceptance step.

## Security references

- RFC 6749, resource-owner authentication and authorization consent: https://www.rfc-editor.org/rfc/rfc6749.html
- RFC 9700, credential-safe redirects and browser authorization protections: https://www.rfc-editor.org/rfc/rfc9700.html
- MCP authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

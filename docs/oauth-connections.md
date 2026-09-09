# OAuth connections for remote MCP

[Back to README](../README.md)

## Connect a client

1. In Administration, select **OAuth connections**.
2. Choose an active child-workspace token configuration and enter a comment, such as `Claude personal`.
3. Copy the generated MCP URL into the remote client's connector configuration:

   `https://ws.example.com/kapsel/connect/<CONNECTION_ID>/mcp`

4. The client discovers OAuth metadata, registers itself, and opens OpenKapsel's authorization page. Sign in with the administrator account if needed.
5. Check the workspace, permissions and callback address, then approve. Client names are self-reported, not verified platform identities.
6. After the client exchanges the authorization code, the connection appears as **Authenticated**.

The URL is a stable identifier, not an access credential. Registration alone cannot claim it. Administrator approval locks the connection to one client ID; only that client can subsequently reauthorize. A client that discards its registration must use a newly created connection. Each successful reauthorization replaces the previous grant. The original URL continues serving MCP requests after binding.

The dashboard shows the comment, pinned workspace, creation/authorization timestamps, latest authenticated use, registered client and callback addresses. Last-use writes are coalesced to once per minute. **Delete connection** removes its registration, outstanding requests and access/refresh credentials immediately; it does not delete files or terminate already-running Shell tasks.

## Permissions and lifetime

Connections refer to the stable `app_id` of a token configuration and pin its workspace directory. Current permissions, workspace expiry, sandbox and network policies remain authoritative on every call. Disabling/deleting the configuration or changing its directory blocks the connection. Read/control credential expiration and renewal do not invalidate OAuth credentials.

The `openkapsel` scope grants the linked configuration's enabled MCP capabilities, without administration access. Configure a separate token record if a client needs a different permission set, even when both records reference the same directory. Permission changes to a linked record also change the connection's effective permissions.

Access tokens expire after one hour. Refresh tokens rotate on every use, with a fixed grant lifetime of 30 days. Reusing a consumed refresh token revokes that entire grant, including its access tokens. After grant expiry, the same registered client can ask the administrator to authorize again. Clients must persist a refresh response before retrying; a lost rotation response may require reauthorization.

OAuth credentials work only on the connection's MCP endpoint and the connection-scoped raw transfer URLs returned by MCP tools. Other REST endpoints require their normal read/control credentials. Use tools for task polling, Context, Memory and other operations instead of following REST examples. `workspace_info` identifies the OAuth mode and masks underlying capability credentials.

## Protocol

Supported: authorization code flow with mandatory PKCE S256, exact registered redirect-URI matching, resource/audience binding and dynamic client registration (DCR). Token-endpoint authentication methods: `none`, `client_secret_basic` and `client_secret_post`. HTTPS redirects and HTTP loopback IP redirects are accepted. Client ID Metadata Documents (CIMD) are not implemented or advertised in this version. Platform-specific interoperability requires testing with the actual connector.

Each connection is an independent issuer:

| Endpoint | Purpose |
|---|---|
| `/kapsel/connect/<id>/mcp` | Streamable HTTP MCP; missing credentials return 401 with a resource metadata challenge |
| `/kapsel/oauth/<id>/resource` | Protected resource metadata referenced by the challenge |
| `/.well-known/oauth-protected-resource/kapsel/connect/<id>/mcp` | Standard resource metadata discovery |
| `/.well-known/oauth-authorization-server/kapsel/oauth/<id>` | Authorization server metadata |
| `/kapsel/oauth/<id>/register` | Dynamic client registration |
| `/kapsel/oauth/<id>/authorize` | Starts administrator authorization |
| `/kapsel/oauth/<id>/token` | Authorization-code exchange and refresh |

Clients must supply `resource` equal to the exact MCP URL in authorization and token requests. Access tokens are opaque and bound to one connection. Authorization codes expire after two minutes and are consumed atomically. Browser authorization requests expire after ten minutes. Public registration is capped at 32 pending clients per connection; authorization requests are capped at 64 per connection. Expired pending records are pruned during registration and token requests. Bound registration remains until deletion.

## Installation and proxy

Set a fixed `public_base_url` and enable administrator login. The issuer uses this configured origin, never the request's Host header. No additional Python dependencies are required.

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

`python3 -m unittest tests.test_oauth -v` exercises discovery, DCR, administrator login and CSRF, code exchange, PKCE, callback/resource binding, concurrent redemption, refresh rotation/replay, restart persistence, credential renewal, transfer handoff and revocation. Actual ChatGPT/Claude connector testing is a separate acceptance step.

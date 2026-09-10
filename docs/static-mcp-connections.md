# Static MCP connections

[Back to README](../README.md)

For clients accepting remote Streamable HTTP with a fixed Bearer header, open **Administration → Static MCP**. Select a workspace configuration, enter a comment, and choose 30, 91, 182, 365 (default), or 730 days. Copy **MCP JSON** into the client:

```json
{
  "mcpServers": {
    "openkapsel": {
      "type": "http",
      "url": "https://ws.example.com/kapsel/mcp-connect/<CONNECTION_ID>/mcp",
      "headers": {"Authorization": "Bearer <MCP_CONNECTION_SECRET>"}
    }
  }
}
```

Each connection has an independent random identifier and secret. The secret is valid only for this connection's MCP endpoint and the raw transfer URLs returned by its tools. It cannot authorize ordinary REST requests, credential renewal, another connection, or administration. This is Streamable HTTP with JSON responses; it does not provide the legacy HTTP+SSE transport or stdio.

Static and OAuth connection pages group entries by workspace directory. Multiple connections can reference the same workspace configuration. Edit a connection to change its comment or move it to another active child-workspace configuration. Its connection ID and secret stay unchanged while the new workspace and permissions take effect immediately. Static connections show their expiration and last authenticated use. Editing leaves expiration unchanged by default. Choosing a duration resets expiration to the save time plus that duration, including for an expired connection. Delete a connection to revoke it. Recreate it when a new secret is required.

Connections inherit their linked configuration's permissions, sandbox, network restrictions, and workspace expiration. They remain usable after REST read/control tokens expire or renew. Disabling/deleting the configuration, or changing its directory, blocks its connections. Deleting a connection does not remove workspace files or stop already-started tasks.

The private registry is `static-mcp.sqlite3` alongside `oauth.sqlite3`, normally under `/var/lib/openkapsel`. It has mode 0600 and is outside workspace sandbox mounts. Static secrets are retained so administrators can copy client JSON again. Protect its backups like the REST credentials database. Last-use timestamps are written at most once per minute.

REST Discovery contains REST/Skill documentation only. The old `/w/<READ_TOKEN>/mcp` endpoint has been removed; migrate its clients by creating static or OAuth connections in administration. Existing OAuth connections remain valid. No extra Caddy route is needed for static connections when `/kapsel/*` is already forwarded.

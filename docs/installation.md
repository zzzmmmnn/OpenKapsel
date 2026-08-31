# Installation and reverse proxy

[Back to README](../README.md)

## Production layout

The installer uses the following layout:

- `/opt/openkapsel`: read-only application source and Python virtual environment
- `/var/lib/openkapsel/config.json`: service configuration
- `/var/lib/openkapsel/tokens.json`: token registry
- `/var/lib/openkapsel/workspace`: Workspace Root
- `/var/lib/openkapsel/shares`: temporary cross-workspace shares
- `/var/lib/openkapsel/network-proxies`: ephemeral token-scoped proxy sockets
- `/var/lib/openkapsel/home`: service-account home and rootless Podman storage
- `/var/lib/openkapsel/run`: service-account runtime directory

The `openkapsel` service account has no interactive login. OpenKapsel does not use `/root` or a human user's home directory.

The installer has been tested on Ubuntu 24.04 with Bubblewrap 0.9.0. Restricted sandboxing, cgroup limits, and workspace images require Linux. Python 3.10 or later is required.

## New installation and upgrade

Run from the project directory:

```bash
sudo ./install.sh
```

The installer creates an eight-character random administrator name and a sixteen-character random password on first installation. They are printed once. Existing credentials are preserved during upgrades.

The default installation provides Python, venv, Bubblewrap, RootlessKit, slirp4netns, uidmap, ACL tools, Git, curl, e2fsprogs, util-linux, CA certificates, Fontconfig, DejaVu and Noto fonts, and all declared Python dependencies. Install and enable Podman with:

```bash
sudo ./install.sh --with-podman
```

Useful options:

- `--no-package-install`: do not invoke the system package manager.
- `--no-start`: install and validate without starting services.
- `--migrate-from /path`: migrate an older combined installation.
- `--grant-ro /path`: grant the service account read-only host access.
- `--grant-rw /path`: grant the service account writable host access.

An existing `/opt/openkapsel` is retained as one UTC-stamped `.previous.*` rollback directory. `/var/lib/openkapsel` is never replaced.

After changing configuration:

```bash
sudo systemctl restart openkapsel
sudo systemctl status openkapsel openkapsel-images
```

## Migrating an older layout

If code, state, and `workspace` currently share one directory:

```bash
sudo ./install.sh --migrate-from /path/to/old/openkapsel
```

The installer preserves administrator settings and token data, rewrites managed paths, and moves the old Workspace only when the new destination is absent or empty. Old code and state remain available for rollback. Back up configuration, tokens, and workspaces before migration.

## Additional host paths

A path outside Workspace Root must be authorized at three layers: host permissions, systemd filesystem policy, and the individual token.

```bash
sudo ./install.sh \
  --grant-ro /srv/reference \
  --grant-rw /var/www/site
```

The installer grants ACL access only to `openkapsel` and writes a systemd drop-in. Add the same normalized absolute path to a token in the administration console and select read-only or writable access.

Re-running the installer without either grant option preserves the current grant list. Supplying at least one grant option replaces the complete list. Restricted workers see only their workspace and their explicit grants; they cannot see other workspaces, configuration, token data, or the complete application directory.

## Caddy routing

Merge the routes into the existing Caddyfile. Do not launch a second Caddy process on the same listeners. Keep the API prefix and forward the independent preview origin without rewriting its root:

```caddyfile
{
    servers {
        timeouts {
            read_header 15s
            idle 2m
        }
        max_header_size 64KB
    }
}

ws.example.com {
    handle /kapsel/* {
        reverse_proxy 127.0.0.1:8765
    }
}

preview.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

OpenKapsel listens on HTTP only. In production, `public_base_url` and `preview_base_url` must use HTTPS. Caddy terminates TLS, supplies HSTS, and forwards the original request information.

### Recommended Caddy connection limits

These values protect public listeners without imposing an accidental total request deadline:

| Setting | Recommended value | What it limits | What it does not limit |
|---|---:|---|---|
| `read_header` | `15s` | Time allowed to finish the client request headers | Upload body duration or response duration |
| `idle` | `2m` | Time a completed downstream Keep-Alive connection waits for the next request | An active proxied request, upload, download, or SSE stream |
| `max_header_size` | `64KB` | Total accepted request-header size | Request or response body size |
| `read_body` | leave unset globally | A configured value would bound client upload reads | Leaving it unset allows legitimate slow or large uploads |
| `write` | leave unset globally | A configured value would bound writes to the client | Leaving it unset allows long downloads and SSE |

Caddy remains in the data path while a request is proxied. The downstream `idle` timer is only relevant after that request has completed and Caddy is waiting for another request on the same connection. Caddy-to-OpenKapsel connection pooling has separate upstream Keep-Alive behavior.

OpenKapsel also has application-side limits:

| Configuration key | Default | Purpose |
|---|---:|---|
| `max_http_connections` | `128` | Maximum accepted OpenKapsel HTTP connections; overload returns `503` |
| `http_socket_timeout_seconds` | `30` | Bounds stalled socket I/O and idle backend Keep-Alive reads; it is not a total task deadline |
| `max_sse_streams` | `16` | Global concurrent Shell SSE streams |
| `max_sse_streams_per_token` | `4` | Concurrent Shell SSE streams for one token |
| `max_sse_duration_seconds` | `3600` | Duration before an SSE `reconnect` event supplies exact output offsets |
| `max_network_proxy_connections` | `64` | Global connections through restricted-domain proxies |
| `max_network_proxy_connections_per_instance` | `16` | Connections through one task or worker proxy instance |
| `network_proxy_header_timeout_seconds` | `15` | Time allowed to finish a restricted-proxy request header |

Do not confuse the one-hour SSE rotation with the Shell task runtime. The stream can reconnect without losing output, while the task follows its own configured runtime limit.

Validate and reload with the existing Caddy installation's normal commands:

```bash
caddy validate --config /path/to/Caddyfile --adapter caddyfile
caddy reload --config /path/to/Caddyfile --adapter caddyfile
```

## Installation checks

```bash
systemctl is-active openkapsel openkapsel-images
curl -I https://ws.example.com/kapsel/admin
curl -I https://preview.example.com/
```

Open `https://ws.example.com/kapsel/admin`, sign in, and create a token. Begin additional path grants as read-only and enable writes only when required.


# OpenKapsel

OpenKapsel is a Python 3 remote-workspace service for AI clients. It gives an AI a scoped project directory, file APIs, asynchronous Shell tasks, browser previews, per-project FastAPI backends, Context and Memory, temporary sharing, and MCP without trying to be an online IDE.

A Workspace Root contains direct child workspaces. Each token record points to one child directory or one capacity-limited ext4 workspace image. Read, control, and browser-preview credentials are independent, so a preview URL never exposes a credential that can modify the project.

Python 3.10 or later is required. Linux production hosts can isolate restricted Shell and application workers with Bubblewrap or rootless Podman, private PID and network namespaces, explicit mounts, cgroup v2 resource limits, and token-scoped network policy.

## What it can do

- Read text and binary files, inspect metadata and SHA-256, list directory trees, and search across files.
- Create directories; write, replace, move, rename, recycle, restore, upload, and download files.
- Transfer large files with resumable raw-byte uploads and HTTP Range downloads.
- Run asynchronous Shell tasks with stdin, incremental output, SSE streaming, process inspection, graceful interruption, and forced termination.
- Persist once, interval, and strict six-field cron Shell schedules with Context attribution and run history.
- Store app-identity-scoped Shell variables and POSIX initialization, then inject them into full, Bubblewrap, and Podman tasks.
- Give each token a restricted Bubblewrap or Podman sandbox, or explicitly grant trusted tokens full Shell access.
- Restrict outbound networking to disabled, an exact domain allowlist, or full network access.
- Publish static browser previews on an independent origin and run project-owned FastAPI applications with live Server-Sent Events.
- Provide project databases through a portable SQLAlchemy runtime without exposing raw database paths.
- Record mutation history and hierarchical Plans in Context, and retain longer project knowledge in Memory.
- Move one file or directory between workspaces through short-lived, capability-addressed shares.
- Expose focused Discovery documents, a portable REST Skill, and a stateless Streamable HTTP MCP endpoint.
- Manage token lifetimes, permissions, workspace images, sandbox limits, preview credentials, and administrator credentials from a browser console.

## Credential model

A workspace has three independent credentials:

- The read token is embedded in the Workspace URL and is always read-only.
- The matching control token is sent as `Authorization: Bearer ...` for mutations, Shell, schedules, Context, Memory, and MCP.
- The preview token only serves the browser preview and can be shared without exposing Workspace access.

Read and control credentials are short-lived and rotate together. The workspace lifetime and preview token are independent. Every state-changing API operation also belongs to a Plan and includes a short task name and operation message, giving later AI clients an auditable project history.

## Production installation

The supported layout is:

- application: `/opt/openkapsel`
- configuration and token registry: `/var/lib/openkapsel`
- Workspace Root: `/var/lib/openkapsel/workspace`
- service account: the non-login `openkapsel` user
- public HTTPS and routing: an existing reverse proxy such as Caddy

Run from the project directory:

```bash
sudo ./install.sh
```

The first installation prints a random eight-character administrator name and sixteen-character password once. Existing credentials, tokens, workspaces, images, and path grants are preserved on upgrade.

Install the optional rootless Podman backend with:

```bash
sudo ./install.sh --with-podman
```

Use `--no-package-install` when dependencies are already installed, `--no-start` to install without starting services, and `--migrate-from /old/path` to migrate an older combined installation. See [Installation and reverse proxy](docs/installation.md) before using migration, host path grants, Podman, or production Caddy routing.

Edit `/var/lib/openkapsel/config.json`, then restart and verify:

```bash
sudo systemctl restart openkapsel
sudo systemctl status openkapsel openkapsel-images
```

### Minimal Caddy routing

Keep the API under a fixed prefix and serve previews from a separate origin:

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

Here `idle 2m` only limits how long an already completed Keep-Alive connection waits for the next request. It does not impose a two-minute limit on an active upload, download, Shell task, or SSE stream. Do not add short global `read_body` or `write` timeouts unless the resulting limits on legitimate large transfers and streaming responses are intentional. The detailed timeout model and recommended values are in [Installation and reverse proxy](docs/installation.md#recommended-caddy-connection-limits).

OpenKapsel itself listens on HTTP. Production configuration requires HTTPS public and preview URLs; the reverse proxy owns certificates, HSTS, and public routing.

## Development mode

```bash
cp config.example.json config.json
python3 set_password.py --config config.json
python3 -m openkapsel --config config.json
```

The service can run locally without HTTPS when both public URLs are configured for local HTTP use. Restricted Linux sandbox features are unavailable on macOS, but regular workspace APIs and trusted full-Shell development remain usable. See [Development and testing](docs/development.md).

## Connecting an AI client

The canonical Workspace URL is:

```text
https://ws.example.com/kapsel/w/<READ_TOKEN>/
```

Open that URL as JSON to receive compact Discovery, capability summaries, current limits, and links to focused documents. Mutating requests add the matching control token:

```http
Authorization: Bearer <CONTROL_TOKEN>
```

The portable `skills/openkapsel-rest` Skill translates the REST interface into higher-level file, directory, retry, resumable-upload, and batch workflows. MCP clients use the same Workspace URL with `/mcp` and always provide the control token. Runtime Discovery is authoritative for the permissions and limits of the current token.

## Documentation

- [Installation and reverse proxy](docs/installation.md): production layout, migration, path grants, Caddy, timeouts, and verification.
- [Authentication and administration](docs/authentication-and-administration.md): credentials, Discovery, token settings, renewal, and workspace images.
- [Sandboxing and networking](docs/sandboxing-and-networking.md): Bubblewrap, Podman, cgroups, path isolation, and domain-restricted egress.
- [REST files, transfers, and sharing](docs/rest-files-and-transfers.md): endpoints, mutation context, ETags, recycle, large files, and temporary shares.
- [Web preview and applications](docs/web-applications.md): preview security, FastAPI layout, bundled libraries, and SQLAlchemy runtime.
- [Shell tasks and MCP](docs/shell-and-mcp.md): environments, task lifecycle, streaming, connection limits, process control, and MCP transport.
- [Scheduled Shell tasks](docs/schedules.md): timing rules, permissions, dispatch behavior, Context, and run history.
- [Context and Memory](docs/context-and-memory.md): Plans, operations, Notes, long-lived Memory, revisions, and queries.
- [REST Skill](docs/rest-skill.md): installation, `.openkapsel.env`, automatic credential renewal, batch uploads, and filtering.
- [Security model](docs/security.md): trust boundaries, private data, sandbox exceptions, and response protections.
- [Development and testing](docs/development.md): source layout, local configuration, tests, and current boundaries.

## Scope

OpenKapsel is AI workspace infrastructure, not a multi-user IDE or a general website account system. Authentication for a project-owned FastAPI application belongs to that application. Restricted sandboxing requires Linux, and full Shell is deliberately outside the token sandbox boundary; grant it only to trusted tokens.

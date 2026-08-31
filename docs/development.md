# Development and testing

[Back to README](../README.md)

## Local configuration

```bash
cp config.example.json config.json
python3 set_password.py --config config.json
python3 -m openkapsel --config config.json
```

`set_password.py` interactively sets and confirms the administrator password. Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and a random sixteen-byte salt:

```text
pbkdf2_sha256$600000$<random-salt>$<derived-digest>
```

Generate both administrator fields:

```bash
python3 set_password.py --config config.json --generate-username --generate
```

Credentials are printed once. Configuration updates are atomic and use mode `0600`. Legacy fixed-salt SHA-256 credentials remain accepted and migrate to PBKDF2 after a successful login.

`config.example.json` documents all settings. Relative paths resolve from the configuration file directory. Important groups include:

- listener, URL prefix, public URL, preview URL, and Workspace Root
- token registry, uploads, shares, task history, and network-proxy state
- file, search, transfer, batch, task, SSE, and connection limits
- Bubblewrap, Podman, RootlessKit, cgroups, and default network domains
- optional workspace-image helper socket

Local HTTP is supported for development. Production public and preview URLs must use HTTPS.

## Source layout

```text
openkapsel/
  admin_handlers.py       administration request handling
  admin_ui.py             dependency-free administration HTML
  api_workers.py          isolated FastAPI application workers
  context_store.py        per-workspace Context database
  discovery.py            Discovery document construction
  discovery_sections.py   focused Discovery metadata
  file_handlers.py        REST file operations
  mcp.py                  MCP schemas and constants
  mcp_handlers.py         MCP transport adapters
  memory_store.py         project Memory database
  network_proxy.py        token-scoped HTTP/HTTPS egress policy
  preview_handlers.py     preview and application routing
  proxy_relay.py          sandbox loopback-to-Unix relay
  routes.py               route registry
  sandbox_backends.py     Bubblewrap and Podman backends
  server.py               HTTP server and shared orchestration
  skill_handlers.py       dynamic REST Skill packaging
  tasks.py                asynchronous Shell tasks
  tokens.py               credentials, permissions, and path grants
  uploads.py              resumable uploads
  workspace_images.py     image client and privileged manager
openkapsel_runtime/        application-facing database runtime
skills/openkapsel-rest/    portable REST Skill and helpers
containers/                optional Podman image recipes
systemd/                   production service units
tests/                     unit and integration tests
install.sh                 production installer
set_password.py            offline administrator credential tool
```

## Tests

Create a virtual environment with project dependencies, then run:

```bash
.venv/bin/python -m unittest discover -s tests
```

The suite covers routes, authorization, files, binary and resumable transfers, Shell, HTTP and SSE limits, strict domain-proxy framing, sandbox isolation, Context, Memory, images, sharing, applications, MCP, Skills, and administration.

GitHub Actions runs the suite on supported Python versions. Some sandbox integration checks require Linux utilities; tests use explicit capability checks where the CI host cannot provide a production namespace backend.

## Current boundaries

- OpenKapsel is not a multi-user IDE.
- Business authentication belongs to each project application.
- Workspace images expand but do not shrink.
- Restricted sandboxing requires Linux.
- Regular-directory workspaces and trusted full Shell can be used elsewhere.
- Full Shell is deliberately powerful and should be granted only to trusted records.

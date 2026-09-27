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

`config.example.json` provides the normal server baseline. Relative paths resolve from the configuration file directory. Important groups include:

- listener, URL prefix, public URL, preview URL, and Workspace Root
- token registry, uploads, shares, task history, application-worker, and network-proxy state
- file, search, transfer, batch, task, SSE, and connection limits
- Bubblewrap, Podman, RootlessKit, cgroups, and default network domains
- optional workspace-image helper socket

The loader also accepts advanced/optional keys that are not required in the example file: `public_base_url`, `workspace_image_socket`, `api_worker_dir`, `default_command_timeout`, `max_task_output_mb`, and the optional bootstrap-only `bootstrap_token`. Runtime defaults remain authoritative when these keys are omitted.

Local HTTP is supported for development. Production public and preview URLs must use HTTPS.

## Source layout

```text
openkapsel/
  api/                     Discovery, MCP, preview and Skill-facing HTTP composition
  auth/                    administrator UI, token policy, OAuth, Static MCP and security
  client_runtime/          mapping-client filesystem, tasks, reload and Windows support
  context/                 Context plans and Memory storage/handlers
  execution/               Shell/tasks, schedules, sandboxing, cgroups and network policy
  files/                   file APIs, safe paths, recycle, uploads/shares and Git primitives
  mapping/                 provider transport, registry, RPC/native views and transfers
  rpc_plugins/             Git, Archive and extensible client RPC families
  server_runtime/          server configuration, lifecycle, dispatch and shared HTTP support
  storage/                 rclone-backed Storage Providers and workspace bindings
  workspace/               workspace layout and workspace-image helpers
  client.py                stable mapping-client entry point
  routes.py                declarative workspace HTTP route registry
  server.py                stable server entry point
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

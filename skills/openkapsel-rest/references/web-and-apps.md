# Static preview and FastAPI applications

Read `GET /discovery/web` with the Bearer token. Use its `web_preview.url` rather than constructing a preview URL from the read token. The preview credential is independent and rotatable.

## Static preview

`GET|HEAD <preview-base>/<workspace-relative-path>` serves files inline. Directories redirect to a trailing slash and resolve `index.html`. Range requests and ETags are supported.

On RPC-first servers, mapped static files are served by bounded RPC reads,
including Range/HEAD and ETags. Static preview does not start FUSE or an API worker.
An online but unmounted mapping is usable.

Preview requires read and preview permissions. `.openkapsel` and any `api` directory are not served as static files. A dedicated preview origin permits same-origin JavaScript modules inside the preview while preventing cross-origin reads from unrelated sites. OpenKapsel does not add permissive CORS headers.

Never send the OpenKapsel control token to a preview URL. Static code can know the preview URL but cannot derive the read or control token from it.

## FastAPI route ownership

Any path component named `api` switches that application subtree to FastAPI. The entrypoint is the parent app directory's `api/app.py`:

```text
site-a/
  index.html
  api/app.py
site-b/
  index.html
  api/app.py
```

Requests to `<preview-base>/site-a/api/<route>` go to `site-a/api/app.py`; nested apps are independent. The module must export `app`, normally a `fastapi.FastAPI` instance.

OpenKapsel supports `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE` application routes and forwards query strings, headers, cookies, and request bodies. Application authentication, users, sessions, cookies, roles, CSRF, and rate limits belong to each app. The OpenKapsel read/control tokens are not application-user credentials.

FastAPI's default `/docs`, `/redoc`, and `/openapi.json` routes are blocked. Publish an explicitly named, authenticated route if the application intentionally exposes documentation.

## Mapped applications and native dependencies

FastAPI runs on the server and needs native paths, unlike static preview. An
application inside a mapping automatically leases its containing mapping.
Declare extra workspace mapping names or IDs in the application's
`api/mappings.json`, limited to 16 KiB and containing only this field:

```json
{"mount_mappings": ["datasets", "assets"]}
```

The declaration does not execute code or request an immediate mount. Route and
manifest discovery use file/RPC access. An authorized API request acquires the
required mounts before worker sandbox creation. Leases belong to that worker,
not an individual request or SSE connection; stop/restart or idle worker cleanup
releases them. A provider generation change invalidates the worker fingerprint.
Disabled/unavailable native support is an error, not permission to run the app
on the client or mount all mappings. Use static preview or client execution only
when those are the intended operations.

Mapped applications keep private runtime/SQL data in the server-managed
`mapping-app-state/<worker-key>` store, outside the client's export. Do not create
or access the provider's forbidden `.openkapsel` path. Use the managed database
API below rather than hard-coding storage paths.

## Server-Sent Events

A FastAPI `GET` response with media type `text/event-stream` is forwarded and flushed incrementally. Use `StreamingResponse`, emit standard SSE records separated by a blank line, and send periodic `: keep-alive` comments more frequently than `limits.http_socket_timeout_seconds`.

Workspace API streams share `limits.max_sse_streams`, `limits.max_sse_streams_per_token`, and `limits.max_sse_duration_seconds` with Shell SSE. The proxy closes a duration-limited or idle stream without inventing application events; browser `EventSource` should reconnect normally.

## Runtime libraries and network

The installed libraries and versions are deployment-dependent; read `capabilities.web_app_api.available_libraries` in `discovery/web`. The maintained contract currently includes FastAPI, SQLAlchemy, python-multipart, Jinja2, HTTPX, NumPy, Numba, pandas, Matplotlib, SciPy, cryptography, lxml, Pillow, PyYAML, and Beautiful Soup. Outbound HTTP still requires the token's network permission.

## Managed database

Application code uses the portable SQLAlchemy wrapper:

```python
from openkapsel_runtime import database

engine = database.engine("main")

with database.session("main") as session:
    ...
```

Normal session exit commits and closes; exceptions roll back, close, and re-raise. Database IDs use 1-64 ASCII letters, digits, underscores, or hyphens. Do not construct storage paths or depend on backend-specific SQL.

Ordinary workspace applications use private runtime-managed database storage
inside `.openkapsel`; mapped applications instead use the server-managed store
described above. Storage is unavailable through file APIs, static preview,
restricted Shell and other applications. Missing private storage is created
automatically for an older workspace.

# Web preview and applications

[Back to README](../README.md)

## Static preview

A token with preview permission receives an independent URL:

```text
https://preview.example.com/<PREVIEW_TOKEN>/path/to/index.html
```

Directories resolve `index.html`. The preview origin is separate from the Workspace API origin and uses:

- an independent rotatable credential
- `Referrer-Policy: no-referrer`
- a restrictive Content Security Policy and permissions policy
- no permissive cross-origin read header
- browser JavaScript support without exposing read or control tokens

Preview requests do not use a restricted Shell worker's domain allowlist. External scripts and resources are governed by preview CSP.

## FastAPI application layout

Any directory named `api` delegates that application subtree to FastAPI. The entrypoint is its parent application's `api/app.py`. Nested applications are independent:

```text
workspace/
  site-a/
    index.html
    api/app.py
  site-b/
    index.html
    api/app.py
```

Example:

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"ok": True}
```

OpenKapsel returns `404` for FastAPI's default `/docs`, `/redoc`, and `/openapi.json` routes. Applications that intentionally publish documentation should use a different explicit route and apply their own authorization.

OpenKapsel does not provide application users, login, CAPTCHA, cookies, sessions, CSRF, or roles. Each application implements its own business authentication.

## Available libraries

The supported application libraries are published in `discovery/web`:

- `fastapi`: ASGI application, routing, requests, and responses
- `sqlalchemy`: portable ORM, Core, schema, and transactions
- `python-multipart`: `UploadFile`, `File`, and `Form`
- `jinja2`: HTML and text templates
- `httpx`: synchronous and asynchronous HTTP clients, subject to token network policy
- `numpy`, `numba`, `pandas`, `scipy`: numerical and scientific computing
- `matplotlib`: non-interactive plotting with DejaVu and Noto fonts
- `cryptography`: high-level recipes and lower-level primitives
- `lxml`, `beautifulsoup4`: XML and HTML parsing and traversal
- `pillow`: image decoding, encoding, resizing, and transformation
- `pyyaml`: YAML parsing and serialization; use `yaml.safe_load` for untrusted input

Uvicorn is worker infrastructure rather than an application-facing contract. Transitive packages such as Pydantic, Starlette, and AnyIO are not promised independently.

Numba installs `llvmlite`; supported wheels bundle its required LLVM components. Building Numba or llvmlite from source is outside the supported installer.

These packages live in `/opt/openkapsel/venv` and are available to application workers. This does not mean they exist in every restricted Shell: Bubblewrap sees host packages and Podman sees its selected image.

## Database runtime

Application code imports:

```python
from openkapsel_runtime import database
```

`database.engine("main")` returns a cached SQLAlchemy Engine for the worker lifetime. `database.session("main")` is a transaction context manager: normal exit commits and closes; exceptions roll back, close, and are re-raised.

Database IDs contain 1–64 ASCII letters, digits, underscores, or hyphens. Use SQLAlchemy ORM, Core, schema, and transaction APIs. Do not construct storage paths or depend on backend-specific SQL.

Storage is private to the application under its `.sql` area. Missing private directories are recreated for older workspaces. Raw database files are unavailable through file APIs, preview, restricted Shell, and other applications.

Workers have private PID namespaces and see only their application workspace and read-only runtime venv. They do not receive the complete application source, host `/proc`, token registry, configuration, another workspace, `.context`, or raw database paths.


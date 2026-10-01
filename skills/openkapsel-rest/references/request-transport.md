# GET-only request transport

This fallback is for AI hosts that can issue only `GET` requests to a fixed Workspace base URL. Prefer ordinary REST paths and `Authorization: Bearer <CONTROL_TOKEN>` whenever the host supports them. Runtime `GET <workspace_url>/discovery/transport` is authoritative for the current wire contract.

## Query-route fallback

For an ordinary read-only GET endpoint, keep the physical request at the exact Workspace root and put the relative endpoint route in `req`:

```text
GET <workspace_url>?req=fs/query/list&path=.
```

`req` must appear exactly once and must not begin with `/`. OpenKapsel consumes it before dispatch, so the endpoint handler receives only its ordinary query parameters. This form does not grant control authorization and does not expose preview, FastAPI, administrator, public-share, OAuth, or MCP routes.

## Signed GET envelope

When the host also cannot send the required HTTP method or an Authorization header, send an HMAC-signed envelope as an actual `GET` to the exact Workspace root:

```text
GET <workspace_url>?req=context&timestamp=<unix-seconds>&nonce=Ab12Cd34&body=<url-encoded-json>&http_method=POST&signature=<base64url-hmac>
```

The envelope fields are:

- `req`: relative endpoint route without a leading `/`.
- `timestamp`: current Unix time in whole seconds. The server accepts a 300-second clock window.
- `nonce`: a fresh random string of exactly 8 ASCII letters or digits. Reuse for the same credential identity inside the active acceptance window is rejected.
- Ordinary endpoint query parameters: place them before `http_method`; they are covered by the HMAC.
- `body`: optional URL-encoded UTF-8 JSON for simple JSON-body endpoints.
- `http_method`: the effective method. It must be the penultimate query parameter and may be `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, or `DELETE`.
- `signature`: the final query parameter, encoded as Base64URL without padding.

## Signing

Use the matching control token directly as the HMAC key:

```text
signature = Base64URL-no-padding(
    HMAC-SHA256(
        key = control_token,
        message = exact raw query string before the final &signature= field
    )
)
```

The signed query string must be ASCII request-target data. Percent-encode UTF-8 values before constructing and signing it. Do not parse, sort, normalize, decode, or re-encode the query after calculating the signature.

Because the exact raw query is signed, `req`, `timestamp`, `nonce`, endpoint query parameters, `body`, and `http_method` are authenticated together. The control token itself never appears in the URL.

## Server verification

The server accepts the envelope only when all of these conditions hold:

1. The physical HTTP request is `GET` to the exact Workspace root URL.
2. `signature` is the final query parameter and appears exactly once.
3. `http_method` is immediately before `signature` and appears exactly once.
4. `req`, `timestamp`, and `nonce` each appear exactly once.
5. `body` appears at most once.
6. The timestamp is inside the acceptance window.
7. The nonce has the required format and has not already been consumed for the same credential identity inside the active window.
8. The HMAC matches in constant time.

After successful verification, OpenKapsel treats the request as control-authorized, internally dispatches `req` using `http_method`, removes the envelope-only fields, and reuses the normal REST endpoint matcher and handler. Signed-envelope responses use `Cache-Control: no-store`.

## Body and protocol limits

`body`, when present, is URL-decoded and supplied to ordinary JSON-body handlers. It is intended only for simple operations that would normally use an `application/json` request body.

Do not use this fallback for raw binary bodies, resumable upload chunks, streaming protocols, or operations that depend on additional request headers. Use the normal REST transport for those cases.

Endpoint query parameters and `body` are still present in the URL and may be recorded by browsers, proxies, or access logs. Do not put unrelated secrets in them. The HMAC prevents modification but does not encrypt URL contents.

The nonce replay cache is intentionally bounded to the signed-envelope validity window and is maintained in server process memory; a server restart clears that short-lived cache.

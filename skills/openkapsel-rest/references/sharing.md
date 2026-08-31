# Temporary cross-workspace sharing

Read `GET /discovery/sharing` for current size, count, and expiry limits. A share contains exactly one source file or directory and is immutable until expiry/deletion.

## Create

`POST <source-workspace-url>/shares` with the source control token:

```json
{
  "path": "dist/package.zip",
  "plan_id": 42,
  "taskname": "handoff",
  "message": "Share the built package"
}
```

The source must be inside the token workspace. The workspace root, extra granted host paths, symlinks, and private `.openkapsel` content are rejected. The response provides `share_id`, public `query_url`, and `expires_at`.

## Inspect without a workspace token

`GET <service-base>/shares/<share_id>?path=<relative-path>&depth=1` needs no Authorization header. Possession of the random ID is the read-only capability. It returns ls-like names, types, sizes, paths, and modification times; it does not download file bodies.

Do not send either workspace's control token to this public URL. Invalid, expired, evicted, and deleted IDs all return the same `404 share_not_found` behavior.

## Import

`POST <destination-workspace-url>/shares/<share_id>/import` uses the destination's matching control token:

```json
{
  "destination": "incoming/package.zip",
  "create_parents": true,
  "plan_id": 73,
  "taskname": "handoff",
  "message": "Import the shared package"
}
```

The destination must be a new path inside the destination workspace. Import never overwrites. The source credential is not needed.

## Delete early

`DELETE <source-workspace-url>/shares/<share_id>` requires the creator's control token and all three `OpenKapsel-*` Context headers. Creation ownership is tied to the stable token application identity, so the creator may still delete after credential rotation.

At the configured global count limit, creating a new share evicts the oldest. Expiry and eviction mean shares are transport conveniences, not durable storage.

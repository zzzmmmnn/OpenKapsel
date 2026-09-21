# OpenKapsel Remaining Implementation Plan

This file lists only work that is not yet implemented. Completed mapping, RPC-first file access, recycle, cross-root transfer, client task execution, proxy transport, lazy native mounts, Context integration, and current administration/discovery work are intentionally omitted.

## 1. Remaining platform validation

- Run native Windows mapping/client test coverage on real Windows, including junction/reparse denial, open-handle behavior, process termination, and source reload.
- Validate Linux client Bubblewrap execution if native Linux sandbox execution is to be supported in production.
- Validate client Podman execution on the intended Linux/macOS/Windows environments.
- Evaluate native macOS and Windows sandbox adapters only if container execution is insufficient.

## 2. Remaining transfer hardening

- Define retention and administrative cleanup for persisted cross-root transfer metadata.
- Strengthen concurrent-writer/source-mutation detection where filesystem identity signals permit it.
- Continue large-file throughput and interruption testing without full server-side staging.

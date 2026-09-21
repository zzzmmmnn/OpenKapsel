"""Immutable share snapshots and imports using the common RPC file backend."""

from __future__ import annotations

import errno
import logging
import os
import secrets
import stat

from .mapping_io import WorkspaceFiles, stream_stat, sync_stream
from .mapping_transport import CHUNK_SIZE
from .share_store import ShareError

LOG = logging.getLogger("openkapsel.mappings")


def fingerprint(details):
    return (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns,
            stat.S_IFMT(details.st_mode))


def copy_tree(files, source, destination, store, state, depth=0):
    from .file_support import FileOperationSupportMixin
    state["nodes"] = state.get("nodes", 0) + 1
    if state["nodes"] > store.max_query_nodes or depth >= store.max_depth:
        raise ShareError(413, "share_tree_limit", "shared tree exceeds configured limits")
    details = files.stat(source)
    before = fingerprint(details)
    if stat.S_ISDIR(details.st_mode):
        files.mkdir(destination)
        for name, _ in files.entries(source):
            store._validate_child_name(name)
            if FileOperationSupportMixin._is_internal_transfer_name(name):
                raise ShareError(403, "reserved_path", "temporary transfer files cannot be shared")
            copy_tree(files, source / name, destination / name, store, state, depth + 1)
        kind = "directory"
    elif stat.S_ISREG(details.st_mode):
        if state["bytes"] + details.st_size > store.max_bytes:
            raise ShareError(413, "share_too_large", "shared content exceeds the configured byte limit")
        with files.open(source) as incoming, files.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL) as outgoing:
            if fingerprint(stream_stat(incoming)) != before:
                raise ShareError(409, "share_source_changed", "source changed before snapshot")
            remaining = details.st_size
            while remaining:
                chunk = incoming.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ShareError(409, "share_source_changed", "source shortened during snapshot")
                outgoing.write(chunk)
                state["bytes"] += len(chunk)
                remaining -= len(chunk)
            sync_stream(outgoing)
            if incoming.read(1) or fingerprint(stream_stat(incoming)) != before:
                raise ShareError(409, "share_source_changed", "source changed during snapshot")
        state["files"] += 1
        kind = "file"
    else:
        raise ShareError(400, "unsupported_share_type", "only regular files and directories can be shared")
    if fingerprint(files.stat(source)) != before:
        raise ShareError(409, "share_source_changed", "source changed during snapshot")
    return kind


def create_share(handler, path):
    store = handler.server.shares
    files = WorkspaceFiles(handler.server.mappings, (handler.token_scope_root, store.root))
    return store.create(None, path.name, handler.token_record.app_id,
                        copier=lambda target, state: copy_tree(files, path, target, store, state))


def import_share(handler, share_id, destination, *, create_parents=False):
    store = handler.server.shares
    files = WorkspaceFiles(handler.server.mappings, (handler.token_scope_root, store.root))
    stage = destination.with_name(".openkapsel-share-" + secrets.token_hex(12))
    with store._lock:
        record = store._get_locked(share_id)
        if create_parents:
            files.mkdir(destination.parent, parents=True, exist_ok=True)
        if files.exists(destination):
            raise ShareError(409, "destination_exists", "shared imports do not overwrite")
        source = store.root / record.id / "payload" / record.name
        published = False
        try:
            copy_tree(files, source, stage, store, {"bytes": 0, "files": 0})
            files.rename(stage, destination, overwrite=False)
            published = True
            return record
        finally:
            if not published:
                try:
                    files.remove_tree(stage, max_nodes=store.max_query_nodes)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        LOG.info("Unpublished share import stage retained after transport failure")

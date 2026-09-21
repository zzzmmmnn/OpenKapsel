"""Binary publication on a provider without FUSE or replaying uncertain writes."""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import secrets
import stat
from contextlib import contextmanager

from openkapsel.errors import ApiError
from openkapsel.mapping.mapping_io import stream_stat, sync_stream
from openkapsel.mapping.mapping_transport import CHUNK_SIZE

LOG = logging.getLogger("openkapsel.mappings")


def prepare_destination(files, path, *, create_parents=False):
    if create_parents:
        files.mkdir(path.parent, parents=True, exist_ok=True)
    parent = files.stat(path.parent)
    if not stat.S_ISDIR(parent.st_mode):
        raise ApiError(400, "parent_not_found", "parent is not a directory")
    if files.exists(path):
        raise ApiError(409, "path_exists", "destination already exists")


@contextmanager
def new_file(files, path, *, create_parents=False, expected_size, expected_sha256=None):
    """Stage in the destination filesystem, verify and publish without overwrite.

    The same backend instance pins every RPC to one session. The destination is
    never removed on failure: a lost rename reply may already have published it.
    """
    prepare_destination(files, path, create_parents=create_parents)
    stage = path.with_name(f".{path.name}.openkapsel-put-{secrets.token_hex(12)}")
    published = False
    created = False
    try:
        with files.open(stage, os.O_RDWR | os.O_CREAT | os.O_EXCL) as output:
            created = True
            yield output
            sync_stream(output)
            if stream_stat(output).st_size != expected_size:
                raise ApiError(409, "upload_size_changed", "staged upload size differs from declared size")
            output.seek(0)
            digest = hashlib.sha256()
            remaining = expected_size
            while remaining:
                chunk = output.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ApiError(409, "upload_size_changed", "staged upload was shortened")
                digest.update(chunk)
                remaining -= len(chunk)
            if output.read(1):
                raise ApiError(409, "upload_size_changed", "staged upload grew during verification")
            if expected_sha256 is not None and not secrets.compare_digest(digest.hexdigest(), expected_sha256.lower()):
                raise ApiError(422, "checksum_mismatch", "staged upload does not match the expected SHA256")
        # Close before rename: native Windows descriptors deny delete sharing.
        files.rename(stage, path, overwrite=False)
        published = True
    finally:
        if created and not published:
            try:
                files.unlink(stage)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    LOG.info("Unpublished mapping upload stage retained after transport failure")


def put_stream(handler, path, length, expected_sha256, *, create_parents=False):
    files = handler._workspace_files()
    handler._check_if_match(None)  # A new-only upload has no existing ETag.
    digest = hashlib.sha256()
    try:
        with new_file(files, path, create_parents=create_parents,
                      expected_size=length, expected_sha256=expected_sha256) as output:
            remaining = length
            while remaining:
                chunk = handler.rfile.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ApiError(400, "incomplete_body", "request body ended before Content-Length")
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if expected_sha256 is not None and not secrets.compare_digest(digest.hexdigest(), expected_sha256.lower()):
                raise ApiError(422, "checksum_mismatch", "uploaded content does not match X-Content-SHA256")
        details = files.stat(path)
    except OSError as exc:
        handler._raise_file_io_error(exc)
    handler._send_json(201, {"path": str(path), "created": True, "bytes_written": length,
                            "sha256": digest.hexdigest(), "etag": handler._path_etag(path, details)})


def commit_upload(handler, upload_id, record, verified, actual_sha256, target):
    files = handler._workspace_files()
    try:
        with new_file(files, target, create_parents=record.create_parents,
                      expected_size=verified.expected_size, expected_sha256=actual_sha256) as output:
            handler.server.uploads.copy_to(upload_id, handler.token_record.token, output)
        details = files.stat(target)
        handler.server.uploads.finish(upload_id, handler.token_record.token)
    except OSError as exc:
        handler._raise_file_io_error(exc)
    handler._send_json(201, {"path": str(target), "created": True,
                            "bytes_written": verified.expected_size, "sha256": actual_sha256,
                            "etag": handler._path_etag(target, details)})

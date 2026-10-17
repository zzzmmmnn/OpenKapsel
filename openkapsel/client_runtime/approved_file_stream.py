"""Descriptor streams over private File functions; no Server scope inference."""
from __future__ import annotations

import errno
import io
import os
from dataclasses import replace
from pathlib import Path

from openkapsel.errors import ApiError
from openkapsel.mapping.mapping_io import RemoteFile, remote_stat
from openkapsel.mapping.mapping_transport import CHUNK_SIZE


class ApprovedRemoteFiles:
    def __init__(self, handler, row, auth, *, write):
        self.handler, self.row, self.auth, self.write = handler, row, auth, write
        with handler.server.mappings.lock:
            session = handler.server.mappings.sessions.get(row['id'])
            if session is None or session.closed:
                raise OSError(errno.EHOSTDOWN, 'Mapping is offline')
            self.generation = session.generation
        mount = handler.server.mappings.mount_path(row)
        self.prefixes = (str(mount).rstrip('/') + '/', row['name'].rstrip('/') + '/')
        self.roots = (str(mount), row['name'])
        self.rules = [{'path': self.relative(row, Path(p.path)), 'access': p.access}
                      for p in handler.token_record.allowed_paths]

    def relative(self, row, path):
        value = str(path).replace('\\', '/')
        if value in self.roots:
            return '.'
        for prefix in self.prefixes:
            if value.startswith(prefix):
                return value[len(prefix):]
        return value

    def call(self, row, operation, args):
        # Pin the provider generation. A disconnect is never retried on a new
        # transport, even for reads using an old descriptor identifier.
        return self.handler.server.mappings.call(row['id'], 'function', {
            'function': 'files.write' if self.write else 'files.read', 'method': 'execute',
            'internal': {'auth': self.auth}, 'args': {'operation': 'file_stream',
                'arguments': {'operation': operation, 'args': args, 'rules': self.rules}}},
            retry=False, generation=self.generation)

    def stat(self, path):
        return remote_stat(self.call(self.row, 'stat', {'path': self.relative(self.row, path)}))

    def exists(self, path):
        try:
            self.stat(path)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return False
            raise

    def open(self, path, flags=os.O_RDONLY):
        raw = RemoteFile(self, self.row, path, flags)
        if raw.readable() and raw.writable():
            return io.BufferedRandom(raw, CHUNK_SIZE)
        return io.BufferedReader(raw, CHUNK_SIZE) if raw.readable() else io.BufferedWriter(raw, CHUNK_SIZE)

    def mkdir(self, path, *, parents=False, exist_ok=False):
        if self.exists(path):
            if exist_ok:
                return
            raise OSError(errno.EEXIST, 'path exists')
        if parents and path.parent != path:
            self.mkdir(path.parent, parents=True, exist_ok=True)
        return self.call(self.row, 'mkdir', {'path': self.relative(self.row, path)})

    def rename(self, source, destination, *, overwrite=False):
        return self.call(self.row, 'rename', {'path': self.relative(self.row, source),
            'destination': self.relative(self.row, destination), 'overwrite': overwrite})

    def unlink(self, path):
        return self.call(self.row, 'unlink', {'path': self.relative(self.row, path)})


class ApprovedStreamRequest:
    """The existing HTTP stream engine uses Client-authorized descriptors."""
    def __init__(self, handler, files):
        self.handler, self.files = handler, files
        self.token_record = replace(handler.token_record, **({'can_write': True} if files.write else {'can_read': True}))

    def __getattr__(self, name):
        return getattr(self.handler, name)

    def _resolve_path(self, value, *, write=False):
        # Presentation only. All filesystem lookups and access decisions run
        # in the Client, including native Windows paths and symlink handling.
        return Path(str(value).replace('\\', '/'))

    def _workspace_files(self):
        return self.files

    def _open_binary(self, path):
        return self.files.open(path)


def execute_approved_stream(handler, row, operation, arguments, auth, *, query=False):
    from openkapsel.files.file_handlers import FileExecutionMixin
    files = ApprovedRemoteFiles(handler, row, auth, write=operation == 'fs_content_put')
    request = ApprovedStreamRequest(handler, files)
    try:
        if operation == 'fs_content':
            FileExecutionMixin._handle_fs_content(request, arguments, head_only=handler.command == 'HEAD')
        elif operation == 'fs_content_put':
            from openkapsel.mapping.mapping_uploads import put_stream
            if 'overwrite' in arguments:
                raise ApiError(400, 'overwrite_not_supported', 'uploads never overwrite')
            path = request._resolve_path(handler._required_query(arguments, 'path'), write=True)
            length = handler._content_length(min(handler.server.config.max_direct_upload_bytes, handler.server.config.max_file_bytes))
            digest = handler.headers.get('X-Content-SHA256')
            if digest is not None and not handler._valid_sha256(digest):
                raise ApiError(400, 'invalid_sha256', 'invalid SHA256')
            put_stream(request, path, length, digest, create_parents=handler._query_bool(arguments, 'create_parents', False))
        elif operation == 'fs_read_binary':
            handler._send_json(200, FileExecutionMixin._read_binary_chunk(request, arguments))
        else:
            raise ApiError(400, 'invalid_request', 'unsupported File stream')
    except OSError as exc:
        handler._raise_file_io_error(exc)
    return True

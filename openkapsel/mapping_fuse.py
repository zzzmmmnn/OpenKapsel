"""Unprivileged FUSE worker; all filesystem work is relayed to the provider."""

from __future__ import annotations

import argparse
import base64
import errno
import os
import socket
import stat
import time

from .mapping_transport import CHUNK_SIZE, encode, recv_line


class RemoteFilesystem:
    def __init__(self, socket_path, mapping_id):
        self.socket_path, self.mapping_id = socket_path, mapping_id
        self.handles = {}
        self.next_handle = 1
        self.uid, self.gid = os.getuid(), os.getgid()

    def rpc(self, op, **args):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            # The server enforces mapping_rpc_timeout_seconds (max 600s).
            # Keep the local broker socket slightly above that ceiling so it
            # never becomes the earlier timeout.
            sock.settimeout(605)
            sock.connect(self.socket_path)
            sock.sendall(encode({"mapping_id": self.mapping_id, "op": op, "args": args}) + b"\n")
            with sock.makefile("rb") as stream:
                response = recv_line(stream)
        if "error" in response:
            raise OSError(response["error"], "mapping operation failed")
        return response["result"]

    @staticmethod
    def relative(path):
        return path.lstrip("/") or "."

    def getattr(self, path, fh=None):
        if path == "/":
            # Keep the mountpoint visible even while offline. Contents never fall
            # back to the backing directory, and every real operation needs RPC.
            return dict(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_size=0,
                        st_uid=self.uid, st_gid=self.gid, st_mtime=0, st_ctime=0, st_atime=0)
        details = self.rpc("stat", path=self.relative(path))
        # Extra descriptor identity metadata is for direct RPC, not the native
        # mount's device identity or fusepy's portable stat structure.
        for key in ("st_dev", "st_atime_ns", "st_mtime_ns", "st_ctime_ns"):
            details.pop(key, None)
        details.update(st_uid=self.uid, st_gid=self.gid)
        return details

    def readdir(self, path, fh):
        yield "."
        yield ".."
        offset = 0
        while True:
            page = self.rpc("list", path=self.relative(path), offset=offset)
            yield from page["names"]
            offset += len(page["names"])
            if offset >= page["total"] or not page["names"]:
                break

    def open(self, path, flags):
        mode = {os.O_RDONLY: "r", os.O_WRONLY: "w", os.O_RDWR: "rw"}[flags & os.O_ACCMODE]
        remote = self.rpc("open", path=self.relative(path), mode=mode, truncate=bool(flags & os.O_TRUNC))
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = remote
        return handle

    def create(self, path, mode, fi=None):
        remote = self.rpc("create", path=self.relative(path), mode="rw")
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = remote
        return handle

    def read(self, path, size, offset, fh):
        return base64.b64decode(self.rpc("read", handle=self.handles[fh], size=min(size, CHUNK_SIZE), offset=offset), validate=True)

    def write(self, path, data, offset, fh):
        done = 0
        while done < len(data):
            chunk = data[done:done + CHUNK_SIZE]
            written = self.rpc("write", handle=self.handles[fh], data=base64.b64encode(chunk).decode(), offset=offset + done)
            if not isinstance(written, int) or written <= 0 or written > len(chunk):
                raise OSError(errno.EIO, "invalid client write result")
            done += written
        return done

    def release(self, path, fh):
        remote = self.handles.pop(fh)
        self.rpc("close", handle=remote)
        return 0

    def flush(self, path, fh):
        self.rpc("flush", handle=self.handles[fh])
        return 0

    def fsync(self, path, datasync, fh):
        return self.flush(path, fh)

    def mkdir(self, path, mode):
        self.rpc("mkdir", path=self.relative(path))
        return 0

    def rmdir(self, path):
        self.rpc("rmdir", path=self.relative(path))
        return 0

    def unlink(self, path):
        self.rpc("unlink", path=self.relative(path))
        return 0

    def rename(self, old, new):
        self.rpc("rename", path=self.relative(old), destination=self.relative(new))
        return 0

    def truncate(self, path, length, fh=None):
        if fh is not None:
            self.rpc("truncate_handle", handle=self.handles[fh], size=length)
        else:
            self.rpc("truncate", path=self.relative(path), size=length)
        return 0

    def chmod(self, path, mode):
        self.rpc("chmod", path=self.relative(path), mode=mode)
        return 0

    def utimens(self, path, times=None):
        self.rpc("utimens", path=self.relative(path), times=times)
        return 0

    def statfs(self, path):
        return self.rpc("statfs")


def main():
    from fuse import FUSE, Operations, FuseOSError
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--mount", required=True)
    args = parser.parse_args()

    class OperationsAdapter(RemoteFilesystem, Operations):
        def __call__(self, op, *args):
            try:
                return super().__call__(op, *args)
            except (OSError, KeyError, ValueError) as exc:
                raise FuseOSError(getattr(exc, "errno", None) or errno.EIO) from None

    FUSE(OperationsAdapter(args.socket, args.id), args.mount, foreground=True,
         nothreads=True, fsname="openkapsel-" + args.id, subtype="openkapsel",
         attr_timeout=0, entry_timeout=0, negative_timeout=0, direct_io=True,
         nodev=True, nosuid=True)


if __name__ == "__main__":
    main()

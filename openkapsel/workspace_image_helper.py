"""Root helper daemon for workspace ext4 image lifecycle operations."""

from __future__ import annotations

import argparse
import grp
import json
import logging
import os
import pwd
import signal
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any

from .workspace_images import MAX_RPC_BYTES, WorkspaceImageEngine, WorkspaceImageError, peer_uid


LOGGER = logging.getLogger("openkapsel.workspace_images")


class ImageRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: ImageUnixServer = self.server  # type: ignore[assignment]
        uid = peer_uid(self.request)
        if uid is None or uid not in {0, server.allowed_uid}:
            self._reply({"ok": False, "error": "workspace image helper access denied"})
            return
        raw = self.rfile.readline(MAX_RPC_BYTES + 1)
        if len(raw) > MAX_RPC_BYTES or not raw.endswith(b"\n"):
            self._reply({"ok": False, "error": "workspace image request is invalid or too large"})
            return
        try:
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise WorkspaceImageError("workspace image request must be an object")
            result = server.engine.dispatch(request)
            self._reply({"ok": True, **result})
        except (ValueError, TypeError, WorkspaceImageError) as exc:
            self._reply({"ok": False, "error": str(exc)})
        except Exception:
            LOGGER.exception("unexpected workspace image helper failure")
            self._reply({"ok": False, "error": "internal workspace image helper error"})

    def _reply(self, value: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")


class ImageUnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, engine: WorkspaceImageEngine, allowed_uid: int):
        self.engine = engine
        self.allowed_uid = allowed_uid
        super().__init__(path, ImageRequestHandler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenKapsel privileged ext4 image helper")
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--image-dir", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--service-user", default="openkapsel")
    parser.add_argument("--service-group", default="openkapsel")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    user = pwd.getpwnam(args.service_user)
    group = grp.getgrnam(args.service_group)
    socket_path = Path(args.socket)
    if not socket_path.is_absolute() or socket_path.name in {"", ".", ".."}:
        raise SystemExit("invalid Unix socket path")
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    engine = WorkspaceImageEngine(
        Path(args.workspace_root), Path(args.image_dir), user.pw_uid, group.gr_gid
    )
    engine.mount_all()
    server = ImageUnixServer(str(socket_path), engine, user.pw_uid)
    os.chown(socket_path, 0, group.gr_gid)
    os.chmod(socket_path, 0o660)

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()

"""Bridge a sandbox-local HTTP proxy port to a host-provided Unix socket."""

from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import threading


def _bridge(client: socket.socket, unix_path: str) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(unix_path)
        client.settimeout(300)
        upstream.settimeout(300)

        def pump(source: socket.socket, destination: socket.socket) -> None:
            try:
                while True:
                    chunk = source.recv(64 * 1024)
                    if not chunk:
                        break
                    destination.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        upload = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        upload.start()
        pump(upstream, client)
        upload.join(timeout=1)
    finally:
        upstream.close()
        client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.command or args.command[0] != "--":
        parser.error("a command must follow --")
    command = args.command[1:]
    if not command:
        parser.error("a command must follow --")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(64)
    listener.settimeout(0.5)
    stopping = threading.Event()

    def accept_loop() -> None:
        while not stopping.is_set():
            try:
                client, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_bridge,
                args=(client, args.socket),
                daemon=True,
            ).start()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    process = subprocess.Popen(command)

    def forward(signum: int, _frame: object) -> None:
        try:
            process.send_signal(signum)
        except ProcessLookupError:
            pass

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, forward)
    try:
        return process.wait()
    finally:
        stopping.set()
        listener.close()
        thread.join(timeout=1)


if __name__ == "__main__":
    sys.exit(main())

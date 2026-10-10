"""Isolated one-shot runner for a Mapping's asynchronous RPC plugin Job.

The manager owns this worker's child-process group and I/O pipes. Private plugin
settings arrive over an anonymous stdin pipe, never via argv or SQLite.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from openkapsel.errors import ApiError


class WorkerContext:
    """Small task interface used by built-in task-based RPC plugins."""

    def __init__(self):
        self._cancel = threading.Event()

    @property
    def cancelled(self):
        return self._cancel.is_set()

    def check_cancelled(self):
        if self.cancelled:
            raise OSError(errno.ECANCELED, "RPC task cancelled")

    def write(self, value):
        data = value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")
        if data:
            # stdout is owned by the Manager, which spools it on disk.
            os.write(sys.stdout.fileno(), data)

    def run_process(self, argv, *, cwd=None, env=None):
        self.check_cancelled()
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=False,
            creationflags=0, shell=False,
        )
        with proc.stdout:
            while chunk := proc.stdout.read1(8192):
                self.write(chunk)
                self.check_cancelled()
        return proc.wait()


def _execute(payload):
    config = payload["config"]
    export_root = payload["root"]
    protected = payload.get("protected_paths", ())
    operation = payload["rpc"]
    from openkapsel.rpc_plugins import load_client_rpc_registry
    from openkapsel.client_runtime.client_files import ClientFiles
    registry = load_client_rpc_registry(config)
    file_cls = ClientFiles
    if os.name == "nt":
        from openkapsel.client_runtime.client_windows import WindowsClientFiles
        file_cls = WindowsClientFiles
    files = file_cls(export_root, writable=config.get("writable", False),
                     rpc_registry=registry, rpc_capabilities=registry.capability_map(config),
                     protected_paths=protected)
    try:
        response = registry.dispatch_task(
            files, operation["family"], operation["operation"],
            operation.get("args", {}), WorkerContext(),
        )
        if not isinstance(response, dict) or type(response.get("status")) is not int:
            raise OSError(errno.EPROTO, "RPC task returned malformed response")
        if response["status"] == 200 and isinstance(response.get("body"), dict):
            return {"result": response["body"]}
        return {"error": response.get("error") or {
            "status": response["status"], "code": "rpc_task_failed",
            "message": "RPC plugin task failed",
        }}
    finally:
        files.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    ns = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("RPC payload too large")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("invalid RPC payload")
        result = _execute(payload)
    except ApiError as exc:
        result = {"error": {
            "status": exc.status, "code": exc.code, "message": exc.message,
            "details": exc.details,
        }}
    except OSError as exc:
        result = {"error": {
            "status": 409 if exc.errno == errno.ECANCELED else 500,
            "code": "rpc_task_cancelled" if exc.errno == errno.ECANCELED else "rpc_task_failed",
            "message": "RPC plugin task failed", "details": {"errno": exc.errno},
        }}
    except Exception:
        # Do not expose local credentials, config, paths or exception repr.
        result = {"error": {
            "status": 500, "code": "rpc_task_failed",
            "message": "RPC worker could not complete task",
        }}
    ns.result.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".result-", dir=ns.result.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        os.replace(name, ns.result)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return 0 if "result" in result else 1


if __name__ == "__main__":
    sys.exit(main())

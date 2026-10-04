"""Bounded concurrent RPC work, with replies and file handles scoped to a session."""

from __future__ import annotations

import errno
import logging
import socket
import threading

from openkapsel.mapping.mapping_transport import encode

LOG = logging.getLogger("openkapsel.client")


class ClientRpcSession:
    def __init__(self, runtime, sock, stopped):
        self.runtime = runtime
        self.sock = sock
        self.stopped = stopped
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.active = 0
        self.closed = False
        base = runtime.files
        self.files = type(base)(
            base.root, writable=base.writable, rpc_registry=base.rpc_registry,
            rpc_capabilities=base.rpc_capabilities, protected_paths=base.protected_paths,
        )
        # Keep local mutations/seek-based handle I/O serialized even across
        # reconnects. Each session has its own handle table, never reused by a
        # late worker from a disconnected session.
        self.local_lock = base.lock

    def _abort(self):
        self.stopped.set()
        raw = getattr(self.sock, "sock", None)
        if raw is not None:
            try:
                raw.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError):
                pass
        try:
            shutdown = getattr(self.sock, "shutdown", None)
            if callable(shutdown):
                shutdown()
            else:
                self.sock.close()
        except Exception:
            pass

    def _reply(self, response):
        with self.send_lock:
            if self.stopped.is_set():
                return
            try:
                self.sock.send(encode(response).decode())
            except Exception as exc:
                # Never send a late response through a newer transport, nor
                # include transport exceptions containing credentials in logs.
                LOG.info("Mapping RPC reply failed (%s)", type(exc).__name__)
                self._abort()

    def submit(self, request):
        if not self.runtime.rpc_slots.acquire(blocking=False):
            self._reply({"id": request["id"], "error": {
                "errno": errno.EBUSY, "message": "client RPC concurrency limit reached"}})
            return
        with self.lock:
            if self.closed or self.stopped.is_set():
                self.runtime.rpc_slots.release()
                return
            self.active += 1
        with self.runtime.rpc_lock:
            self.runtime.rpc_active += 1
        try:
            threading.Thread(target=self._run, args=(request,),
                             name="openkapsel-client-rpc", daemon=True).start()
        except Exception:
            self._finished()
            raise

    def _run(self, request):
        try:
            # A request waiting for the local file lock must not begin a
            # mutation after its session has been invalidated.
            op, args = request.get("op"), request.get("args")
            is_ssh = op == "rpc" and isinstance(args, dict) and args.get("family") == "ssh"
            if is_ssh or isinstance(op, str) and op.startswith("task_"):
                response = self._dispatch(request)
            else:
                with self.local_lock:
                    response = self._dispatch(request)
            if response is not None:
                self._reply(response)
        finally:
            self._finished()

    def _dispatch(self, request):
        if self.stopped.is_set():
            return None
        op, args = request.get("op"), request.get("args")
        try:
            if not isinstance(op, str) or not isinstance(args, dict):
                raise OSError(errno.EINVAL, "invalid operation")
            result = (self.runtime.tasks.dispatch(op, args) if op.startswith("task_")
                      else self.files.dispatch(op, args))
            response = {"id": request["id"], "result": result}
            encode(response)
            return response
        except Exception as exc:
            error = {"errno": getattr(exc, "errno", None) or errno.EINVAL}
            if isinstance(exc, OSError) and isinstance(exc.strerror, str):
                message = " ".join(exc.strerror.split())
                if message:
                    error["message"] = message[:200]
            return {"id": request["id"], "error": error}

    def _finished(self):
        with self.lock:
            self.active -= 1
            cleanup = self.closed
        try:
            if cleanup:
                self._cleanup_handles()
        finally:
            with self.runtime.rpc_lock:
                self.runtime.rpc_active -= 1
            self.runtime.rpc_slots.release()

    def close(self):
        self.stopped.set()
        with self.lock:
            self.closed = True
            cleanup = True
        # Running workers clean up their own old handle table when they finish;
        # reconnect does not join a worker blocked on remote I/O.
        if cleanup:
            self._cleanup_handles()

    def _cleanup_handles(self):
        # SSH workers never touch this table. If a local worker still owns the
        # lock, it retries cleanup on completion; shutdown never waits for it.
        if self.files.lock.acquire(blocking=False):
            try:
                self.files.close_handles()
            finally:
                self.files.lock.release()

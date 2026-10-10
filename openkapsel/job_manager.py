"""On-demand, per-OS-user shared Mapping job manager.

Client processes are stateless proxies. The manager owns child processes and
stdin/stdout pipes, and stores metadata in SQLite plus append-only disk output.
IPC uses authenticated multiprocessing.connection byte frames, never pickle.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import queue
import re
import secrets
import signal
import sqlite3
import string
import subprocess
import sys
import tempfile
import threading
import time
from multiprocessing.connection import Client, Listener
from pathlib import Path

MAPPING_RE = re.compile(r"[A-Za-z0-9_-]{24}\Z")
JOB_RE = re.compile(r"&[A-Za-z0-9]{4}&\Z")
CHARS = string.ascii_letters + string.digits
MAX_RUNNING = 16
MAX_PER_MAPPING = 4
DEFAULT_TIMEOUT = 600
MAX_OUTPUT = 64 * 1024 * 1024
PROTOCOL = 1
MAX_MESSAGE = 2 * 1024 * 1024


def new_job_id():
    return "&" + "".join(secrets.choice(CHARS) for _ in range(4)) + "&"


def state_home() -> Path:
    override = os.environ.get("OPENKAPSEL_JOB_MANAGER_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return (root / "OpenKapsel" / "job-manager").resolve()


def prepare_home(home):
    home = Path(home).expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        if home.stat().st_uid != os.getuid():
            raise PermissionError("job manager state directory has another owner")
        home.chmod(0o700)
    keyfile = home / "auth.key"
    try:
        fd = os.open(keyfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(32))
    if os.name != "nt" and (keyfile.stat().st_uid != os.getuid() or keyfile.stat().st_mode & 0o077):
        raise PermissionError("insecure job manager authentication key")
    # Another Client may observe the file between O_EXCL and its first write.
    # Retry that single first-start race without ever replacing an existing key.
    key = b""
    for _ in range(80):
        key = keyfile.read_bytes()
        if len(key) == 32:
            break
        time.sleep(.025)
    if len(key) != 32:
        raise ValueError("invalid job manager authentication key")
    return home, key


def endpoint(home):
    home = Path(home)
    suffix = hashlib.sha256(str(home).encode("utf-8")).hexdigest()[:20]
    if os.name == "nt":
        return rf"\\.\pipe\openkapsel-jobs-{suffix}", "AF_PIPE"
    # Keep AF_UNIX under the kernel's short address limit on macOS, and make
    # its parent private to avoid another user's socket spoofing.
    base = Path(tempfile.gettempdir()) / f"okjobs-{os.getuid()}-{suffix}"
    base.mkdir(mode=0o700, exist_ok=True)
    if base.stat().st_uid != os.getuid() or base.stat().st_mode & 0o077:
        raise PermissionError("insecure job manager runtime directory")
    return str(base / "manager.sock"), "AF_UNIX"


def wire_send(conn, message):
    encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MESSAGE:
        raise ValueError("job IPC response too large")
    conn.send_bytes(encoded)


def wire_recv(conn):
    raw = conn.recv_bytes(MAX_MESSAGE)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid job IPC message")
    return data


def singleton_lock(home):
    path = Path(home) / "manager.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                os.close(fd)
                return None
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                return None
    except BaseException:
        os.close(fd)
        raise
    return fd


class Manager:
    def __init__(self, home):
        self.home, self.key = prepare_home(home)
        self.address, self.family = endpoint(self.home)
        self.db = sqlite3.connect(self.home / "jobs.sqlite3", check_same_thread=False,
                                  timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS owners (
            mapping_id TEXT PRIMARY KEY, credential_hash TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, mapping_id TEXT NOT NULL, kind TEXT NOT NULL,
            started_at REAL NOT NULL, finished_at REAL, pid INTEGER,
            exit_code INTEGER, interrupted INTEGER NOT NULL DEFAULT 0,
            force_killed INTEGER NOT NULL DEFAULT 0,
            timed_out INTEGER NOT NULL DEFAULT 0, interactive INTEGER NOT NULL,
            stdin_closed INTEGER NOT NULL DEFAULT 0,
            output_base INTEGER NOT NULL DEFAULT 0,
            output_end INTEGER NOT NULL DEFAULT 0,
            truncated INTEGER NOT NULL DEFAULT 0,
            collected_at REAL, deadline REAL,
            container TEXT, input_base INTEGER NOT NULL DEFAULT 0,
            input_end INTEGER NOT NULL DEFAULT 0,
            rpc_family TEXT, rpc_operation TEXT, rpc_write INTEGER NOT NULL DEFAULT 0,
            request_digest TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS jobs_owner_start ON jobs(mapping_id, started_at DESC)")
        with self.db:
            # A manager restart cannot reattach anonymous pipes.
            self.db.execute("""UPDATE jobs SET finished_at=?, interrupted=1,
                exit_code=1 WHERE finished_at IS NULL""", (time.time(),))
        self.lock = threading.RLock()
        self.processes = {}
        self.writers = {}
        self.stopping = threading.Event()
        self.last_access = time.monotonic()

    def _authorize(self, request):
        mapping = request.get("mapping_id")
        credential = request.get("credential")
        if not isinstance(mapping, str) or not MAPPING_RE.fullmatch(mapping):
            raise PermissionError("invalid mapping identity")
        if not isinstance(credential, str) or len(credential) < 16:
            raise PermissionError("missing mapping credential")
        digest = hashlib.sha256(credential.encode()).hexdigest()
        previous = self.db.execute(
            "SELECT credential_hash FROM owners WHERE mapping_id=?", (mapping,)
        ).fetchone()
        if previous is None:
            with self.db:
                self.db.execute("INSERT OR IGNORE INTO owners VALUES (?,?)",
                                (mapping, digest))
            previous = self.db.execute(
                "SELECT credential_hash FROM owners WHERE mapping_id=?", (mapping,)
            ).fetchone()
        if not secrets.compare_digest(previous[0], digest):
            raise PermissionError("mapping credential does not match registered owner")
        return mapping

    def _row(self, mid, tid):
        if not isinstance(tid, str) or not JOB_RE.fullmatch(tid):
            raise FileNotFoundError("invalid job id")
        row = self.db.execute(
            "SELECT id, mapping_id, kind, started_at, finished_at, pid, exit_code,"
            " interrupted, force_killed, timed_out, interactive, stdin_closed,"
            " output_base, output_end, truncated, collected_at, deadline, container,"
            " rpc_family, rpc_operation, rpc_write"
            " FROM jobs WHERE id=? AND mapping_id=?", (tid, mid)
        ).fetchone()
        if row is None:
            raise FileNotFoundError("job not found")
        return dict(zip(("id", "mapping_id", "kind", "started_at", "finished_at",
                         "pid", "exit_code", "interrupted", "force_killed",
                         "timed_out", "interactive", "stdin_closed", "output_base",
                         "output_end", "truncated", "collected_at", "deadline",
                         "container", "rpc_family", "rpc_operation", "rpc_write"), row))

    def _summary(self, job):
        result = {
            "task_id": job["id"], "kind": job["kind"], "location": "client",
            "started_at": job["started_at"], "finished_at": job["finished_at"],
            "exit_code": job["exit_code"], "interactive": bool(job["interactive"]),
            "stdin_open": not job["stdin_closed"] and job["finished_at"] is None,
            "interrupted": bool(job["interrupted"]), "force_killed": bool(job["force_killed"]),
            "timed_out": bool(job["timed_out"]),
            "running": job["finished_at"] is None,
            "output_truncated": bool(job["truncated"]),
        }
        if job["kind"] == "rpc":
            result.update(
                rpc_family=job["rpc_family"], rpc_operation=job["rpc_operation"],
                write=bool(job["rpc_write"]), execution="task",
            )
            if job["finished_at"] is not None:
                path = self.home / "results" / (job["id"] + ".json")
                try:
                    details = json.loads(path.read_text("utf-8"))
                except (OSError, ValueError):
                    details = {"error": {"status": 500, "code": "rpc_task_interrupted",
                                         "message": "RPC worker did not produce a result"}}
                if "result" in details:
                    result["result_available"] = True
                    result["result"] = details["result"]
                else:
                    result["error"] = details.get("error", {
                        "status": 500, "code": "rpc_task_failed",
                        "message": "RPC worker failed",
                    })
        return result

    def _prune(self, mid):
        # Once output is consumed, completed jobs may be discarded to reclaim
        # space; retain the newest four, and never remove a running job.
        rows = self.db.execute(
            "SELECT id, collected_at FROM jobs WHERE mapping_id=? AND finished_at IS NOT NULL "
            "ORDER BY finished_at DESC", (mid,)
        ).fetchall()
        for index, (tid, collected) in enumerate(rows):
            if collected is not None and (index >= 4 or time.time()-collected > 3600):
                self.db.execute("DELETE FROM jobs WHERE id=?", (tid,))
                (self.home / "output" / (tid + ".bin")).unlink(missing_ok=True)
                (self.home / "input" / (tid + ".bin")).unlink(missing_ok=True)
                (self.home / "results" / (tid + ".json")).unlink(missing_ok=True)
        self.db.commit()

    def _append(self, tid, data):
        if not data:
            return
        path = self.home / "output" / (tid + ".bin")
        with self.lock:
            row = self.db.execute(
                "SELECT output_base, output_end, truncated FROM jobs WHERE id=?",
                (tid,)
            ).fetchone()
            if row is None:
                return
            base, end, truncated = row
            with path.open("ab") as handle:
                handle.write(data)
            end += len(data)
            if end - base > MAX_OUTPUT:
                # Physical spool stays bounded, and output offsets never rewind.
                discard = end - base - MAX_OUTPUT
                with path.open("rb") as handle:
                    handle.seek(discard)
                    tail = handle.read()
                temporary = path.with_suffix(".tmp")
                temporary.write_bytes(tail)
                temporary.replace(path)
                base += discard
                truncated = 1
            self.db.execute("UPDATE jobs SET output_base=?, output_end=?, truncated=? "
                            "WHERE id=?", (base, end, truncated, tid))
            self.db.commit()

    def _collect(self, tid, process, timeout):
        def read_output():
            try:
                with process.stdout:
                    while data := process.stdout.read1(8192):
                        self._append(tid, data)
            except OSError:
                pass
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            try:
                exit_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                with self.lock:
                    self.db.execute("UPDATE jobs SET timed_out=1 WHERE id=?", (tid,))
                    self.db.commit()
                self._signal(tid, force=True)
                exit_code = process.wait()
            reader.join()
            with self.lock:
                self.db.execute(
                    "UPDATE jobs SET exit_code=?, finished_at=? WHERE id=?",
                    (exit_code, time.time(), tid)
                )
                self.db.commit()
        finally:
            with self.lock:
                self.processes.pop(tid, None)
                writer = self.writers.pop(tid, None)
                if writer is not None:
                    try:
                        writer.put_nowait(None)
                    except queue.Full:
                        pass

    def _input_worker(self, tid, process, inputs):
        try:
            while True:
                next_item = inputs.get()
                if next_item is None:
                    return
                start, count, eof = next_item
                with self.lock:
                    row = self.db.execute(
                        "SELECT input_base FROM jobs WHERE id=?", (tid,)
                    ).fetchone()
                    if row is None:
                        return
                    with (self.home / "input" / (tid + ".bin")).open("rb") as handle:
                        handle.seek(start - row[0])
                        data = handle.read(count)
                if len(data) != count:
                    raise OSError("incomplete disk-spooled stdin")
                if data:
                    process.stdin.write(data)
                    process.stdin.flush()
                with self.lock:
                    path = self.home / "input" / (tid + ".bin")
                    with path.open("rb") as handle:
                        handle.seek(start - row[0] + count)
                        unread = handle.read()
                    temporary = path.with_suffix(".tmp")
                    temporary.write_bytes(unread)
                    temporary.replace(path)
                    self.db.execute("UPDATE jobs SET input_base=? WHERE id=?",
                                    (start + count, tid))
                    self.db.commit()
                if eof:
                    process.stdin.close()
                    return
        except (OSError, ValueError, BrokenPipeError):
            pass

    @staticmethod
    def _feed_worker(process, payload):
        try:
            with process.stdin:
                process.stdin.write(payload)
                process.stdin.flush()
        except (OSError, ValueError, BrokenPipeError):
            pass

    def _start(self, mid, args):
        tid = args.get("task_id")
        if not isinstance(tid, str) or not JOB_RE.fullmatch(tid):
            raise ValueError("job ID must be & followed by 4 alphanumeric chars and &")
        request_digest = hashlib.sha256(json.dumps(
            args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest()
        # Windows and default macOS filesystems are case-insensitive even
        # though job IDs are case-sensitive. Never allow two live/spooled IDs
        # with distinct spelling but the same disk filename.
        collision = self.db.execute(
            "SELECT id FROM jobs WHERE id=? COLLATE NOCASE", (tid,)
        ).fetchone()
        if collision is not None and collision[0] != tid:
            raise FileExistsError("job ID differs only by letter case")
        previous = self.db.execute(
            "SELECT mapping_id, request_digest FROM jobs WHERE id=?", (tid,)
        ).fetchone()
        if previous is not None:
            if previous[0] != mid or previous[1] != request_digest:
                raise FileExistsError("job ID already belongs to a different request")
            return self._summary(self._row(mid, tid))
        if self.db.execute("SELECT COUNT(*) FROM jobs WHERE finished_at IS NULL").fetchone()[0] >= MAX_RUNNING:
            raise BlockingIOError("Job Manager is at its global limit of 16")
        if self.db.execute("SELECT COUNT(*) FROM jobs WHERE finished_at IS NULL AND mapping_id=?",
                           (mid,)).fetchone()[0] >= MAX_PER_MAPPING:
            raise BlockingIOError("mapping has reached its limit of 4 jobs")
        kind = args.get("kind", "shell")
        if kind not in {"shell", "rpc"}:
            raise ValueError("unsupported Job kind")
        argv = args.get("argv")
        cwd = args.get("cwd")
        rpc_payload = None
        if kind == "rpc":
            operation = args.get("rpc_payload")
            if (not isinstance(operation, dict) or
                    not isinstance(operation.get("rpc"), dict) or
                    not isinstance(operation.get("config"), dict)):
                raise ValueError("invalid RPC worker configuration")
            rpc_payload = json.dumps(operation, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")
            if len(rpc_payload) > MAX_MESSAGE:
                raise ValueError("RPC worker request too large")
            (self.home / "results").mkdir(mode=0o700, exist_ok=True)
            executable = args.get("worker_python")
            if not isinstance(executable, str) or not Path(executable).is_file():
                raise ValueError("invalid RPC worker interpreter")
            argv = [executable, "-m", "openkapsel.job_worker", "--result",
                    str(self.home / "results" / (tid + ".json"))]
        valid_argv = (
            isinstance(argv, list) and 1 <= len(argv) <= 512 and
            all(isinstance(x, str) and "\x00" not in x for x in argv) and
            sum(map(len, argv)) <= 100000
        ) or (
            os.name == "nt" and isinstance(argv, str) and
            "\x00" not in argv and len(argv) <= 100000
        )
        if not valid_argv or not isinstance(cwd, str) or not Path(cwd).is_dir():
            raise ValueError("invalid job process arguments")
        timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
        if type(timeout) not in (float, int) or not 0.1 <= timeout < float("inf"):
            raise ValueError("invalid job timeout")
        interactive = args.get("interactive", False)
        if type(interactive) is not bool:
            raise ValueError("invalid interactive flag")
        environment = args.get("env")
        if environment is not None and (
            not isinstance(environment, dict)
            or not all(isinstance(k,str) and isinstance(v,str) for k,v in environment.items())
        ):
            raise ValueError("invalid process environment")
        executable = args.get("executable")
        if executable is not None and not isinstance(executable, str):
            raise ValueError("invalid executable")
        name = args.get("container")
        # Only the manager owns subprocess handles, even if the client exits.
        process = subprocess.Popen(
            argv, cwd=cwd, env=environment, executable=executable, shell=False,
            stdin=subprocess.PIPE if (interactive or kind == "rpc") else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
            close_fds=True,
        )
        started = time.time()
        rpc = args["rpc_payload"]["rpc"] if kind == "rpc" else {}
        self.db.execute(
            "INSERT INTO jobs(id,mapping_id,kind,started_at,pid,interactive,stdin_closed,"
            "deadline,container,rpc_family,rpc_operation,rpc_write,request_digest)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, mid, kind, started, process.pid, int(interactive),
             int(not interactive), started+timeout, name,
             rpc.get("family"), rpc.get("operation"), int(bool(args.get("rpc_write"))),
             request_digest)
        )
        self.db.commit()
        (self.home / "output").mkdir(mode=0o700, exist_ok=True)
        (self.home / "output" / (tid + ".bin")).touch(exist_ok=True)
        (self.home / "input").mkdir(mode=0o700, exist_ok=True)
        (self.home / "input" / (tid + ".bin")).touch(exist_ok=True)
        self.processes[tid] = process
        if rpc_payload is not None:
            threading.Thread(target=self._feed_worker, args=(process, rpc_payload),
                             daemon=True).start()
        if interactive:
            inputs = queue.Queue(maxsize=16)
            self.writers[tid] = inputs
            threading.Thread(target=self._input_worker,
                             args=(tid, process, inputs), daemon=True).start()
        threading.Thread(target=self._collect, args=(tid, process, timeout), daemon=True).start()
        return self._summary(self._row(mid, tid))

    def _signal(self, tid, force):
        process = self.processes.get(tid)
        if process is None or process.poll() is not None:
            return
        self.db.execute("UPDATE jobs SET force_killed=?, interrupted=? WHERE id=?",
                        (int(force), int(not force), tid))
        self.db.commit()
        try:
            container = self.db.execute(
                "SELECT container FROM jobs WHERE id=?", (tid,)
            ).fetchone()
            if container and container[0]:
                try:
                    subprocess.run(
                        ["podman", "kill", "--signal", "KILL" if force else "INT",
                         container[0]],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=8,
                    )
                except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                    pass
            if os.name == "nt":
                if force:
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
                else:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGKILL if force else signal.SIGINT)
        except (ProcessLookupError, OSError):
            pass

    def _read(self, job, offset):
        if type(offset) is not int or offset < 0:
            raise ValueError("invalid output offset")
        tid = job["id"]
        base, end = job["output_base"], job["output_end"]
        actual = max(base, min(offset, end))
        with (self.home / "output" / (tid + ".bin")).open("rb") as handle:
            handle.seek(actual - base)
            data = handle.read(65536)
        # A request at an advanced offset confirms that preceding output was
        # successfully received. Reclaim the consumed prefix on disk.
        if offset > base:
            with (self.home / "output" / (tid + ".bin")).open("rb") as handle:
                handle.seek(actual - base)
                remaining = handle.read()
            temp = self.home / "output" / (tid + ".tmp")
            temp.write_bytes(remaining)
            temp.replace(self.home / "output" / (tid + ".bin"))
            self.db.execute("UPDATE jobs SET output_base=? WHERE id=?", (actual, tid))
            self.db.commit()
        if job["finished_at"] is not None and actual + len(data) == end:
            self.db.execute("UPDATE jobs SET collected_at=? WHERE id=?", (time.time(), tid))
            self.db.commit()
        return {"output": base64.b64encode(data).decode(),
                "output_size": end, "next_offset": actual + len(data),
                "output_base": actual if offset > base else base,
                "gap": offset < base}

    def request(self, req):
        op = req.get("op")
        if op in {"ping", "shutdown"}:
            if op == "ping":
                return {"version": PROTOCOL, "pid": os.getpid()}
            if req.get("auth") != self.key.hex():
                raise PermissionError("manager shutdown requires local administrative key")
            self.stopping.set()
            return {"stopping": True}
        mid = self._authorize(req)
        args = req.get("args", {})
        if not isinstance(args, dict):
            raise ValueError("invalid job arguments")
        with self.lock:
            self.last_access = time.monotonic()
            self._prune(mid)
            if op == "task_list":
                ids = self.db.execute(
                    "SELECT id FROM jobs WHERE mapping_id=? ORDER BY started_at DESC",
                    (mid,)
                ).fetchall()
                return [self._summary(self._row(mid, tid)) for (tid,) in ids]
            if op == "task_start":
                return self._start(mid, args)
            job = self._row(mid, args.get("task_id"))
            if op == "task_get":
                return dict(self._summary(job), **self._read(job, args.get("offset", 0)))
            if op in {"task_interrupt", "task_kill"}:
                self._signal(job["id"], force=op == "task_kill")
                return self._summary(self._row(mid, job["id"]))
            if op == "task_stdin":
                if job["kind"] != "shell" or job["finished_at"] is not None or job["stdin_closed"]:
                    raise BrokenPipeError("job stdin closed")
                data = base64.b64decode(args.get("data", ""), validate=True)
                if len(data) > 16384:
                    raise ValueError("stdin chunk too large")
                eof = args.get("eof", False)
                if type(eof) is not bool:
                    raise ValueError("invalid EOF")
                input_queue = self.writers.get(job["id"])
                if input_queue is None:
                    raise BrokenPipeError("job stdin unavailable")
                if input_queue.full():
                    raise BlockingIOError("stdin disk queue is full")
                row = self.db.execute(
                    "SELECT input_end FROM jobs WHERE id=?", (job["id"],)
                ).fetchone()
                end = row[0]
                with (self.home / "input" / (job["id"] + ".bin")).open("ab") as spool:
                    spool.write(data)
                self.db.execute(
                    "UPDATE jobs SET input_end=?, stdin_closed=? WHERE id=?",
                    (end + len(data), int(eof), job["id"])
                )
                self.db.commit()
                input_queue.put_nowait((end, len(data), eof))
                return {"accepted": len(data)}
        raise ValueError("unsupported manager request")

    def _connection(self, conn):
        try:
            req = wire_recv(conn)
            try:
                result = self.request(req)
                wire_send(conn, {"result": result})
            except (PermissionError, FileNotFoundError, ValueError,
                    FileExistsError, BlockingIOError, BrokenPipeError, OSError) as exc:
                wire_send(conn, {"error": {"errno": getattr(exc, "errno", None),
                                          "message": str(exc)[:200]}})
        except (EOFError, OSError, ValueError):
            pass
        finally:
            conn.close()

    def serve(self):
        if self.family == "AF_UNIX":
            Path(self.address).unlink(missing_ok=True)
        listener = Listener(self.address, family=self.family, authkey=self.key)
        if self.family == "AF_UNIX":
            os.chmod(self.address, 0o600)
        try:
            while not self.stopping.is_set():
                # Listener accepts one authenticated connection at a time, then
                # dispatches fast RPCs concurrently. A wake-up is needed to quit.
                try:
                    conn = listener.accept()
                except (OSError, EOFError):
                    if self.stopping.is_set():
                        break
                    continue
                threading.Thread(target=self._connection, args=(conn,), daemon=True).start()
        finally:
            listener.close()
            with self.lock:
                for tid in list(self.processes):
                    self._signal(tid, force=True)
            self.db.close()
            if self.family == "AF_UNIX":
                Path(self.address).unlink(missing_ok=True)


def connect_once(home, request):
    home, key = prepare_home(home)
    address, family = endpoint(home)
    conn = Client(address, family=family, authkey=key)
    try:
        wire_send(conn, request)
        response = wire_recv(conn)
        if "error" in response:
            err = response["error"]
            import errno
            raise OSError(err.get("errno") or errno.EINVAL, err.get("message", "job operation failed"))
        return response["result"]
    finally:
        conn.close()


def ensure_running(home):
    home, key = prepare_home(home)
    try:
        return connect_once(home, {"op": "ping"})
    except (OSError, EOFError, ConnectionError):
        pass
    log = open(home / "manager.log", "ab", buffering=0)
    try:
        daemon_process = subprocess.Popen(
            [sys.executable, "-m", "openkapsel.job_manager", "--state", str(home)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            close_fds=True, start_new_session=os.name != "nt",
            creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                           if os.name == "nt" else 0),
        )
        # Reap the detached daemon on its eventual exit without blocking
        # ClientRuntime or triggering Popen ResourceWarning at garbage collection.
        threading.Thread(target=daemon_process.wait, daemon=True).start()
    finally:
        log.close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            return connect_once(home, {"op": "ping"})
        except (OSError, EOFError, ConnectionError):
            time.sleep(.05)
    raise ConnectionError("shared Job Manager did not start")


def request(home, mapping_id, credential, op, args=None):
    if not MAPPING_RE.fullmatch(mapping_id):
        raise ValueError("mapping URL must end with a 24-character mapping ID")
    ensure_running(home)
    return connect_once(home, {"mapping_id": mapping_id,
                               "credential": credential, "op": op,
                               "args": args or {}})


def shutdown(home):
    home, key = prepare_home(home)
    result = connect_once(home, {"op": "shutdown", "auth": key.hex()})
    # Wake the single accept loop so it can notice the stop event.
    try:
        connect_once(home, {"op": "ping"})
    except (OSError, EOFError, ConnectionError):
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description="OpenKapsel shared local Job Manager")
    parser.add_argument("--state", type=Path, default=state_home())
    parser.add_argument("--stop", action="store_true", help="kill managed jobs and stop manager")
    ns = parser.parse_args()
    if ns.stop:
        shutdown(ns.state)
        return
    home, _ = prepare_home(ns.state)
    locked = singleton_lock(home)
    if locked is None:
        return
    try:
        Manager(home).serve()
    finally:
        os.close(locked)


if __name__ == "__main__":
    main()

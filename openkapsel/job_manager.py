"""On-demand, per-OS-user shared Mapping job manager.

Client processes are stateless proxies. The manager owns child processes and
stdin/stdout pipes, and stores metadata in SQLite plus append-only disk output.
IPC uses authenticated multiprocessing.connection byte frames, never pickle.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.metadata
from functools import lru_cache
import json
import os
import queue
import re
import shlex
import secrets
import signal
import stat
import sqlite3
import string
import subprocess
import sys
import tempfile
import threading
import time
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Listener
from pathlib import Path

MAPPING_RE = re.compile(r"[A-Za-z0-9_-]{24}\Z")
JOB_RE = re.compile(r"&[A-Za-z0-9]{4}&\Z")
CHARS = string.ascii_letters + string.digits
MAX_RUNNING = 16
MAX_PER_MAPPING = 4
DEFAULT_TIMEOUT = 120
MAX_OUTPUT = 64 * 1024 * 1024
PROTOCOL = 2
AUTH_MAGIC = b"OKJ2"
IDLE_SECONDS = 10 * 60
IDLE_POLL_SECONDS = 5.0
MAX_MESSAGE = 2 * 1024 * 1024
# Serialize cold starts in one Client process. The daemon's file lock still
# enforces the singleton across separate Client processes.
_START_LOCK = threading.Lock()



@lru_cache(maxsize=1)
def manager_identity():
    """Identify imported code, even if an upgrade overwrites files in place.

    Cached at first handshake: never claim new on-disk code is already
    running in an older Python process.
    """
    files = (Path(__file__), Path(__file__).with_name("job_sandbox.py"),
             Path(__file__).parent / "client_runtime" / "job_sandbox_config.py")
    digest = hashlib.sha256()
    for path in files:
        if path.is_file():
            digest.update(path.read_bytes())
    digest.update(os.path.realpath(sys.executable).encode())
    digest.update(str(Path(sys.prefix).resolve()).encode())
    digest.update(str(sys.version_info[:3]).encode())
    # The Client may dynamically load its source from a checkout while the
    # venv contains an older installed dist-info. Use the imported code's
    # package version, never stale pip metadata, for upgrade ordering.
    from openkapsel import __version__ as version
    try:
        dist = importlib.metadata.distribution("openkapsel")
        # Installation time orders builds when a version number is unchanged.
        installed = dist._path.stat().st_mtime_ns
    except (importlib.metadata.PackageNotFoundError, OSError, AttributeError):
        installed = 0
    newest_code = max((p.stat().st_mtime_ns for p in files if p.exists()), default=0)
    return {"version": version, "runtime_id": digest.hexdigest(),
            "installed_at": max(installed, newest_code)}


def _recv_auth(conn, size, timeout=5.0):
    if not conn.poll(timeout):
        raise AuthenticationError("Job Manager IPC authentication timed out")
    return conn.recv_bytes(size)


def _server_auth(conn, key):
    """Stable HMAC-SHA256 mutual authentication independent of Python versions."""
    challenge = secrets.token_bytes(32)
    conn.send_bytes(AUTH_MAGIC + b"S" + challenge)
    reply = _recv_auth(conn, 4 + 1 + 32 + 32)
    if len(reply) != 69 or not reply.startswith(AUTH_MAGIC + b"C"):
        raise AuthenticationError("invalid Client IPC challenge reply")
    client_nonce = reply[5:37]
    mac = reply[37:]
    expected = hmac.digest(key, b"client" + challenge + client_nonce, "sha256")
    if not hmac.compare_digest(mac, expected):
        raise AuthenticationError("Client Job Manager IPC authentication failed")
    conn.send_bytes(AUTH_MAGIC + b"A" +
                    hmac.digest(key, b"manager" + challenge + client_nonce, "sha256"))


def _client_auth(conn, key):
    challenge = _recv_auth(conn, 4 + 1 + 32)
    if len(challenge) != 37 or not challenge.startswith(AUTH_MAGIC + b"S"):
        raise AuthenticationError("incompatible Job Manager IPC authentication protocol")
    nonce = secrets.token_bytes(32)
    conn.send_bytes(AUTH_MAGIC + b"C" + nonce +
                    hmac.digest(key, b"client" + challenge[5:] + nonce, "sha256"))
    answer = _recv_auth(conn, 4 + 1 + 32)
    expected = AUTH_MAGIC + b"A" + hmac.digest(
        key, b"manager" + challenge[5:] + nonce, "sha256")
    if not hmac.compare_digest(answer, expected):
        raise AuthenticationError("Job Manager IPC server authentication failed")


def _version_parts(value):
    import re
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[+.-].*)?", value)
    return tuple(map(int, match.groups())) if match else (0, 0, 0)


def new_job_id():
    return "&" + "".join(secrets.choice(CHARS) for _ in range(4)) + "&"


def state_home() -> Path:
    override = os.environ.get("OPENKAPSEL_JOB_MANAGER_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        root = Path(local_appdata) if local_appdata else Path.home() / "AppData" / "Local"
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
    # Drop the former IPC authentication secret if an old local state exists.
    (home / "auth.key").unlink(missing_ok=True)
    return home


def ipc_authkey(home) -> bytes:
    """Private per-Manager IPC credential, atomically published in state home.

    A sandboxed child can share our UID, so AF_UNIX filesystem permissions
    alone are NOT sufficient authentication. The key stays outside mounted
    workspaces and is additionally denied by the native Seatbelt policy.
    """
    home = Path(home)
    path = home / "ipc.key"
    if not path.exists() and not path.is_symlink():
        fd, temporary = tempfile.mkstemp(prefix=".ipc-", dir=home)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            # Linking a fully written file publishes the key atomically.
            # Racing Clients must never replace an existing Manager secret.
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            Path(temporary).unlink(missing_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        status = os.fstat(stream.fileno())
        if not stat.S_ISREG(status.st_mode) or (
            os.name != "nt" and status.st_mode & 0o077
        ):
            raise PermissionError("insecure Job Manager IPC credential")
        if os.name != "nt" and status.st_uid != os.getuid():
            raise PermissionError("Job Manager IPC credential has another owner")
        key = stream.read(33)
    if len(key) != 32:
        raise PermissionError("invalid Job Manager IPC credential")
    return key


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
        self.home = prepare_home(home)
        self.ipc_key = ipc_authkey(self.home)
        # Snapshot the running code BEFORE an installer can replace the
        # corresponding files; do not calculate the identity on first ping.
        self.identity = manager_identity()
        self.address, self.family = endpoint(self.home)
        self.db = sqlite3.connect(self.home / "jobs.sqlite3", check_same_thread=False,
                                  timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
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
            request_digest TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS jobs_owner_start ON jobs(mapping_id, started_at DESC)")
        with self.db:
            # Remove obsolete per-Mapping credential records during upgrades.
            self.db.execute("DROP TABLE IF EXISTS owners")
            # A manager restart cannot reattach anonymous pipes.
            self.db.execute("""UPDATE jobs SET finished_at=?, interrupted=1,
                exit_code=1 WHERE finished_at IS NULL""", (time.time(),))
        self.lock = threading.RLock()
        self.processes = {}
        self.writers = {}
        self.collectors = {}
        self.sandboxes = {}
        self.stopping = threading.Event()
        self.last_access = time.monotonic()
        self.idle_exit = threading.Event()
        # A peer can open a Windows named pipe or AF_UNIX socket and stall
        # before finishing authentication. Bound these handshakes without
        # allowing one incomplete peer to block every subsequent request.
        self.ipc_slots = threading.BoundedSemaphore(64)
        # Linux --die-with-parent (PR_SET_PDEATHSIG) watches the *creating
        # thread*, not merely the Manager process. IPC handlers are short-lived;
        # starting Bubblewrap inside one kills the job when that handler exits.
        # Keep one launcher thread alive for the entire Manager lifetime. Only
        # process creation is serialized; jobs still execute concurrently.
        self.launch_queue = queue.Queue()
        self.launcher = threading.Thread(
            target=self._launch_loop, name="openkapsel-job-launcher", daemon=True,
        )
        self.launcher.start()

    def _launch_loop(self):
        while True:
            item = self.launch_queue.get()
            if item is None:
                return
            argv, options, response = item
            try:
                outcome = subprocess.Popen(argv, **options)
            except BaseException as exc:
                outcome = exc
            response.put(outcome)

    def _spawn(self, argv, **options):
        response = queue.Queue(maxsize=1)
        self.launch_queue.put((argv, options, response))
        outcome = response.get()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    @staticmethod
    def _mapping_key(request):
        mapping = request.get("mapping_id")
        if not isinstance(mapping, str) or not MAPPING_RE.fullmatch(mapping):
            raise ValueError("invalid mapping key")
        # The mapping key is a partition selector, not a credential.
        return mapping

    @staticmethod
    def _key(mid, tid):
        if not isinstance(tid, str) or not JOB_RE.fullmatch(tid):
            raise FileNotFoundError("invalid job id")
        # Public 4-character IDs are private to a Mapping; this scoped,
        # stable internal key also segregates on-disk I/O across owners.
        return mid + "." + tid

    def _row(self, mid, tid):
        key = self._key(mid, tid)
        row = self.db.execute(
            "SELECT id, mapping_id, kind, started_at, finished_at, pid, exit_code,"
            " interrupted, force_killed, timed_out, interactive, stdin_closed,"
            " output_base, output_end, truncated, collected_at, deadline, container"
            " FROM jobs WHERE id=? AND mapping_id=? AND kind='shell'", (key, mid)
        ).fetchone()
        if row is None:
            raise FileNotFoundError("job not found")
        return dict(zip(("id", "mapping_id", "kind", "started_at", "finished_at",
                         "pid", "exit_code", "interrupted", "force_killed",
                         "timed_out", "interactive", "stdin_closed", "output_base",
                         "output_end", "truncated", "collected_at", "deadline",
                         "container"), row))

    def _summary(self, job):
        result = {
            "task_id": job["id"].rsplit(".", 1)[-1], "kind": job["kind"], "location": "client",
            "started_at": job["started_at"], "finished_at": job["finished_at"],
            "exit_code": job["exit_code"], "interactive": bool(job["interactive"]),
            "stdin_open": not job["stdin_closed"] and job["finished_at"] is None,
            "interrupted": bool(job["interrupted"]), "force_killed": bool(job["force_killed"]),
            "timed_out": bool(job["timed_out"]),
            "running": job["finished_at"] is None,
            "output_truncated": bool(job["truncated"]),
        }
        return result

    def _prune(self, mid):
        # Once output is consumed, completed jobs may be discarded to reclaim
        # space; retain the newest four, and never remove a running job.
        rows = self.db.execute(
            "SELECT id, collected_at FROM jobs WHERE mapping_id=? AND kind='shell' AND finished_at IS NOT NULL "
            "ORDER BY finished_at DESC", (mid,)
        ).fetchall()
        for index, (tid, collected) in enumerate(rows):
            if collected is not None and (index >= 4 or time.time()-collected > 3600):
                self.db.execute("DELETE FROM jobs WHERE id=?", (tid,))
                (self.home / "output" / (tid + ".bin")).unlink(missing_ok=True)
                (self.home / "input" / (tid + ".bin")).unlink(missing_ok=True)
                (self.home / "masks" / tid).unlink(missing_ok=True)
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
                self.last_access = time.monotonic()
                # This file may still be in use by Podman during startup. It is
                # intentionally not tied to the initiating Client lifetime.
                (self.home / "masks" / tid).unlink(missing_ok=True)
                writer = self.writers.pop(tid, None)
                if writer is not None:
                    try:
                        writer.put_nowait(None)
                    except queue.Full:
                        pass
                self.collectors.pop(tid, None)
                sandbox = self.sandboxes.pop(tid, None)
            if sandbox is not None:
                sandbox.cleanup()

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

    def _start(self, mid, args):
        public_id = args.get("task_id")
        try:
            tid = self._key(mid, public_id)
        except FileNotFoundError:
            raise ValueError("job ID must be & followed by 4 alphanumeric chars and &") from None
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
            return self._summary(self._row(mid, public_id))
        if self.db.execute("SELECT COUNT(*) FROM jobs WHERE kind='shell' AND finished_at IS NULL").fetchone()[0] >= MAX_RUNNING:
            raise BlockingIOError("Job Manager is at its global limit of 16")
        if self.db.execute("SELECT COUNT(*) FROM jobs WHERE kind='shell' AND finished_at IS NULL AND mapping_id=?",
                           (mid,)).fetchone()[0] >= MAX_PER_MAPPING:
            raise BlockingIOError("mapping has reached its limit of 4 jobs")
        if args.get("kind", "shell") != "shell" or "rpc_payload" in args:
            raise ValueError("Job Manager supports only asynchronous Shell jobs")
        argv = args.get("argv")
        cwd = args.get("cwd")
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
        # Reserved job execution sandbox environment. This is a JSON *string*;
        # omitting it preserves the current OS-user execution behavior.
        # Never silently run an unsupported sandbox request without isolation.
        sandbox = args.get("sandbox")
        if sandbox is not None:
            if not isinstance(sandbox, str):
                raise ValueError("sandbox must be a JSON string")
            try:
                specification = json.loads(sandbox)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid sandbox JSON string") from exc
            if not isinstance(specification, dict):
                raise ValueError("sandbox JSON must contain an object")
            if specification.get("type") == "current_user":
                if specification != {"type": "current_user"}:
                    raise ValueError("current_user sandbox takes no options")
            elif specification.get("type") not in {"bubblewrap", "seatbelt"}:
                raise ValueError("unsupported sandbox environment")
        else:
            specification = {"type": "current_user"}
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
        prepared = None
        if specification["type"] != "current_user":
            if not isinstance(argv, list):
                raise ValueError("restricted sandbox requires argv array")
            if executable is not None or name is not None:
                raise ValueError("sandbox launcher does not accept executable or container override")
            from openkapsel.job_sandbox import prepare_job
            prepared = prepare_job(specification, argv, cwd, environment or {}, self.home)
            argv = prepared.argv
            environment = prepared.environment
        # Only the manager owns subprocess handles, even if the client exits.
        try:
            process = self._spawn(
                argv, cwd=cwd, env=environment, executable=executable, shell=False,
                stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
                close_fds=True,
                pass_fds=prepared.pass_fds if prepared is not None else (),
            )
        except BaseException:
            if prepared is not None:
                prepared.cleanup()
            raise
        if prepared is not None:
            prepared.launched()
        started = time.time()
        self.db.execute(
            "INSERT INTO jobs(id,mapping_id,kind,started_at,pid,interactive,stdin_closed,"
            "deadline,container,request_digest)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (tid, mid, "shell", started, process.pid, int(interactive),
             int(not interactive), started+timeout, name, request_digest)
        )
        self.db.commit()
        (self.home / "output").mkdir(mode=0o700, exist_ok=True)
        (self.home / "output" / (tid + ".bin")).touch(exist_ok=True)
        (self.home / "input").mkdir(mode=0o700, exist_ok=True)
        (self.home / "input" / (tid + ".bin")).touch(exist_ok=True)
        self.processes[tid] = process
        if prepared is not None:
            self.sandboxes[tid] = prepared
        if interactive:
            inputs = queue.Queue(maxsize=16)
            self.writers[tid] = inputs
            threading.Thread(target=self._input_worker,
                             args=(tid, process, inputs), daemon=True).start()
        collector = threading.Thread(target=self._collect, args=(tid, process, timeout), daemon=True)
        self.collectors[tid] = collector
        collector.start()
        return self._summary(self._row(mid, public_id))

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
        if offset > base and (actual == end or actual - base >= 1024 * 1024):
            # Avoid O(N^2) rewrites when output is consumed in 64-KiB pages:
            # trim on EOF or each accumulated MiB of acknowledged output.
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
                "output_base": actual if offset > base and
                (actual == end or actual - base >= 1024 * 1024) else base,
                "gap": offset < base}

    def request(self, req):
        op = req.get("op")
        if op == "ping":
            identity = self.identity
            return {"version": PROTOCOL, "pid": os.getpid(),
                    "release_version": identity["version"],
                    "runtime_id": identity["runtime_id"],
                    "installed_at": identity["installed_at"],
                    "stopping": self.stopping.is_set()}
        if op == "shutdown":
            force = req.get("force", False)
            if type(force) is not bool:
                raise ValueError("force must be a boolean")
            with self.lock:
                pending = self.db.execute(
                    "SELECT mapping_id,id FROM jobs WHERE kind='shell' "
                    "AND finished_at IS NULL ORDER BY started_at,id"
                ).fetchall()
                jobs = [dict(self._summary(self._row(mid, key.rsplit(".", 1)[-1])),
                             mapping_id=mid) for mid, key in pending]
                if self.stopping.is_set():
                    return {"stopping": True, "jobs": jobs}
                if jobs and not force:
                    return {"stopping": False, "jobs": jobs}
                self.stopping.set()
                if force:
                    for _mid, key in pending:
                        self._signal(key, force=True)
                return {"stopping": True, "jobs": jobs}
        with self.lock:
            if self.stopping.is_set():
                raise BlockingIOError("Job Manager is stopping")
            mid = self._mapping_key(req)
            args = req.get("args", {})
            if not isinstance(args, dict):
                raise ValueError("invalid job arguments")
            self.last_access = time.monotonic()
            self._prune(mid)
            if op == "task_list":
                ids = self.db.execute(
                    "SELECT id FROM jobs WHERE mapping_id=? AND kind='shell' ORDER BY started_at DESC",
                    (mid,)
                ).fetchall()
                return [self._summary(self._row(mid, tid.rsplit(".", 1)[-1]))
                        for (tid,) in ids]
            if op == "task_start":
                return self._start(mid, args)
            job = self._row(mid, args.get("task_id"))
            if op == "task_get":
                return dict(self._summary(job), **self._read(job, args.get("offset", 0)))
            if op in {"task_interrupt", "task_kill"}:
                self._signal(job["id"], force=op == "task_kill")
                return self._summary(self._row(mid, args["task_id"]))
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
                    FileExistsError, BlockingIOError, BrokenPipeError, OSError,
                    RuntimeError) as exc:
                wire_send(conn, {"error": {"errno": getattr(exc, "errno", None),
                                          "message": str(exc)[:200]}})
        except (EOFError, OSError, ValueError):
            pass
        finally:
            conn.close()

    def _serve_peer(self, conn):
        try:
            # Cross-Python fixed HMAC challenge; half-open peers cannot
            # block the accept loop or consume a slot indefinitely.
            _server_auth(conn, self.ipc_key)
        except (AuthenticationError, EOFError, OSError, ValueError):
            conn.close()
        else:
            self._connection(conn)
        finally:
            self.ipc_slots.release()

    def _check_idle(self):
        with self.lock:
            if self.stopping.is_set() or time.monotonic() - self.last_access < IDLE_SECONDS:
                return False
            if self.db.execute(
                "SELECT 1 FROM jobs WHERE finished_at IS NULL LIMIT 1"
            ).fetchone():
                return False
            self.stopping.set()
            self.idle_exit.set()
            return True

    def _idle_watch(self):
        while not self.stopping.wait(IDLE_POLL_SECONDS):
            if self._check_idle():
                # Wake listener.accept() so its loop sees the stopping flag.
                try:
                    with Client(self.address, family=self.family, authkey=None):
                        pass
                except (OSError, EOFError):
                    pass
                break

    def serve(self):
        if self.family == "AF_UNIX":
            Path(self.address).unlink(missing_ok=True)
        # Accept raw peers without blocking for authentication. Each bounded
        # worker executes the same authenticated multiprocessing handshake
        # before it is allowed to dispatch even a read-only request.
        listener = Listener(self.address, family=self.family, backlog=64,
                            authkey=None)
        if self.family == "AF_UNIX":
            os.chmod(self.address, 0o600)
        watcher = threading.Thread(target=self._idle_watch, daemon=True)
        watcher.start()
        try:
            while not self.stopping.is_set():
                # Listener accepts one connection at a time, then
                # dispatches fast RPCs concurrently. A wake-up is needed to quit.
                try:
                    conn = listener.accept()
                except (OSError, EOFError, AuthenticationError):
                    if self.stopping.is_set():
                        break
                    continue
                if not self.ipc_slots.acquire(blocking=False):
                    conn.close()
                    continue
                try:
                    threading.Thread(target=self._serve_peer, args=(conn,), daemon=True).start()
                except BaseException:
                    self.ipc_slots.release()
                    conn.close()
                    raise
        finally:
            self.stopping.set()
            listener.close()
            watcher.join(timeout=1)
            with self.lock:
                for tid in list(self.processes):
                    self._signal(tid, force=True)
                collectors = list(self.collectors.values())
            # Wait for the actual output collectors to reap killed subprocesses
            # and persist exit state before closing their shared SQLite DB.
            for collector in collectors:
                collector.join(timeout=15)
            if any(collector.is_alive() for collector in collectors):
                raise RuntimeError("Job Manager collectors did not stop")
            # Keep the launcher alive until every child has exited so
            # Bubblewrap's parent-death signal cannot fire prematurely.
            self.launch_queue.put(None)
            self.launcher.join(timeout=10)
            if self.launcher.is_alive():
                raise RuntimeError("Job Manager launcher did not stop")
            with self.lock:
                self.db.close()
            if self.family == "AF_UNIX":
                Path(self.address).unlink(missing_ok=True)


def connect_once(home, request):
    home = prepare_home(home)
    address, family = endpoint(home)
    if family == "AF_UNIX" and not (home / "ipc.key").exists() and Path(address).exists():
        # Legacy Managers accepted unauthenticated local peers. Authenticating
        # against one would block forever: the old listener never sends an
        # authentication challenge. Fail fast until the old daemon exits.
        raise RuntimeError(
            "unauthenticated legacy Job Manager still owns the socket; "
            "stop the old Manager before upgrading"
        )
    conn = Client(address, family=family, authkey=None)
    try:
        _client_auth(conn, ipc_authkey(home))
        wire_send(conn, request)
        response = wire_recv(conn)
        if "error" in response:
            err = response["error"]
            import errno
            raise OSError(err.get("errno") or errno.EINVAL, err.get("message", "job operation failed"))
        return response["result"]
    finally:
        conn.close()


def _await_manager_exit(home, timeout=20):
    """Wait for *actual* singleton lock release, not just socket removal."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fd = singleton_lock(home)
        if fd is not None:
            os.close(fd)
            return
        time.sleep(.03)
    raise TimeoutError("Job Manager did not finish exiting")


def _legacy_manager_interpreter(home):
    """Select exactly one same-user Manager bound to this exact state home.

    This one-time pre-v2 migration does not trust a PID file or a merely
    matching process name. When identification is uncertain, fail closed.
    """
    home = str(Path(home).resolve())
    candidates = []

    def check(argv, executable=None):
        argv = [word.strip('"') for word in argv]
        if len(argv) < 5 or argv[1:3] != ["-m", "openkapsel.job_manager"]:
            return
        if "--state" not in argv:
            return
        idx = argv.index("--state")
        if idx + 1 >= len(argv) or str(Path(argv[idx + 1]).resolve()) != home:
            return
        binary = executable or argv[0]
        if Path(binary).is_file():
            candidates.append(str(Path(binary).resolve()))

    if sys.platform == "linux":
        for proc in Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                if proc.stat().st_uid != os.getuid():
                    continue
                args = (proc / "cmdline").read_bytes().rstrip(b"\x00").split(b"\x00")
                argv = [arg.decode("utf-8", "surrogateescape") for arg in args]
                check(argv)
            except (FileNotFoundError, ProcessLookupError, PermissionError,
                    OSError, ValueError):
                continue
    elif sys.platform == "darwin":
        try:
            listing = subprocess.run(
                ["ps", "-ww", "-axo", "pid=,uid=,command="],
                capture_output=True, text=True, timeout=5, check=True)
        except (OSError, subprocess.SubprocessError):
            return None
        for row in listing.stdout.splitlines():
            try:
                _pid, uid, cmd = row.strip().split(None, 2)
                if int(uid) == os.getuid():
                    check(shlex.split(cmd))
            except (ValueError, OSError):
                continue
    elif os.name == "nt":
        try:
            listing = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-CimInstance Win32_Process | Where-Object {$_.CommandLine -like '*openkapsel.job_manager*'} | "
                 "ForEach-Object { $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner; "
                 "if ($owner.User -eq $env:USERNAME -and $owner.Domain -eq $env:USERDOMAIN) "
                 "{ $_ | Select-Object ExecutablePath,CommandLine } } | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=10, check=True)
            records = json.loads(listing.stdout or "[]")
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        for item in (records if isinstance(records, list) else [records]):
            try:
                check(shlex.split(item.get("CommandLine", ""), posix=False),
                      item.get("ExecutablePath"))
            except (ValueError, OSError, AttributeError):
                continue

    if len(candidates) != 1:
        return None
    return candidates[0]

def _retire_legacy_manager(home):
    """Migrate old multiprocessing-auth Managers using their own interpreter.

    Never SIGKILL a running Job, or make a new daemon overwrite old metadata.
    The legacy --stop command atomically refuses shutdown when jobs exist.
    """
    old_python = _legacy_manager_interpreter(home)
    if old_python is None:
        raise RuntimeError("legacy Manager IPC is incompatible; unable to identify its interpreter safely")
    outcome = subprocess.run(
        [old_python, "-I", "-m", "openkapsel.job_manager",
         "--state", str(home), "--stop"],
        cwd=str(Path(home).parent), capture_output=True, text=True, timeout=30)
    if outcome.returncode:
        raise RuntimeError(
            "old Manager has active jobs or could not be retired: " +
            (outcome.stdout or outcome.stderr)[-300:])
    _await_manager_exit(home)


def _upgrade_if_older(home, running, *, allow_stale=False):
    if running.get("stopping"):
        _await_manager_exit(home)
        return None
    if running.get("version") != PROTOCOL:
        raise RuntimeError("Job Manager wire protocol incompatible with current Client")
    actual = manager_identity()
    current_version = _version_parts(actual["version"])
    running_version = _version_parts(running.get("release_version", "0.0.0"))
    # ping uses "version" for wire protocol and "release_version" for package.
    if running_version > current_version:
        return running  # Never downgrade a Manager shared by newer Clients.
    if running_version == current_version:
        if running.get("runtime_id") == actual["runtime_id"]:
            return running
        if running.get("installed_at", 0) >= actual["installed_at"]:
            return running  # Prevent same-version clients from flip-flopping.
    response = connect_once(home, {"op": "shutdown", "force": False})
    if not response["stopping"]:
        if allow_stale:
            return running
        raise RuntimeError("manager_upgrade_pending: active jobs must finish before Manager replacement")
    # Wake accept loop; this operation is not a job and cannot interrupt one.
    try:
        connect_once(home, {"op": "ping"})
    except (OSError, EOFError, ConnectionError, AuthenticationError):
        pass
    _await_manager_exit(home)
    return None


def ensure_running(home, *, allow_stale=False):
    home = prepare_home(home)
    with _START_LOCK:
        # Serialize cold start and upgrade within this Client; daemon's file
        # lock and atomic shutdown keep multiple independent Clients safe.
        try:
            running = connect_once(home, {"op": "ping"})
        except AuthenticationError:
            _retire_legacy_manager(home)
            running = None
        except (OSError, EOFError, ConnectionError) as exc:
            # A mismatched 3.11/3.12 multiprocessing challenge may raise
            # 'bad message length', not AuthenticationError. The verified
            # legacy interpreter still has an atomic idle-only --stop.
            if (isinstance(exc, OSError)
                    and "bad message length" in str(exc).lower()
                    and _legacy_manager_interpreter(home) is not None):
                _retire_legacy_manager(home)
            running = None
        if running is not None:
            result = _upgrade_if_older(home, running, allow_stale=allow_stale)
            if result is not None:
                return result
        log = open(home / "manager.log", "ab", buffering=0)
        try:
            daemon_process = subprocess.Popen(
                [sys.executable, "-m", "openkapsel.job_manager", "--state", str(home)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                close_fds=True, start_new_session=os.name != "nt",
                creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                               if os.name == "nt" else 0),
            )
            threading.Thread(target=daemon_process.wait, daemon=True).start()
        finally:
            log.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                running = connect_once(home, {"op": "ping"})
                if running.get("version") != PROTOCOL:
                    raise RuntimeError("Job Manager IPC protocol mismatch")
                return _upgrade_if_older(home, running, allow_stale=allow_stale) or running
            except (OSError, EOFError, ConnectionError, AuthenticationError):
                time.sleep(.05)
        raise ConnectionError("shared Job Manager did not start")


def request(home, mapping_id, op, args=None):
    if not isinstance(mapping_id, str) or not MAPPING_RE.fullmatch(mapping_id):
        raise ValueError("mapping URL must end with a 24-character Mapping key")
    ensure_running(home, allow_stale=op not in {"task_start"})
    return connect_once(home, {"mapping_id": mapping_id, "op": op,
                               "args": args or {}})


def shutdown(home, *, force=False):
    """Request shutdown without starting a missing Manager.

    Without force, running jobs veto shutdown and are returned in jobs.
    With force, all active jobs are terminated and their final status is
    persisted before the Manager process finishes exiting.
    """
    if type(force) is not bool:
        raise ValueError("force must be a boolean")
    home = prepare_home(home)
    result = connect_once(home, {"op": "shutdown", "force": force})
    if result["stopping"]:
        # Wake the single accept loop only if shutdown was accepted.
        try:
            connect_once(home, {"op": "ping"})
        except (OSError, EOFError, ConnectionError):
            pass
        # Waiting only for AF_UNIX socket unlink is insufficient: the old
        # process can still hold the singleton lock, causing the next launch
        # to lose the lock race and time out. Wait for actual lock release.
        deadline = time.monotonic() + 20
        while True:
            fd = singleton_lock(home)
            if fd is not None:
                os.close(fd)
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Job Manager did not finish exiting")
            time.sleep(.03)
    return result


def main():
    parser = argparse.ArgumentParser(description="OpenKapsel shared local Job Manager")
    parser.add_argument("--state", type=Path, default=None)
    parser.add_argument("--stop", action="store_true",
                        help="stop only when no jobs are running")
    parser.add_argument("--force", action="store_true",
                        help="with --stop, terminate every running job")
    ns = parser.parse_args()
    if ns.state is None:
        ns.state = state_home()
    if ns.force and not ns.stop:
        parser.error("--force requires --stop")
    if ns.stop:
        result = shutdown(ns.state, force=ns.force)
        print(json.dumps(result, ensure_ascii=False))
        if not result["stopping"]:
            raise SystemExit(2)
        return
    home = prepare_home(ns.state)
    locked = singleton_lock(home)
    if locked is None:
        return
    try:
        Manager(home).serve()
    finally:
        os.close(locked)


if __name__ == "__main__":
    main()

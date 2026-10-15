"""Persistent cross-process Mapping Shell manager contracts."""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import ClientRuntime
from openkapsel.job_manager import ensure_running, new_job_id, request, shutdown


class SharedManagerTests(unittest.TestCase):
    MAPPING_A = "A" * 24
    MAPPING_B = "B" * 24
    TOKEN_A = "a" * 32

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-shared-job-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.home = self.base / "state"
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.env = patch.dict(os.environ, {"OPENKAPSEL_JOB_MANAGER_HOME": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)

        def cleanup():
            try:
                shutdown(self.home, force=True)
            except (OSError, ConnectionError, EOFError):
                pass
            else:
                if os.name != "nt":
                    # shutdown() acknowledges the stop request before the
                    # daemon closes SQLite and unlinks its socket. Never
                    # delete the temporary state while it is still writing.
                    from openkapsel.job_manager import endpoint
                    address, _ = endpoint(self.home)
                    deadline = time.monotonic() + 10
                    while Path(address).exists() and time.monotonic() < deadline:
                        time.sleep(.02)
                    self.assertFalse(Path(address).exists(),
                                     "Job Manager still running during test cleanup")
        self.addCleanup(cleanup)

    def _start(self, mid, tid, program, *, timeout=40, interactive=False):
        return request(self.home, mid, "task_start", {
            "task_id": tid, "argv": [sys.executable, "-u", "-c", program],
            "cwd": str(self.root), "env": {}, "interactive": interactive,
            "timeout_seconds": timeout,
        })

    def _get(self, mid, tid, offset=0):
        return request(self.home, mid, "task_get", {
            "task_id": tid, "offset": offset
        })

    def _wait(self, mid, tid, *, timeout=5):
        limit = time.monotonic() + timeout
        while time.monotonic() < limit:
            item = self._get(mid, tid)
            if not item["running"]:
                return item
            time.sleep(.035)
        self.fail(f"job {tid} did not finish")

    def _start_short_idle_daemon(self, seconds=.30):
        import subprocess
        # Run the real Manager in a child, with a shorter test-only clock.
        command = (
            "import sys; from openkapsel import job_manager as manager; "
            f"manager.IDLE_SECONDS={seconds}; "
            "manager.IDLE_POLL_SECONDS=.03; "
            "manager.main()"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", command, "--state", str(self.home)],
            cwd=str(Path(__file__).resolve().parents[1]),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        from openkapsel.job_manager import connect_once
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output = proc.communicate()
                self.fail(f"short-idle daemon exited before handshake: {output!r}")
            try:
                self.assertEqual(proc.pid, connect_once(self.home, {"op": "ping"})["pid"])
                return proc
            except (OSError, EOFError, ConnectionError):
                time.sleep(.02)
        proc.kill()
        proc.wait()
        self.fail("short-idle manager failed to start")

    def test_idle_manager_self_exits_then_next_job_starts_new_manager(self):
        from openkapsel.job_manager import connect_once
        proc = self._start_short_idle_daemon()
        try:
            proc.wait(timeout=4)
            self.assertEqual(0, proc.returncode, proc.communicate()[1])
            self.assertNotEqual(proc.pid, ensure_running(self.home)["pid"])
            started = self._start(self.MAPPING_A, "&Id1e&", 'print("after-idle")')
            self.assertEqual("&Id1e&", started["task_id"])
            self.assertEqual(0, self._wait(self.MAPPING_A, "&Id1e&")["exit_code"])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_idle_manager_never_exits_during_running_job(self):
        from openkapsel.job_manager import connect_once
        proc = self._start_short_idle_daemon()
        try:
            tid = "&Busy&"
            self._start(self.MAPPING_A, tid, "import time;time.sleep(.8)")
            time.sleep(.45)  # Past idle deadline, but the job is still alive.
            self.assertIsNone(proc.poll(), "Manager killed an active Job")
            self.assertTrue(self._get(self.MAPPING_A, tid)["running"])
            self.assertEqual(0, self._wait(self.MAPPING_A, tid)["exit_code"])
            proc.wait(timeout=4)
            self.assertEqual(0, proc.returncode)
            proc.communicate(timeout=1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_older_idle_manager_replaced_automatically_without_force(self):
        from openkapsel import job_manager as jm
        before = ensure_running(self.home)["pid"]
        real = jm.connect_once
        first = [True]
        def simulate_old_version(home, req):
            info = real(home, req)
            if req["op"] == "ping" and first[0]:
                first[0] = False
                return dict(info, release_version="2.0.0", runtime_id="outdated")
            return info
        with patch.object(jm, "connect_once", simulate_old_version):
            new = ensure_running(self.home)
        self.assertNotEqual(before, new["pid"])
        self.assertEqual(jm.manager_identity()["runtime_id"], new["runtime_id"])

    def test_same_version_older_build_replaced_newer_build_never_downgraded(self):
        from openkapsel import job_manager as jm
        before = ensure_running(self.home)["pid"]
        current = jm.manager_identity()
        old_seen = [False]
        real = jm.connect_once

        def older_build(home, req):
            response = real(home, req)
            if req["op"] == "ping" and not old_seen[0]:
                old_seen[0] = True
                return dict(response, release_version=current["version"],
                            runtime_id="old-code", installed_at=current["installed_at"] - 1)
            return response

        with patch.object(jm, "connect_once", older_build):
            latest = ensure_running(self.home)
        self.assertNotEqual(before, latest["pid"])
        self.assertEqual(current["runtime_id"], latest["runtime_id"])

        def newer_build(home, req):
            response = real(home, req)
            if req["op"] == "ping":
                return dict(response, runtime_id="newer-code",
                            installed_at=current["installed_at"] + 1)
            return response
        with patch.object(jm, "connect_once", newer_build):
            reused = ensure_running(self.home)
        self.assertEqual(latest["pid"], reused["pid"])
        self.assertEqual(latest["pid"], real(self.home, {"op": "ping"})["pid"])

    def test_concurrent_upgrade_does_not_spawn_multiple_managers(self):
        from concurrent.futures import ThreadPoolExecutor
        from openkapsel import job_manager as jm
        before = ensure_running(self.home)["pid"]
        real = jm.connect_once
        unseen = [True]
        def first_older(home, req):
            result = real(home, req)
            if req["op"] == "ping" and unseen[0]:
                unseen[0] = False
                return dict(result, release_version="2.0.0",
                            runtime_id="old-code")
            return result
        with patch.object(jm, "connect_once", first_older):
            with ThreadPoolExecutor(max_workers=6) as pool:
                pids = list(pool.map(lambda _: ensure_running(self.home)["pid"], range(12)))
        self.assertEqual(1, len(set(pids)), pids)
        self.assertNotEqual(before, pids[0])

    def test_old_manager_with_live_job_not_killed_for_auto_upgrade(self):
        from openkapsel import job_manager as jm
        first = ensure_running(self.home)
        tid = "&Keep&"
        self._start(self.MAPPING_A, tid, "import time;time.sleep(1)")
        real = jm.connect_once
        visits = [0]
        def simulate_old_version(home, req):
            info = real(home, req)
            if req["op"] == "ping" and visits[0] == 0:
                visits[0] += 1
                return dict(info, release_version="2.0.0", runtime_id="outdated")
            return info
        with patch.object(jm, "connect_once", simulate_old_version):
            with self.assertRaisesRegex(RuntimeError, "active jobs"):
                ensure_running(self.home)
        self.assertEqual(first["pid"], ensure_running(self.home)["pid"])
        self.assertTrue(self._get(self.MAPPING_A, tid)["running"])
        self.assertEqual(0, self._wait(self.MAPPING_A, tid)["exit_code"])

    def test_old_manager_active_jobs_allow_inspection_but_block_new_job(self):
        from openkapsel import job_manager as jm
        tid = "&Stay&"
        self._start(self.MAPPING_A, tid, "import time; time.sleep(1)")
        real = jm.connect_once
        def older_for_ping(home, req):
            info = real(home, req)
            if req["op"] == "ping":
                return dict(info, release_version="2.0.0", runtime_id="old")
            return info
        with patch.object(jm, "connect_once", older_for_ping):
            status = request(self.home, self.MAPPING_A, "task_get", {
                "task_id": tid, "offset": 0,
            })
            self.assertTrue(status["running"])
            with self.assertRaisesRegex(RuntimeError, "manager_upgrade_pending"):
                self._start(self.MAPPING_A, "&NewJ&", 'print("should-not-start")')
        self.assertEqual(0, self._wait(self.MAPPING_A, tid)["exit_code"])

    def test_legacy_migration_uses_old_interpreter_nonforce_stop(self):
        import subprocess
        from openkapsel import job_manager as jm
        with (patch.object(jm, "_legacy_manager_interpreter", return_value=sys.executable),
              patch.object(jm.subprocess, "run", return_value=subprocess.CompletedProcess(
                  [], 0, stdout='{"stopping":true,"jobs":[]}', stderr="")) as stopped,
              patch.object(jm, "_await_manager_exit") as awaited):
            jm._retire_legacy_manager(self.home)
        argv = stopped.call_args.args[0]
        self.assertEqual([sys.executable, "-I", "-m", "openkapsel.job_manager"],
                         argv[:4])
        self.assertIn("--stop", argv)
        self.assertNotIn("--force", argv)
        awaited.assert_called_once()

    def test_manager_identity_persists_across_on_disk_updates(self):
        from openkapsel import job_manager as jm
        first = jm.manager_identity()
        with patch.object(Path, "read_bytes", side_effect=AssertionError("reread source")):
            again = jm.manager_identity()
        self.assertEqual(first, again)

    def test_manager_never_auto_downgrades_newer_runtime(self):
        from openkapsel import job_manager as jm
        first = ensure_running(self.home)
        real = jm.connect_once
        def simulate_newer(home, req):
            info = real(home, req)
            if req["op"] == "ping":
                return dict(info, release_version="999.0.0", runtime_id="future")
            return info
        with patch.object(jm, "connect_once", simulate_newer):
            self.assertEqual(first["pid"], ensure_running(self.home)["pid"])
        self.assertEqual(first["pid"], real(self.home, {"op": "ping"})["pid"])

    def test_hmac_authentication_is_cross_python_version_stable(self):
        import shutil
        import subprocess
        from openkapsel.job_manager import connect_once
        other = None
        for name in ("python3.11", "python3.12", "python3.13"):
            exe = shutil.which(name)
            if exe and os.path.realpath(exe) != os.path.realpath(sys.executable):
                other = exe
                break
        if other is None:
            self.skipTest("no alternate Python interpreter available")
        manager = ensure_running(self.home)
        source = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(source))
        command = (
            "import sys; from openkapsel.job_manager import connect_once;"
            "print(connect_once(sys.argv[1], {'op':'ping'})['pid'])"
        )
        result = subprocess.run([other, "-c", command, str(self.home)],
                                capture_output=True, text=True, env=env, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(manager["pid"], int(result.stdout.strip()))

    def test_job_identifier_case_sensitive_four_alphanumeric(self):
        for _ in range(40):
            self.assertRegex(new_job_id(), r"^&[A-Za-z0-9]{4}&$")

    def test_manager_singleton_scoped_jobs_and_disk_output(self):
        first = ensure_running(self.home)
        second = ensure_running(self.home)
        self.assertEqual(first["pid"], second["pid"])
        tid = "&Ab1C&"
        started = self._start(self.MAPPING_A, tid, 'print("managed-job")')
        self.assertTrue(started["running"])
        self.assertEqual(started["task_id"], tid)
        repeated = self._start(self.MAPPING_A, tid, 'print("managed-job")')
        # A fast job may finish between requests; status fields are live.
        # Idempotency means reusing the original job, not freezing its state.
        for key in ("task_id", "kind", "location", "started_at", "interactive"):
            self.assertEqual(started[key], repeated[key], key)
        with self.assertRaises(OSError):
            self._start(self.MAPPING_A, tid,
                        'raise Exception("different command must fail")')
        finished = self._wait(self.MAPPING_A, tid)
        self.assertEqual(0, finished["exit_code"])
        self.assertEqual(b"managed-job\n", base64.b64decode(finished["output"]))
        self.assertTrue((self.home / "jobs.sqlite3").is_file())
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self.home / "jobs.sqlite3")) as db:
            indexes = list(db.execute("PRAGMA index_list(jobs)"))
            self.assertTrue(any(row[1] == "jobs_owner_start" for row in indexes))

        spool = self.home / "output" / (self.MAPPING_A + "." + tid + ".bin")
        self.assertEqual(b"managed-job\n", spool.read_bytes())
        # Resume at the consumed offset: manager physically truncates the spool.
        acknowledged = self._get(self.MAPPING_A, tid,
                                 finished["next_offset"])
        self.assertEqual("", acknowledged["output"])
        self.assertEqual(b"", spool.read_bytes())
        self.assertEqual(tid, request(
            self.home, self.MAPPING_A, "task_list"
        )[0]["task_id"])
        # Mapping keys partition the query namespace and disk output. Client
        # code fixes the key from its Mapping URL, not caller-supplied args.
        for other_id in (tid, "&bD2e&"):
            other = self._start(self.MAPPING_B, other_id,
                                "print('different-owner')")
            self.assertEqual(other_id, other["task_id"])
            different = self._wait(self.MAPPING_B, other_id)
            self.assertEqual(0, different["exit_code"])
            self.assertEqual(b"different-owner\n",
                             base64.b64decode(different["output"]))
        self.assertEqual({tid, "&bD2e&"}, {j["task_id"] for j in request(
            self.home, self.MAPPING_B, "task_list"
        )})
        with self.assertRaises(OSError):
            self._get(self.MAPPING_A, "&bD2e&")
        # Both owners use identical public IDs, but output remains distinct.
        own = self._get(self.MAPPING_A, tid)
        other = self._get(self.MAPPING_B, tid)
        self.assertNotEqual(base64.b64decode(own["output"]),
                            base64.b64decode(other["output"]))

    def test_manager_has_no_auth_records_or_credentials(self):
        tid = "&R0tE&"
        self._start(self.MAPPING_A, tid, 'print("no-manager-auth")')
        finished = self._wait(self.MAPPING_A, tid)
        self.assertEqual(0, finished["exit_code"])
        self.assertFalse((self.home / "auth.key").exists())
        self.assertEqual(32, len((self.home / "ipc.key").read_bytes()))
        from contextlib import closing
        import sqlite3
        with closing(sqlite3.connect(self.home / "jobs.sqlite3")) as db:
            self.assertNotIn("owners", {
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")
            })
        # The manager does not implement credential registration/rotation.
        with self.assertRaises(OSError):
            request(self.home, self.MAPPING_A, "rotate_owner")
        self.assertEqual(tid, request(
            self.home, self.MAPPING_A, "task_list"
        )[0]["task_id"])

    def test_upgrades_remove_old_credential_table_and_key_file(self):
        import sqlite3
        from contextlib import closing
        self.home.mkdir(parents=True, exist_ok=True)
        (self.home / "auth.key").write_bytes(b"old-manager-auth-secret" * 2)
        with closing(sqlite3.connect(self.home / "jobs.sqlite3")) as db:
            db.execute("CREATE TABLE owners (mapping_id TEXT PRIMARY KEY,"
                       " credential_hash TEXT NOT NULL)")
            db.execute("INSERT INTO owners VALUES (?, ?)",
                       (self.MAPPING_A, "obsolete-hash"))
            db.commit()
        ensure_running(self.home)
        self.assertFalse((self.home / "auth.key").exists())
        self.assertEqual(32, len((self.home / "ipc.key").read_bytes()))
        with closing(sqlite3.connect(self.home / "jobs.sqlite3")) as db:
            names = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("owners", names)
        self.assertIn("jobs", names)

    def test_ipc_key_created_atomically_across_concurrent_clients(self):
        from concurrent.futures import ThreadPoolExecutor
        from openkapsel.job_manager import ipc_authkey, prepare_home
        home = prepare_home(self.home)
        with ThreadPoolExecutor(max_workers=12) as pool:
            keys = list(pool.map(lambda _: ipc_authkey(home), range(60)))
        self.assertEqual(1, len(set(keys)))
        self.assertEqual(32, len(keys[0]))
        self.assertEqual(keys[0], (home / "ipc.key").read_bytes())

    @unittest.skipIf(os.name == "nt", "Legacy detection uses an AF_UNIX socket path")
    def test_legacy_unauthenticated_socket_fails_fast_before_handshake(self):
        from openkapsel.job_manager import connect_once, endpoint, prepare_home
        import socket
        home = prepare_home(self.home)
        address, _ = endpoint(home)
        legacy = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        legacy.bind(address)
        try:
            with self.assertRaisesRegex(RuntimeError, "legacy Job Manager"):
                connect_once(home, {"op": "ping"})
            self.assertFalse((home / "ipc.key").exists())
        finally:
            legacy.close()
            Path(address).unlink(missing_ok=True)

    def test_ipc_requires_authentication_even_for_same_uid(self):
        from multiprocessing import AuthenticationError
        from multiprocessing.connection import Client as IpcClient
        from openkapsel.job_manager import (
            _client_auth, endpoint, ipc_authkey, wire_recv, wire_send,
            PROTOCOL,
        )
        ensure_running(self.home)
        address, family = endpoint(self.home)
        with self.assertRaises((AuthenticationError, ConnectionResetError, EOFError, OSError)):
            with IpcClient(address, family=family, authkey=None) as conn:
                _client_auth(conn, b"unauthorized")
                wire_send(conn, {"op": "shutdown", "force": True})
                wire_recv(conn)
        self.assertGreater(ensure_running(self.home)["pid"], 0)
        key = ipc_authkey(self.home)
        self.assertEqual(32, len(key))
        with IpcClient(address, family=family, authkey=None) as conn:
            _client_auth(conn, key)
            wire_send(conn, {"op": "ping"})
            result = wire_recv(conn)
        self.assertEqual(PROTOCOL, result["result"]["version"])

    def test_explicit_manager_state_does_not_read_default_user_home(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from openkapsel import job_manager
        # --force without --stop triggers argument validation after parsing.
        # If --state were still evaluated eagerly, the injected home lookup
        # would raise before argparse could report the intended usage error.
        with (patch.object(job_manager, "state_home", side_effect=AssertionError("home accessed")),
              patch.object(sys, "argv", ["job_manager", "--state", str(self.home), "--force"]),
              redirect_stderr(StringIO())):
            with self.assertRaises(SystemExit) as caught:
                job_manager.main()
        self.assertEqual(2, caught.exception.code)

    def test_half_open_ipc_authentication_does_not_block_valid_jobs(self):
        # An AF_PIPE/AF_UNIX peer may connect without completing the auth
        # challenge. It must not hold the Manager's only accept loop hostage.
        import threading
        from multiprocessing.connection import Client as IpcClient
        from openkapsel.job_manager import connect_once, endpoint

        ensure_running(self.home)
        address, family = endpoint(self.home)
        unfinished = IpcClient(address, family=family, authkey=None)
        done = threading.Event()
        result = {}

        def valid_request():
            try:
                result["ping"] = connect_once(self.home, {"op": "ping"})
                result["job"] = self._start(
                    self.MAPPING_A, "&Ha1f&", 'print("not-blocked")')
            except BaseException as exc:
                result["error"] = exc
            finally:
                done.set()

        worker = threading.Thread(target=valid_request, daemon=True)
        try:
            worker.start()
            self.assertTrue(done.wait(5), "incomplete IPC auth blocked valid requests")
            if "error" in result:
                raise result["error"]
            self.assertEqual(2, result["ping"]["version"])
            self.assertEqual("&Ha1f&", result["job"]["task_id"])
            self.assertEqual(0, self._wait(self.MAPPING_A, "&Ha1f&")["exit_code"])
        finally:
            unfinished.close()
            worker.join(timeout=5)

    def test_mapping_token_change_does_not_affect_existing_jobs(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        first = ClientRuntime(config)
        tid = "&T0kN&"
        try:
            first.tasks.dispatch("task_start", {
                "task_id": tid,
                "argv": [sys.executable, "-u", "-c",
                         'import time; print("survives-token-change", flush=True); time.sleep(.3)'],
                "timeout_seconds": 1e9, "interactive": False,
            })
        finally:
            first.close()
        # Token is a Server/Client transport credential, not Manager input.
        config["token"] = "new-server-transport-token-123456789"
        second = ClientRuntime(config)
        try:
            finished = self._wait(self.MAPPING_A, tid)
            self.assertEqual(0, finished["exit_code"])
            self.assertIn(tid, [row["task_id"] for row in
                                second.tasks.dispatch("task_list", {})])
            self.assertIn(b"survives-token-change",
                          base64.b64decode(finished["output"]))
        finally:
            second.close()

    def test_forcibly_killed_client_process_does_not_kill_job_and_output_resumes(self):
        import subprocess
        import json
        tid = "&K1lL&"
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        launcher = """
import json,sys,time
from openkapsel.client import ClientRuntime
runtime = ClientRuntime(json.loads(sys.argv[1]))
runtime.tasks.dispatch("task_start", {
    "task_id": "&K1lL&",
    "argv": [sys.executable, "-u", "-c",
        "import time; print('alpha',flush=True); time.sleep(.9); print('omega',flush=True)"],
    "timeout_seconds": 1e9, "interactive": False,
})
print("STARTED", flush=True)
time.sleep(30)
"""
        parent = subprocess.Popen(
            [sys.executable, "-u", "-c", launcher, json.dumps(config)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=str(Path(__file__).resolve().parents[1]),
            env=os.environ.copy(),
        )
        try:
            self.assertEqual(b"STARTED\n", parent.stdout.readline())
            parent.kill()
            parent.wait(timeout=5)
            after = ClientRuntime(config)
            try:
                first = self._get(self.MAPPING_A, tid)
                offset = first["next_offset"]
                captured = bytearray(base64.b64decode(first["output"]))
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    page = self._get(self.MAPPING_A, tid, offset)
                    captured.extend(base64.b64decode(page["output"]))
                    offset = page["next_offset"]
                    if not page["running"] and offset >= page["output_size"]:
                        break
                    time.sleep(.025)
                self.assertEqual(b"alpha\nomega\n", bytes(captured))
                self.assertEqual(0, page["exit_code"])
                self.assertIn(tid, [row["task_id"] for row in
                                   after.tasks.dispatch("task_list", {})])
                # The last response's cursor is the acknowledgment for those
                # bytes; reading that offset triggers physical spool cleanup.
                self._get(self.MAPPING_A, tid, offset)
                self.assertEqual(b"", (self.home / "output" / (self.MAPPING_A+"."+tid+".bin")).read_bytes())
            finally:
                after.close()
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=5)
            parent.stdout.close()

    def test_manager_owned_running_job_does_not_defer_client_source_reload(self):
        from openkapsel.client_runtime.job_backend import JobBackend
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        runtime = ClientRuntime(config)
        tid = "&R1Ld&"
        try:
            self.assertIsInstance(runtime.tasks, JobBackend)
            runtime.tasks.dispatch("task_start", {
                "task_id": tid,
                "argv": [sys.executable, "-u", "-c",
                         "import time; time.sleep(1.0)"],
                "timeout_seconds": 1e9, "interactive": False,
            })
            self.assertTrue(self._get(self.MAPPING_A, tid)["running"])
            # ClientRuntime may re-exec for automatic source updates while
            # the Manager's child process continues running.
            self.assertFalse(runtime.has_active_tasks())
        finally:
            runtime.close()
        self.assertEqual(0, self._wait(self.MAPPING_A, tid)["exit_code"])

    def test_graceful_shutdown_rejects_active_jobs_and_returns_mapping_scoped_list(self):
        tid1, tid2 = "&Veto&", "&List&"
        self._start(self.MAPPING_A, tid1, "import time;time.sleep(30)")
        self._start(self.MAPPING_B, tid2, "import time;time.sleep(30)")
        pid = ensure_running(self.home)["pid"]
        result = shutdown(self.home)
        self.assertFalse(result["stopping"], result)
        self.assertEqual({(self.MAPPING_A, tid1), (self.MAPPING_B, tid2)},
                         {(item["mapping_id"], item["task_id"]) for item in result["jobs"]})
        self.assertTrue(all(item["running"] for item in result["jobs"]))
        self.assertEqual(pid, ensure_running(self.home)["pid"])
        # Without force, both jobs must still be alive.
        self.assertTrue(self._get(self.MAPPING_A, tid1)["running"])
        self.assertTrue(self._get(self.MAPPING_B, tid2)["running"])
        stopped = shutdown(self.home, force=True)
        self.assertTrue(stopped["stopping"])
        self.assertEqual(2, len(stopped["jobs"]))
        self._await_manager_exit()
        # Restart exposes persisted real kill results for both mappings.
        self.assertNotEqual(pid, ensure_running(self.home)["pid"])
        for mid, tid in ((self.MAPPING_A, tid1), (self.MAPPING_B, tid2)):
            final = self._get(mid, tid)
            self.assertFalse(final["running"])
            self.assertTrue(final["force_killed"], final)

    def test_graceful_shutdown_when_idle_does_not_spawn_another_manager(self):
        from openkapsel.job_manager import endpoint
        before = ensure_running(self.home)["pid"]
        stopped = shutdown(self.home)
        self.assertEqual({"stopping": True, "jobs": []}, stopped)
        self._await_manager_exit()
        self.assertNotEqual(before, ensure_running(self.home)["pid"])

    def test_sandbox_json_is_reserved_and_never_silently_ignored(self):
        good = {"task_id": "&Sand&", "argv": [sys.executable, "-c", "print('user')"],
                "cwd": str(self.root), "interactive": False,
                "timeout_seconds": 10, "env": {}}
        # No sandbox field remains backward-compatible.
        started = request(self.home, self.MAPPING_A, "task_start", good)
        self.assertEqual("&Sand&", started["task_id"])
        self.assertEqual(0, self._wait(self.MAPPING_A, "&Sand&")["exit_code"])
        valid = dict(good, task_id="&Us3r&", sandbox='{"type":"current_user"}')
        started = request(self.home, self.MAPPING_A, "task_start", valid)
        self.assertEqual("&Us3r&", started["task_id"])
        self.assertEqual(0, self._wait(self.MAPPING_A, "&Us3r&")["exit_code"])
        for sandbox in ('not JSON', '{}', '{"type":"bubblewrap"}', '[]', True):
            with self.subTest(sandbox=sandbox):
                with self.assertRaises(OSError):
                    request(self.home, self.MAPPING_A, "task_start",
                            dict(good, task_id=new_job_id(), sandbox=sandbox))

    def test_client_cli_stop_requires_exclusive_config_and_force(self):
        import subprocess
        from openkapsel.client_runtime.client_config import ClientConfigLock
        config = self.base / "client.json"
        config.write_text(json.dumps({"url": "ws://localhost/mapping-connect/" + self.MAPPING_A}))
        if os.name != "nt":
            config.chmod(0o600)
        def cli(*extra):
            return subprocess.run(
                [sys.executable, "-m", "openkapsel.client", "--config", str(config),
                 "--stop-manager", *extra], cwd=str(Path(__file__).resolve().parents[1]),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=15,
            )
        lock = ClientConfigLock.acquire(config)
        try:
            pid = ensure_running(self.home)["pid"]
            refused = cli()
            self.assertNotEqual(0, refused.returncode)
            self.assertIn("locked", refused.stderr)
            self.assertEqual(pid, ensure_running(self.home)["pid"])
        finally:
            lock.close()
        tid = "&CL1x&"
        self._start(self.MAPPING_A, tid, "import time;time.sleep(30)")
        refused = cli()
        self.assertEqual(2, refused.returncode, refused.stderr)
        self.assertFalse(json.loads(refused.stdout)["stopping"])
        self.assertTrue(self._get(self.MAPPING_A, tid)["running"])
        forced = cli("--force")
        self.assertEqual(0, forced.returncode, forced.stderr)
        reply = json.loads(forced.stdout)
        self.assertTrue(reply["stopping"])
        self.assertEqual([tid], [row["task_id"] for row in reply["jobs"]])
        self._await_manager_exit()

    def _await_manager_exit(self):
        if os.name != "nt":
            from openkapsel.job_manager import endpoint
            address, _ = endpoint(self.home)
            deadline = time.monotonic() + 10
            while Path(address).exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertFalse(Path(address).exists(), "manager did not exit")
        else:
            # On Windows, AF_PIPE has no path: try new launch only after
            # the original manager process has stopped responding.
            from openkapsel.job_manager import connect_once
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    connect_once(self.home, {"op": "ping"})
                except (OSError, EOFError, ConnectionError):
                    return
                time.sleep(.02)
            self.fail("manager did not exit")

    def test_manager_stop_requires_no_credentials(self):
        import subprocess
        self._start(self.MAPPING_A, "&St0p&", "import time; time.sleep(30)")
        proc = subprocess.run(
            [sys.executable, "-m", "openkapsel.job_manager",
             "--state", str(self.home), "--stop", "--force"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        # Starting a new request creates the singleton again.
        self.assertFalse(self._get(self.MAPPING_A, "&St0p&")["running"])

    def test_stdin_is_managed_and_timeout_is_enforced(self):
        tid = "&Yz92&"
        self._start(self.MAPPING_A, tid,
                    'import sys; print("input="+sys.stdin.readline().strip(), flush=True)',
                    interactive=True)
        self.assertEqual(4, request(
            self.home, self.MAPPING_A,
            "task_stdin", {"task_id": tid, "data": base64.b64encode(b"abc\n").decode(),
                           "eof": True}
        )["accepted"])
        outcome = self._wait(self.MAPPING_A, tid)
        self.assertIn(b"input=abc", base64.b64decode(outcome["output"]))
        # Only the Manager handles stdin pipes; consumed data is removed from disk.
        self.assertEqual(b"", (self.home / "input" / (self.MAPPING_A + "." + tid + ".bin")).read_bytes())
        tid2 = "&T1mE&"
        self._start(self.MAPPING_A, tid2,
                    "import time; time.sleep(20)", timeout=.15)
        result = self._wait(self.MAPPING_A, tid2)
        self.assertTrue(result["timed_out"])

    def test_manager_caps_four_per_mapping_independent_of_clients(self):
        running = []
        try:
            for _ in range(4):
                tid = new_job_id()
                self._start(self.MAPPING_A, tid,
                            "import time; time.sleep(30)")
                running.append(tid)
            with self.assertRaises(OSError):
                self._start(self.MAPPING_A, new_job_id(),
                            "import time; time.sleep(30)")
            # A different Mapping gets its own quota on the same manager.
            own = new_job_id()
            self._start(self.MAPPING_B, own,
                        'print("separate")')
            self.assertEqual(0, self._wait(self.MAPPING_B, own)["exit_code"])
        finally:
            for tid in running:
                request(self.home, self.MAPPING_A,
                        "task_kill", {"task_id": tid})

    def test_global_limit_sixteen_across_four_mapping_keys(self):
        jobs = []
        try:
            for n in range(4):
                mapping = str(n) * 24
                for _ in range(4):
                    tid = new_job_id()
                    self._start(mapping, tid,
                                "import time; time.sleep(30)")
                    jobs.append((mapping, tid))
            with self.assertRaises(OSError):
                self._start("9" * 24,
                            new_job_id(), "print('overflow')")
            self.assertEqual(16, sum(
                row["running"] for mid, _ in jobs[::4]
                for row in request(self.home, mid, "task_list")
            ))
        finally:
            for mid, tid in jobs:
                try:
                    request(self.home, mid, "task_kill",
                            {"task_id": tid})
                except (OSError, ConnectionError):
                    pass

    def test_concurrent_client_startup_resolves_one_singleton(self):
        from concurrent.futures import ThreadPoolExecutor
        from openkapsel import job_manager

        # Observe real daemon launches instead of mocking the startup path:
        # identical PIDs alone do not reveal redundant losing processes.
        launch = job_manager.subprocess.Popen
        launched = []
        def record_launch(*args, **kwargs):
            process = launch(*args, **kwargs)
            argv = args[0] if args else kwargs.get("args", ())
            if (isinstance(argv, (tuple, list)) and len(argv) >= 5
                    and argv[1:4] == ["-m", "openkapsel.job_manager", "--state"]
                    and argv[4] == str(self.home)):
                launched.append(process)
            return process

        with patch.object(job_manager.subprocess, "Popen", side_effect=record_launch):
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(lambda _: ensure_running(self.home), range(12)))
        self.assertEqual(1, len({row["pid"] for row in results}))
        self.assertEqual(1, len(launched),
                         f"concurrent clients launched redundant managers: "
                         f"pids={[(p.pid, p.poll()) for p in launched]} "
                         f"responses={[row['pid'] for row in results]} "
                         f"log={(self.home / 'manager.log').read_text(errors='replace')[-500:]}")
        self.assertEqual(results[0]["pid"], launched[0].pid)
        self.assertTrue((self.home / "jobs.sqlite3").is_file())

    def test_new_client_runtime_recovers_job_after_previous_client_closes(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        one = ClientRuntime(config)
        try:
            tid = "&R1vE&"
            result = one.tasks.dispatch("task_start", {
                "task_id": tid,
                "argv": [sys.executable, "-u", "-c",
                         'import time; print("before",flush=True); time.sleep(.6); print("after",flush=True)'],
                "interactive": False,
                "timeout_seconds": 1e9,
            })
            self.assertEqual(tid, result["task_id"])
        finally:
            one.close()
        two = ClientRuntime(config)
        try:
            self.assertTrue(two.tasks.capabilities()["restart_persistence"])
            self.assertIn(tid, [row["task_id"] for row in
                                two.tasks.dispatch("task_list", {})])
            until = time.monotonic() + 5
            while time.monotonic() < until:
                result = two.tasks.dispatch("task_get", {"task_id": tid, "offset": 0})
                if not result["running"]:
                    break
                time.sleep(.03)
            self.assertFalse(result["running"])
            self.assertIn(b"before", base64.b64decode(result["output"]))
            self.assertIn(b"after", base64.b64decode(result["output"]))
        finally:
            two.close()

    def test_async_rpc_never_uses_job_manager_or_transfers_config(self):
        import zipfile
        (self.root / "source").mkdir()
        (self.root / "source" / "hello.txt").write_text("normal rpc")
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": False, "sandbox": True,
            "rpc": {"archive": True},
        }
        runtime = ClientRuntime(config)
        tid = "rpc-kept-client-1"
        try:
            self.assertFalse((self.home / "jobs.sqlite3").exists())
            started = runtime.tasks.dispatch("task_start", {
                "task_id": tid,
                "rpc": {
                    "family": "archive", "operation": "create",
                    "args": {"sources": ["source"], "destination": "bundle.zip",
                             "format": "zip"},
                },
            })
            self.assertEqual("rpc", started["kind"])
            self.assertEqual(tid, started["task_id"])
            until = time.monotonic() + 6
            while time.monotonic() < until:
                finished = runtime.tasks.dispatch("task_get", {
                    "task_id": tid, "offset": 0,
                })
                if not finished["running"]:
                    break
                time.sleep(.025)
            self.assertFalse(finished["running"])
            self.assertEqual(0, finished["exit_code"], finished)
            with zipfile.ZipFile(self.root / "bundle.zip") as archive:
                self.assertEqual(b"normal rpc", archive.read("source/hello.txt"))
            # Neither RPC start nor status request can create/consult Manager.
            self.assertFalse((self.home / "jobs.sqlite3").exists())
            self.assertFalse((self.home / "manager.lock").exists())
        finally:
            runtime.close()
        newer = ClientRuntime(config)
        try:
            with self.assertRaises(OSError):
                newer.tasks.dispatch("task_get", {"task_id": tid, "offset": 0})
            self.assertFalse((self.home / "jobs.sqlite3").exists())
        finally:
            newer.close()

    def test_shell_sends_only_key_and_current_invocation_no_config(self):
        from unittest.mock import patch
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": "private-token-never-sent-to-manager",
            "root": str(self.root), "writable": True,
            "allow_exec": True, "sandbox": False,
            "rpc": {"archive": {"enabled": True, "config": {"secret": "private-plugin-setting"}}},
        }
        runtime = ClientRuntime(config)
        try:
            self.assertFalse((self.home / "jobs.sqlite3").exists())
            from openkapsel.client_runtime import shared_job_tasks
            seen = []
            original = shared_job_tasks.request
            def observed(home, key, operation, args=None):
                seen.append((key, operation, args))
                return original(home, key, operation, args)
            with patch.object(shared_job_tasks, "request", side_effect=observed):
                runtime.tasks.dispatch("task_start", {
                    "task_id": "&Sh1L&",
                    "argv": [sys.executable, "-c", "print('shell only')"],
                    "timeout_seconds": 121, "interactive": False,
                })
            self.assertEqual(1, len(seen))
            key, operation, payload = seen[0]
            self.assertEqual(self.MAPPING_A, key)
            self.assertEqual("task_start", operation)
            self.assertEqual("&Sh1L&", payload["task_id"])
            self.assertNotIn("config", payload)
            self.assertNotIn("rpc", payload)
            self.assertNotIn("rpc_payload", payload)
            import json
            text = json.dumps(payload)
            self.assertNotIn("private-token-never-sent-to-manager", text)
            self.assertNotIn("private-plugin-setting", text)
            self.assertEqual(0, self._wait(self.MAPPING_A, "&Sh1L&")["exit_code"])
        finally:
            runtime.close()

    def test_unsandboxed_short_and_long_shell_keep_operator_environment(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        runtime = ClientRuntime(config)
        custom_home = str(self.base / "operator-home")
        try:
            with patch.dict(os.environ, {
                "HOME": custom_home,
                "SSH_AUTH_SOCK": str(self.base / "agent.sock"),
                "OPENKAPSEL_OPERATOR_ENV_TEST": "operator-trusted",
            }):
                started = runtime.tasks.dispatch("task_start", {
                    "task_id": "&EnVr&", "unsandboxed": True,
                    "argv": [sys.executable, "-c",
                             "import os; print(os.environ.get('HOME')); "
                             "print(os.environ.get('OPENKAPSEL_OPERATOR_ENV_TEST'))"],
                    "timeout_seconds": 30, "interactive": False,
                })
                self.assertEqual("&EnVr&", started["task_id"])
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    result = runtime.tasks.dispatch("task_get", {"task_id": "&EnVr&", "offset": 0})
                    if not result["running"]:
                        break
                    time.sleep(.02)
                self.assertEqual(0, result["exit_code"], result)
                self.assertEqual([custom_home, "operator-trusted"],
                                 base64.b64decode(result["output"]).decode().splitlines())
                long_job = runtime.tasks._prepare({
                    "task_id": "&EnVl&", "unsandboxed": True,
                    "argv": [sys.executable, "-c", "pass"],
                    "timeout_seconds": 121, "interactive": False,
                })
                self.assertEqual(custom_home, long_job["env"]["HOME"])
                self.assertEqual("operator-trusted", long_job["env"]["OPENKAPSEL_OPERATOR_ENV_TEST"])
                self.assertEqual(str(self.base / "agent.sock"), long_job["env"]["SSH_AUTH_SOCK"])
        finally:
            runtime.close()

    def test_default_and_120_second_shell_stay_in_client_without_manager(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
            "limits": {"max_seconds": 30},
        }
        runtime = ClientRuntime(config)
        try:
            self.assertEqual(30, runtime.tasks.capabilities()["max_seconds"])
            self.assertEqual(120, runtime.tasks.capabilities()["default_seconds"])
            for job_id, specified in (("&Df1t&", None), ("&B120&", 120)):
                operation = {
                    "task_id": job_id,
                    "argv": [sys.executable, "-u", "-c", "print('short-shell')"],
                    "interactive": False,
                }
                if specified is not None:
                    operation["timeout_seconds"] = specified
                started = runtime.tasks.dispatch("task_start", operation)
                self.assertEqual(job_id, started["task_id"])
                self.assertIn(job_id, runtime.tasks.legacy.tasks)
                self.assertEqual(120, runtime.tasks.legacy.tasks[job_id]["timeout"])
                self.assertFalse((self.home / "jobs.sqlite3").exists())
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    result = runtime.tasks.dispatch("task_get", {"task_id": job_id, "offset": 0})
                    if not result["running"]:
                        break
                    time.sleep(.02)
                self.assertEqual(0, result["exit_code"])
                self.assertEqual(b"short-shell\n", base64.b64decode(result["output"]))
            self.assertFalse((self.home / "jobs.sqlite3").exists())
        finally:
            runtime.close()

    def test_short_shell_stdin_and_status_stay_client_local(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        runtime = ClientRuntime(config)
        tid = "&St1n&"
        try:
            runtime.tasks.dispatch("task_start", {
                "task_id": tid,
                "argv": [sys.executable, "-u", "-c",
                         "import sys; print(sys.stdin.readline().strip(), flush=True)"],
                "timeout_seconds": 120, "interactive": True,
            })
            accepted = runtime.tasks.dispatch("task_stdin", {
                "task_id": tid, "data": base64.b64encode(b"client-input\n").decode(),
                "eof": True,
            })
            self.assertEqual(13, accepted["accepted"])
            end = time.monotonic() + 5
            while time.monotonic() < end:
                result = runtime.tasks.dispatch("task_get", {"task_id": tid, "offset": 0})
                if not result["running"]:
                    break
                time.sleep(.02)
            self.assertEqual(0, result["exit_code"])
            self.assertEqual(b"client-input\n", base64.b64decode(result["output"]))
            self.assertFalse((self.home / "jobs.sqlite3").exists())
        finally:
            runtime.close()

    def test_long_shell_121_seconds_uses_manager_and_outlives_client(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        runtime = ClientRuntime(config)
        job_id = "&L121&"
        try:
            started = runtime.tasks.dispatch("task_start", {
                "task_id": job_id,
                "argv": [sys.executable, "-u", "-c",
                         "import time; print('persistent-shell',flush=True); time.sleep(.3)"],
                "timeout_seconds": 121, "interactive": False,
            })
            self.assertEqual(job_id, started["task_id"])
            self.assertNotIn(job_id, runtime.tasks.legacy.tasks)
            self.assertTrue((self.home / "jobs.sqlite3").exists())
        finally:
            runtime.close()
        self.assertEqual(0, self._wait(self.MAPPING_A, job_id)["exit_code"])

    def test_short_shell_is_terminated_when_client_runtime_closes(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        runtime = ClientRuntime(config)
        tid = "&Sh0r&"
        try:
            runtime.tasks.dispatch("task_start", {
                "task_id": tid, "argv": [sys.executable, "-u", "-c",
                                        "import time; time.sleep(60)"],
                "timeout_seconds": 120, "interactive": False,
            })
            self.assertTrue(runtime.has_active_tasks())
            self.assertFalse((self.home / "jobs.sqlite3").exists())
        finally:
            runtime.close()
        self.assertFalse((self.home / "jobs.sqlite3").exists())

    def test_shell_cannot_bypass_manager_by_using_a_legacy_task_id(self):
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": True, "sandbox": False,
        }
        runtime = ClientRuntime(config)
        try:
            with self.assertRaises(OSError):
                runtime.tasks.dispatch("task_start", {
                    "task_id": "legacy-shell-id",
                    "argv": [sys.executable, "-c", "print('should not run')"],
                })
            self.assertFalse((self.home / "jobs.sqlite3").exists())
        finally:
            runtime.close()

    def test_manager_rejects_rpc_jobs(self):
        with self.assertRaises(OSError):
            request(self.home, self.MAPPING_A, "task_start", {
                "task_id": "&RpC1&", "kind": "rpc",
                "rpc_payload": {"config": {"foo": 1}},
            })
        self.assertEqual([], request(self.home, self.MAPPING_A, "task_list"))

    def test_private_state_must_not_be_inside_mapping_root(self):
        from openkapsel.client_runtime.client_files import ClientFiles
        from openkapsel.client_runtime.client_tasks import ClientTasks
        from openkapsel.client_runtime.shared_job_tasks import SharedClientTasks
        files = ClientFiles(self.root, writable=True)
        tasks = ClientTasks(files, enabled=False, sandbox=False)
        try:
            with self.assertRaisesRegex(ValueError, "outside Mapping exports"):
                SharedClientTasks(tasks,
                                  url="ws://host/mapping-connect/" + self.MAPPING_A,
                                  home=self.root / "secret-job-state")
        finally:
            tasks.close()
            files.close()

    def test_sandbox_mask_lives_with_manager_not_client(self):
        from openkapsel.client_runtime.client_files import ClientFiles
        from openkapsel.client_runtime.client_tasks import ClientTasks
        from openkapsel.client_runtime.shared_job_tasks import SharedClientTasks
        protected = self.root / ".hidden-client-config"
        protected.write_text("PRIVATE CONFIG")
        files = ClientFiles(self.root, writable=True,
                            protected_paths=[protected])
        tasks = ClientTasks(files, enabled=False, sandbox=False)
        adapter = SharedClientTasks(
            tasks, url="ws://host/mapping-connect/" + self.MAPPING_A,
            home=self.home,
        )
        try:
            # Simulate the already configured sandbox backend without invoking
            # Podman itself (it is optional on macOS/Windows test machines).
            tasks.sandbox = True
            prepared = adapter._prepare({
                "task_id": "&M4sk&", "command": "echo sandbox",
                "cwd": ".", "timeout_seconds": 121,
            })
            args = prepared["argv"]
            binds = [args[i+1] for i, x in enumerate(args[:-1]) if x == "--volume"]
            mask = self.home / "masks" / (self.MAPPING_A+".&M4sk&")
            self.assertTrue(mask.is_file())
            self.assertTrue(any(str(mask) in item for item in binds))
            self.assertNotIn(str(protected), mask.read_text())
            adapter.close()  # deletes original in-client temporary files
            self.assertTrue(mask.is_file())
        finally:
            tasks.close()
            files.close()

    def test_manager_shutdown_kills_jobs_and_persists_completed_history(self):
        tid = "&Stop&"
        self._start(self.MAPPING_A, tid,
                    'import time; time.sleep(20)')
        pid = ensure_running(self.home)["pid"]
        result = shutdown(self.home, force=True)
        self.assertTrue(result["stopping"])
        self.assertEqual([tid], [job["task_id"] for job in result["jobs"]])
        # Manager is allowed to finish process termination asynchronously.
        for _ in range(60):
            time.sleep(.05)
            try:
                next_pid = ensure_running(self.home)["pid"]
                if next_pid != pid:
                    break
            except (OSError, ConnectionError):
                continue
        else:
            self.fail("manager did not restart after --stop")
        finished = self._get(self.MAPPING_A, tid)
        self.assertFalse(finished["running"])
        self.assertTrue(finished["force_killed"])


if __name__ == "__main__":
    unittest.main()

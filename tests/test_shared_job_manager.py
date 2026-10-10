"""Persistent cross-process Mapping Shell manager contracts."""
from __future__ import annotations

import base64
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import ClientRuntime
from openkapsel.job_manager import ensure_running, new_job_id, request, rotate_owner, shutdown


class SharedManagerTests(unittest.TestCase):
    MAPPING_A = "A" * 24
    MAPPING_B = "B" * 24
    TOKEN_A = "a" * 32
    TOKEN_B = "b" * 32

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
                shutdown(self.home)
            except (OSError, ConnectionError, EOFError):
                pass
        self.addCleanup(cleanup)

    def _start(self, mid, token, tid, program, *, timeout=40, interactive=False):
        return request(self.home, mid, token, "task_start", {
            "task_id": tid, "argv": [sys.executable, "-u", "-c", program],
            "cwd": str(self.root), "env": {}, "interactive": interactive,
            "timeout_seconds": timeout,
        })

    def _get(self, mid, token, tid, offset=0):
        return request(self.home, mid, token, "task_get", {
            "task_id": tid, "offset": offset
        })

    def _wait(self, mid, token, tid, *, timeout=5):
        limit = time.monotonic() + timeout
        while time.monotonic() < limit:
            item = self._get(mid, token, tid)
            if not item["running"]:
                return item
            time.sleep(.035)
        self.fail(f"job {tid} did not finish")

    def test_job_identifier_case_sensitive_four_alphanumeric(self):
        for _ in range(40):
            self.assertRegex(new_job_id(), r"^&[A-Za-z0-9]{4}&$")

    def test_manager_singleton_scoped_jobs_and_disk_output(self):
        first = ensure_running(self.home)
        second = ensure_running(self.home)
        self.assertEqual(first["pid"], second["pid"])
        tid = "&Ab1C&"
        started = self._start(self.MAPPING_A, self.TOKEN_A, tid, 'print("managed-job")')
        self.assertTrue(started["running"])
        self.assertEqual(started["task_id"], tid)
        self.assertEqual(started, self._start(
            self.MAPPING_A, self.TOKEN_A, tid, 'print("managed-job")'
        ))
        with self.assertRaises(OSError):
            self._start(self.MAPPING_A, self.TOKEN_A, tid,
                        'raise Exception("different command must fail")')
        finished = self._wait(self.MAPPING_A, self.TOKEN_A, tid)
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
        acknowledged = self._get(self.MAPPING_A, self.TOKEN_A, tid,
                                 finished["next_offset"])
        self.assertEqual("", acknowledged["output"])
        self.assertEqual(b"", spool.read_bytes())
        self.assertEqual(tid, request(
            self.home, self.MAPPING_A, self.TOKEN_A, "task_list"
        )[0]["task_id"])
        # Another Mapping cannot read, control or enumerate this job.
        # Even when a Mapping ID differs, a case-insensitive filesystem
        # must never alias another Job's disk-spooled I/O.
        for other_id in (tid, "&bD2e&"):
            other = self._start(self.MAPPING_B, self.TOKEN_B, other_id,
                                "print('different-owner')")
            self.assertEqual(other_id, other["task_id"])
            different = self._wait(self.MAPPING_B, self.TOKEN_B, other_id)
            self.assertEqual(0, different["exit_code"])
            self.assertEqual(b"different-owner\n",
                             base64.b64decode(different["output"]))
        self.assertEqual({tid, "&bD2e&"}, {j["task_id"] for j in request(
            self.home, self.MAPPING_B, self.TOKEN_B, "task_list"
        )})
        with self.assertRaises(OSError):
            self._get(self.MAPPING_A, self.TOKEN_A, "&bD2e&")
        with self.assertRaises(OSError):
            self._get(self.MAPPING_A, self.TOKEN_B, tid)
        # Both owners use identical public IDs, but output remains distinct.
        own = self._get(self.MAPPING_A, self.TOKEN_A, tid)
        other = self._get(self.MAPPING_B, self.TOKEN_B, tid)
        self.assertNotEqual(base64.b64decode(own["output"]),
                            base64.b64decode(other["output"]))

    def test_token_rotation_requires_old_credential_and_preserves_job(self):
        tid = "&R0tE&"
        next_token = "freshly-rotated-mapping-token-" * 2
        self._start(self.MAPPING_A, self.TOKEN_A, tid,
                    'import time; print("old-token",flush=True); time.sleep(.5); print("new-token",flush=True)')
        with self.assertRaises(OSError):
            request(self.home, self.MAPPING_A, next_token, "task_list")
        with self.assertRaises(OSError):
            rotate_owner(self.home, self.MAPPING_A, "forged-old-token-" * 2,
                         next_token)
        self.assertEqual(
            {"mapping_id": self.MAPPING_A, "rotated": True},
            rotate_owner(self.home, self.MAPPING_A, self.TOKEN_A, next_token)
        )
        with self.assertRaises(OSError):
            self._get(self.MAPPING_A, self.TOKEN_A, tid)
        with self.assertRaises(OSError):
            rotate_owner(self.home, self.MAPPING_A, self.TOKEN_A, "other-token-" * 4)
        finished = self._wait(self.MAPPING_A, next_token, tid)
        self.assertIn(b"old-token", base64.b64decode(finished["output"]))
        self.assertIn(b"new-token", base64.b64decode(finished["output"]))
        self.assertEqual(0, finished["exit_code"])
        self.assertEqual(tid, request(
            self.home, self.MAPPING_A, next_token, "task_list"
        )[0]["task_id"])

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
                first = self._get(self.MAPPING_A, self.TOKEN_A, tid)
                offset = first["next_offset"]
                captured = bytearray(base64.b64decode(first["output"]))
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    page = self._get(self.MAPPING_A, self.TOKEN_A, tid, offset)
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
                self._get(self.MAPPING_A, self.TOKEN_A, tid, offset)
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
            self.assertTrue(self._get(self.MAPPING_A, self.TOKEN_A, tid)["running"])
            # ClientRuntime may re-exec for automatic source updates while
            # the Manager's child process continues running.
            self.assertFalse(runtime.has_active_tasks())
        finally:
            runtime.close()
        self.assertEqual(0, self._wait(self.MAPPING_A, self.TOKEN_A, tid)["exit_code"])

    def test_cli_token_rotation_only_reads_secrets_from_stdin(self):
        import json
        import subprocess
        tid = "&T0kN&"
        self._start(self.MAPPING_A, self.TOKEN_A, tid, "print('cli-rotation')")
        new_token = "CLI-ROTATION-NEW-TOKEN-12345678"
        proc = subprocess.run(
            [sys.executable, "-m", "openkapsel.job_manager",
             "--state", str(self.home), "--rotate-owner", self.MAPPING_A],
            input=json.dumps({"old_token": self.TOKEN_A,
                              "new_token": new_token}),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertNotIn(self.TOKEN_A, proc.stdout+proc.stderr)
        self.assertNotIn(new_token, proc.stdout+proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["rotated"])
        self.assertEqual(0, self._wait(self.MAPPING_A, new_token, tid)["exit_code"])
        with self.assertRaises(OSError):
            request(self.home, self.MAPPING_A, self.TOKEN_A, "task_list")

    def test_stdin_is_managed_and_timeout_is_enforced(self):
        tid = "&Yz92&"
        self._start(self.MAPPING_A, self.TOKEN_A, tid,
                    'import sys; print("input="+sys.stdin.readline().strip(), flush=True)',
                    interactive=True)
        self.assertEqual(4, request(
            self.home, self.MAPPING_A, self.TOKEN_A,
            "task_stdin", {"task_id": tid, "data": base64.b64encode(b"abc\n").decode(),
                           "eof": True}
        )["accepted"])
        outcome = self._wait(self.MAPPING_A, self.TOKEN_A, tid)
        self.assertIn(b"input=abc", base64.b64decode(outcome["output"]))
        # Only the Manager handles stdin pipes; consumed data is removed from disk.
        self.assertEqual(b"", (self.home / "input" / (self.MAPPING_A + "." + tid + ".bin")).read_bytes())
        tid2 = "&T1mE&"
        self._start(self.MAPPING_A, self.TOKEN_A, tid2,
                    "import time; time.sleep(20)", timeout=.15)
        result = self._wait(self.MAPPING_A, self.TOKEN_A, tid2)
        self.assertTrue(result["timed_out"])

    def test_manager_caps_four_per_mapping_independent_of_clients(self):
        running = []
        try:
            for _ in range(4):
                tid = new_job_id()
                self._start(self.MAPPING_A, self.TOKEN_A, tid,
                            "import time; time.sleep(30)")
                running.append(tid)
            with self.assertRaises(OSError):
                self._start(self.MAPPING_A, self.TOKEN_A, new_job_id(),
                            "import time; time.sleep(30)")
            # A different Mapping gets its own quota on the same manager.
            own = new_job_id()
            self._start(self.MAPPING_B, self.TOKEN_B, own,
                        'print("separate")')
            self.assertEqual(0, self._wait(self.MAPPING_B, self.TOKEN_B, own)["exit_code"])
        finally:
            for tid in running:
                request(self.home, self.MAPPING_A, self.TOKEN_A,
                        "task_kill", {"task_id": tid})

    def test_global_limit_sixteen_across_four_mapping_keys(self):
        jobs = []
        try:
            for n in range(4):
                mapping = str(n) * 24
                token = ("owner-secret-" + str(n)) * 3
                for _ in range(4):
                    tid = new_job_id()
                    self._start(mapping, token, tid,
                                "import time; time.sleep(30)")
                    jobs.append((mapping, token, tid))
            with self.assertRaises(OSError):
                self._start("9" * 24, "owner-secret-global-limit-123",
                            new_job_id(), "print('overflow')")
            self.assertEqual(16, sum(
                row["running"] for mid, token, _ in jobs[::4]
                for row in request(self.home, mid, token, "task_list")
            ))
        finally:
            for mid, token, tid in jobs:
                try:
                    request(self.home, mid, token, "task_kill",
                            {"task_id": tid})
                except (OSError, ConnectionError):
                    pass

    def test_concurrent_client_startup_resolves_one_singleton(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: ensure_running(self.home), range(12)))
        self.assertEqual(1, len({row["pid"] for row in results}))

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

    def test_mapping_rpc_runs_in_separate_worker_and_result_survives_client_close(self):
        import zipfile
        (self.root / "source").mkdir()
        (self.root / "source" / "hello.txt").write_text("persistent archive")
        config = {
            "url": "ws://127.0.0.1/mapping-connect/" + self.MAPPING_A,
            "token": self.TOKEN_A, "root": str(self.root),
            "writable": True, "allow_exec": False, "sandbox": True,
        }
        runtime = ClientRuntime(config)
        tid = "&Rpc1&"
        try:
            started = runtime.tasks.dispatch("task_start", {
                "task_id": tid, "rpc": {
                    "family": "archive", "operation": "create",
                    "args": {
                        "sources": ["source"], "destination": "bundle.zip",
                        "format": "zip",
                    },
                },
                "timeout_seconds": 1e9,
            })
            self.assertEqual("rpc", started["kind"])
            self.assertTrue(started["write"])
        finally:
            runtime.close()
        restarted = ClientRuntime(config)
        try:
            finished = self._wait(self.MAPPING_A, self.TOKEN_A, tid)
            self.assertFalse(finished["running"])
            self.assertEqual(0, finished["exit_code"], finished)
            self.assertTrue(finished["result_available"])
            self.assertEqual("bundle.zip", finished["result"]["destination"])
            self.assertIn("archive", base64.b64decode(finished["output"]).decode())
            self.assertEqual(tid, restarted.tasks.dispatch(
                "task_get", {"task_id": tid, "offset": 0}
            )["task_id"])
            with zipfile.ZipFile(self.root / "bundle.zip") as f:
                self.assertEqual(b"persistent archive", f.read("source/hello.txt"))
            self.assertTrue((self.home / "results" / (self.MAPPING_A + "." + tid + ".json")).exists())
        finally:
            restarted.close()

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
                                  token=self.TOKEN_A,
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
            token=self.TOKEN_A, home=self.home,
        )
        try:
            # Simulate the already configured sandbox backend without invoking
            # Podman itself (it is optional on macOS/Windows test machines).
            tasks.sandbox = True
            prepared = adapter._prepare({
                "task_id": "&M4sk&", "command": "echo sandbox",
                "cwd": ".", "timeout_seconds": 40,
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
        self._start(self.MAPPING_A, self.TOKEN_A, tid,
                    'import time; time.sleep(20)')
        pid = ensure_running(self.home)["pid"]
        shutdown(self.home)
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
        finished = self._get(self.MAPPING_A, self.TOKEN_A, tid)
        self.assertFalse(finished["running"])
        self.assertTrue(finished["interrupted"])


if __name__ == "__main__":
    unittest.main()

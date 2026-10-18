"""Podman kill/stop/remove accept only owned container names, never CLI options."""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from openkapsel.client_runtime.client_tasks import ClientTasks
from openkapsel.execution.sandbox_backends import PodmanController
from openkapsel.job_manager import Manager
from openkapsel.podman_identifiers import (
    is_client_container, is_mapping_job_container, is_server_container,
)


class PodmanNameSecurityTests(unittest.TestCase):
    MID = "A" * 24
    TID = "&aB12&"
    NAME = "openkapsel-client-" + MID + "-aB12"

    def test_only_openkapsel_generated_ids_are_accepted(self):
        self.assertTrue(is_mapping_job_container(self.NAME, self.MID, self.TID))
        self.assertTrue(is_server_container("openkapsel-a1b2c3d4-abcdef012345"))
        self.assertTrue(is_client_container("openkapsel-client-aB12"))
        for name in (None, [], "", "-f", "--all", "--latest", "container",
                     "../openkapsel", "openkapsel-client--all",
                     "openkapsel-client-" + self.MID + "-aB12 --all",
                     "openkapsel-client-" + self.MID + "-aB12\n--all",
                     "openkapsel-client-" + self.MID + "-aB12\x00",
                     "openkapsel-client-" + "B" * 24 + "-aB12",
                     "openkapsel-client-" + self.MID + "-XXXX"):
            with self.subTest(name=name):
                self.assertFalse(is_mapping_job_container(name, self.MID, self.TID))
        self.assertFalse(is_server_container("openkapsel-client-aB12"))

    def test_podman_controller_rejects_non_owned_container(self):
        for bad in ("--all", "other-container", "-l",
                    "openkapsel-client-aB12", "openkapsel-xx-12"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    PodmanController(Path("/usr/bin/podman"), bad)

    @staticmethod
    def _manager_with_container(container):
        tid = "A" * 24 + ".&aB12&"
        manager = Manager.__new__(Manager)
        manager.db = sqlite3.connect(":memory:")
        manager.db.execute(
            "CREATE TABLE jobs(id TEXT PRIMARY KEY, container TEXT, "
            "force_killed INTEGER, interrupted INTEGER)")
        manager.db.execute("INSERT INTO jobs VALUES(?,?,0,0)", (tid, container))
        process = MagicMock()
        process.poll.return_value = None
        process.pid = 12345
        manager.processes = {tid: process}
        return manager, tid

    def test_manager_rejects_forged_start_before_process_spawn(self):
        # Exercise the real _start validator without IPC/sockets or Podman.
        from openkapsel.job_manager import Manager
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            manager = Manager.__new__(Manager)
            manager.db = sqlite3.connect(":memory:")
            try:
                manager.db.execute(
                    "CREATE TABLE jobs(id TEXT PRIMARY KEY, mapping_id TEXT, "
                    "request_digest TEXT, kind TEXT, finished_at REAL)"
                )
                manager._spawn = MagicMock()
                args = {"task_id": self.TID, "argv": ["true"],
                        "cwd": tmp, "timeout_seconds": 3}
                for forged in ("--all", "-l", "other-container",
                               "openkapsel-client-" + "B" * 24 + "-aB12",
                               "openkapsel-client-" + self.MID + "-XXXX"):
                    with self.subTest(name=forged):
                        with self.assertRaisesRegex(ValueError, "non-owned"):
                            manager._start(self.MID, {**args, "container": forged})
                manager._spawn.assert_not_called()
                self.assertEqual(
                    0, manager.db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
            finally:
                manager.db.close()

    def test_manager_never_kills_unrelated_or_option_named_container(self):
        for name in ("--all", "other-container", "openkapsel-client-" + "B" * 24 + "-aB12",
                     "openkapsel-client-" + self.MID + "-XXXX"):
            with self.subTest(name=name):
                manager, tid = self._manager_with_container(name)
                try:
                    with patch("openkapsel.job_manager.subprocess.run") as run, \
                         patch("openkapsel.job_manager.os.killpg") as killpg:
                        manager._signal(tid, True)
                    run.assert_not_called()
                    killpg.assert_called_once()
                finally:
                    manager.db.close()

    def test_manager_valid_name_uses_option_terminator(self):
        manager, tid = self._manager_with_container(self.NAME)
        try:
            with patch("openkapsel.job_manager.subprocess.run") as run, \
                 patch("openkapsel.job_manager.os.killpg"):
                manager._signal(tid, True)
            self.assertEqual(
                ["podman", "kill", "--signal", "KILL", "--", self.NAME],
                run.call_args.args[0])
        finally:
            manager.db.close()

    def test_client_signal_does_not_interpret_untrusted_container(self):
        def task_for(name):
            process = MagicMock()
            process.pid = 12345
            return {"kind": "shell", "finished_at": None,
                    "process": process, "container": name, "force_killed": False}
        for name in ("--all", "unrelated", self.NAME.replace("aB12", "-bad")):
            with self.subTest(name=name):
                with patch("openkapsel.client_runtime.client_tasks.subprocess.run") as run, \
                     patch("openkapsel.client_runtime.client_tasks.os.killpg"):
                    ClientTasks._signal(task_for(name), force=True)
                run.assert_not_called()
        with patch("openkapsel.client_runtime.client_tasks.subprocess.run") as run, \
             patch("openkapsel.client_runtime.client_tasks.os.killpg"):
            ClientTasks._signal(task_for(self.NAME), force=True)
        self.assertEqual(
            ["podman", "kill", "--signal", "KILL", "--", self.NAME],
            run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

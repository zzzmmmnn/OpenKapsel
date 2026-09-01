from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.api_workers import ApiWorker, ApiWorkerManager
from openkapsel.cgroups import TokenCgroupManager
from openkapsel.tokens import TokenRecord, utc_now


class ApiWorkerSandboxTests(unittest.TestCase):
    def test_active_connection_holds_worker_lease_until_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            class RunningProcess:
                stopped = False

                def poll(self) -> int | None:
                    return 0 if self.stopped else None

                def terminate(self) -> None:
                    self.stopped = True

                @staticmethod
                def wait(timeout: float) -> int:
                    return 0

                def kill(self) -> None:
                    self.stopped = True

            class LogHandle:
                @staticmethod
                def close() -> None:
                    return None

            record = TokenRecord(
                token="lease-token",
                name="Lease test",
                created_at=utc_now(),
                preview_token="preview-token",
                control_token="control-token",
                app_id="lease-app",
            )
            worker = ApiWorker(
                app_id=record.app_id,
                process=RunningProcess(),
                socket_path=root / "worker.sock",
                fingerprint=(),
                last_used=0,
                log_handle=LogHandle(),
            )
            manager = ApiWorkerManager(
                worker_root=root / "manager",
                bubblewrap_path=Path("/usr/bin/bwrap"),
                rootlesskit_path=Path("/usr/bin/rootlesskit"),
                cgroups=TokenCgroupManager(enabled=False),
            )
            manager._workers["lease-worker"] = worker
            try:
                with patch.object(manager, "_ensure", return_value=worker):
                    connection = manager.connection(
                        record,
                        root,
                        "/preview/api",
                        "lease-worker",
                )
                self.assertEqual(1, worker.active_connections)
                self.assertFalse(manager._worker_is_stale(worker, time.monotonic()))
                connection.close()
                self.assertEqual(0, worker.active_connections)
                released_at = worker.last_used
                self.assertTrue(manager._worker_is_stale(worker, released_at + 1))
                connection.close()
                self.assertEqual(0, worker.active_connections)
                self.assertEqual(released_at, worker.last_used)
            finally:
                manager.close()

    def test_systemd_policy_permits_nested_private_proc(self) -> None:
        service = (
            Path(__file__).resolve().parents[1] / "systemd" / "openkapsel.service"
        ).read_text(encoding="utf-8")
        self.assertIn("ProtectProc=invisible", service)
        self.assertIn("ProtectKernelTunables=false", service)
        self.assertIn("ProtectKernelModules=true", service)
        self.assertIn("ProtectKernelLogs=false", service)
        self.assertNotIn("ProtectKernelTunables=true", service)
        self.assertNotIn("ProtectKernelLogs=true", service)

    def test_worker_mounts_only_its_app_venv_and_private_proc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace" / "site-a"
            sibling = root / "workspace" / "site-b"
            worker_dir = root / "workers" / "site-a"
            (workspace / "api").mkdir(parents=True)
            sibling.mkdir(parents=True)
            worker_dir.mkdir(parents=True)
            (sibling / "secret.txt").write_text("private", encoding="utf-8")
            record = TokenRecord(
                token="sandbox-test-token",
                name="Sandbox test",
                created_at=utc_now(),
                preview_token="preview-token",
                control_token="control-token",
                app_id="sandbox-test-app",
                can_preview=True,
                shell_mode="restricted",
            )
            manager = ApiWorkerManager(
                worker_root=root / "manager",
                bubblewrap_path=Path("/usr/bin/bwrap"),
                rootlesskit_path=Path("/usr/bin/rootlesskit"),
                cgroups=TokenCgroupManager(enabled=False),
            )
            try:
                with patch(
                    "openkapsel.api_workers.apparmor_restricts_user_namespaces",
                    return_value=False,
                ):
                    argv = manager._sandbox_argv(
                        record,
                        workspace,
                        worker_dir,
                        worker_dir / "app.sock",
                        "/preview/api",
                    )
            finally:
                manager.close()

            bwrap_index = argv.index("/usr/bin/bwrap")
            sandbox_argv = argv[bwrap_index:]
            pairs = set(zip(sandbox_argv, sandbox_argv[1:]))
            triples = set(zip(sandbox_argv, sandbox_argv[1:], sandbox_argv[2:]))
            self.assertIn("--unshare-pid", sandbox_argv)
            self.assertIn(("--proc", "/proc"), pairs)
            self.assertNotIn(("--ro-bind", "/proc", "/proc"), triples)
            self.assertIn(
                (
                    "--ro-bind",
                    "/opt/openkapsel/venv",
                    "/opt/openkapsel/venv",
                ),
                triples,
            )
            self.assertNotIn(
                ("--ro-bind", "/opt/openkapsel", "/opt/openkapsel"),
                triples,
            )
            self.assertIn(("--bind", str(workspace), str(workspace)), triples)
            self.assertIn(
                (
                    "--tmpfs",
                    str(workspace.resolve() / ".openkapsel"),
                ),
                pairs,
            )
            self.assertIn(
                (
                    "--bind",
                    str(workspace.resolve() / ".openkapsel" / "sql"),
                    "/run/openkapsel-sql",
                ),
                triples,
            )
            self.assertIn("OPENKAPSEL_SQL_ROOT", sandbox_argv)
            self.assertNotIn(str(sibling), sandbox_argv)
            self.assertNotIn("PYTHONPATH", sandbox_argv)


if __name__ == "__main__":
    unittest.main()

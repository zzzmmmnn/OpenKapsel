from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openkapsel.api_workers import ApiWorkerManager
from openkapsel.cgroups import TokenCgroupManager
from openkapsel.tokens import TokenRecord, utc_now


class ApiWorkerSandboxTests(unittest.TestCase):
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
            (workspace / ".context").mkdir()
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
                    str(workspace / ".context"),
                ),
                pairs,
            )
            self.assertNotIn(str(sibling), sandbox_argv)
            self.assertNotIn("PYTHONPATH", sandbox_argv)


if __name__ == "__main__":
    unittest.main()

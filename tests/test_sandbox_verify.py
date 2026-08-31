from __future__ import annotations

import subprocess
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openkapsel.sandbox_verify import verify_api_worker_isolation


class SandboxVerificationTests(unittest.TestCase):
    def test_api_worker_probe_creates_nested_private_marker(self) -> None:
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as workers:
            true_path = Path(shutil.which("true") or "/usr/bin/true")
            manager = mock.Mock()
            manager._sandbox_argv.return_value = [str(true_path)]
            completed = subprocess.CompletedProcess(
                [str(true_path)],
                0,
                stdout=b"API worker isolation probe passed\n",
                stderr=b"",
            )
            with mock.patch(
                "openkapsel.sandbox_verify.ApiWorkerManager",
                return_value=manager,
            ), mock.patch(
                "openkapsel.sandbox_verify.subprocess.run",
                return_value=completed,
            ):
                verify_api_worker_isolation(
                    Path(workspace),
                    Path(workers),
                    true_path,
                    true_path,
                )

            manager._sandbox_argv.assert_called_once()
            manager.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()

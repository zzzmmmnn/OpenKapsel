"""Unit-level API isolation probe contracts and opt-in *real* Linux sandbox test.

The subprocess-mocked tests validate only control flow. CI runs the real
Bubblewrap test separately with OPENKAPSEL_REAL_SANDBOX_TESTS=1.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from openkapsel.execution.sandbox_verify import verify_api_worker_isolation


class SandboxVerificationTests(unittest.TestCase):
    def test_api_worker_probe_builds_private_marker_assertions(self) -> None:
        """Check generated probe contents; this is NOT an isolation test."""
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as workers:
            true_path = Path(shutil.which("true") or "/usr/bin/true")
            manager = mock.Mock()
            manager._sandbox_argv.return_value = [str(true_path)]
            completed = subprocess.CompletedProcess(
                [str(true_path)], 0,
                stdout=b"API worker isolation probe passed\n", stderr=b"",
            )
            with mock.patch(
                "openkapsel.execution.sandbox_verify.ApiWorkerManager",
                return_value=manager,
            ), mock.patch(
                "openkapsel.execution.sandbox_verify.subprocess.run",
                return_value=completed,
            ):
                verify_api_worker_isolation(
                    Path(workspace), Path(workers), true_path, true_path,
                )

            manager._sandbox_argv.assert_called_once()
            command = manager._sandbox_argv.call_args.kwargs["command"]
            self.assertEqual(["/opt/openkapsel/venv/bin/python", "-I", "-c"],
                             command[:3])
            probe = command[-1]
            for assertion in (
                "assert own.read_text(", "assert not other.exists()",
                "assert not Path(", "/.openkapsel", "private.txt",
                "assert not Path(f'/proc/{host_pid}')",
                "assert not (Path('/proc/1/root')",
            ):
                self.assertIn(assertion, probe)
            manager.close.assert_called_once()

    def test_api_worker_probe_does_not_accept_fake_or_failed_result(self) -> None:
        """A subprocess error or missing marker must fail, even with a mock."""
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as workers:
            true_path = Path(shutil.which("true") or "/usr/bin/true")
            for return_code, output in ((1, b"API worker isolation probe passed\n"),
                                        (0, b"no evidence of isolation\n")):
                with self.subTest(return_code=return_code, output=output):
                    manager = mock.Mock()
                    manager._sandbox_argv.return_value = [str(true_path)]
                    completed = subprocess.CompletedProcess(
                        [str(true_path)], return_code, stdout=output,
                        stderr=b"failed",
                    )
                    with mock.patch(
                        "openkapsel.execution.sandbox_verify.ApiWorkerManager",
                        return_value=manager,
                    ), mock.patch(
                        "openkapsel.execution.sandbox_verify.subprocess.run",
                        return_value=completed,
                    ):
                        with self.assertRaises(RuntimeError):
                            verify_api_worker_isolation(
                                Path(workspace), Path(workers), true_path, true_path,
                            )
                    manager.close.assert_called_once()

    @unittest.skipUnless(
        os.environ.get("OPENKAPSEL_REAL_SANDBOX_TESTS") == "1",
        "actual Linux Bubblewrap isolation runs in dedicated CI job",
    )
    def test_real_bubblewrap_enforces_private_files_pid_and_readonly(self) -> None:
        """Execute the production Bubblewrap backend, not a fake subprocess."""
        self.assertTrue(sys.platform.startswith("linux"),
                        "real sandbox integration requires Linux")
        from openkapsel.execution.cgroups import SandboxLimits
        from openkapsel.execution.sandbox_backends import (
            BubblewrapBackend, SandboxSpec,
        )

        bwrap = shutil.which("bwrap")
        self.assertIsNotNone(bwrap, "real sandbox CI requires installed bubblewrap")
        rootlesskit = shutil.which("rootlesskit") or "/nonexistent/rootlesskit"
        backend = BubblewrapBackend(
            Path(bwrap), Path(rootlesskit), aggregate_resources=False,
        )
        with tempfile.TemporaryDirectory(prefix="opk-real-sandbox-") as directory:
            base = Path(directory).resolve()
            own = base / "own"
            other = base / "other"
            hidden = own / ".openkapsel"
            own.mkdir()
            other.mkdir()
            hidden.mkdir()
            (own / "visible.txt").write_text("visible", encoding="utf-8")
            (other / "secret.txt").write_text("never-visible", encoding="utf-8")
            (hidden / "private.txt").write_text("private-context", encoding="utf-8")
            host_pid = os.getpid()
            probe = textwrap.dedent(f"""
                from pathlib import Path
                import os
                own = Path({str(own)!r})
                other = Path({str(other)!r})
                hidden = Path({str(hidden)!r})
                assert (own / 'visible.txt').read_text() == 'visible'
                assert not other.exists(), 'sibling workspace leaked'
                assert not (hidden / 'private.txt').exists(), 'private context leaked'
                assert os.getpid() != {host_pid}, 'host PID namespace leaked'
                assert Path('/proc/self/status').is_file()
                assert not (Path('/proc/1/root') / str(other).lstrip('/')).exists()
                try:
                    (own / 'unauthorized.txt').write_text('bad')
                except OSError:
                    pass
                else:
                    raise AssertionError('read-only workspace is writable')
                print('REAL_BUBBLEWRAP_ISOLATION_OK')
            """)
            spec = SandboxSpec(
                command="python3 -c " + shlex.quote(probe),
                cwd=own, scope_root=own, can_write=False,
                network_mode="none", allowed_domains=(),
                proxy_root=base / "proxy", allowed_paths=(),
                hidden_paths=(hidden,),
                limits=SandboxLimits(16, 64 * 1024 * 1024, 100),
                owner_token="real-sandbox-integration",
            )
            launch = backend.build_shell(spec)
            try:
                result = subprocess.run(
                    launch.argv, input=launch.stdin_data,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=35, check=False,
                )
            finally:
                if launch.controller is not None:
                    launch.controller.cleanup()
            self.assertEqual(0, result.returncode,
                             result.stderr.decode(errors="replace")[-3000:])
            self.assertIn(b"REAL_BUBBLEWRAP_ISOLATION_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()

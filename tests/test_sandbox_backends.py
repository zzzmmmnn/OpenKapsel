from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.admin_ui import _sandbox_backend_options
from openkapsel.cgroups import SandboxLimits
from openkapsel.sandbox_backends import (
    BubblewrapBackend,
    PodmanBackend,
    PodmanController,
    ProxyController,
    SandboxSpec,
)
from openkapsel.tokens import PathGrant


class PodmanBackendTests(unittest.TestCase):
    def _backend(self, executable: Path) -> PodmanBackend:
        backend = PodmanBackend(
            executable,
            "registry.example.test/openkapsel-runtime@sha256:" + "a" * 64,
            "crun",
            aggregate_resources=True,
        )
        backend.host_is_macos = False
        return backend

    def test_builds_hardened_token_scoped_container_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "podman"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            workspace = root / "workspace"
            workspace.mkdir()
            context = workspace / ".context"
            context.mkdir()
            environment_file = root / "token.rc"
            environment_file.write_text("export API_KEY=container-secret\n", encoding="utf-8")
            extra = root / "published"
            extra.mkdir()
            spec = SandboxSpec(
                command="python3 -c 'print(7)'",
                cwd=workspace,
                scope_root=workspace,
                can_write=True,
                network_mode="none",
                allowed_domains=(),
                proxy_root=root / "proxies",
                allowed_paths=(PathGrant(str(extra), read_only=True),),
                hidden_paths=(context,),
                limits=SandboxLimits(64, 256 * 1024 * 1024, 150),
                owner_token="secret-control-token",
                sandbox_image="registry.example.test/python:3.14-slim",
                environment_file=environment_file,
            )
            probe = subprocess.CompletedProcess([], 0, "crun\n", "")
            with patch("openkapsel.sandbox_backends.subprocess.run", return_value=probe):
                launch = self._backend(executable).build_shell(spec)
            argv = launch.argv
            self.assertEqual("podman", launch.backend)
            self.assertIn("--read-only", argv)
            self.assertIn("--runtime=crun", argv)
            self.assertIn("--cap-drop=ALL", argv)
            self.assertIn("--security-opt=no-new-privileges", argv)
            self.assertIn("--pid=private", argv)
            self.assertIn("--network", argv)
            self.assertEqual("none", argv[argv.index("--network") + 1])
            self.assertEqual("64", argv[argv.index("--pids-limit") + 1])
            self.assertEqual(str(256 * 1024 * 1024), argv[argv.index("--memory") + 1])
            self.assertEqual("1.5", argv[argv.index("--cpus") + 1])
            volume_values = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--volume"]
            self.assertIn(f"{workspace}:{workspace}:rw", volume_values)
            self.assertIn(f"{extra}:{extra}:ro", volume_values)
            self.assertIn(
                f"{environment_file}:/run/openkapsel-environment.rc:ro",
                volume_values,
            )
            tmpfs_values = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--tmpfs"]
            self.assertTrue(any(value.startswith(f"{context}:") for value in tmpfs_values))
            self.assertNotIn("secret-control-token", " ".join(argv))
            self.assertNotIn("container-secret", " ".join(argv))
            self.assertIn(". /run/openkapsel-environment.rc", argv[-1])
            self.assertIn("--pull=never", argv)
            self.assertIn("registry.example.test/python:3.14-slim", argv)
            self.assertIsInstance(launch.controller, PodmanController)

    def test_lists_installed_images_and_renders_one_option_per_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "podman"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            probe = subprocess.CompletedProcess([], 0, "crun\n", "")
            images = subprocess.CompletedProcess(
                [],
                0,
                "docker.io/library/python:3.12-slim\n"
                "docker.io/library/python:3.14-slim-trixie\n"
                "<none>:<none>\n",
                "",
            )
            with patch(
                "openkapsel.sandbox_backends.subprocess.run",
                side_effect=[probe, images],
            ):
                installed = self._backend(executable).installed_images()
        self.assertEqual(
            (
                "docker.io/library/python:3.12-slim",
                "docker.io/library/python:3.14-slim-trixie",
            ),
            installed,
        )
        options = _sandbox_backend_options(
            ("bubblewrap", "podman"),
            "bubblewrap",
            "docker.io/library/python:3.12-slim",
            installed,
            selected_backend="podman",
            selected_image="docker.io/library/python:3.14-slim-trixie",
        )
        self.assertIn("Podman · docker.io/library/python:3.12-slim", options)
        self.assertIn("Podman · docker.io/library/python:3.14-slim-trixie", options)
        self.assertIn(
            'value="podman::docker.io/library/python:3.14-slim-trixie" selected',
            options,
        )

    def test_controller_uses_stop_kill_and_forced_cleanup(self) -> None:
        controller = PodmanController(Path("/usr/bin/podman"), "openkapsel-test")
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("openkapsel.sandbox_backends.subprocess.run", return_value=completed) as run:
            controller.terminate()
            controller.kill()
            controller.cleanup()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            [
                ("/usr/bin/podman", "stop", "--time", "2", "openkapsel-test"),
                ("/usr/bin/podman", "kill", "openkapsel-test"),
                ("/usr/bin/podman", "rm", "--force", "openkapsel-test"),
            ],
            commands,
        )

    def test_macos_refuses_to_claim_no_network_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "podman"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            backend = self._backend(executable)
            backend.host_is_macos = True
            spec = SandboxSpec(
                command="true", cwd=workspace, scope_root=workspace,
                can_write=False, network_mode="none", allowed_domains=(),
                proxy_root=Path(directory) / "proxies", allowed_paths=(), hidden_paths=(),
                limits=SandboxLimits(4, 16 * 1024 * 1024, 100), owner_token="token",
            )
            probe = subprocess.CompletedProcess([], 0, "crun\n", "")
            with patch("openkapsel.sandbox_backends.subprocess.run", return_value=probe):
                with self.assertRaisesRegex(RuntimeError, "cannot guarantee"):
                    backend.build_shell(spec)

    def test_domain_mode_remains_offline_except_for_token_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "bwrap"
            rootlesskit = root / "rootlesskit"
            for path in (executable, rootlesskit):
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o755)
            workspace = root / "workspace"
            workspace.mkdir()
            environment_file = root / "token.rc"
            environment_file.write_text("export API_KEY=bubble-secret\n", encoding="utf-8")
            spec = SandboxSpec(
                command="git clone https://github.com/example/project.git",
                cwd=workspace,
                scope_root=workspace,
                can_write=True,
                network_mode="domain_allowlist",
                allowed_domains=("github.com",),
                proxy_root=root / "proxies",
                allowed_paths=(),
                hidden_paths=(),
                limits=SandboxLimits(64, 256 * 1024 * 1024, 100),
                owner_token="token",
                environment_file=environment_file,
            )
            with patch(
                "openkapsel.sandbox_backends.apparmor_restricts_user_namespaces",
                return_value=False,
            ):
                launch = BubblewrapBackend(
                    executable,
                    rootlesskit,
                    aggregate_resources=False,
                ).build_shell(spec)
            try:
                argv = launch.argv
                self.assertIn("--unshare-net", argv)
                self.assertNotEqual(str(rootlesskit), argv[0])
                self.assertIn("HTTP_PROXY", argv)
                self.assertIn("http://127.0.0.1:18080", argv)
                self.assertIn("/run/openkapsel-proxy-relay.py", argv)
                triples = set(zip(argv, argv[1:], argv[2:]))
                self.assertIn(
                    (
                        "--ro-bind",
                        str(environment_file),
                        "/run/openkapsel-environment.rc",
                    ),
                    triples,
                )
                self.assertNotIn("bubble-secret", " ".join(argv))
                self.assertIn(". /run/openkapsel-environment.rc", argv[-1])
                self.assertIsInstance(launch.controller, ProxyController)
                proxy_directory = launch.controller.proxy.directory
                self.assertTrue(proxy_directory.is_dir())
            finally:
                assert launch.controller is not None
                launch.controller.cleanup()
            self.assertFalse(proxy_directory.exists())


if __name__ == "__main__":
    unittest.main()

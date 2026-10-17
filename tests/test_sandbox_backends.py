from __future__ import annotations

import subprocess
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.auth.admin_ui import _sandbox_backend_options
from openkapsel.execution.cgroups import SandboxLimits
from openkapsel.execution.sandbox_backends import (
    BubblewrapBackend,
    PodmanBackend,
    PodmanController,
    ProxyController,
    SandboxSpec,
)
from openkapsel.auth.tokens import PathGrant


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
            with patch("openkapsel.execution.sandbox_backends.subprocess.run", return_value=probe):
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
                "openkapsel.execution.sandbox_backends.subprocess.run",
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

    def test_nested_directory_and_file_denies_override_writable_grants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            executable = base / "podman"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            scope = base / "workspace"
            scope.mkdir()
            extra = base / "extra"
            extra.mkdir()
            metadata = extra / ".openkapsel"
            metadata.mkdir()
            secret = extra / "secret.json"
            secret.write_text("sensitive", encoding="utf-8")
            spec = SandboxSpec(
                command="true", cwd=scope, scope_root=scope,
                can_write=True, network_mode="none", allowed_domains=(),
                proxy_root=base / "proxy",
                allowed_paths=(PathGrant(str(extra), access="rw"),),
                hidden_paths=(metadata, secret),
                limits=SandboxLimits(16, 256 * 1024 * 1024, 100),
                owner_token="token",
            )
            probe = subprocess.CompletedProcess([], 0, "crun\n", "")
            with patch("openkapsel.execution.sandbox_backends.subprocess.run", return_value=probe):
                podman = self._backend(executable).build_shell(spec).argv
            i_rw = podman.index(f"{extra}:{extra}:rw")
            i_hidden_dir = podman.index(f"{metadata}:rw,nosuid,nodev,noexec,mode=700")
            i_hidden_file = podman.index(f"/dev/null:{secret}:ro")
            self.assertLess(i_rw, i_hidden_dir)
            self.assertLess(i_rw, i_hidden_file)

            bwrap = base / "bwrap"
            rootlesskit = base / "rootlesskit"
            for entry in (bwrap, rootlesskit):
                entry.write_text("#!/bin/sh\n", encoding="utf-8")
                entry.chmod(0o755)
            with patch(
                "openkapsel.execution.sandbox_backends.apparmor_restricts_user_namespaces",
                return_value=False,
            ):
                linux = BubblewrapBackend(bwrap, rootlesskit, aggregate_resources=False).build_shell(spec).argv
            i_rw = linux.index(str(extra))
            i_hidden_dir = linux.index(str(metadata))
            i_hidden_file = linux.index(str(secret))
            self.assertLess(i_rw, i_hidden_dir)
            self.assertLess(i_rw, i_hidden_file)
            self.assertEqual("--ro-bind", linux[i_hidden_file - 2])
            self.assertEqual("/dev/null", linux[i_hidden_file - 1])

    def test_bubblewrap_parent_grant_cannot_reopen_mapping_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outer = base / "shared"
            outer.mkdir()
            workspace = outer / "mapping"
            workspace.mkdir()
            config = outer / "client.json"
            config.write_text('{"token":"sensitive"}')
            bwrap = base / "bwrap"
            rootlesskit = base / "rootlesskit"
            for executable in (bwrap, rootlesskit):
                executable.write_text("#!/bin/sh\n")
                executable.chmod(0o755)
            for can_write, parent_access, expected_root, expected_parent in (
                (False, "rw", "--ro-bind", "--bind"),
                (True, "ro", "--bind", "--ro-bind"),
                (True, "rw", "--bind", "--bind"),
            ):
                with self.subTest(can_write=can_write, parent_access=parent_access):
                    spec = SandboxSpec(
                        command="true", cwd=workspace, scope_root=workspace,
                        can_write=can_write, network_mode="none", allowed_domains=(),
                        proxy_root=base / "proxy",
                        allowed_paths=(PathGrant(str(outer), access=parent_access),),
                        hidden_paths=(config,),
                        limits=SandboxLimits(16, 256 * 1024 * 1024, 100),
                        owner_token="token",
                        allow_grant_writes_when_scope_readonly=True,
                    )
                    with patch(
                        "openkapsel.execution.sandbox_backends.apparmor_restricts_user_namespaces",
                        return_value=False,
                    ):
                        argv = BubblewrapBackend(
                            bwrap, rootlesskit, aggregate_resources=False
                        ).build_shell(spec).argv
                    def mount(path):
                        return next((i, argv[i]) for i in range(len(argv) - 2)
                                    if argv[i] in {"--bind", "--ro-bind"}
                                    and argv[i + 1] == str(path) and argv[i + 2] == str(path))
                    parent_pos, parent_mode = mount(outer)
                    root_pos, root_mode = mount(workspace)
                    self.assertLess(parent_pos, root_pos)
                    self.assertEqual(expected_parent, parent_mode)
                    self.assertEqual(expected_root, root_mode)
                    hidden_pos = argv.index(str(config))
                    self.assertGreater(hidden_pos, root_pos)
                    self.assertEqual(["--ro-bind", "/dev/null"], list(argv[hidden_pos - 2:hidden_pos]))

    def test_bubblewrap_deepest_child_overrides_parent_readonly_and_deny(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "workspace"; root.mkdir()
            parent = root / "parent"; parent.mkdir()
            child = parent / "child"; child.mkdir()
            denied = child / "denied"; denied.mkdir()
            reopened = denied / "reopened"; reopened.mkdir()
            hard = reopened / ".openkapsel"; hard.mkdir()
            bwrap, rootlesskit = base / "bwrap", base / "rootlesskit"
            for exe in (bwrap, rootlesskit):
                exe.write_text("#!/bin/sh\n")
                exe.chmod(0o755)
            spec = SandboxSpec(
                command="true", cwd=root, scope_root=root, can_write=True,
                network_mode="none", allowed_domains=(), proxy_root=base / "proxy",
                allowed_paths=tuple(PathGrant(str(p), access=mode)
                    for p, mode in ((parent,"ro"), (child,"rw"),
                                    (denied,"deny"), (reopened,"rw"))),
                hidden_paths=(hard,), limits=SandboxLimits(16, 256*1024*1024,100),
                owner_token="test", allow_grant_writes_when_scope_readonly=True,
            )
            with patch("openkapsel.execution.sandbox_backends.apparmor_restricts_user_namespaces",
                       return_value=False):
                argv = BubblewrapBackend(bwrap,rootlesskit,aggregate_resources=False).build_shell(spec).argv
            def mount(path):
                return next((i,argv[i]) for i in range(len(argv)-2)
                            if argv[i] in {"--bind","--ro-bind","--tmpfs"}
                            and ((argv[i]=="--tmpfs" and argv[i+1]==str(path))
                                 or (argv[i+1]==str(path) and argv[i+2]==str(path))))
            p0,p1,p2,p3 = (mount(p) for p in (parent,child,denied,reopened))
            self.assertEqual(["--ro-bind","--bind","--tmpfs","--bind"],
                             [p0[1],p1[1],p2[1],p3[1]])
            self.assertLess(p0[0],p1[0])
            self.assertLess(p1[0],p2[0])
            self.assertLess(p2[0],p3[0])
            self.assertGreater(argv.index(str(hard)),p3[0])

    def test_controller_uses_stop_kill_and_forced_cleanup(self) -> None:
        controller = PodmanController(Path("/usr/bin/podman"), "openkapsel-test")
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("openkapsel.execution.sandbox_backends.subprocess.run", return_value=completed) as run:
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
            with patch("openkapsel.execution.sandbox_backends.subprocess.run", return_value=probe):
                with self.assertRaisesRegex(RuntimeError, "cannot guarantee"):
                    backend.build_shell(spec)

    def test_bubblewrap_binds_rhel_certificate_store_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "bwrap"
            rootlesskit = root / "rootlesskit"
            workspace = root / "workspace"
            for path in (executable, rootlesskit):
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o755)
            workspace.mkdir()
            spec = SandboxSpec(
                command="true", cwd=workspace, scope_root=workspace,
                can_write=True, network_mode="full", allowed_domains=(),
                proxy_root=root / "proxies", allowed_paths=(), hidden_paths=(),
                limits=SandboxLimits(64, 256 * 1024 * 1024, 100), owner_token="token",
            )
            original_exists = Path.exists
            def exists(path: Path) -> bool:
                return str(path) == "/etc/pki" or original_exists(path)
            with (
                patch(
                    "openkapsel.execution.sandbox_backends.apparmor_restricts_user_namespaces",
                    return_value=False,
                ),
                patch("pathlib.Path.exists", autospec=True, side_effect=exists),
            ):
                argv = BubblewrapBackend(
                    executable, rootlesskit, aggregate_resources=False
                ).build_shell(spec).argv
            triples = set(zip(argv, argv[1:], argv[2:]))
            self.assertIn(("--ro-bind", "/etc/pki", "/etc/pki"), triples)

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
                "openkapsel.execution.sandbox_backends.apparmor_restricts_user_namespaces",
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


@unittest.skipIf(os.name == "nt", "POSIX Shell descriptor handoff")
class BubblewrapResolverTests(unittest.TestCase):
    def test_resolver_survives_rootlesskit_closing_all_extra_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bwrap, rootlesskit = root / "bwrap", root / "rootlesskit"
            bwrap.write_text("#!" + sys.executable + "\nimport os,sys\n"
                "i=sys.argv.index('--file'); print(os.read(int(sys.argv[i+1]),256).decode(),end='')\n"
                "print('stdin=' + sys.stdin.read())\n")
            rootlesskit.write_text("#!" + sys.executable + "\nimport os,sys\n"
                "os.closerange(3,1024)\n"
                "args=sys.argv[sys.argv.index('--')+1:]; os.execv(args[0],args)\n")
            for executable in (bwrap, rootlesskit):
                executable.chmod(0o700)
            spec = SandboxSpec(command="true", cwd=root, scope_root=root,
                can_write=False, network_mode="full", allowed_domains=(),
                proxy_root=root, allowed_paths=(), hidden_paths=(),
                limits=SandboxLimits(64, 256*1024*1024, 100),
                owner_token="test")
            launch = BubblewrapBackend(bwrap, rootlesskit, aggregate_resources=False).build_shell(spec)
            result = subprocess.run(launch.argv, input=b'caller input', capture_output=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn(b'nameserver 10.0.2.3\n', result.stdout)
            self.assertIn(b'stdin=caller input', result.stdout)


if __name__ == "__main__":
    unittest.main()

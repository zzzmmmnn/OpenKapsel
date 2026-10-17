"""Real restricted Job Manager launch checks.

Tests do not claim isolation by mocking the sandbox subprocess.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import textwrap
import tempfile
import time
import unittest
from unittest.mock import patch

from openkapsel.job_sandbox import prepare_job
from openkapsel.job_manager import request, shutdown


class JobSandboxTests(unittest.TestCase):
    MAPPING = "S" * 24

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-job-sandbox-")
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name).resolve()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.state = self.base / "manager"
        self.state.mkdir()
        (self.workspace / "allowed.txt").write_text("VISIBLE", encoding="utf-8")
        (self.base / "private.txt").write_text("SECRET", encoding="utf-8")

    def _spec(self, kind, **kw):
        return dict(type=kind, root=str(self.workspace), **kw)

    def test_macos_selected_xcode_developer_root_is_narrowly_trusted(self):
        from openkapsel.job_sandbox import _trusted_macos_xcode_developer_dir
        allowed = [
            "/Applications/Xcode.app/Contents/Developer",
            "/Applications/Xcode_26.6.app/Contents/Developer",
            "/Applications/Xcode-beta.app/Contents/Developer",
        ]
        denied = [
            "/Applications",
            "/Applications/Xcode_26.6.app",
            "/Applications/Other.app/Contents/Developer",
            "/Users/runner/Xcode_26.6.app/Contents/Developer",
            "/Applications/Xcode_26.6.app/Contents/Developer/usr/lib",
            "/Applications/Xcode_26.6.app/Contents/Developer/../../..",
        ]
        for item in allowed:
            with self.subTest(item=item):
                self.assertTrue(_trusted_macos_xcode_developer_dir(pathlib.Path(item)))
        for item in denied:
            with self.subTest(item=item):
                self.assertFalse(_trusted_macos_xcode_developer_dir(pathlib.Path(item)))

    @unittest.skipUnless(platform.system() == "Darwin", "Only Seatbelt is configured on macOS")
    def test_seatbelt_grants_only_selected_xcode_app_tree(self):
        from openkapsel import job_sandbox
        selected = pathlib.Path("/Applications/Xcode_26.6.app/Contents/Developer")
        with patch.object(job_sandbox, "_macos_xcode_developer_dir", return_value=selected):
            prepared = prepare_job(
                self._spec("seatbelt", writable=True, network_mode="none"),
                ["/usr/bin/python3", "-c", "print('ok')"],
                str(self.workspace), dict(os.environ), self.state,
            )
        try:
            profile = prepared.argv[prepared.argv.index("-p") + 1]
            # Xcode's xcodebuild loads frameworks outside Contents/Developer,
            # including Contents/SharedFrameworks/DVTSystemPrerequisites.
            app_root = selected.parent.parent
            framework = app_root / "Contents/SharedFrameworks/DVTSystemPrerequisites.framework"
            self.assertTrue(framework.is_relative_to(app_root))
            self.assertIn(f'(allow file-read* (subpath "{app_root}"))', profile)
            self.assertNotIn(f'(allow file-read* (subpath "{selected}"))', profile)
            self.assertNotIn('(allow file-read* (subpath "/Applications"))', profile)
            self.assertNotIn('(allow file-read* (subpath "/Users"))', profile)
            self.assertIn('(allow file-write* (literal "/dev/null"))', profile)
            self.assertNotIn('(allow file-write* (subpath "/dev"))', profile)
            self.assertIn('deny network-outbound (remote unix-socket)', profile)
            self.assertIn('deny file-read* (literal', profile)
        finally:
            prepared.cleanup()

    def test_invalid_grants_and_modes_rejected_before_launch(self):
        if platform.system() == "Windows":
            self.skipTest("Windows has no native Job Manager sandbox")
        kind = {"Darwin": "seatbelt", "Linux": "bubblewrap"}[platform.system()]
        cases = [
            dict(root="/"),
            dict(writable="yes"),
            dict(network_mode="surprise"),
            dict(allowed_domains=["example.com"]),
            dict(network_mode="domain_allowlist", allowed_domains=[]),
            dict(allowed_paths=[{"path": "/", "access": "rw"}]),
            dict(hidden_paths=[str(self.base / "private.txt")]),
            dict(root=str(self.state)),
        ]
        for override in cases:
            with self.subTest(override=override):
                spec = self._spec(kind)
                spec.update(override)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    prepared = prepare_job(spec, ["/bin/echo", "ok"], str(self.workspace), {}, self.state)
                    prepared.cleanup()

    def test_broad_parent_grant_masks_manager_state_in_bubblewrap(self):
        """Parent RW access must not expose Manager DB, spools or IPC key."""
        from openkapsel.execution.sandbox_backends import SandboxLaunch

        (self.state / "ipc.key").write_text("PRIVATE")
        spec = self._spec(
            "bubblewrap", writable=False, network_mode="none",
            allowed_paths=[{"path": str(self.base), "access": "rw"}],
        )
        with (
            patch("openkapsel.job_sandbox.platform.system", return_value="Linux"),
            patch("openkapsel.job_sandbox.BubblewrapBackend.build_shell",
                  return_value=SandboxLaunch("bubblewrap", ("/bin/true",))) as build,
        ):
            prepared = prepare_job(
                spec, ["/bin/true"], str(self.workspace), {}, self.state,
            )
        try:
            policy = build.call_args.args[0]
            self.assertEqual(str(self.base), policy.allowed_paths[0].path)
            self.assertIn(self.state, policy.hidden_paths)
            self.assertFalse(policy.can_write)
        finally:
            prepared.cleanup()

    def test_explicit_manager_deny_merges_with_auto_exclusion(self):
        """A user's explicit deny must not make an otherwise valid grant fail."""
        from openkapsel.execution.sandbox_backends import SandboxLaunch
        key = self.state / "ipc.key"
        key.write_text("PRIVATE")
        with (
            patch("openkapsel.job_sandbox.platform.system", return_value="Linux"),
            patch("openkapsel.job_sandbox.BubblewrapBackend.build_shell",
                  return_value=SandboxLaunch("bubblewrap", ("/bin/true",))) as build,
        ):
            prepared = prepare_job({
                "type": "bubblewrap", "root": str(self.workspace),
                "allowed_paths": [{"path": str(self.base), "access": "rw"}],
                "hidden_paths": [str(self.state), str(key)],
            }, ["/bin/true"], str(self.workspace), {}, self.state)
        try:
            excluded = build.call_args.args[0].hidden_paths
            self.assertEqual(1, excluded.count(self.state))
            self.assertNotIn(key, excluded)
        finally:
            prepared.cleanup()

    def test_workspace_containing_manager_state_is_masked(self):
        """Also support an exported workspace that encloses private state."""
        from openkapsel.execution.sandbox_backends import SandboxLaunch

        with (
            patch("openkapsel.job_sandbox.platform.system", return_value="Linux"),
            patch("openkapsel.job_sandbox.BubblewrapBackend.build_shell",
                  return_value=SandboxLaunch("bubblewrap", ("/bin/true",))) as build,
        ):
            prepared = prepare_job(
                {"type": "bubblewrap", "root": str(self.base), "writable": True},
                ["/bin/true"], str(self.workspace), {}, self.state,
            )
        try:
            self.assertIn(self.state, build.call_args.args[0].hidden_paths)
        finally:
            prepared.cleanup()

    def test_cannot_grant_paths_inside_manager_private_state(self):
        inside = self.state / "spool"
        inside.mkdir()
        for grant in (self.state, inside):
            with self.subTest(grant=grant), patch(
                "openkapsel.job_sandbox.platform.system", return_value="Linux"
            ):
                with self.assertRaisesRegex(ValueError, "grant is inside Manager state"):
                    prepare_job({
                        "type": "bubblewrap", "root": str(self.workspace),
                        "allowed_paths": [{"path": str(grant), "access": "rw"}],
                    }, ["/bin/true"], str(self.workspace), {}, self.state)

    def test_seatbelt_parent_rw_denies_state_but_allows_job_scratch(self):
        (self.state / "ipc.key").write_text("PRIVATE")
        with (
            patch("openkapsel.job_sandbox.platform.system", return_value="Darwin"),
            patch("openkapsel.job_sandbox.shutil.which", return_value=sys.executable),
            patch("openkapsel.job_sandbox._macos_xcode_developer_dir", return_value=None),
        ):
            prepared = prepare_job({
                "type": "seatbelt", "root": str(self.workspace), "writable": False,
                "allowed_paths": [{"path": str(self.base), "access": "rw"}],
            }, ["/bin/true"], str(self.workspace), {}, self.state)
        try:
            profile = prepared.argv[prepared.argv.index("-p") + 1]
            state_deny = f'(deny file-read* (subpath "{self.state}"))'
            scratch_allow = f'(allow file-write* (subpath "{prepared.temp_dir}"))'
            self.assertIn(f'(allow file-read* (subpath "{self.base}"))', profile)
            self.assertIn(state_deny, profile)
            self.assertIn(f'(deny file-write* (subpath "{self.state}"))', profile)
            self.assertIn(f'(deny file-read* (literal "{self.state / "ipc.key"}"))', profile)
            self.assertIn(scratch_allow, profile)
            self.assertLess(profile.index(state_deny), profile.index(scratch_allow))
        finally:
            prepared.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin", "requires actual macOS Seatbelt")
    def test_real_macos_broad_parent_grant_excludes_manager_state(self):
        """Probe real read/write access: siblings allowed, Manager files denied."""
        import shlex
        secret = self.state / "ipc.key"
        secret.write_text("MANAGER_SECRET")
        output = self.base / "parent-write.txt"
        command = (
            f"if cat {shlex.quote(str(self.base / 'private.txt'))} >/dev/null 2>&1; "
            "then echo parent-readable; else echo parent-denied; fi; "
            f"if cat {shlex.quote(str(secret))} >/dev/null 2>&1; "
            "then echo manager-readable; else echo manager-denied; fi; "
            f"if printf allowed > {shlex.quote(str(output))} 2>/dev/null; "
            "then echo parent-writable; else echo parent-write-denied; fi; "
            f"if printf blocked > {shlex.quote(str(secret))} 2>/dev/null; "
            "then echo manager-writable; else echo manager-write-denied; fi; "
            'if printf scratch > "$TMPDIR/test-scratch" 2>/dev/null; '
            "then echo scratch-writable; else echo scratch-denied; fi"
        )
        prepared = prepare_job({
            "type": "seatbelt", "root": str(self.workspace), "writable": False,
            "allowed_paths": [{"path": str(self.base), "access": "rw"}],
        }, ["/bin/sh", "-c", command], str(self.workspace), dict(os.environ),
            self.state)
        try:
            result = subprocess.run(
                prepared.argv, cwd=self.workspace, env=prepared.environment,
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            for expected in ("parent-readable", "manager-denied",
                             "parent-writable", "manager-write-denied",
                             "scratch-writable"):
                self.assertIn(expected, result.stdout, result.stdout + result.stderr)
            self.assertEqual("MANAGER_SECRET", secret.read_text())
            self.assertEqual("allowed", output.read_text())
        finally:
            prepared.cleanup()

    def test_parent_grant_and_config_deny_survive_manager_policy(self):
        from openkapsel.execution.sandbox_backends import SandboxLaunch
        outer = self.base / "shared"
        outer.mkdir()
        root = outer / "mapping"
        root.mkdir()
        secret = outer / "client.json"
        secret.write_text('{"token":"private"}')
        spec = {
            "type": "bubblewrap", "root": str(root), "writable": False,
            "allowed_paths": [{"path": str(outer), "access": "rw"}],
            "hidden_paths": [str(secret)], "network_mode": "none",
        }
        with (
            patch("openkapsel.job_sandbox.platform.system", return_value="Linux"),
            patch("openkapsel.job_sandbox.BubblewrapBackend.build_shell",
                  return_value=SandboxLaunch("bubblewrap", ("/bin/true",), None)) as build,
        ):
            prepared = prepare_job(spec, ["/bin/true"], str(root), {}, self.state)
        try:
            normalized = build.call_args.args[0]
            self.assertEqual(str(root), str(normalized.scope_root))
            self.assertFalse(normalized.can_write)
            self.assertIn(secret, normalized.hidden_paths)
            self.assertEqual("rw", normalized.allowed_paths[0].access)
        finally:
            prepared.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin", "needs macOS Seatbelt")
    def test_real_seatbelt_nested_readonly_deny_then_child_writable(self):
        parent = self.workspace / "parent"; parent.mkdir()
        child = parent / "rw"; child.mkdir()
        denied = child / "deny"; denied.mkdir()
        reopened = denied / "reopen"; reopened.mkdir()
        secret = reopened / ".openkapsel"; secret.mkdir()
        (secret / "config").write_text("PRIVATE")
        code = (
            "from pathlib import Path; p=Path.cwd();"
            "\nfor f in ('parent/nope','parent/rw/yes','parent/rw/deny/nope',"
            "'parent/rw/deny/reopen/yes'):\n"
            " try: (p/f).write_text('ok'); print(f, 'WRITTEN')\n"
            " except OSError: print(f, 'DENIED')\n"
            "\ntry: (p/'parent/rw/deny/reopen/.openkapsel/config').read_text();"
            " print('CONFIG_READABLE')\n"
            "except OSError: print('CONFIG_DENIED')\n"
        )
        launch = prepare_job({
            "type": "seatbelt", "root": str(self.workspace), "writable": True,
            "network_mode": "none", "allowed_paths": [
                {"path":str(parent),"access":"ro"},
                {"path":str(child),"access":"rw"},
                {"path":str(denied),"access":"deny"},
                {"path":str(reopened),"access":"rw"},
            ], "hidden_paths": [str(secret)],
        }, [sys.executable,"-c",code],str(self.workspace),dict(os.environ),self.state)
        try:
            result = subprocess.run(launch.argv,cwd=self.workspace,env=launch.environment,
                                    capture_output=True,text=True,timeout=20)
            self.assertEqual(0,result.returncode,result.stderr)
            for expected in ("parent/nope DENIED","parent/rw/yes WRITTEN",
                             "parent/rw/deny/nope DENIED",
                             "parent/rw/deny/reopen/yes WRITTEN","CONFIG_DENIED"):
                self.assertIn(expected,result.stdout,result.stderr)
            self.assertFalse((denied/"nope").exists())
            self.assertEqual("ok",(reopened/"yes").read_text())
            self.assertEqual("PRIVATE",(secret/"config").read_text())
        finally:
            launch.cleanup()

    def test_seatbelt_parent_write_grant_keeps_readonly_mapping_and_denied_config(self):
        outer = self.base / "shared-mac"
        outer.mkdir()
        root = outer / "mapping"
        root.mkdir()
        secret = outer / "client.json"
        secret.write_text('{"token":"private"}')
        with (
            patch("openkapsel.job_sandbox.platform.system", return_value="Darwin"),
            patch("openkapsel.job_sandbox.shutil.which", return_value=sys.executable),
            patch("openkapsel.job_sandbox._macos_xcode_developer_dir", return_value=None),
        ):
            prepared = prepare_job(
                {"type": "seatbelt", "root": str(root), "writable": False,
                 "allowed_paths": [{"path": str(outer), "access": "rw"}],
                 "hidden_paths": [str(secret)], "network_mode": "none"},
                ["/bin/sh", "-c", "true"], str(root), {}, self.state,
            )
        try:
            profile = prepared.argv[prepared.argv.index("-p") + 1]
            self.assertIn(f'(allow file-write* (subpath "{outer}"))', profile)
            self.assertIn(f'(deny file-write* (subpath "{root}"))', profile)
            self.assertIn(f'(deny file-read* (literal "{secret}"))', profile)
            self.assertIn(f'(deny file-write* (literal "{secret}"))', profile)
        finally:
            prepared.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin", "requires actual macOS Seatbelt")
    def test_real_macos_parent_rw_cannot_override_mapping_ro_or_config_deny(self):
        import shlex
        outer = self.base / "shared-real-mac"
        outer.mkdir()
        root = outer / "mapping"
        root.mkdir()
        visible = root / "visible.txt"
        visible.write_text("visible")
        secret = outer / "client.json"
        secret.write_text('{"token":"private"}')
        blocked = root / "blocked.txt"
        writable = outer / "created.txt"
        cmd = (
            f"if (exec 3< {shlex.quote(str(visible))}) 2>/dev/null; then "
            "echo root-readable; else echo root-unreadable; fi; "
            f"if (printf blocked > {shlex.quote(str(blocked))}) 2>/dev/null; then "
            "echo root-writable; else echo root-denied; fi; "
            f"if (exec 3< {shlex.quote(str(secret))}) 2>/dev/null; then "
            "echo config-readable; else echo config-denied; fi; "
            f"if (printf allowed > {shlex.quote(str(writable))}) 2>/dev/null; then "
            "echo parent-writable; else echo parent-denied; fi"
        )
        prepared = prepare_job(
            {"type": "seatbelt", "root": str(root), "writable": False,
             "allowed_paths": [{"path": str(outer), "access": "rw"}],
             "hidden_paths": [str(secret)], "network_mode": "none"},
            ["/bin/sh", "-c", cmd], str(root), dict(os.environ), self.state,
        )
        try:
            outcome = subprocess.run(
                prepared.argv, cwd=root, env=prepared.environment,
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(0, outcome.returncode, outcome.stderr)
            for expected in ("root-readable", "root-denied", "config-denied",
                             "parent-writable"):
                self.assertIn(expected, outcome.stdout, outcome.stderr)
            self.assertFalse(blocked.exists())
            self.assertEqual("allowed", writable.read_text())
        finally:
            prepared.cleanup()

    def test_manager_launcher_survives_transient_request_thread(self):
        # Bubblewrap's --die-with-parent monitors the Popen caller's Linux
        # thread, not the entire process. The Manager's IPC request threads
        # finish quickly, so a long-lived launcher must create each child.
        import threading
        from openkapsel.job_manager import Manager

        manager = Manager(self.state)
        try:
            result = {}

            def start():
                result["process"] = manager._spawn(
                    [sys.executable, "-c", "import time; time.sleep(.2)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )

            handler = threading.Thread(target=start)
            handler.start()
            handler.join(timeout=5)
            self.assertFalse(handler.is_alive())
            self.assertIn("process", result)
            self.assertTrue(manager.launcher.is_alive())
            self.assertEqual(0, result["process"].wait(timeout=5))
        finally:
            manager.launch_queue.put(None)
            manager.launcher.join(timeout=5)
            manager.db.close()

    @unittest.skipUnless(
        platform.system() == "Linux"
        and os.environ.get("OPENKAPSEL_REAL_SANDBOX_TESTS") == "1",
        "requires real Linux Bubblewrap and a running Job Manager",
    )
    def test_manager_bubblewrap_survives_early_ipc_thread_exit(self):
        # A short RPC handler must not kill a longer-running sandboxed job.
        # Last-command exec optimization also exposed intermittent SIGKILLs.
        self.assertIsNotNone(shutil.which("bwrap"))
        self.addCleanup(shutdown, self.state, force=True)
        job_id = "&Pb4w&"
        request(self.state, self.MAPPING, "task_start", {
            "task_id": job_id,
            "argv": ["/bin/sh", "-c",
                     "/usr/bin/sleep .3; /usr/bin/printf 'LAUNCH_SURVIVED\\n'"],
            "cwd": str(self.workspace),
            "env": {"PATH": "/usr/bin:/bin"},
            "interactive": False,
            "timeout_seconds": 15,
            "sandbox": json.dumps(self._spec(
                "bubblewrap", writable=False, network_mode="none")),
        })
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            result = request(self.state, self.MAPPING, "task_get",
                             {"task_id": job_id})
            if not result["running"]:
                break
            time.sleep(.05)
        else:
            self.fail("sandboxed Job Manager process failed to exit")
        output = base64.b64decode(result.get("output", ""))
        self.assertEqual(0, result["exit_code"], output)
        self.assertIn(b"LAUNCH_SURVIVED", output)

    @unittest.skipUnless(
        platform.system() == "Linux"
        and os.environ.get("OPENKAPSEL_REAL_SANDBOX_TESTS") == "1",
        "real Job Manager Bubblewrap runs in dedicated Linux CI",
    )
    def test_bubblewrap_real_filesystem_network_and_hidden_files(self):
        self.assertIsNotNone(shutil.which("bwrap"))
        hidden = self.workspace / "hidden.txt"
        hidden.write_text("HIDDEN", encoding="utf-8")
        code = (
            'import pathlib,socket;'
            'print("inside",pathlib.Path("allowed.txt").read_text());'
            '\ntry:print("outside",pathlib.Path("../private.txt").read_text())'
            '\nexcept OSError:print("outside_denied")'
            '\ntry:print("masked",repr(pathlib.Path("hidden.txt").read_text()))'
            '\nexcept OSError:print("masked_denied")'
            '\ntry:pathlib.Path("created.txt").write_text("bad")'
            '\nexcept OSError:print("write_denied")'
            '\ns=socket.socket();print("net_denied",s.connect_ex(("1.1.1.1",443)))'
        )
        prepared = prepare_job(
            self._spec("bubblewrap", writable=False, network_mode="none",
                       hidden_paths=[str(hidden)]),
            ["/usr/bin/python3", "-c", code], str(self.workspace),
            dict(os.environ), self.state,
        )
        try:
            result = subprocess.run(
                prepared.argv, cwd=self.workspace, env=prepared.environment,
                pass_fds=prepared.pass_fds, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            for needle in ("inside VISIBLE", "outside_denied",
                           "write_denied", "net_denied"):
                self.assertIn(needle, result.stdout)
            self.assertNotIn("HIDDEN", result.stdout)
            self.assertTrue("masked ''" in result.stdout or "masked_denied" in result.stdout)
            self.assertFalse((self.workspace / "created.txt").exists())
        finally:
            prepared.cleanup()

    @unittest.skipIf(os.name == "nt", "POSIX pass_fds is required")
    def test_manager_bubblewrap_resolver_fd_three_survives_rootlesskit(self):
        # Force the Job Manager's tempfile to get fd=3 in a fresh process,
        # then simulate RootlessKit consuming/closing descriptor 3. This
        # reproduces the actual CI failure without needing bwrap installed.
        probe = textwrap.dedent(r"""
            import os
            import pathlib
            import subprocess
            import sys
            import tempfile
            from unittest.mock import patch

            from openkapsel.execution.sandbox_backends import SandboxLaunch
            from openkapsel.execution.tasks import RESOLVER_FD_MARKER
            from openkapsel.job_sandbox import prepare_job

            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                workspace = root / "workspace"
                state = root / "state"
                workspace.mkdir()
                state.mkdir()
                # The fake rootlesskit child closes fd3 before reading the
                # resolver content using Bubblewrap's --file descriptor.
                reader = (
                    "import os,sys;"
                    "\ntry:os.close(3)"
                    "\nexcept OSError:pass"
                    "\nprint(os.read(int(sys.argv[1]), 256).decode())"
                )
                launch = SandboxLaunch(
                    "bubblewrap",
                    (sys.executable, "-c", reader, RESOLVER_FD_MARKER),
                    b"nameserver 10.0.2.3\n",
                )
                with (
                    patch("openkapsel.job_sandbox.platform.system",
                          return_value="Linux"),
                    patch("openkapsel.job_sandbox.BubblewrapBackend.build_shell",
                          return_value=launch),
                ):
                    try:
                        os.close(3)
                    except OSError:
                        pass
                    prepared = prepare_job(
                        {"type": "bubblewrap", "root": str(workspace),
                         "network_mode": "full"},
                        ["/usr/bin/python3", "-c", "print('ok')"],
                        str(workspace), {}, state,
                    )
                try:
                    descriptor = prepared.pass_fds[0]
                    assert descriptor > 3, f"fd collision: {descriptor}"
                    child = subprocess.run(
                        prepared.argv, pass_fds=prepared.pass_fds,
                        capture_output=True, text=True, timeout=10,
                    )
                    assert child.returncode == 0, child.stderr
                    assert child.stdout.strip() == "nameserver 10.0.2.3"
                    prepared.launched()
                    try:
                        os.fstat(descriptor)
                    except OSError:
                        pass
                    else:
                        raise AssertionError("launched() leaked resolver fd")
                finally:
                    prepared.cleanup()
            print("fd-3-rootlesskit-safe")
        """)
        outcome = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=pathlib.Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(0, outcome.returncode, outcome.stdout + outcome.stderr)
        self.assertIn("fd-3-rootlesskit-safe", outcome.stdout)

    @unittest.skipUnless(
        platform.system() == "Linux"
        and os.environ.get("OPENKAPSEL_REAL_SANDBOX_TESTS") == "1",
        "requires real Linux Bubblewrap installation and namespaces",
    )
    def test_bubblewrap_cannot_reach_manager_unix_socket(self):
        from openkapsel.job_manager import endpoint, ensure_running
        ensure_running(self.state)
        self.addCleanup(shutdown, self.state, force=True)
        address, family = endpoint(self.state)
        self.assertEqual("AF_UNIX", family)
        secret = self.state / "ipc.key"
        code = (
            "import socket,pathlib;"
            "s=socket.socket(socket.AF_UNIX);"
            "print('socket_result',s.connect_ex(" + repr(address) + "));"
            "\ntry:print('secret',pathlib.Path(" + repr(str(secret)) + ").read_bytes())"
            "\nexcept OSError:print('secret_blocked')"
        )
        prepared = prepare_job(
            self._spec("bubblewrap", writable=True, network_mode="full"),
            ["/usr/bin/python3", "-c", code], str(self.workspace),
            dict(os.environ), self.state,
        )
        try:
            result = subprocess.run(
                prepared.argv, cwd=self.workspace, env=prepared.environment,
                pass_fds=prepared.pass_fds,
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("secret_blocked", result.stdout)
            self.assertRegex(result.stdout, r"socket_result (?!0\b)\d+")
        finally:
            prepared.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin" and shutil.which("sandbox-exec"),
                         "macOS Seatbelt is required")
    def test_seatbelt_cannot_contact_manager_unix_socket_even_with_full_network(self):
        from openkapsel.job_manager import endpoint, ensure_running
        ensure_running(self.state)
        self.addCleanup(shutdown, self.state, force=True)
        address, family = endpoint(self.state)
        self.assertEqual("AF_UNIX", family)
        secret = self.state / "ipc.key"
        code = (
            "import pathlib,socket,tempfile,os;"
            "s=socket.socket(socket.AF_UNIX);"
            "print('socket_result',s.connect_ex(" + repr(address) + "));"
            "\ntry:print('manager_secret',pathlib.Path(" + repr(str(secret)) + ").read_bytes())"
            "\nexcept OSError:print('manager_secret_blocked')"
            "\nwith tempfile.TemporaryFile(dir=os.environ['TMPDIR']) as f: f.write(b'OK')"
            "\nprint('job_temp_writable')"
        )
        prepared = prepare_job(
            self._spec("seatbelt", writable=True, network_mode="full"),
            [sys.executable, "-c", code], str(self.workspace),
            dict(os.environ), self.state,
        )
        try:
            result = subprocess.run(
                prepared.argv, cwd=self.workspace, env=prepared.environment,
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("manager_secret_blocked", result.stdout)
            self.assertIn("job_temp_writable", result.stdout)
            self.assertRegex(result.stdout, r"socket_result (?:1|2|13|61)")
        finally:
            prepared.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin" and shutil.which("sandbox-exec"),
                         "macOS Seatbelt is required")
    def test_seatbelt_real_filesystem_and_network_isolation(self):
        # read-only sandbox cannot modify root, and cannot read sibling files.
        code = (
            'import pathlib,socket;'
            'print("inside",pathlib.Path("allowed.txt").read_text());'
            '\ntry: print("outside",pathlib.Path("../private.txt").read_text())'
            '\nexcept OSError as e: print("outside_denied",e.errno)'
            '\ntry: pathlib.Path("created.txt").write_text("bad")'
            '\nexcept OSError as e: print("write_denied",e.errno)'
            '\ns=socket.socket();print("network_denied",s.connect_ex(("1.1.1.1",443)))'
        )
        sandbox = prepare_job(
            self._spec("seatbelt", writable=False, network_mode="none"),
            [sys.executable, "-c", code], str(self.workspace), dict(os.environ), self.state,
        )
        try:
            result = subprocess.run(sandbox.argv, cwd=self.workspace,
                                    env=sandbox.environment, capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("inside VISIBLE", result.stdout)
            self.assertIn("outside_denied 1", result.stdout)
            self.assertIn("write_denied 1", result.stdout)
            self.assertIn("network_denied 1", result.stdout)
            self.assertFalse((self.workspace / "created.txt").exists())
        finally:
            sandbox.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin" and shutil.which("sandbox-exec"),
                         "macOS Seatbelt is required")
    def test_seatbelt_domain_proxy_is_exclusive_network_egress(self):
        code = (
            'import os,socket,urllib.parse;'
            'p=urllib.parse.urlsplit(os.environ["HTTP_PROXY"]);'
            's=socket.socket();print("proxy_connect",s.connect_ex((p.hostname,p.port)));s.close();'
            '\ns=socket.socket();print("localhost_other_denied",s.connect_ex(("127.0.0.1",1)));s.close();'
            '\ns=socket.socket();print("external_denied",s.connect_ex(("1.1.1.1",443)));s.close();'
            '\ns=socket.create_connection((p.hostname,p.port),timeout=3);'
            's.sendall(b"GET http://blocked.example/ HTTP/1.1\\r\\nHost: blocked.example\\r\\n\\r\\n");'
            'print("proxy_policy",s.recv(100).split(b"\\r\\n",1)[0].decode());s.close()'
        )
        sandbox = prepare_job(
            self._spec("seatbelt", network_mode="domain_allowlist",
                       allowed_domains=["example.com"]),
            [sys.executable, "-c", code], str(self.workspace), dict(os.environ), self.state,
        )
        try:
            result = subprocess.run(sandbox.argv, cwd=self.workspace,
                                    env=sandbox.environment, capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stderr)
            for phrase in ("proxy_connect 0", "localhost_other_denied 1",
                           "external_denied 1", "proxy_policy HTTP/1.1 403"):
                self.assertIn(phrase, result.stdout)
        finally:
            sandbox.cleanup()

    @unittest.skipUnless(platform.system() == "Darwin" and shutil.which("sandbox-exec"),
                         "macOS Seatbelt is required")
    def test_seatbelt_managed_job_persists_output_and_cleans_proxy(self):
        tid = "&Sb1x&"
        args = dict(
            task_id=tid,
            argv=[sys.executable, "-c", 'import pathlib;print(pathlib.Path("allowed.txt").read_text())'],
            cwd=str(self.workspace), timeout_seconds=10, env={},
            sandbox=json.dumps(self._spec("seatbelt", network_mode="domain_allowlist",
                                           allowed_domains=["example.com"])),
        )
        try:
            started = request(self.state, self.MAPPING, "task_start", args)
            self.assertEqual(tid, started["task_id"])
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                result = request(self.state, self.MAPPING, "task_get", {"task_id": tid})
                if not result["running"]:
                    break
                time.sleep(.05)
            self.assertFalse(result["running"])
            self.assertEqual(0, result["exit_code"])
            self.assertIn(b"VISIBLE", base64.b64decode(result["output"]))
            # Proxy and temporary workspace are cleaned by the Job collector.
            deadline = time.monotonic() + 5
            while list((self.state / "sandboxes").glob("job-*")) and time.monotonic() < deadline:
                time.sleep(.04)
            self.assertFalse(list((self.state / "sandboxes").glob("job-*")))
        finally:
            try:
                shutdown(self.state, force=True)
            except (OSError, ConnectionError):
                pass


if __name__ == "__main__":
    unittest.main()

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
import tempfile
import time
import unittest

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

    def test_invalid_grants_and_modes_rejected_before_launch(self):
        kind = {"Darwin": "seatbelt", "Linux": "bubblewrap",
                "Windows": "srt_windows"}[platform.system()]
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
            ["/usr/bin/python3", "-c", code], str(self.workspace), dict(os.environ), self.state,
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
            ["/usr/bin/python3", "-c", code], str(self.workspace), dict(os.environ), self.state,
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
            argv=["/usr/bin/python3", "-c", 'import pathlib;print(pathlib.Path("allowed.txt").read_text())'],
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

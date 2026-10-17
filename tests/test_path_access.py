"""Access mode, overlap and legacy Server token compatibility regression tests."""
from __future__ import annotations

import errno
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.auth.tokens import PathGrant, TokenRecord, TokenStore, utc_now
from openkapsel.auth.path_access import effective_path_access
from openkapsel.auth.admin_ui import _path_grant_rows
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.job_sandbox_config import make_job_sandbox
from openkapsel.errors import ApiError
from openkapsel.job_sandbox import prepare_job
from openkapsel.server_runtime.http_support import HttpSupportMixin


class PathAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-access-rules-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.sub = self.root / "data"
        self.sub.mkdir()
        self.secret = self.sub / "secret.json"
        self.secret.write_text("SENSITIVE")
        self.metadata = self.sub / ".openkapsel"
        self.metadata.mkdir()
        (self.metadata / "config.json").write_text("HIDDEN")

    def test_restrictive_priority_and_implicit_workspace(self):
        grants = (
            PathGrant(str(self.sub), access="ro"),
            PathGrant(str(self.secret), access="deny"),
            PathGrant(str(self.sub), access="rw"),
        )
        self.assertEqual("deny", effective_path_access(self.secret, self.root, True, grants))
        self.assertEqual("ro", effective_path_access(self.sub / "normal.txt", self.root, True, grants))
        self.assertEqual("rw", effective_path_access(self.root / "other.txt", self.root, True, grants))
        self.assertEqual("deny", effective_path_access(self.metadata / "config.json", self.root, True, ()))
        self.assertIsNone(effective_path_access(self.base / "elsewhere", self.root, True, grants))
        # A deny outside any normal permitted root still wins when checked
        # as the lexical alias of a separately approved canonical directory.
        external_alias = self.base / "external-alias"
        self.assertEqual("deny", effective_path_access(
            external_alias / "blocked", self.root, True,
            (SimpleNamespace(path=str(external_alias), access="deny"),),
            resolve_symlinks=False))
        # Child rw overrides parent protect, but never absolute deny.
        # Same-depth ties follow deny > protect > ro > rw. Configuration ordering is irrelevant.
        child = self.sub / "writable"
        nested = child / "restricted"
        for reverse in (False, True):
            entries = [
                PathGrant(str(self.sub), access="ro"),
                PathGrant(str(child), access="rw"),
                PathGrant(str(nested), access="protect"),
                PathGrant(str(nested / "override"), access="rw"),
            ]
            if reverse:
                entries.reverse()
            self.assertEqual("rw", effective_path_access(child / "ok", self.root, True, entries))
            self.assertEqual("protect", effective_path_access(nested / "blocked", self.root, True, entries))
            self.assertEqual("rw", effective_path_access(nested / "override" / "ok", self.root, True, entries))
            self.assertEqual("ro", effective_path_access(self.sub / "other", self.root, True, entries))
        self.assertEqual("ro", effective_path_access(child / "file", self.root, True, (
            PathGrant(str(child), access="ro"), PathGrant(str(child), access="rw"))))
        self.assertEqual("deny", effective_path_access(child / "file", self.root, True, (
            PathGrant(str(child), access="deny"), PathGrant(str(child), access="rw"))))
        # An absolute ancestor deny cannot be reopened by a deeper rw.
        self.assertEqual("deny", effective_path_access(
            nested / "override" / "file", self.root, True, (
                PathGrant(str(nested), access="deny"),
                PathGrant(str(nested / "override"), access="rw"))))
        self.assertEqual("protect", effective_path_access(
            child / "file", self.root, True, (
                PathGrant(str(child), access="protect"),
                PathGrant(str(child), access="rw"))))
        self.assertEqual("deny", effective_path_access(
            child / "file", self.root, True, (
                PathGrant(str(child), access="protect"),
                PathGrant(str(child), access="deny"))))
        self.assertEqual("ro", PathGrant(str(self.sub), access="r").access)

    def test_legacy_server_record_read_only_is_normalized(self):
        legacy = PathGrant.from_data({"path": str(self.sub), "read_only": True})
        self.assertEqual("ro", legacy.access)
        old_rw = PathGrant.from_data({"path": str(self.sub), "read_only": False})
        self.assertEqual("rw", old_rw.access)
        record = TokenRecord(
            token="a" * 40, name="legacy", created_at=utc_now(),
            path_prefix=".", allowed_paths=(legacy, old_rw),
            shell_mode="restricted",
        )
        encoded = record.to_dict()
        self.assertEqual([{"path": str(self.sub), "access": "ro"},
                          {"path": str(self.sub), "access": "rw"}],
                         encoded["allowed_paths"])
        restored = TokenRecord.from_dict(encoded)
        self.assertEqual(["ro", "rw"], [g.access for g in restored.allowed_paths])

    def test_server_normalizes_overlaps_and_denies_full_shell(self):
        store = TokenStore(self.root, None, None)
        extra = self.base / "extra"
        extra.mkdir()
        (extra / "config.json").write_text("secret")
        outside = self.base / "outside"
        outside.write_text("ungranted")
        record = TokenRecord(
            token="b" * 40, name="restricted", created_at=utc_now(),
            preview_token="p" * 16, control_token="c" * 40,
            app_id="i" * 16, path_prefix=".", shell_mode="restricted",
            allowed_paths=(
                PathGrant(str(extra), access="rw"),
                PathGrant(str(extra), access="r"),
                PathGrant(str(extra / "config.json"), access="deny"),
                PathGrant(str(self.secret), access="deny"),
            ),
        )
        normalized = store._validate(record)
        self.assertEqual("ro", next(g for g in normalized.allowed_paths if g.path == str(extra)).access)
        self.assertIn(str(self.secret), [g.path for g in normalized.allowed_paths if g.access == "deny"])
        same_path = TokenRecord.from_dict({
            **record.to_dict(),
            "allowed_paths": [
                {"path": str(extra), "access": "rw"},
                {"path": str(extra), "access": "deny"},
            ],
        })
        collapsed = store._validate(same_path)
        self.assertEqual("deny", collapsed.allowed_paths[0].access)
        with self.assertRaisesRegex(ValueError, "full Shell"):
            store._validate(TokenRecord.from_dict({
                **record.to_dict(), "shell_mode": "full",
            }))
        with self.assertRaisesRegex(ValueError, "within workspace"):
            store._validate(TokenRecord.from_dict({
                **record.to_dict(),
                "allowed_paths": [{"path": str(outside), "access": "deny"}],
            }))

    def test_server_http_path_authorization_and_deny(self):
        handler = object.__new__(type("Handler", (HttpSupportMixin,), {}))
        handler.token_scope_root = self.root
        handler.token_record = SimpleNamespace(
            can_write=True, allowed_paths=(
                PathGrant(str(self.sub), access="ro"),
                PathGrant(str(self.secret), access="deny"),
            ),
        )
        handler._assert_inside_root(self.root / "normal.txt")
        with self.assertRaises(ApiError):
            handler._assert_inside_root(self.secret)
        with self.assertRaises(ApiError):
            handler._assert_inside_root(self.metadata / "config.json")
        with self.assertRaises(ApiError):
            handler._assert_path_writable(self.sub / "normal.txt")
        with self.assertRaises(ApiError):
            handler._assert_path_writable(self.sub)  # cannot rename/delete parent of deny
        handler._assert_path_writable(self.root / "normal.txt")

    def test_absolute_deny_refuses_unsandboxed_server_shell(self):
        from openkapsel.execution.shell_execution import start_shell_task
        record = TokenRecord(
            token="z" * 40, name="absolute-deny", created_at=utc_now(),
            path_prefix=".", shell_mode="restricted",
            allowed_paths=(PathGrant(str(self.secret), access="deny"),),
        )
        with self.assertRaises(ApiError):
            start_shell_task(None, record, self.root, command="echo EXPOSED",
                             cwd_value=".", timeout_seconds=5, unsandboxed=True)

    def test_admin_deny_option_and_legacy_form_modes(self):
        markup = _path_grant_rows((
            PathGrant(str(self.sub), read_only=False),
            PathGrant(str(self.secret), access="deny"),
        ))
        self.assertIn('value="deny" selected', markup)
        self.assertIn('value="rw" selected', markup)
        selected = _path_grant_rows((PathGrant(str(self.sub), access="protect"),))
        self.assertIn('value="protect" selected', selected)

    def test_client_same_path_deny_overrides_rw_and_ancestor_deny(self):
        extra = self.base / "another"
        extra.mkdir()
        child = extra / "child"
        child.mkdir()
        files = ClientFiles(self.root, writable=True)
        try:
            spec = make_job_sandbox({
                "job_sandbox": {"paths": [
                    {"path": str(extra), "access": "rw"},
                    {"path": str(extra), "access": "deny"},
                ]},
            }, files)
            self.assertEqual([{"path": str(extra), "access": "deny"}], spec["allowed_paths"])
            self.assertNotIn(str(extra), spec["hidden_paths"])
            spec = make_job_sandbox({
                "job_sandbox": {"paths": [
                    {"path": str(child), "access": "rw"},
                    {"path": str(extra), "access": "protect"},
                ]},
            }, files)
            self.assertIn({"path": str(extra), "access": "protect"}, spec["allowed_paths"])
            self.assertIn({"path": str(child), "access": "rw"}, spec["allowed_paths"])
            self.assertNotIn(str(extra), spec["hidden_paths"])
            files.sandbox_path_rules = tuple(SimpleNamespace(**r) for r in spec["allowed_paths"])
            self.assertTrue(files.is_protected_path(extra / "ungranted"))
            self.assertFalse(files.is_protected_path(child / "accessible"))
            files.ensure_mutable_path(child / "writable")
            with self.assertRaises(OSError):
                files.ensure_mutable_path(extra / "ungranted")
        finally:
            files.close()

    def test_client_denies_in_nested_allowed_parent_and_file_tools(self):
        readonly = self.base / "readonly"
        readonly.mkdir()
        (readonly / ".openkapsel").mkdir()
        files = ClientFiles(self.root, writable=True)
        try:
            spec = make_job_sandbox({
                "job_sandbox": {
                    "paths": [
                        {"path": str(self.sub), "access": "rw"},
                        {"path": str(self.sub), "access": "r"},
                        {"path": str(self.secret), "access": "deny"},
                        {"path": str(readonly), "access": "ro"},
                    ]
                },
            }, files)
            self.assertIn({"path": str(self.secret), "access": "deny"}, spec["allowed_paths"])
            self.assertNotIn(str(self.secret), spec["hidden_paths"])
            self.assertIn(str(self.root / "data" / ".openkapsel"), spec["hidden_paths"])
            self.assertIn(str(readonly / ".openkapsel"), spec["hidden_paths"])
            self.assertIn({"path": str(self.sub), "access": "ro"}, spec["allowed_paths"])
            files.sandbox_denied_paths = frozenset(
                Path(p) for p in spec["hidden_paths"] if self.root in Path(p).parents
            )
            files.sandbox_path_rules = tuple(SimpleNamespace(**r) for r in spec["allowed_paths"])
            with self.assertRaises(OSError):
                files.path("data/secret.json")
            with self.assertRaises(OSError):
                files.ensure_mutable_path(self.sub)
            if os.name != "nt":
                items = files.dispatch("list", {"path": "data"})["names"]
                self.assertNotIn("secret.json", items)
                self.assertNotIn(".openkapsel", items)
        finally:
            files.close()

    @unittest.skipUnless(platform.system() == "Darwin",
                         "uses macOS native Seatbelt sandbox")
    def test_real_macos_parent_rw_child_ro_deny(self):
        state = self.base / "manager"
        state.mkdir()
        ro = self.sub / "readonly"
        ro.mkdir()
        secret = self.sub / "secret.json"
        safe = self.sub / "safe.txt"
        spec = {
            "type": "seatbelt", "root": str(self.root), "writable": True,
            "network_mode": "none",
            "allowed_paths": [{"path": str(ro), "access": "r"}],
            "hidden_paths": [str(secret), str(self.metadata)],
        }
        code = (
            'from pathlib import Path; w=Path.cwd();'
            '\nfor p in ["data/secret.json","data/.openkapsel/config.json"]:'
            '\n try: print(p,"READ", (w/p).read_text())'
            '\n except OSError: print(p,"DENIED")'
            '\ntry: (w/"data/readonly/test").write_text("FAIL"); print("RO_WRITABLE")'
            '\nexcept OSError: print("RO_DENIED")'
            '\n(w/"data/safe.txt").write_text("OK"); print("RW_OK")'
            '\nwith open("/dev/null", "w") as sink: sink.write("ignored")'
            '\nprint("DEVNULL_OK")'
        )
        # GitHub macOS images use an xcrun shim at /usr/bin/python3. Under
        # Xcode 26.6 it may invoke xcodebuild -find python3 and fail before
        # exercising any sandbox path rule. Use setup-python's real runtime.
        launch = prepare_job(spec, [sys.executable, "-c", code],
                             str(self.root), dict(os.environ), state)
        try:
            outcome = subprocess.run(
                launch.argv, cwd=self.root, env=launch.environment,
                capture_output=True, text=True, timeout=25,
            )
            self.assertEqual(0, outcome.returncode,
                             f"stdout={outcome.stdout!r}\nstderr={outcome.stderr!r}")
            self.assertIn("secret.json DENIED", outcome.stdout)
            self.assertIn("config.json DENIED", outcome.stdout)
            self.assertIn("RO_DENIED", outcome.stdout)
            self.assertIn("RW_OK", outcome.stdout)
            self.assertIn("DEVNULL_OK", outcome.stdout)
            self.assertEqual("SENSITIVE", secret.read_text())
        finally:
            launch.cleanup()


if __name__ == "__main__":
    unittest.main()

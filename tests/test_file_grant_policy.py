"""FileApproval policy regressions without native descriptor/sockets.

Native File RPC, symlink races and HTTP/WS lifecycle are separately verified
by the existing integration suites (which require a permissive test runner).
"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.auth.function_grants import FunctionGrants
from openkapsel.client_runtime.file_approval import FileApproval
from openkapsel.errors import ApiError


class FileGrantPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.a = self.base / "a"
        self.b = self.base / "b"
        self.a.mkdir()
        self.b.mkdir()
        self.policy = FileApproval()

    def test_new_path_and_renewal_keep_existing_client_owned_timestamps(self):
        now = [1000.0]
        with patch("openkapsel.client_runtime.file_approval.time.time",
                   side_effect=lambda: now[0]):
            a = self.policy.grant(None, {"path": str(self.a)}, 600)
            first_stamp = a["grants"][0]["expires_at"]
            a["custom"] = {"hello": ["world"]}
            now[0] = 1100
            both = self.policy.grant(a, {"path": str(self.b)}, 1800)
            self.assertEqual(first_stamp, both["grants"][0]["expires_at"])
            self.assertEqual([str(self.a), str(self.b)],
                             [str(scope) for scope in FileApproval.paths(both)])
            self.assertEqual({"hello": ["world"]}, both["custom"])
            now[0] = 1200
            renewed = self.policy.grant(both, {"path": str(self.a)}, 60)
            self.assertEqual([str(self.b), str(self.a)],
                             [str(scope) for scope in FileApproval.paths(renewed)])
            self.assertEqual(both["grants"][1]["expires_at"],
                             renewed["grants"][0]["expires_at"])
            self.assertEqual(1260, renewed["grants"][1]["expires_at"])

    def test_server_prunes_a_before_policy_checks_b(self):
        now = [100.0]
        with patch("openkapsel.client_runtime.file_approval.time.time",
                   side_effect=lambda: 200_000 + now[0]), patch(
                   "openkapsel.auth.function_grants.time.monotonic",
                   side_effect=lambda: now[0]):
            store = FunctionGrants()
            for path, issued, seconds in ((self.a, 100, 60),
                                          (self.b, 120, 600)):
                now[0] = issued
                ticket = store.request("owner", 8, "mapping", "files.read",
                                       {"path": str(path)})
                store.approve(ticket, seconds=seconds,
                    grant=self.policy.grant)
            both = store.current("owner", 8, "mapping", "files.read")
            self.assertEqual((self.a, self.b), FileApproval.paths(both))
            preserved = both["grants"][1]["expires_at"]
            now[0] = 160  # Client A expires before Server's grace elapses.
            current = store.current("owner", 8, "mapping", "files.read")
            self.assertEqual(2, len(current["grants"]))
            self.assertEqual((self.b,), FileApproval.paths(current))
            self.assertEqual(self.b, self.policy.check(str(self.b), self.root, current))
            with self.assertRaises(ApiError):
                self.policy.check(str(self.a), self.root, current)
            now[0] = 220  # Server may now remove A, leaving B unchanged.
            current = store.current("owner", 8, "mapping", "files.read")
            self.assertEqual((self.b,), FileApproval.paths(current))
            self.assertEqual(preserved, current["grants"][0]["expires_at"])
            now[0] = 780
            self.assertIsNone(store.current("owner", 8, "mapping", "files.read"))

    def test_workspace_client_expiry_without_server_pruning(self):
        now = [1000.0]
        with patch("openkapsel.client_runtime.file_approval.time.time",
                   side_effect=lambda: now[0]):
            workspace = self.policy.grant(None, {"path": ""}, 60)
            self.assertTrue(FileApproval.workspace_granted(workspace))
            self.assertEqual(self.root, self.policy.check(str(self.root), self.root, workspace))
            now[0] = 1060.0
            self.assertFalse(FileApproval.workspace_granted(workspace))
            self.assertFalse(self.policy.status({"path": ""}, workspace))
            with self.assertRaises(ApiError):
                self.policy.check(str(self.root), self.root, workspace)
            renewed = self.policy.grant(workspace, {"path": str(self.a)}, 120)
            self.assertEqual(1, len(renewed["grants"]))
            self.assertEqual(self.a, FileApproval.paths(renewed)[0])
            self.assertFalse(FileApproval.workspace_granted(renewed))
            now[0] = 1180.0
            self.assertEqual((), FileApproval.paths(renewed))
            with self.assertRaises(ApiError):
                self.policy.check(str(self.a), self.root, renewed)

    def test_protect_requires_independent_nested_scope_and_deny_never_approvable(self):
        protected = self.a / "protected"
        protected.mkdir()
        denied = self.a / "denied"
        denied.mkdir()
        rules = (SimpleNamespace(path=str(protected), access="protect"),
                 SimpleNamespace(path=str(denied), access="deny"))
        broad = self.policy.grant(None, {"path": str(self.a)}, 600)
        self.assertEqual(self.a, self.policy.check(str(self.a), self.root,
                                                    broad, rules=rules))
        with self.assertRaises(ApiError):
            self.policy.check(str(protected), self.root, broad, rules=rules)
        own = self.policy.grant(broad, {"path": str(protected)}, 600)
        self.assertEqual(protected, self.policy.check(str(protected), self.root,
                                                      own, rules=rules))
        for auth in (broad, own):
            with self.assertRaises(ApiError):
                self.policy.check(str(denied), self.root, auth, rules=rules)

    def test_file_policy_invalid_structure_fails_closed(self):
        malformed = (
            {"paths": [str(self.a)]},
            {"grants": []},
            {"grants": [{"path": str(self.a)}]},
            {"grants": [{"path": str(self.a), "expires_at": True}]},
            {"grants": [{"path": str(self.a), "expires_at": "later"}]},
        )
        for auth in malformed:
            with self.subTest(auth=auth), self.assertRaises(ApiError):
                FileApproval.check(str(self.a), self.root, auth)


if __name__ == "__main__":
    unittest.main()

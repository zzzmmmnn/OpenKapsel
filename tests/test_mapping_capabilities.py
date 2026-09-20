"""Mapping RPC capability state negotiation and client preferences."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.mapping_capabilities import client_rpc_capabilities
from openkapsel.mapping_manager import MappingManager


class ClientRpcCapabilityTests(unittest.TestCase):
    def test_defaults_enable_file_and_git_when_dependency_exists(self):
        capabilities = client_rpc_capabilities({}, git_available=True)
        self.assertEqual("available", capabilities["file"]["state"])
        self.assertEqual("available", capabilities["git"]["state"])
        self.assertIn("fs_read", capabilities["file"]["operations"])
        self.assertIn("log", capabilities["git"]["operations"])

    def test_client_can_disable_individual_rpc_families(self):
        capabilities = client_rpc_capabilities(
            {"rpc": {"file": True, "git": False}},
            git_available=True,
        )
        self.assertEqual("available", capabilities["file"]["state"])
        self.assertEqual("disabled", capabilities["git"]["state"])
        self.assertEqual("client_config", capabilities["git"]["reason"])

    def test_missing_git_dependency_is_unsupported(self):
        capabilities = client_rpc_capabilities({}, git_available=False)
        self.assertEqual("unsupported", capabilities["git"]["state"])
        self.assertEqual("dependency_missing", capabilities["git"]["reason"])

    def test_invalid_rpc_configuration_is_rejected(self):
        for config in (
            {"rpc": []},
            {"rpc": {"git": "yes"}},
            {"rpc": {"future_typo": True}},
        ):
            with self.subTest(config=config), self.assertRaises(ValueError):
                client_rpc_capabilities(config, git_available=True)


class MappingRpcCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.root = base / "workspace"
        self.root.mkdir()
        (self.root / "project").mkdir()
        self.manager = MappingManager(self.root, base / "state", enabled=False)
        self.row, _ = self.manager.store.create("project", "laptop", writable=True)

    def tearDown(self):
        self.manager.sessions.clear()
        self.manager.store.delete(self.row["id"])
        self.temp.cleanup()

    def session(self, capabilities):
        session = SimpleNamespace(closed=False, capabilities=capabilities, close=lambda: None)
        self.manager.sessions[self.row["id"]] = session
        return session

    def test_admin_disabled_and_offline_are_distinct(self):
        self.manager.store.update(self.row["id"], enabled=False)
        state = self.manager.rpc_capability(self.row["id"], "git", operation="status", min_version=2)
        self.assertEqual("disabled", state.state)
        self.assertEqual("mapping_disabled", state.reason)
        self.assertIsNone(state.fallback)

        self.manager.store.update(self.row["id"], enabled=True)
        state = self.manager.rpc_capability(self.row["id"], "git", operation="status", min_version=2)
        self.assertEqual("offline", state.state)
        self.assertEqual("client_offline", state.reason)

    def test_legacy_client_is_translated_and_old_file_rpc_can_fallback(self):
        self.session({
            "file_api": {"version": 1, "operations": ["fs_list"]},
            "git_api": {"version": 2, "read_only": True},
        })
        file_state = self.manager.rpc_capability(
            self.row["id"], "file", operation="fs_read_many", min_version=2, max_version=3
        )
        self.assertEqual("unsupported", file_state.state)
        self.assertEqual("version_mismatch", file_state.reason)
        self.assertEqual("fuse", file_state.fallback)

        git_state = self.manager.rpc_capability(
            self.row["id"], "git", operation="status", min_version=2, max_version=2,
            required={"read_only": True},
        )
        self.assertTrue(git_state.available)

    def test_client_disabled_and_dependency_unsupported_preserve_family_fallback_policy(self):
        session = self.session({
            "rpc": {
                "file": {"state": "disabled", "reason": "client_config", "version": 3, "operations": ["fs_list"]},
                "git": {"state": "unsupported", "reason": "dependency_missing", "version": 2,
                        "operations": ["status"], "read_only": True},
            }
        })
        file_state = self.manager.rpc_capability(
            self.row["id"], "file", operation="fs_list", min_version=1, max_version=3
        )
        self.assertEqual("disabled", file_state.state)
        self.assertEqual("fuse", file_state.fallback)

        git_state = self.manager.rpc_capability(
            self.row["id"], "git", operation="status", min_version=2, max_version=2,
            required={"read_only": True},
        )
        self.assertEqual("unsupported", git_state.state)
        self.assertIsNone(git_state.fallback)

        session.capabilities["rpc"]["git"] = {
            "state": "disabled", "reason": "client_config", "version": 2,
            "operations": ["status"], "read_only": True,
        }
        git_state = self.manager.rpc_capability(
            self.row["id"], "git", operation="status", min_version=2, max_version=2,
            required={"read_only": True},
        )
        self.assertEqual("disabled", git_state.state)
        self.assertIsNone(git_state.fallback)


if __name__ == "__main__":
    unittest.main()

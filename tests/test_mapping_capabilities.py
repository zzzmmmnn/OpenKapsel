"""Mapping RPC capability state negotiation and client preferences."""

import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.mapping_manager import MappingManager
from openkapsel.rpc_plugins import load_client_rpc_registry


class ClientRpcCapabilityTests(unittest.TestCase):
    def capabilities(self, config=None):
        config = config or {}
        return load_client_rpc_registry(config).capability_map(config)

    def test_defaults_enable_file_git_and_archive_plugins(self):
        capabilities = self.capabilities()
        self.assertEqual("available", capabilities["file"]["state"])
        self.assertIn(capabilities["git"]["state"], {"available", "unsupported"})
        self.assertEqual("available", capabilities["archive"]["state"])
        self.assertIn("fs_read", capabilities["file"]["operations"])
        self.assertIn("log", capabilities["git"]["operations"])
        self.assertEqual(
            ["create", "extract", "list", "read"],
            capabilities["archive"]["operations"],
        )
        self.assertIn("archive", capabilities["archive"]["description"].lower())
        self.assertEqual(
            ["path", "member"],
            capabilities["archive"]["operation_specs"]["read"]["input_schema"]["required"],
        )
        self.assertEqual("sync", capabilities["archive"]["operation_specs"]["read"]["execution"])
        self.assertFalse(capabilities["archive"]["operation_specs"]["read"]["write"])
        self.assertEqual("task", capabilities["archive"]["operation_specs"]["create"]["execution"])
        self.assertTrue(capabilities["archive"]["operation_specs"]["create"]["write"])
        for operation in ("status", "diff", "log", "show", "ls_files", "diff_stat"):
            self.assertEqual("sync", capabilities["git"]["operation_specs"][operation]["execution"])
            self.assertFalse(capabilities["git"]["operation_specs"][operation]["write"])
        for operation in ("add", "commit", "restore", "checkout"):
            self.assertEqual("task", capabilities["git"]["operation_specs"][operation]["execution"])
            self.assertTrue(capabilities["git"]["operation_specs"][operation]["write"])
        self.assertIn(".zip", capabilities["archive"]["details"]["extensions"])

    def test_client_can_disable_extensions_but_core_files_remain_available(self):
        capabilities = self.capabilities({"rpc": {"git": False, "archive": False}})
        self.assertEqual("available", capabilities["file"]["state"])
        self.assertEqual("disabled", capabilities["git"]["state"])
        self.assertEqual("disabled", capabilities["archive"]["state"])
        self.assertEqual("client_config", capabilities["git"]["reason"])

    def test_removed_file_switch_is_rejected_with_migration_guidance(self):
        for value in (True, False, "disabled", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "rpc.file has been removed"):
                self.capabilities({"rpc": {"file": value}})

    def test_core_files_work_with_extensions_disabled_and_respect_readonly(self):
        from openkapsel.client_files import ClientFiles
        config = {"rpc": {"git": False, "archive": False}}
        registry = load_client_rpc_registry(config)
        capabilities = registry.capability_map(config)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("sample", encoding="utf-8")
            for writable in (False, True):
                with self.subTest(writable=writable):
                    files = ClientFiles(directory, writable=writable,
                                        rpc_capabilities=capabilities, rpc_registry=registry)
                    try:
                        response = files.dispatch("api_fs_read", {"query": {"path": ["sample.txt"]}})
                        self.assertEqual(200, response["status"])
                        self.assertEqual("sample", response["body"]["content"])
                        arguments = {"body": {"path": "new.txt", "content": "new"}}
                        if writable:
                            self.assertEqual(201, files.dispatch("api_fs_write", arguments)["status"])
                        else:
                            with self.assertRaises(OSError):
                                files.dispatch("api_fs_write", arguments)
                            self.assertFalse((Path(directory) / "new.txt").exists())
                    finally:
                        files.close()

    def test_missing_git_dependency_is_unsupported(self):
        with patch("openkapsel.rpc_plugins.git.shutil.which", return_value=None):
            capabilities = self.capabilities()
        self.assertEqual("unsupported", capabilities["git"]["state"])
        self.assertEqual("dependency_missing", capabilities["git"]["reason"])

    def test_explicit_import_spec_registers_third_party_plugin(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "vendor_rpc.py"
            module.write_text(
                "class Plugin:\n"
                "    family='vendor'\n"
                "    version=1\n"
                "    description='Inspect vendor metadata.'\n"
                "    operations={\n"
                "      'inspect': {'description':'Inspect one value.', 'input_schema': {'type':'object','properties': {'value': {'type':'integer'}}, 'required':['value'], 'additionalProperties':False}},\n"
                "      'update': {'description':'Update one value.', 'input_schema': {'type':'object','properties': {'value': {'type':'integer'}}, 'required':['value'], 'additionalProperties':False}, 'write': True}\n"
                "    }\n"
                "    read_only=True\n"
                "    def probe(self, config): return ('available', None, {'kind':'test'})\n"
                "    def dispatch(self, files, operation, args): return {'status':200,'body':{'ok':True}}\n"
                "    def dispatch_task(self, files, operation, args, task): return {'status':200,'body':{'updated':True}}\n"
                "plugin=Plugin()\n"
            )
            sys.path.insert(0, directory)
            try:
                importlib.invalidate_caches()
                config = {"rpc_plugins": ["vendor_rpc:plugin"], "rpc": {"vendor": True}}
                registry = load_client_rpc_registry(config)
                capabilities = registry.capability_map(config)
                self.assertEqual("available", capabilities["vendor"]["state"])
                self.assertEqual("vendor_rpc:plugin", capabilities["vendor"]["plugin"])
                self.assertEqual("Inspect vendor metadata.", capabilities["vendor"]["description"])
                self.assertEqual(
                    "integer",
                    capabilities["vendor"]["operation_specs"]["inspect"]["input_schema"]["properties"]["value"]["type"],
                )
                self.assertFalse(capabilities["vendor"]["operation_specs"]["inspect"]["write"])
                self.assertEqual("sync", capabilities["vendor"]["operation_specs"]["inspect"]["execution"])
                self.assertTrue(capabilities["vendor"]["operation_specs"]["update"]["write"])
                self.assertEqual("task", capabilities["vendor"]["operation_specs"]["update"]["execution"])
                self.assertFalse(capabilities["vendor"]["read_only"])
                self.assertTrue(registry.accepts("vendor_inspect"))
                self.assertTrue(registry.accepts("vendor_update"))
                from openkapsel.client_files import ClientFiles
                export = Path(directory) / "export"
                export.mkdir()
                files = ClientFiles(
                    export,
                    writable=False,
                    rpc_registry=registry,
                    rpc_capabilities=capabilities,
                )
                try:
                    result = files.dispatch("vendor_inspect", {"value": 1})
                    self.assertEqual({"status": 200, "body": {"ok": True}}, result)
                finally:
                    files.close()
            finally:
                sys.path.remove(directory)
                sys.modules.pop("vendor_rpc", None)

    def test_invalid_rpc_configuration_and_plugin_specs_are_rejected(self):
        for config in (
            {"rpc": []},
            {"rpc": {"git": "yes"}},
            {"rpc": {"future_typo": True}},
            {"rpc_plugins": "vendor:plugin"},
            {"rpc_plugins": ["missing_separator"]},
        ):
            with self.subTest(config=config), self.assertRaises((ValueError, ModuleNotFoundError)):
                self.capabilities(config)


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
        session = SimpleNamespace(closed=False, ready=True, capabilities=capabilities, close=lambda: None)
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

    def test_legacy_client_is_translated_without_native_fallback(self):
        self.session({
            "file_api": {"version": 1, "operations": ["fs_list"]},
            "git_api": {"version": 2, "read_only": True},
        })
        file_state = self.manager.rpc_capability(
            self.row["id"], "file", operation="fs_read_many", min_version=2, max_version=3
        )
        self.assertEqual("unsupported", file_state.state)
        self.assertEqual("version_mismatch", file_state.reason)
        self.assertIsNone(file_state.fallback)

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
        self.assertIsNone(file_state.fallback)

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

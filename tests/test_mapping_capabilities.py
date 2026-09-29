"""Mapping RPC capability state negotiation and client preferences."""

import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.mapping.mapping_manager import MappingManager
from openkapsel.rpc_plugins import load_client_rpc_registry


class ClientRpcCapabilityTests(unittest.TestCase):
    def capabilities(self, config=None):
        config = config or {}
        return load_client_rpc_registry(config).capability_map(config)

    def test_defaults_enable_supported_builtin_plugins(self):
        with (
            patch("openkapsel.rpc_plugins.git.shutil.which", return_value="/usr/bin/git"),
            patch(
                "openkapsel.rpc_plugins.file_search._backend_status",
                return_value={"backend": "mock", "available": True},
            ),
        ):
            capabilities = self.capabilities()
        self.assertEqual("available", capabilities["file"]["state"])
        self.assertEqual("available", capabilities["git"]["state"])
        self.assertEqual("available", capabilities["archive"]["state"])
        self.assertEqual("available", capabilities["file_search"]["state"])
        self.assertEqual("available", capabilities["structured"]["state"])
        self.assertEqual("available", capabilities["tabular"]["state"])
        self.assertNotIn("ssh", capabilities)
        self.assertIn("fs_read", capabilities["file"]["operations"])
        self.assertIn("log", capabilities["git"]["operations"])
        self.assertEqual(["search", "status"], capabilities["file_search"]["operations"])
        self.assertTrue(capabilities["file_search"]["read_only"])
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
        for operation in ("add", "commit", "restore", "checkout", "fetch", "pull", "clone"):
            self.assertEqual("task", capabilities["git"]["operation_specs"][operation]["execution"])
            self.assertTrue(capabilities["git"]["operation_specs"][operation]["write"])
        self.assertIn(".zip", capabilities["archive"]["details"]["extensions"])

    def test_client_can_disable_extensions_but_core_files_remain_available(self):
        with patch(
            "openkapsel.rpc_plugins.git.GitRpcPlugin.probe",
            side_effect=AssertionError("disabled plugin must not be probed"),
        ):
            capabilities = self.capabilities({"rpc": {"git": False, "archive": False}})
        self.assertEqual("available", capabilities["file"]["state"])
        self.assertNotIn("git", capabilities)
        self.assertNotIn("archive", capabilities)

    def test_removed_file_switch_is_rejected_with_migration_guidance(self):
        for value in (True, False, "disabled", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "rpc.file has been removed"):
                self.capabilities({"rpc": {"file": value}})

    def test_core_files_work_with_extensions_disabled_and_respect_readonly(self):
        from openkapsel.client_runtime.client_files import ClientFiles
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
                        arguments = {"body": {"items": [{
                            "op": "file.create", "path": "new.txt", "content": "new",
                        }]}}
                        if writable:
                            self.assertEqual(200, files.dispatch("api_fs_mutate", arguments)["status"])
                        else:
                            with self.assertRaises(OSError):
                                files.dispatch("api_fs_mutate", arguments)
                            self.assertFalse((Path(directory) / "new.txt").exists())
                    finally:
                        files.close()

    def test_missing_git_dependency_is_not_advertised(self):
        with patch("openkapsel.rpc_plugins.git.shutil.which", return_value=None):
            capabilities = self.capabilities()
        self.assertNotIn("git", capabilities)

    def test_missing_file_search_backend_is_not_advertised(self):
        with patch(
            "openkapsel.rpc_plugins.file_search._backend_status",
            return_value={"backend": "plocate", "available": False, "reason": "dependency_missing"},
        ):
            capabilities = self.capabilities()
        self.assertNotIn("file_search", capabilities)

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
                disabled_config = {"rpc_plugins": ["vendor_rpc:plugin"]}
                disabled_registry = load_client_rpc_registry(disabled_config)
                try:
                    self.assertNotIn("vendor", disabled_registry.capability_map(disabled_config))
                finally:
                    disabled_registry.close()
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
                self.assertIsNotNone(registry.operation_spec("vendor", "inspect"))
                self.assertIsNotNone(registry.operation_spec("vendor", "update"))
                from openkapsel.client_runtime.client_files import ClientFiles
                export = Path(directory) / "export"
                export.mkdir()
                files = ClientFiles(
                    export,
                    writable=False,
                    rpc_registry=registry,
                    rpc_capabilities=capabilities,
                )
                try:
                    result = files.dispatch("rpc", {
                        "family": "vendor",
                        "operation": "inspect",
                        "args": {"value": 1},
                    })
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

    def test_legacy_capability_aliases_are_not_accepted(self):
        self.session({
            "file_api": {"version": 4, "operations": ["fs_list"]},
            "git_api": {"version": 2, "read_only": True},
        })
        file_state = self.manager.rpc_capability(
            self.row["id"], "file", operation="fs_list", min_version=1, max_version=4
        )
        self.assertEqual("unsupported", file_state.state)
        self.assertEqual("not_advertised", file_state.reason)
        self.assertIsNone(file_state.fallback)

        git_state = self.manager.rpc_capability(
            self.row["id"], "git", operation="status", min_version=2, max_version=2,
        )
        self.assertEqual("unsupported", git_state.state)
        self.assertEqual("not_advertised", git_state.reason)

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

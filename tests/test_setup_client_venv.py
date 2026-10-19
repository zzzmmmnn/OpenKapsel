"""Tests for the stdlib-only cross-platform Client virtualenv bootstrap."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTPATH = Path(__file__).resolve().parents[1] / "scripts" / "setup_client_venv.py"
SPEC = importlib.util.spec_from_file_location("setup_client_venv_tested", SCRIPTPATH)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class _FakeDistribution:
    def __init__(self, version, *, requires=(), metadata=None):
        self.version = version
        self.requires = list(requires)
        self._metadata = metadata

    def read_text(self, key):
        return self._metadata


class BootstrapTests(unittest.TestCase):
    def test_every_client_extra_is_in_default_requirement_set(self):
        requirements = bootstrap.load_requirements(bootstrap.PROJECT_ROOT)
        for dependency in (
            "websocket-client", "python-socks", "paramiko", "ruamel.yaml",
            "openpyxl", "defusedxml", "watchfiles",
        ):
            self.assertTrue(
                any(req.lower().startswith(dependency) for req in requirements),
                dependency,
            )
        self.assertEqual(len(requirements), len(set(requirements)))
        # The Client environment must not pull Server/scientific packages.
        for server_only in (
            "fastapi", "matplotlib", "numba", "numpy", "pandas", "scipy",
            "uvicorn", "lxml", "pillow",
        ):
            self.assertFalse(
                any(req.lower().startswith(server_only) for req in requirements),
                server_only,
            )
        self.assertGreaterEqual(len(requirements), 9)

    def test_missing_and_incompatible_dependencies_only(self):
        fake = {
            "already": _FakeDistribution("2.0", requires=["transitive>=1"]),
            "transitive": _FakeDistribution("1.5"),
            "old": _FakeDistribution("0.9"),
            "marker_skip": _FakeDistribution("1"),
        }
        original = bootstrap.importlib.metadata.distribution

        def distribution(name):
            if name not in fake:
                raise bootstrap.importlib.metadata.PackageNotFoundError(name)
            return fake[name]

        try:
            bootstrap.importlib.metadata.distribution = distribution
            missing = bootstrap.audit_requirements([
                "already>=1,<3", "old>=2", "missing>=1",
                "marker_skip>=1; sys_platform == 'nonexistent'",
            ])
            self.assertEqual({"old>=2", "missing>=1"}, set(missing))
        finally:
            bootstrap.importlib.metadata.distribution = original

    def test_missing_transitive_and_extra_dependencies(self):
        fake = {
            "parent": _FakeDistribution("1.0", requires=[
                "dep>=2",
                "optionaldep>=1; extra == 'features'",
                "ignoreddep>=1; extra == 'somethingelse'",
            ]),
            "dep": _FakeDistribution("1.0"),
        }
        with patch.object(bootstrap.importlib.metadata, "distribution") as get_dist:
            def distribution(name):
                if name not in fake:
                    raise bootstrap.importlib.metadata.PackageNotFoundError(name)
                return fake[name]
            get_dist.side_effect = distribution
            self.assertEqual(
                {"dep>=2", "optionaldep>=1"},
                set(bootstrap.audit_requirements(["parent[features]>=1"])),
            )

    def test_editable_checkout_must_match_exact_source(self):
        import json
        from pathlib import Path
        info = {"dir_info": {"editable": True}, "url": bootstrap.PROJECT_ROOT.as_uri()}
        with patch.object(bootstrap.importlib.metadata, "distribution",
                          return_value=_FakeDistribution("2.2", metadata=json.dumps(info))):
            self.assertTrue(bootstrap.editable_installed(bootstrap.PROJECT_ROOT))
        info["url"] = (bootstrap.PROJECT_ROOT / "somewhere-else").as_uri()
        with patch.object(bootstrap.importlib.metadata, "distribution",
                          return_value=_FakeDistribution("2.2", metadata=json.dumps(info))):
            self.assertFalse(bootstrap.editable_installed(bootstrap.PROJECT_ROOT))

    def test_healthy_existing_venv_is_preserved_in_check_only_mode(self):
        # Exercise the actual venv on the test runner. No pip install/network.
        if sys.prefix == sys.base_prefix:
            self.skipTest("test runner is not using a virtual environment")
        root = Path(sys.prefix)
        with patch.object(bootstrap, "run_command") as install:
            python = bootstrap.ensure_virtualenv(root, check_only=True)
            self.assertTrue(python.is_file())
            install.assert_not_called()

    def test_existing_nonvenv_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder) / "venv"
            location.mkdir()
            (location / "file").write_text("do not delete")
            with self.assertRaisesRegex(RuntimeError, "healthy venv"):
                bootstrap.ensure_virtualenv(location, check_only=False)
            self.assertEqual("do not delete", (location / "file").read_text())

    def test_missing_venv_check_mode_does_not_create_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder) / "venv"
            with self.assertRaisesRegex(RuntimeError, "not found"):
                bootstrap.ensure_virtualenv(location, check_only=True)
            self.assertFalse(location.exists())

    def test_os_names_are_distinct(self):
        for system, expected in (
            ("Windows", "Windows"), ("Linux", "Linux"), ("Darwin", "macOS"),
        ):
            with self.subTest(system=system):
                with patch.object(bootstrap.platform, "system", return_value=system):
                    self.assertEqual(expected, bootstrap.platform_name())
        with patch.object(bootstrap.platform, "system", return_value="Plan9"):
            with self.assertRaisesRegex(RuntimeError, "unsupported"):
                bootstrap.platform_name()

    def test_pip_install_selection_is_missing_only(self):
        with patch.object(bootstrap, "run_command") as run:
            bootstrap.install_missing(Path("/example/venv/python"), [])
            run.assert_not_called()
            bootstrap.install_missing(
                Path("/example/venv/python"), ["extra>=1", "dep<3"],
            )
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(["extra>=1", "dep<3"], argv[-2:])
            self.assertNotIn("--upgrade", argv)
            self.assertIn("only-if-needed", argv)


if __name__ == "__main__":
    unittest.main()

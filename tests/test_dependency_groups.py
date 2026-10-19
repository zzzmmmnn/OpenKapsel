"""Regression tests for Client/Server packaging and deployment paths."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "test_dep_bootstrap", ROOT / "scripts" / "setup_client_venv.py"
)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class DependencyGroupsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = bootstrap.load_toml().loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        cls.extras = cls.project["optional-dependencies"]

    def test_base_dependencies_do_not_force_server_packages_on_client(self):
        self.assertEqual([], self.project["dependencies"])
        self.assertIn("client", self.extras)
        self.assertIn("server", self.extras)

    def test_client_is_websocket_proxy_and_cross_platform_watch_only(self):
        deps = self.extras["client"]
        self.assertEqual(3, len(deps))
        for name in ("websocket-client", "python-socks", "watchfiles"):
            self.assertEqual(
                1, sum(req.startswith(name + ">=") for req in deps), name
            )
        self.assertIn("sys_platform == 'linux'", deps[2])
        self.assertIn("sys_platform == 'win32'", deps[2])

    def test_server_extra_preserves_old_server_dependencies(self):
        server_reqs = self.extras["server"]
        expected = (
            "beautifulsoup4", "cryptography", "fastapi", "httpx",
            "jinja2", "lxml", "matplotlib", "numba", "numpy", "pandas",
            "pillow", "python-multipart", "PyYAML", "scipy", "sqlalchemy",
            "uvicorn", "wsproto", "fusepy", "watchfiles",
        )
        self.assertEqual(len(expected), len(server_reqs))
        self.assertEqual(
            {name.lower() for name in expected},
            {req.split(";", 1)[0].split(">=", 1)[0].lower()
             for req in server_reqs},
        )

    def test_bootstrap_full_client_does_not_include_server_extra(self):
        actual = bootstrap.load_requirements(ROOT)
        expected = [
            req
            for extra in bootstrap.DEFAULT_EXTRAS
            for req in self.extras[extra]
        ]
        self.assertEqual(expected, actual)
        # watchfiles intentionally belongs to both Client and Server.
        server_only = set(self.extras["server"]) - set(self.extras["client"])
        for dependency in server_only:
            self.assertNotIn(dependency, actual)

    def test_installer_and_ci_explicitly_install_server_extra(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('"$INSTALL_DIR[server]"', installer)
        workflow = (ROOT / ".github/workflows/tests.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(3, workflow.count("'"+".[server,client,data-rpc]'"))
        self.assertNotIn("'"+".[client,data-rpc]'", workflow)


if __name__ == "__main__":
    unittest.main()

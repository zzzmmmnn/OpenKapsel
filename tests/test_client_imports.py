"""Client imports must not initialize the Linux-only server stack."""
import subprocess
import os
import sys
import unittest
from pathlib import Path


class ClientImportTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "server API is not supported on Windows")
    def test_public_server_exports_remain_available(self):
        from openkapsel import ServerConfig, create_server, server
        self.assertIs(ServerConfig, server.ServerConfig)
        self.assertIs(create_server, server.create_server)

    @unittest.skipIf(os.name == "nt", "server API is not supported on Windows")
    def test_public_server_exports_do_not_import_httpx(self):
        code = '''
import builtins
import sys

original_import = builtins.__import__
def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "httpx" or name.startswith("httpx."):
        raise ModuleNotFoundError("httpx intentionally unavailable during import")
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = blocked_import
from openkapsel import ServerConfig, create_server, server
assert ServerConfig is server.ServerConfig
assert create_server is server.create_server
assert "httpx" not in sys.modules
'''
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_client_imports_without_unix_socket_server(self):
        code = '''
import socketserver
import sys
for name in ("UnixStreamServer", "UnixDatagramServer"):
    if hasattr(socketserver, name):
        delattr(socketserver, name)
import openkapsel
from openkapsel import client, client_files, client_tasks, client_file_api, git_read
assert "openkapsel.server" not in sys.modules
assert "openkapsel.execution.network_proxy" not in sys.modules
assert openkapsel.__version__
try:
    openkapsel.nonexistent_attribute
except AttributeError:
    pass
else:
    raise AssertionError("unknown attributes must raise AttributeError")
'''
        result = subprocess.run([sys.executable, "-c", code],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_client_rpc_registry_loads_without_unix_socket_server(self):
        code = '''
import socketserver
for name in (
    "UnixStreamServer",
    "UnixDatagramServer",
    "ThreadingUnixStreamServer",
    "ThreadingUnixDatagramServer",
):
    if hasattr(socketserver, name):
        delattr(socketserver, name)
from openkapsel.rpc_plugins import load_client_rpc_registry
registry = load_client_rpc_registry({})
try:
    assert "git" in registry.families
    assert "archive" in registry.families
finally:
    registry.close()
'''
        result = subprocess.run([sys.executable, "-c", code],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

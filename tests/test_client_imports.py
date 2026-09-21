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

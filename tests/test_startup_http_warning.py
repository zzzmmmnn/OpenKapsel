"""Non-loopback HTTP listeners must always warn that credentials are exposed."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from openkapsel.server_runtime import startup


class HTTPBindWarningTests(unittest.TestCase):
    def _create(self, requested: str, bound: str, port: int = 8765):
        # Test the real startup decision using the bound socket address,
        # without binding a public interface or needing network privileges.
        with patch.object(startup, "WorkspaceHTTPServer") as server_type, \
             patch.object(startup.LOGGER, "warning") as warning:
            server_type.return_value.server_address = (bound, port)
            server = startup.create_server(requested, 0, object())
            self.assertIs(server, server_type.return_value)
            server_type.assert_called_once()
            return warning.call_args_list

    def test_ipv4_and_ipv6_wildcards_warn(self):
        for host in ("0.0.0.0", "::"):
            with self.subTest(host=host):
                calls = self._create(host, host)
                self.assertEqual(1, len(calls))
                message, bound, port = calls[0].args
                self.assertIn("without TLS", message)
                self.assertIn("passwords", message)
                self.assertIn("Bearer tokens", message)
                self.assertIn("plaintext", message)
                self.assertIn("HTTPS reverse proxy", message)
                self.assertEqual(host, bound)
                self.assertEqual(8765, port)

    def test_lan_public_and_unknown_hostnames_warn(self):
        for host in ("192.168.1.10", "10.0.0.4", "2001:db8::5",
                     "::ffff:192.168.1.8", "example.internal"):
            with self.subTest(host=host):
                self.assertEqual(1, len(self._create(host, host)))

    def test_only_loopback_bind_addresses_suppress_warning(self):
        for host in ("127.0.0.1", "127.5.6.7", "::1",
                     "::ffff:127.0.0.1", "localhost", "localhost."):
            with self.subTest(host=host):
                self.assertEqual([], self._create(host, host))

    def test_warning_follows_bound_socket_not_requested_host(self):
        self.assertEqual(1, len(self._create("127.0.0.1", "0.0.0.0")))
        self.assertEqual([], self._create("0.0.0.0", "127.0.0.1"))

    def test_failed_bind_does_not_log_a_false_running_service(self):
        with patch.object(startup, "WorkspaceHTTPServer", side_effect=OSError("bind failed")), \
             patch.object(startup.LOGGER, "warning") as warning:
            with self.assertRaises(OSError):
                startup.create_server("0.0.0.0", 8765, object())
            warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()

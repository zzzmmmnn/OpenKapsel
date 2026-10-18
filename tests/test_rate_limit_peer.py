"""Authentication limiters never let HTTP headers select an IP bucket."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from openkapsel.auth.admin_handlers import AdminHandlersMixin


class RateLimitPeerSecurityTests(unittest.TestCase):
    def test_forwarded_headers_are_not_security_identities(self):
        for peer in ("127.0.0.1", "127.4.5.6", "::1",
                     "192.168.0.7", "203.0.113.12"):
            with self.subTest(peer=peer):
                selected = set()
                for spoof in ("", "198.51.100.1",
                              "198.51.100.2, 203.0.113.55",
                              "127.0.0.1", "--bad-ip", "1.2.3.4, 5.6.7.8"):
                    request = SimpleNamespace(
                        client_address=(peer, 54321),
                        headers={"X-Forwarded-For": spoof,
                                 "Forwarded": "for=192.0.2.23",
                                 "X-Real-IP": "192.0.2.99"})
                    selected.add(AdminHandlersMixin._admin_rate_limit_address(request))
                self.assertEqual(1, len(selected))
                self.assertIn(peer, selected)

    def test_unparseable_peer_falls_back_only_to_socket_value(self):
        for peer in ("non-ip-peer", "", "127.0.0.1%foo"):
            with self.subTest(peer=peer):
                request = SimpleNamespace(
                    client_address=(peer, 777),
                    headers={"X-Forwarded-For": "198.51.100.8"})
                self.assertEqual(
                    peer, AdminHandlersMixin._admin_rate_limit_address(request))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import socket
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.network_proxy import (
    DomainProxy,
    ProxyPolicyError,
    domain_allowed,
    normalize_domain_rules,
    public_destination,
)
from openkapsel.tokens import TokenStore


class DomainProxyTests(unittest.TestCase):
    def test_domain_rules_are_exact_or_explicit_suffixes(self) -> None:
        rules = normalize_domain_rules(
            ["GitHub.COM", ".githubusercontent.com", "github.com"]
        )
        self.assertEqual(("github.com", ".githubusercontent.com"), rules)
        self.assertTrue(domain_allowed("github.com", rules))
        self.assertFalse(domain_allowed("api.github.com", rules))
        self.assertTrue(domain_allowed("raw.githubusercontent.com", rules))
        self.assertFalse(domain_allowed("github.com.example.test", rules))
        with self.assertRaisesRegex(ValueError, "invalid network domain"):
            normalize_domain_rules(["https://github.com/path"])

    def test_only_globally_routable_destination_addresses_are_accepted(self) -> None:
        self.assertTrue(public_destination("140.82.112.4"))
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1"):
            self.assertFalse(public_destination(address))

    def test_proxy_rejects_disallowed_domains_ip_literals_and_private_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proxy = DomainProxy.start(Path(directory), ("github.com",))
            try:
                with self.assertRaisesRegex(ProxyPolicyError, "not allowed"):
                    proxy.connect("gitlab.com", 443)
                with self.assertRaisesRegex(ProxyPolicyError, "IP-literal"):
                    proxy.connect("140.82.112.4", 443)
                with patch(
                    "openkapsel.network_proxy.socket.getaddrinfo",
                    return_value=[
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
                    ],
                ):
                    with self.assertRaisesRegex(ProxyPolicyError, "non-public"):
                        proxy.connect("github.com", 443)
            finally:
                proxy.close()

    def test_each_proxy_instance_enforces_its_own_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            github = DomainProxy.start(root, ("github.com",))
            gitlab = DomainProxy.start(root, ("gitlab.com",))
            try:
                self.assertTrue(domain_allowed("github.com", github.domains))
                self.assertFalse(domain_allowed("github.com", gitlab.domains))
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(2)
                client.connect(str(github.socket_path))
                client.sendall(
                    b"CONNECT gitlab.com:443 HTTP/1.1\r\nHost: gitlab.com:443\r\n\r\n"
                )
                response = client.recv(1024)
                client.close()
                self.assertTrue(response.startswith(b"HTTP/1.1 403"), response)
            finally:
                github.close()
                gitlab.close()

    def test_plain_http_framing_is_strict_and_hop_headers_are_rebuilt(self) -> None:
        def parsed(raw: bytes):
            return DomainProxy.parse_header(raw)[1]

        for raw, message in (
            (
                b"POST http://github.com/ HTTP/1.1\r\nHost: github.com\r\n"
                b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n",
                "multiple Content-Length",
            ),
            (
                b"POST http://github.com/ HTTP/1.1\r\nHost: github.com\r\n"
                b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                "Transfer-Encoding",
            ),
            (
                b"POST http://github.com/ HTTP/1.1\r\nHost: github.com\r\n"
                b"Content-Length: +1\r\n\r\n",
                "invalid Content-Length",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ProxyPolicyError, message):
                    DomainProxy.request_content_length(parsed(raw))

        duplicate_host = parsed(
            b"GET http://github.com/ HTTP/1.1\r\n"
            b"Host: github.com\r\nHost: github.com\r\n\r\n"
        )
        with self.assertRaisesRegex(ProxyPolicyError, "exactly one Host"):
            DomainProxy.validate_host_header(duplicate_host, "github.com", 80, 80)

        headers = parsed(
            b"POST http://github.com/upload HTTP/1.1\r\n"
            b"Host: github.com\r\nContent-Length: 4\r\n"
            b"Connection: keep-alive, x-remove\r\nX-Remove: secret\r\n"
            b"X-Keep: value\r\n\r\n"
        )
        length, present = DomainProxy.request_content_length(headers)
        rebuilt = DomainProxy.origin_header(
            "POST", "/upload", "HTTP/1.1", headers, "github.com", 80,
            length, present, None,
        )
        self.assertEqual(1, rebuilt.lower().count(b"content-length:"))
        self.assertIn(b"Content-Length: 4\r\n", rebuilt)
        self.assertIn(b"Connection: close\r\n", rebuilt)
        self.assertIn(b"x-keep: value\r\n", rebuilt)
        self.assertNotIn(b"x-remove", rebuilt.lower())

    def test_plain_http_forwards_one_exact_body_and_rejects_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proxy = DomainProxy.start(Path(directory), ("github.com",))
            try:
                with patch.object(proxy, "connect") as connect:
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.settimeout(2)
                    client.connect(str(proxy.socket_path))
                    client.sendall(
                        b"GET http://github.com/first HTTP/1.1\r\n"
                        b"Host: github.com\r\n\r\n"
                        b"GET /second HTTP/1.1\r\nHost: blocked.example\r\n\r\n"
                    )
                    response = client.recv(1024)
                    client.close()
                    self.assertTrue(response.startswith(b"HTTP/1.1 403"), response)
                    connect.assert_not_called()

                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.settimeout(2)
                    client.connect(str(proxy.socket_path))
                    client.sendall(
                        b"CONNECT github.com:80 HTTP/1.1\r\n"
                        b"Host: github.com:80\r\n\r\n"
                    )
                    response = client.recv(1024)
                    client.close()
                    self.assertTrue(response.startswith(b"HTTP/1.1 403"), response)
                    connect.assert_not_called()

                proxy_side, origin_side = socket.socketpair()
                received: list[bytes] = []

                def origin() -> None:
                    data = bytearray()
                    while True:
                        chunk = origin_side.recv(4096)
                        if not chunk:
                            break
                        data.extend(chunk)
                    received.append(bytes(data))
                    origin_side.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                        b"Connection: close\r\n\r\nok"
                    )
                    origin_side.close()

                origin_thread = threading.Thread(target=origin)
                origin_thread.start()
                with patch.object(proxy, "connect", return_value=proxy_side):
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.settimeout(2)
                    client.connect(str(proxy.socket_path))
                    client.sendall(
                        b"POST http://github.com/upload HTTP/1.1\r\n"
                        b"Host: github.com\r\nContent-Length: 4\r\n"
                        b"Connection: keep-alive\r\n\r\ntest"
                    )
                    response = bytearray()
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response.extend(chunk)
                    client.close()
                origin_thread.join(timeout=2)
                self.assertFalse(origin_thread.is_alive())
                self.assertTrue(bytes(response).startswith(b"HTTP/1.1 200 OK"))
                request = received[0]
                self.assertTrue(request.startswith(b"POST /upload HTTP/1.1\r\n"))
                self.assertEqual(1, request.lower().count(b"content-length:"))
                self.assertIn(b"Connection: close\r\n", request)
                self.assertTrue(request.endswith(b"\r\n\r\ntest"))
            finally:
                proxy.close()

    def test_legacy_boolean_network_permission_migrates_without_weakening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            data_file = Path(directory) / "tokens.json"
            store = TokenStore(root, data_file, None)
            record = store.create(
                name="legacy",
                expires_at=None,
                path_prefix="project",
                can_read=True,
                can_write=True,
                shell_mode="restricted",
                network_mode="full",
            )
            payload = json.loads(data_file.read_text(encoding="utf-8"))
            item = payload["tokens"][0]
            item.pop("network_mode")
            item["allow_network"] = True
            data_file.write_text(json.dumps(payload), encoding="utf-8")
            restored = TokenStore(root, data_file, None).get(record.token)
            self.assertEqual("full", restored.network_mode)
            saved = json.loads(data_file.read_text(encoding="utf-8"))["tokens"][0]
            self.assertEqual("full", saved["network_mode"])
            self.assertNotIn("allow_network", saved)


if __name__ == "__main__":
    unittest.main()

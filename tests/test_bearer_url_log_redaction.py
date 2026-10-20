"""Bearer approval and password-setup tickets must never reach access logs."""
from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.server_runtime.http_support import (
    HttpSupportMixin, LOGGER, OAUTH_DISCOVERY_LOGGER,
)


class BearerURLLogRedactionTests(unittest.TestCase):
    @staticmethod
    def _emit(path: str, method: str = "GET", status: int = 200) -> None:
        handler = SimpleNamespace(
            path=path,
            server=SimpleNamespace(config=SimpleNamespace(url_base_path="/kapsel")),
            address_string=lambda: "127.0.0.1",
        )
        # BaseHTTPRequestHandler's access log format includes requestline.
        HttpSupportMixin.log_message(
            handler, '"%s" %s %s',
            f"{method} {path} HTTP/1.1", str(status), "-",
        )
        # Error-log paths must go through the same redactor.
        HttpSupportMixin.log_message(
            handler, "code %d, message %s: %s",
            status, "bad request", path,
        )

    def test_verbose_file_log_never_persists_workspace_password_ticket(self):
        ticket = "A" * 43
        approval = "B" * 43
        cases = [
            ("/kapsel/password-setup/" + ticket, "GET", 200),
            ("/kapsel/password-setup/" + ticket + "?utm_source=chatgpt.com", "POST", 403),
            ("/kapsel/admin/password-setup/" + ticket, "GET", 303),
            ("/kapsel/admin/password-setup/" + ticket + "?utm_source=chatgpt.com", "POST", 403),
            ("/admin/password-setup/" + ticket, "HEAD", 405),
            ("/custom/admin/password-setup/" + ticket + "?next=" + ticket, "GET", 400),
            ("/kapsel/capability/" + approval + "?utm_source=example", "GET", 200),
            ("/kapsel/admin/capability/" + approval, "POST", 403),
        ]
        with tempfile.TemporaryDirectory(prefix="openkapsel-redact-") as directory:
            file_path = Path(directory) / "verbose.log"
            output = logging.FileHandler(file_path, encoding="utf-8")
            original_level = LOGGER.level
            LOGGER.setLevel(logging.INFO)
            LOGGER.addHandler(output)
            try:
                for path, method, status in cases:
                    self._emit(path, method, status)
            finally:
                LOGGER.removeHandler(output)
                output.close()
                LOGGER.setLevel(original_level)
            logged = file_path.read_text(encoding="utf-8")
        self.assertEqual(16, logged.count("127.0.0.1 -"))
        self.assertNotIn(ticket, logged)
        self.assertNotIn(approval, logged)
        self.assertNotIn("utm_source=", logged)
        self.assertNotIn("?next=", logged)
        self.assertIn("/password-setup/[redacted]", logged)
        self.assertIn("/admin/password-setup/[redacted]", logged)
        self.assertIn("/capability/[redacted]", logged)
        self.assertIn("GET ", logged)
        self.assertIn("POST ", logged)
        self.assertIn("HEAD ", logged)

    def test_normal_url_remains_in_log(self):
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self._emit("/kapsel/admin", "GET", 200)
        joined = "\n".join(captured.output)
        self.assertIn("GET /kapsel/admin HTTP/1.1", joined)
        self.assertNotIn("[redacted]", joined)

    def test_oauth_requests_still_strip_sensitive_queries(self):
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self._emit("/kapsel/oauth/authorize?secret=not-for-logs")
        self.assertNotIn("not-for-logs", "\n".join(captured.output))


if __name__ == "__main__":
    unittest.main()

"""Control-token OAuth consent against isolated temporary servers and fixtures."""
from __future__ import annotations

import concurrent.futures
import json
import re
import time
import unittest
from dataclasses import replace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from openkapsel.auth.oauth_consent import ConsentLimiter, ConsentProtector
from openkapsel.auth.oauth_store import OAuthError, OAuthStore, challenge
from tests import test_oauth


class ControlConsentHTTPTests(unittest.TestCase):
    setUp = test_oauth.OAuthHTTPTests.setUp
    tearDown = test_oauth.OAuthHTTPTests.tearDown
    request = test_oauth.OAuthHTTPTests.request
    form = test_oauth.OAuthHTTPTests.form
    rpc = test_oauth.OAuthHTTPTests.rpc
    authorize = test_oauth.OAuthHTTPTests.authorize

    def pending(self, *, cookie=None, client_name="Test client"):
        metadata = {"redirect_uris": ["https://client.test/callback"], "token_endpoint_auth_method": "none", "client_name": client_name}
        status, _, raw = self.request("POST", self.prefix + "/register", json.dumps(metadata), {"Content-Type": "application/json"})
        self.assertEqual(201, status, raw)
        client = json.loads(raw)
        verifier = "z" * 64
        params = {"client_id": client["client_id"], "response_type": "code", "redirect_uri": metadata["redirect_uris"][0], "code_challenge": challenge(verifier), "code_challenge_method": "S256", "resource": self.resource, "state": "return-state"}
        status, headers, raw = self.request("GET", self.prefix + "/authorize?" + urlencode(params))
        self.assertEqual(303, status, raw)
        location = headers["Location"]
        status, headers, raw = self.request("GET", location, headers={"Cookie": cookie} if cookie else {})
        self.assertEqual(200, status, raw)
        return {"rid": parse_qs(urlsplit(location).query)["request"][0], "location": location,
                "cookie": headers["Set-Cookie"].split(";", 1)[0],
                "csrf": re.search(r'name="csrf" value="([^"]+)"', raw.decode()).group(1),
                "client": client, "verifier": verifier, "headers": headers, "page": raw}

    def submit(self, pending, *, values=None, headers=None):
        form = {"request": pending["rid"], "csrf": pending["csrf"], "decision": "approve", "control_token": self.record.control_token}
        form.update(values or {})
        auth = {"Cookie": pending["cookie"], "Origin": self.server.config.public_base_url}
        auth.update(headers or {})
        return self.form(self.prefix + "/consent", form, auth)

    def assert_pending(self, pending):
        self.assertEqual(pending["rid"], self.server.oauth.request(pending["rid"])["id"])
        self.assertIsNone(self.server.oauth.get(self.cid)["client_id"])

    def test_standalone_page_security_headers_and_no_admin_session(self):
        from openkapsel.auth.tokens import PathGrant
        external = self.server.config.root.parent / "permitted-external-fixture"
        external.mkdir()
        self.server.tokens.update(self.record.token, shell_mode="full", allowed_paths=(PathGrant(str(external)),))
        pending = self.pending(client_name='<script>alert("x")</script>')
        self.assertIn(b"Full Shell:", pending["page"])
        self.assertNotIn(str(external).encode(), pending["page"])
        headers, page = pending["headers"], pending["page"]
        self.assertIn(b"&lt;script&gt;", page)
        self.assertNotIn(b"<script", page)
        self.assertNotIn(b"localStorage", page)
        self.assertNotIn(b"/admin/login", page)
        self.assertIn(b'type="password" name="control_token"', page)
        self.assertIn("__Host-openkapsel_oauth=", headers["Set-Cookie"])
        for attr in ("HttpOnly", "Secure", "SameSite=Lax", "Max-Age=600", "Path=/"):
            self.assertIn(attr, headers["Set-Cookie"])
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual("no-referrer", headers["Referrer-Policy"])
        self.assertEqual("DENY", headers["X-Frame-Options"])
        self.assertIn("script-src 'none'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        for secret in (self.record.token, self.record.control_token, self.record.preview_token):
            self.assertNotIn(secret, page.decode() + json.dumps(headers))
        self.assertEqual({}, self.server.admin_sessions._sessions)
        self.assert_pending(pending)
        status, headers, body = self.submit(pending)
        self.assertEqual(303, status, body)
        self.assertEqual({}, self.server.admin_sessions._sessions)
        query = parse_qs(urlsplit(headers["Location"]).query)
        self.assertEqual({"code", "state"}, set(query))
        self.assertEqual(["return-state"], query["state"])
        self.assertNotIn(self.record.control_token, headers["Location"])
        self.assertNotIn(self.record.control_token.encode(), self.server.oauth.path.read_bytes())
        status, _, page = self.request("GET", "/kapsel/admin", headers={"Cookie": pending["cookie"]})
        self.assertEqual(200, status)
        self.assertIn(b"Sign in to administration", page)

    def test_only_exact_configuration_control_is_accepted_even_for_same_directory(self):
        same = self.server.tokens.create(name="Other config", path_prefix="project", shell_mode="none", expires_at=None, can_read=True, can_write=False)
        other = self.server.tokens.create(name="Other workspace", path_prefix="other", shell_mode="none", expires_at=None, can_read=True, can_write=True)
        pending = self.pending()
        for token in (self.record.token, self.record.preview_token, same.control_token, other.control_token):
            status, _, raw = self.submit(pending, values={"control_token": token})
            self.assertEqual(403, status, raw)
            self.assertNotIn(token.encode(), raw)
            self.assert_pending(pending)
        self.assertEqual(303, self.submit(pending)[0])

    def test_malformed_and_missing_control_tokens_are_safe_failures(self):
        pending = self.pending()
        for token in ("", "\u4e2d\u6587", "x\x00y", "x" * 1025):
            status, _, raw = self.submit(pending, values={"control_token": token})
            self.assertEqual(403, status, raw)
            self.assert_pending(pending)

    def test_expired_credentials_rejected_and_current_rotated_token_works(self):
        pending = self.pending()
        self.server.tokens.update(self.record.token, credentials_expires_at="2000-01-01T00:00:00+00:00")
        self.assertEqual(403, self.submit(pending)[0])
        self.assert_pending(pending)
        self.server.tokens.renew_credentials(self.record.token)
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.assertEqual(403, self.submit(pending)[0])
        self.assertEqual(303, self.submit(pending, values={"control_token": current.control_token})[0])

    def test_disabled_and_expired_configuration_cannot_approve(self):
        pending = self.pending()
        self.server.tokens.update(self.record.token, enabled=False)
        self.assertEqual(403, self.submit(pending)[0])
        self.server.tokens.update(self.record.token, enabled=True, expires_at="2000-01-01T00:00:00+00:00")
        self.assertEqual(403, self.submit(pending)[0])
        self.assert_pending(pending)

    def test_csrf_requires_matching_browser_and_unambiguous_cookie(self):
        pending = self.pending()
        attempts = [({"csrf": "wrong"}, {}), ({}, {"Cookie": ""}),
                    ({}, {"Cookie": "__Host-openkapsel_oauth=" + "a" * 43}),
                    ({}, {"Cookie": pending["cookie"] + "; " + pending["cookie"]})]
        for values, headers in attempts:
            self.assertEqual(403, self.submit(pending, values=values, headers=headers)[0])
            self.assert_pending(pending)
        self.assertEqual(303, self.submit(pending)[0])

    def test_cross_request_proof_and_wrong_connection_rejected(self):
        first = self.pending()
        second = self.pending(cookie=first["cookie"])
        self.assertEqual(first["cookie"], second["cookie"])
        self.assertEqual(403, self.submit(second, values={"csrf": first["csrf"]})[0])
        other = self.server.oauth.create(self.record.app_id, "project", "Other connection")
        status, _, _ = self.request("GET", "/kapsel/oauth/" + other["id"] + "/consent?request=" + first["rid"])
        self.assertEqual(403, status)
        self.assertEqual(303, self.submit(second)[0])

    def test_foreign_null_and_malformed_origin_are_rejected(self):
        pending = self.pending()
        for origin in ("https://evil.test", "null", "https://example.test/path", "https://example.test#fragment"):
            self.assertEqual(403, self.submit(pending, headers={"Origin": origin})[0])
        self.assertEqual(403, self.submit(pending, headers={"Sec-Fetch-Site": "cross-site"})[0])
        self.assert_pending(pending)
        self.assertEqual(303, self.submit(pending)[0])

    def test_permissions_changed_after_display_require_fresh_confirmation(self):
        pending = self.pending()
        self.server.tokens.update(self.record.token, can_write=False)
        self.assertEqual(403, self.submit(pending)[0])
        self.assert_pending(pending)
        status, _, raw = self.request("GET", pending["location"], headers={"Cookie": pending["cookie"]})
        self.assertEqual(200, status)
        pending["csrf"] = re.search(r'name="csrf" value="([^"]+)"', raw.decode()).group(1)
        self.assertIn(b"Write: Not allowed", raw)
        self.assertEqual(303, self.submit(pending)[0])

    def test_reassignment_invalidates_pending_requests_and_old_codes(self):
        pending = self.pending()
        other = self.server.tokens.create(name="Other", path_prefix="other", shell_mode="none", expires_at=None, can_read=True, can_write=True)
        self.server.oauth.update(self.cid, "Reassigned", app_id=other.app_id, workspace="other")
        self.assertEqual(400, self.submit(pending)[0])
        self.server.oauth.update(self.cid, "Returned", app_id=self.record.app_id, workspace="project")
        self.assertEqual(400, self.submit(pending)[0])
        fresh = self.pending()
        status, headers, _ = self.submit(fresh)
        self.assertEqual(303, status)
        code = parse_qs(urlsplit(headers["Location"]).query)["code"][0]
        self.server.oauth.update(self.cid, "Again", app_id=other.app_id, workspace="other")
        status, _, _ = self.form(self.prefix + "/token", {"grant_type": "authorization_code", "client_id": fresh["client"]["client_id"],
            "code": code, "code_verifier": fresh["verifier"], "resource": self.resource, "redirect_uri": "https://client.test/callback"})
        self.assertEqual(400, status)

    def test_reassignment_inside_approval_is_checked_in_transaction(self):
        pending = self.pending()
        original = self.server.oauth.approve
        def changed(*args, **kwargs):
            self.server.oauth.update(self.cid, "Reassigned", app_id="different-app", workspace="project")
            return original(*args, **kwargs)
        with patch.object(self.server.oauth, "approve", side_effect=changed):
            self.assertEqual(400, self.submit(pending)[0])
        self.assertIsNone(self.server.oauth.get(self.cid)["client_id"])

    def test_expired_request_server_restart_and_replay_fail_closed(self):
        pending = self.pending()
        self.server.oauth_consent = ConsentProtector()
        self.assertEqual(403, self.submit(pending)[0])
        with self.server.oauth._db() as db:
            db.execute("UPDATE requests SET expires_at=? WHERE id=?", (time.time() - 1, pending["rid"]))
        self.assertEqual(400, self.submit(pending)[0])
        fresh = self.pending()
        self.assertEqual(303, self.submit(fresh)[0])
        self.assertEqual(400, self.submit(fresh)[0])

    def test_cancel_requires_csrf_but_not_control_credential(self):
        pending = self.pending()
        self.assertEqual(403, self.submit(pending, values={"decision": "deny", "csrf": "bad", "control_token": ""})[0])
        self.assert_pending(pending)
        status, headers, raw = self.submit(pending, values={"decision": "deny", "control_token": ""})
        self.assertEqual(303, status, raw)
        self.assertEqual({"error": ["access_denied"], "state": ["return-state"]}, parse_qs(urlsplit(headers["Location"]).query))
        self.assertIsNone(self.server.oauth.get(self.cid)["client_id"])
        with self.assertRaises(OAuthError):
            self.server.oauth.request(pending["rid"])

    def test_admin_session_does_not_bypass_token_and_legacy_posts_are_closed(self):
        pending = self.pending()
        session = self.server.admin_sessions.create()
        admin_cookie = "ws_admin=" + session.id
        self.assertEqual(403, self.submit(pending, values={"control_token": ""}, headers={"Cookie": pending["cookie"] + "; " + admin_cookie})[0])
        status, headers, _ = self.request("GET", "/kapsel/admin/oauth/approve?request=" + pending["rid"])
        self.assertEqual(303, status)
        self.assertEqual(pending["location"], headers["Location"])
        status, headers, _ = self.form("/kapsel/admin/oauth/approve", {"request": pending["rid"], "csrf": session.csrf, "decision": "approve"}, {"Cookie": admin_cookie})
        self.assertEqual(400, status)
        self.assertNotIn("Location", headers)
        self.assert_pending(pending)

    def test_duplicate_fields_unknown_decision_and_query_credentials_are_rejected(self):
        pending = self.pending()
        values = [("request", pending["rid"]), ("csrf", pending["csrf"]), ("decision", "approve"),
                  ("control_token", self.record.control_token), ("control_token", "other")]
        self.assertEqual(400, self.form(self.prefix + "/consent", values, {"Cookie": pending["cookie"]})[0])
        self.assertEqual(400, self.submit(pending, values={"decision": "unknown"})[0])
        self.assertEqual(400, self.submit(pending, values={"unexpected": True})[0])
        with self.assertLogs("openkapsel", level="INFO") as captured:
            status, _, raw = self.request("GET", pending["location"] + "&control_token=" + self.record.control_token)
        self.assertEqual(400, status)
        self.assertNotIn(self.record.control_token.encode(), raw)
        self.assertNotIn(self.record.control_token, "\n".join(captured.output))
        self.assert_pending(pending)

    def test_rate_limits_do_not_affect_admin_login(self):
        pending = self.pending()
        for _ in range(5):
            self.assertEqual(403, self.submit(pending, values={"control_token": "wrong"})[0])
        status, headers, _ = self.submit(pending)
        self.assertEqual(429, status)
        self.assertGreater(int(headers["Retry-After"]), 0)
        self.assertEqual({}, self.server.admin_login_limiter._failures)
        self.assert_pending(pending)

    def test_existing_connections_work_without_admin_and_metadata_advertises_consent(self):
        self.server.config = replace(self.server.config, admin_username=None, admin_password_hash=None)
        token, _, _ = self.authorize()
        self.assertEqual(200, self.rpc(token["access_token"], "tools/list")[0])
        self.assertEqual(404, self.request("GET", "/kapsel/admin")[0])
        status, _, raw = self.request("GET", "/.well-known/oauth-authorization-server" + self.prefix)
        self.assertEqual(200, status)
        consent = json.loads(raw)["openkapsel_consent"]
        self.assertEqual("matching_control_token", consent["authentication"])
        self.assertFalse(consent["administrator_login_required"])
        status, payload = self.rpc(token["access_token"], "tools/call", {"name": "workspace_info", "arguments": {}})
        self.assertEqual(200, status, payload)
        self.assertEqual(consent, payload["result"]["structuredContent"]["authentication"]["consent"])

    def test_refresh_survives_control_expiry_but_configuration_disable_blocks_it(self):
        token, _, _ = self.authorize()
        client_id = self.server.oauth.get(self.cid)["client_id"]
        self.server.tokens.renew_credentials(self.record.token)
        current = self.server.tokens.get_by_app_id(self.record.app_id)
        self.server.tokens.update(current.token, credentials_expires_at="2000-01-01T00:00:00+00:00")
        body = {"grant_type": "refresh_token", "client_id": client_id, "resource": self.resource, "refresh_token": token["refresh_token"]}
        status, _, raw = self.form(self.prefix + "/token", body)
        self.assertEqual(200, status, raw)
        refreshed = json.loads(raw)
        self.assertEqual(200, self.rpc(refreshed["access_token"], "tools/list")[0])
        self.server.tokens.update(current.token, enabled=False)
        body["refresh_token"] = refreshed["refresh_token"]
        self.assertEqual(403, self.form(self.prefix + "/token", body)[0])

    def test_concurrent_browser_submissions_issue_only_one_code(self):
        pending = self.pending()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: self.submit(pending)[0], range(2)))
        self.assertEqual([303, 400], sorted(statuses))

    def test_public_https_required_except_loopback_development(self):
        self.server.config = replace(self.server.config, public_base_url="http://public.example.test")
        self.assertEqual(503, self.request("GET", "/.well-known/oauth-authorization-server" + self.prefix)[0])
        self.server.config = replace(self.server.config, public_base_url="http://127.0.0.1")
        self.resource = "http://127.0.0.1" + self.mcp
        pending = self.pending()
        self.assertTrue(pending["cookie"].startswith("openkapsel_oauth="))
        self.assertNotIn("; Secure", pending["headers"]["Set-Cookie"])
        self.assertEqual(303, self.submit(pending)[0])


class ConsentLimiterTests(unittest.TestCase):
    def test_atomic_address_and_request_budgets_and_expiration(self):
        limiter = ConsentLimiter()
        with patch("openkapsel.auth.oauth_consent.time.monotonic", return_value=100):
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(lambda i: limiter.take("one-address", str(i)), range(20)))
            self.assertEqual(10, results.count(0))
        with patch("openkapsel.auth.oauth_consent.time.monotonic", return_value=161):
            self.assertEqual(0, limiter.take("one-address", "new"))
        limiter = ConsentLimiter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda i: limiter.take(str(i), "one-request"), range(20)))
        self.assertEqual(5, results.count(0))

    def test_memory_is_bounded_and_does_not_evict_live_buckets(self):
        limiter = ConsentLimiter()
        with patch("openkapsel.auth.oauth_consent.MAX_CONSENT_BUCKETS", 2):
            self.assertEqual(0, limiter.take("address", "request"))
            self.assertGreater(limiter.take("other", "different"), 0)
            self.assertEqual(2, len(limiter._buckets))
            self.assertEqual(0, limiter.take("address", "request"))


class ConsentRequestStoreTests(unittest.TestCase):
    setUp = test_oauth.OAuthStoreTests.setUp
    tearDown = test_oauth.OAuthStoreTests.tearDown
    params = test_oauth.OAuthStoreTests.params
    form = test_oauth.OAuthStoreTests.form
    issue = test_oauth.OAuthStoreTests.issue

    def test_expected_owner_binding_is_checked_without_consuming_request(self):
        rid = self.store.start(self.cid, self.params(), self.resource)
        for binding in (("other", "project"), ("app", "other")):
            with self.assertRaises(OAuthError):
                self.store.approve(rid, expected_binding=binding)
            self.assertEqual(rid, self.store.request(rid)["id"])
        self.store.approve(rid, expected_binding=("app", "project"))

    def test_independent_store_instances_cannot_double_approve(self):
        rid = self.store.start(self.cid, self.params(), self.resource)
        stores = [OAuthStore(self.path) for _ in range(4)]
        def approve(store):
            try:
                return store.approve(rid, expected_binding=("app", "project"))[1]
            except OAuthError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            codes = list(pool.map(approve, stores))
        self.assertEqual(1, sum(code is not None for code in codes))

    def test_migration_discards_unpinned_handshakes_but_preserves_existing_grants(self):
        issued = self.issue()
        with self.store._db() as db:
            db.execute("DROP TABLE requests")
            db.execute("CREATE TABLE requests(id TEXT PRIMARY KEY, connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE, client_id TEXT NOT NULL, params TEXT NOT NULL, expires_at REAL NOT NULL, code_hash TEXT UNIQUE)")
            db.execute("INSERT INTO requests VALUES(?,?,?,?,?,NULL)", ("legacy-request", self.cid, self.client["client_id"], json.dumps(self.params()), time.time() + 600))
        migrated = OAuthStore(self.path)
        with self.assertRaises(OAuthError):
            migrated.request("legacy-request")
        self.assertEqual(self.cid, migrated.authenticate(self.cid, issued["access_token"])["id"])
        with migrated._db() as db:
            self.assertTrue({"app_id", "workspace"} <= {row["name"] for row in db.execute("PRAGMA table_info(requests)")})
        rid = migrated.start(self.cid, self.params(), self.resource)
        self.assertEqual("app", migrated.request(rid)["app_id"])

    def test_comment_edit_preserves_pending_request_but_owner_edit_invalidates(self):
        rid = self.store.start(self.cid, self.params(), self.resource)
        self.store.update(self.cid, "New label")
        self.assertEqual(rid, self.store.request(rid)["id"])
        self.store.update(self.cid, "Different owner", app_id="other-app", workspace="project")
        with self.assertRaises(OAuthError):
            self.store.request(rid)


if __name__ == "__main__":
    unittest.main()

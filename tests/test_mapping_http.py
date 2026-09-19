"""Administration and HTTP credential boundaries without mounting FUSE."""

import html
import json
import re
import unittest
from unittest.mock import patch

from tests import test_oauth


class MappingHTTPTests(unittest.TestCase):
    setUp = test_oauth.OAuthHTTPTests.setUp
    tearDown = test_oauth.OAuthHTTPTests.tearDown
    request = test_oauth.OAuthHTTPTests.request
    form = test_oauth.OAuthHTTPTests.form

    def test_admin_csrf_and_one_time_provider_configuration(self):
        path = "/kapsel/admin/mappings"
        self.assertNotEqual(200, self.request("GET", path)[0])
        status, headers, _ = self.form("/kapsel/admin/login", {"username": "admin", "password": "test-password-123"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        auth = {"Cookie": cookie}
        session = self.server.admin_sessions.get(cookie.split("=", 1)[1])
        form = {"action": "create", "app_id": self.record.app_id, "name": "laptop", "writable": "on"}
        self.assertEqual(403, self.form(path, form, auth)[0])
        self.assertEqual([], self.server.mappings.store.list())
        form["csrf"] = session.csrf
        with patch.object(self.server.mappings, "mount"):
            status, _, raw = self.form(path, form, auth)
        self.assertEqual(status, 200)
        config = json.loads(html.unescape(re.search(r'<pre>[^\n]*\n(.*?)</pre>', raw.decode(), re.S)[1]))
        row = self.server.mappings.store.list()[0]
        self.assertEqual(config["url"], "wss://example.test/kapsel/mapping-connect/" + row["id"])
        self.server.mappings.store.authenticate(row["id"], config["token"])
        self.assertTrue(config["sandbox"])
        self.assertFalse(config["allow_exec"])
        self.assertNotIn(config["token"].encode(), self.request("GET", path, headers=auth)[2])
        base = "/kapsel/w/" + self.record.token
        self.assertNotIn(config["token"].encode(), self.request("GET", base + "/mappings")[2])
        # Provider credentials cannot grant REST control or task access.
        for credential in (None, config["token"]):
            headers = {} if credential is None else {"Authorization": "Bearer " + credential}
            self.assertEqual(401, self.request("GET", base + "/mappings/" + row["id"] + "/tasks", headers=headers)[0])

    def test_offline_mapping_is_not_an_empty_local_directory(self):
        row, _ = self.server.mappings.store.create(self.record.path_prefix, "offline")
        root = self.server.tokens.scope_root(self.record)
        (root / row["name"]).mkdir()
        base = "/kapsel/w/" + self.record.token
        self.assertEqual(503, self.request("GET", base + "/fs/list?path=offline")[0])
        self.assertEqual(200, self.request("GET", base + "/fs/list?path=.")[0])

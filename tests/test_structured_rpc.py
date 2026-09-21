"""Structured data RPC correctness, permissions and atomic-publication tests."""
import errno
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins.structured import plugin, _installed
from openkapsel.rpc_plugins._data import Snapshot


class Task:
    def __init__(self, cancelled=False):
        self.cancelled = cancelled
        self.output = []
    def check_cancelled(self):
        if self.cancelled:
            raise OSError(errno.ECANCELED, "cancelled")
    def write(self, value):
        self.output.append(value)


class StructuredTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        cls = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            cls = WindowsClientFiles
        self.files = cls(self.root, writable=True)
    def tearDown(self):
        self.files.close()
        self.temp.cleanup()
    def source(self, name="a.json", value='{"a":1,"list":[1,2,3]}\n'):
        (self.root / name).write_bytes(value.encode("utf-8"))
        return name
    def call(self, operation, args, expected=200, task=None):
        if operation in {"write", "patch"}:
            value = plugin.dispatch_task(self.files, operation, args, task or Task())
        else:
            value = self.files.dispatch("structured_" + operation, args)
        self.assertEqual(expected, value["status"], value)
        return value.get("body", value.get("error"))
    def tag(self, path):
        return self.call("read", {"path": path})["etag"]

    def test_read_pointer_pagination_and_native_integer(self):
        path = self.source(value='{"a/b":{"~key":[1,2,3]},"big":9007199254740993}')
        page = self.call("read", {"path": path, "pointer": "/a~1b/~0key", "offset": 1, "limit": 1})
        self.assertEqual([2], page["value"])
        self.assertEqual(2, page["next_offset"])
        self.assertTrue(page["truncated"])
        big = self.call("read", {"path": path, "pointer": "/big"})
        self.assertEqual("9007199254740993", big["value"])
        self.assertEqual("integer", big["native_types"][""])
        self.call("read", {"path": path, "pointer": "/a~2b"}, 400)
        self.call("read", {"path": path, "pointer": "/missing"}, 404)

    def test_create_only_write_and_conditional_replace(self):
        first = self.call("write", {"path": "new.json", "content": '{"a":1}'})
        self.assertTrue(first["created"])
        self.call("write", {"path": "new.json", "content": '{"a":2}'}, 409)
        self.assertEqual('{"a":1}', (self.root / "new.json").read_text())
        second = self.call("write", {"path": "new.json", "content": '{"a":2}', "expected_etag": first["etag"]})
        self.assertFalse(second["created"])
        self.assertNotEqual(first["etag"], second["etag"])
        for old in (first["etag"], "*"):
            self.call("write", {"path": "new.json", "content": '{}', "expected_etag": old}, 412)
        self.call("write", {"path": "nested/new.toml", "format": "json", "content": '{}', "create_parents": True})
        self.assertTrue((self.root / "nested/new.toml").exists())
        self.assertFalse(list(self.root.glob(".*.openkapsel-put-*")))

    def test_preview_patch_test_failure_and_noop(self):
        path = self.source()
        before = (self.root / path).read_bytes()
        tag = self.tag(path)
        operations = [{"op": "test", "path": "/a", "value": 1},
                      {"op": "replace", "path": "/a", "value": 4},
                      {"op": "add", "path": "/list/-", "value": 9},
                      {"op": "remove", "path": "/list/0"}]
        preview = self.call("preview", {"path": path, "operations": operations, "expected_etag": tag})
        self.assertTrue(preview["changed"])
        self.assertIn("after", preview["diff"])
        self.assertEqual(before, (self.root / path).read_bytes())
        broken = operations + [{"op": "test", "path": "/a", "value": 99}]
        self.call("patch", {"path": path, "operations": broken, "expected_etag": tag}, 409)
        self.assertEqual(before, (self.root / path).read_bytes())
        same = self.call("patch", {"path": path, "expected_etag": tag, "operations": [operations[0]]})
        self.assertFalse(same["changed"])
        self.assertEqual(tag, same["etag"])
        self.call("patch", {"path": path, "operations": operations, "expected_etag": tag})
        self.assertEqual({"a": 4, "list": [2, 3, 9]}, json.loads((self.root / path).read_text()))

    def test_boolean_test_is_not_numeric_equality(self):
        path = self.source(value='{"a":true}')
        self.call("preview", {"path": path, "operations": [{"op": "test", "path": "/a", "value": 1}]}, 409)

    def test_invalid_documents_arguments_and_limits(self):
        for source in ('{"a":1,"a":2}', '{bad', '{"a":NaN}', r'{"a":"\ud800"}', r'{"\ud800":1}', '[' * 80 + '0' + ']' * 80):
            path = self.source(value=source)
            result = plugin.dispatch(self.files, "validate", {"path": path})
            self.assertIn(result["status"], (413, 422), result)
        path = self.source()
        self.call("read", {"path": path, "unknown": True}, 400)
        self.call("patch", {"path": path, "operations": [{"op": "remove", "path": "/a"}]}, 400)
        self.call("preview", {"path": path, "operations": [{"op": "remove", "path": "/a", "value": 1}]}, 400)
        self.call("preview", {"path": path, "operations": [{"op": "remove", "path": ""}]}, 400)
        self.call("write", {"path": "bad.toml", "format": "json", "content": 'x'}, 422)
        self.assertFalse((self.root / "bad.toml").exists())
        (self.root / "huge.json").write_bytes(b' ' * (2 * 1024 * 1024 + 1))
        self.call("read", {"path": "huge.json"}, 413)

    def test_readonly_private_paths_and_cancel(self):
        path = self.source()
        self.files.writable = False
        self.call("read", {"path": path})
        self.call("preview", {"path": path, "operations": [{"op": "replace", "path": "/a", "value": 2}]})
        self.call("write", {"path": "new.json", "content": '{}'}, 403)
        for name in ("../outside.json", ".openkapsel/x.json", ".a.openkapsel-put-secret"):
            value = plugin.dispatch(self.files, "read", {"path": name})
            self.assertEqual(403, value["status"], value)
        self.files.writable = True
        with self.assertRaises(OSError) as error:
            self.call("write", {"path": "cancel.json", "content": '{}'}, task=Task(True))
        self.assertEqual(errno.ECANCELED, error.exception.errno)
        self.assertFalse((self.root / "cancel.json").exists())

    @unittest.skipIf(os.name == "nt", "symlink privilege differs on Windows")
    def test_symlink_source_and_parent_are_rejected(self):
        path = self.source()
        (self.root / "link.json").symlink_to(self.root / path)
        self.assertNotEqual(200, plugin.dispatch(self.files, "read", {"path": "link.json"})["status"])
        (self.root / "dirlink").symlink_to(self.root, target_is_directory=True)
        self.assertNotEqual(200, plugin.dispatch_task(self.files, "write", {"path": "dirlink/escape.json", "content": '{}'}, Task())["status"])
        self.assertFalse((self.root / "escape.json").exists())

    def test_missing_optional_parsers_are_explicit(self):
        for suffix in ("yaml", "toml"):
            self.source("a." + suffix, "a: 1" if suffix == "yaml" else "a = 1")
            with patch("openkapsel.rpc_plugins.structured._installed", return_value=False):
                self.call("read", {"path": "a." + suffix}, 415)
                self.assertEqual(["json"], plugin.probe({})[2]["formats"])

    @unittest.skipUnless(_installed("ruamel.yaml"), "optional YAML dependency")
    def test_yaml_comments_quotes_dates_and_alias_policy(self):
        path = self.source("a.yaml", '# keep\r\na: "on"  # inline\r\nwhen: 2026-09-21\r\nitems: [1, 2]\r\n')
        tag = self.tag(path)
        self.call("patch", {"path": path, "expected_etag": tag,
                  "operations": [{"op": "replace", "path": "/a", "value": "off"}]})
        raw = (self.root / path).read_bytes()
        self.assertIn(b'# keep', raw)
        self.assertRegex(raw, rb'"off" +# inline')
        self.assertNotIn(b'\n', raw.replace(b'\r\n', b''))
        body = self.call("read", {"path": path})
        self.assertEqual("2026-09-21", body["value"]["when"])
        self.assertIn("/when", body["native_types"])
        self.source(path, 'base: &base {a: 1}\ncopy: *base\n')
        self.assertTrue(self.call("read", {"path": path})["yaml_aliases"])
        self.call("preview", {"path": path, "operations": [{"op": "replace", "path": "/base/a", "value": 2}]}, 409)
        for bad in ('x: !!python/object/apply:os.system ["echo NO"]', 'a: 1\na: 2\n', 'a: &a [*a]'):
            self.source(path, bad)
            out = plugin.dispatch(self.files, "read", {"path": path})
            self.assertIn(out["status"], (413, 422), out)

    @unittest.skipUnless(_installed("tomlkit"), "optional TOML dependency")
    def test_toml_comments_arrays_dates_and_null_rejection(self):
        path = self.source("a.toml", '# keep\na = 1 # inline\nitems = [1, 2]\nwhen = 2026-09-21\n[config]\nenabled = true\n')
        tag = self.tag(path)
        self.call("patch", {"path": path, "expected_etag": tag, "operations": [
            {"op": "replace", "path": "/a", "value": 3}, {"op": "add", "path": "/items/-", "value": 5}]})
        raw = (self.root / path).read_text()
        self.assertIn('a = 3 # inline', raw)
        self.assertIn('# keep', raw)
        self.assertIn('when = 2026-09-21', raw)
        before = (self.root / path).read_bytes()
        self.call("patch", {"path": path, "expected_etag": self.tag(path),
                  "operations": [{"op": "replace", "path": "/a", "value": None}]}, 422)
        self.assertEqual(before, (self.root / path).read_bytes())


if __name__ == "__main__":
    unittest.main()

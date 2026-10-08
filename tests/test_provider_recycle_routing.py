"""A Storage Provider uses its own remote-root recycle, never the server bin."""
from __future__ import annotations

import hashlib
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from openkapsel.files.file_handlers import FileHandlersMixin
from openkapsel.files.mutation import MutationPlan, _relocation_verified, _rollback, _transaction_domain
from openkapsel.files.recycle import RecycleBin
from openkapsel.files.safe_paths import SafePathAccess
from openkapsel.mapping.mapping_handlers import MappingHandlersMixin


class ProviderManager:
    def __init__(self, root):
        self.root = root
        self.row = {"name": "nextcloud", "id": "provider1"}

    def mapping_at_path(self, path):
        return self.row if Path(path).is_relative_to(self.root) else None

    def mapping_path(self, row):
        return self.root

    def check_path(self, path, **kwargs):
        if not Path(path).is_relative_to(self.root):
            raise RuntimeError("outside provider")


class Handler(MappingHandlersMixin, FileHandlersMixin):
    def __init__(self, server_root):
        self.token_scope_root = server_root
        self.provider_root = server_root / "nextcloud"
        self.provider_root.mkdir()
        self.server = SimpleNamespace(
            storage_providers=ProviderManager(self.provider_root),
            recycle_for=lambda root: RecycleBin(root),
            mappings=SimpleNamespace(at_path=lambda path: None,
                                     store=SimpleNamespace(list=lambda prefix: [])),
        )
        self.token_record = SimpleNamespace(path_prefix="work", allowed_paths=(), can_read=True, can_write=True)

    def _safe_path_access(self):
        return SafePathAccess((self.token_scope_root,))

    def _file_stat(self, path):
        return Path(path).stat()

    def _open_binary(self, path):
        return Path(path).open("rb")


class ProviderRecycleRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.handler = Handler(self.root)

    def test_provider_recycle_restore_and_purge_are_separate_from_server(self):
        handler = self.handler
        victim = handler.provider_root / "docs" / "file.txt"
        victim.parent.mkdir()
        victim.write_bytes(b"provider payload")
        result = handler._recycle_path(victim)
        self.assertEqual("nextcloud", result["root"])
        self.assertFalse(victim.exists())
        self.assertFalse((self.root / ".openkapsel").exists())
        self.assertTrue((handler.provider_root / result["stored_path"]).is_file())
        self.assertIsNone(handler._mapped_recycle_root("nextcloud"))
        self.assertEqual(handler.provider_root, handler._storage_recycle_named_root("nextcloud"))

        listing, total = RecycleBin(handler.provider_root, initialize_layout=False).list_items(0, 10)
        self.assertEqual(1, total)
        self.assertEqual(result["recycle_id"], listing[0]["recycle_id"])
        restored = handler._transaction_restore_recycle(result["recycle_id"], root="nextcloud")
        self.assertTrue(restored["restored"])
        self.assertEqual(b"provider payload", victim.read_bytes())

        another = handler._transaction_recycle(victim, victim)
        self.assertEqual("nextcloud", another["root"])
        self.assertFalse(victim.exists())
        purged = RecycleBin(handler.provider_root, initialize_layout=False).purge(another["recycle_id"])
        self.assertTrue(purged["purged"])
        self.assertFalse(victim.exists())

    def test_provider_public_list_restore_and_purge_use_provider_bin(self):
        handler = self.handler
        victim = handler.provider_root / "for-api.txt"
        victim.write_bytes(b"api")
        record = handler._recycle_path(victim)
        handler._require_permission = lambda *args: None
        handler._query_int = lambda query, name, default, **kwargs: default
        handler._query_one = lambda query, name, default: query.get(name, [default])[0]
        responses = []
        handler._send_json = lambda status, result: responses.append((status, result))
        handler._handle_recycle_list({"root": ["nextcloud"]})
        self.assertEqual(1, responses[-1][1]["total"])
        self.assertEqual(record["recycle_id"], responses[-1][1]["entries"][0]["recycle_id"])

        handler._read_json = lambda: {"root": "nextcloud", "recycle_id": record["recycle_id"]}
        handler._required_string = lambda body, key: body[key]
        handler._handle_recycle_restore()
        self.assertEqual(b"api", victim.read_bytes())

        record = handler._recycle_path(victim)
        handler._read_json = lambda: {"root": "nextcloud", "recycle_id": record["recycle_id"], "confirm": True}
        handler._handle_recycle_purge()
        self.assertTrue(responses[-1][1]["purged"])
        self.assertFalse(victim.exists())

    def test_provider_rollback_restores_using_provider_root(self):
        handler = self.handler
        plan = MutationPlan(0, "nextcloud/removed", handler.provider_root / "removed",
                            "path.delete", '"etag"', '"etag"', b"", 0o600,
                            deleted=True, recycle_id="rid", recycle_root="nextcloud")
        handler._transaction_restore_recycle = Mock(return_value={"restored": True})
        _rollback(handler, [plan])
        handler._transaction_restore_recycle.assert_called_once_with("rid", root="nextcloud")

    def test_server_bin_is_unchanged(self):
        file = self.root / "server.txt"
        file.write_text("local")
        result = self.handler._recycle_path(file)
        self.assertNotIn("root", result)
        self.assertFalse(file.exists())
        self.assertTrue((self.root / result["stored_path"]).is_file())
        self.assertFalse((self.handler.provider_root / ".openkapsel").exists())

    def test_rclone_relocation_verifies_file_bytes_without_inode_or_mtime(self):
        file = self.handler.provider_root / "file.txt"
        file.write_bytes(b"alpha")
        plan = MutationPlan(0, "nextcloud/file.txt", file, "path.delete", '"etag"',
                            '"etag"', b"", 0o600,
                            relocation_mode=stat.S_IFREG, relocation_size=5,
                            relocation_digest=hashlib.sha256(b"alpha").hexdigest())
        self.assertTrue(_relocation_verified(self.handler, plan, file))
        file.write_bytes(b"bravo")
        self.assertFalse(_relocation_verified(self.handler, plan, file))

    def test_provider_is_distinct_transaction_domain(self):
        handler = self.handler
        self.assertEqual(handler.provider_root, _transaction_domain(handler, handler.provider_root / "f"))
        self.assertNotEqual(handler.provider_root, _transaction_domain(handler, handler.token_scope_root / "f"))


if __name__ == "__main__":
    unittest.main()

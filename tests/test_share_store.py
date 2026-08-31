from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from openkapsel.share_store import ShareError, ShareStore


class ShareStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ShareStore(
            self.root / "shares",
            ttl_seconds=86400,
            max_entries=2,
            max_bytes=1024,
            max_depth=8,
            max_query_nodes=100,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _create(self, path: Path, owner: str = "owner-a"):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            return self.store.create(descriptor, path.name, owner)
        finally:
            os.close(descriptor)

    def test_directory_create_inspect_import_and_owner_delete(self) -> None:
        source = self.root / "project"
        (source / "nested").mkdir(parents=True)
        (source / "hello.txt").write_text("hello", encoding="utf-8")
        (source / "nested" / "world.bin").write_bytes(b"world")

        record, evicted = self._create(source)
        self.assertIsNone(evicted)
        self.assertEqual("directory", record.kind)
        self.assertEqual(10, record.size_bytes)
        self.assertEqual(2, record.file_count)

        listing = self.store.inspect(record.id, "", 2)
        self.assertEqual(
            ["project", "project/hello.txt", "project/nested", "project/nested/world.bin"],
            [item["path"] for item in listing["entries"]],
        )

        destination = self.root / "destination"
        destination.mkdir()
        parent_fd = os.open(destination, os.O_RDONLY)
        try:
            imported = self.store.import_into(record.id, parent_fd, "received")
        finally:
            os.close(parent_fd)
        self.assertEqual(record.id, imported.id)
        self.assertEqual("hello", (destination / "received" / "hello.txt").read_text())
        self.assertEqual(b"world", (destination / "received" / "nested" / "world.bin").read_bytes())

        with self.assertRaises(ShareError) as duplicate:
            parent_fd = os.open(destination, os.O_RDONLY)
            try:
                self.store.import_into(record.id, parent_fd, "received")
            finally:
                os.close(parent_fd)
        self.assertEqual("destination_exists", duplicate.exception.code)

        with self.assertRaises(ShareError) as wrong_owner:
            self.store.delete(record.id, "owner-b")
        self.assertEqual("share_not_found", wrong_owner.exception.code)
        self.store.delete(record.id, "owner-a")
        with self.assertRaises(ShareError) as deleted:
            self.store.inspect(record.id, "", 1)
        self.assertEqual("share_not_found", deleted.exception.code)

    def test_capacity_expiry_size_and_reserved_content(self) -> None:
        files = []
        for index in range(3):
            path = self.root / f"file-{index}.txt"
            path.write_text(str(index), encoding="utf-8")
            files.append(path)
        first, _ = self._create(files[0])
        second, _ = self._create(files[1])
        third, evicted = self._create(files[2])
        self.assertEqual(first.id, evicted)
        with self.assertRaises(ShareError):
            self.store.inspect(first.id, "", 0)
        self.assertEqual(files[1].name, self.store.inspect(second.id, "", 0)["name"])
        self.assertEqual(files[2].name, self.store.inspect(third.id, "", 0)["name"])

        database = self.root / "shares" / "index.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("UPDATE shares SET expires_at = 0 WHERE id = ?", (second.id,))
        with self.assertRaises(ShareError) as expired:
            self.store.inspect(second.id, "", 0)
        self.assertEqual("share_not_found", expired.exception.code)

        oversized = self.root / "large.bin"
        oversized.write_bytes(b"x" * 1025)
        with self.assertRaises(ShareError) as too_large:
            self._create(oversized)
        self.assertEqual("share_too_large", too_large.exception.code)

        private = self.root / "private"
        (private / ".openkapsel").mkdir(parents=True)
        (private / ".openkapsel" / "secret").write_text("secret")
        with self.assertRaises(ShareError) as reserved:
            self._create(private)
        self.assertEqual("reserved_path", reserved.exception.code)


if __name__ == "__main__":
    unittest.main()

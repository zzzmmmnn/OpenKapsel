"""Archive extraction quotas are enforced on decompressed bytes, not ZIP size."""
from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.errors import ApiError
from openkapsel.rpc_plugins.archive import (
    _ExtractionBudget, _write_extracted_stream, archive_extract_task,
)


class ArchiveExtractionLimitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="openkapsel-archive-quota-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.files = ClientFiles(self.root, writable=True)
        self.addCleanup(self.files.close)
        self.logs = []
        self.task = SimpleNamespace(
            check_cancelled=lambda: None, write=self.logs.append)

    def _extract(self, filename: str, destination="out"):
        return archive_extract_task(
            self.files, {"path": filename, "destination": destination},
            self.task)

    def _no_stage(self, destination="out"):
        self.assertFalse((self.root / destination).exists())
        internal = self.root / ".openkapsel" / "rpc-tasks"
        self.assertEqual([], list(internal.iterdir()))

    def test_zip_bomb_declared_member_limit_rejected_before_writes(self):
        with zipfile.ZipFile(self.root / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("huge.txt", b"z" * 8192)
        with patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_EXTRACT_BYTES", 4096), \
             patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_MEMBER_BYTES", 4096):
            with self.assertRaises(ApiError) as raised:
                self._extract("bomb.zip")
        self.assertEqual(413, raised.exception.status)
        self.assertEqual("archive_extracted_size_limit", raised.exception.code)
        self._no_stage()

    def test_zip_aggregate_limit_rejected_even_when_members_are_small(self):
        with zipfile.ZipFile(self.root / "multi.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("one.txt", b"A" * 40)
            z.writestr("two.txt", b"B" * 40)
        with patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_EXTRACT_BYTES", 64), \
             patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_MEMBER_BYTES", 48):
            with self.assertRaises(ApiError) as raised:
                self._extract("multi.zip")
        self.assertEqual("archive_extracted_size_limit", raised.exception.code)
        self._no_stage()

    def test_tar_member_and_aggregate_limits_leave_no_staged_files(self):
        def create_tar(path, sizes):
            with tarfile.open(path, "w:gz") as tar:
                for i, length in enumerate(sizes):
                    item = tarfile.TarInfo(f"file-{i}")
                    item.size = length
                    tar.addfile(item, io.BytesIO(b"A" * length))
        create_tar(self.root / "member.tar.gz", [80])
        create_tar(self.root / "total.tar.gz", [40, 40])
        with patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_EXTRACT_BYTES", 64), \
             patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_MEMBER_BYTES", 48):
            for archive in ("member.tar.gz", "total.tar.gz"):
                with self.subTest(archive=archive):
                    with self.assertRaises(ApiError) as raised:
                        self._extract(archive)
                    self.assertEqual("archive_extracted_size_limit", raised.exception.code)
                    self._no_stage()

    def test_stream_rejects_more_bytes_than_declared_before_writing_them(self):
        output = self.root / "new-parent" / "bad.txt"
        with patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_EXTRACT_BYTES", 8), \
             patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_MEMBER_BYTES", 8):
            with self.assertRaises(ApiError) as raised:
                _write_extracted_stream(
                    self.files, output, io.BytesIO(b"X" * 9),
                    self.task, _ExtractionBudget(), 8)
        self.assertEqual(422, raised.exception.status)
        self.assertFalse(output.exists())

    def test_unreadable_archive_cleans_empty_staging_directory(self):
        (self.root / "broken.zip").write_bytes(b"not a zip archive")
        with self.assertRaises(ApiError) as raised:
            self._extract("broken.zip")
        self.assertEqual("archive_invalid", raised.exception.code)
        self._no_stage()

    def test_exact_limit_success_and_reports_actual_extracted_bytes(self):
        with zipfile.ZipFile(self.root / "valid.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("dir/one.txt", b"1234")
            z.writestr("dir/two.txt", b"5678")
        with patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_EXTRACT_BYTES", 8), \
             patch("openkapsel.rpc_plugins.archive.MAX_ARCHIVE_MEMBER_BYTES", 4):
            result = self._extract("valid.zip")
        self.assertEqual(8, result["extracted_bytes"])
        self.assertEqual(b"1234", (self.root / "out/dir/one.txt").read_bytes())
        self.assertEqual(b"5678", (self.root / "out/dir/two.txt").read_bytes())


if __name__ == "__main__":
    unittest.main()

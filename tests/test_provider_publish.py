"""Create-only publication on rclone FUSE without POSIX hard-link support."""
from __future__ import annotations

import errno
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openkapsel.errors import ApiError
from openkapsel.files.file_handlers import FileHandlersMixin
from openkapsel.files.safe_paths import SafePathAccess


class ProviderPublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.handler = FileHandlersMixin()

    def configure(self, provider):
        self.handler.server = SimpleNamespace(
            storage_providers=SimpleNamespace(
                mapping_at_path=lambda path: {"id": "provider"} if provider else None
            )
        )

    def publish(self, data: bytes, *, dest_name="final.bin", digest=None):
        staging = self.root / ".final.bin.openkapsel-put-test"
        staging.write_bytes(data)
        with SafePathAccess((self.root,)).parent(self.root / dest_name) as parent:
            self.handler._publish_new_upload(
                parent, staging.name,
                expected_sha256=digest or hashlib.sha256(data).hexdigest(),
            )
        return staging, self.root / dest_name

    def test_local_keeps_hard_link_atomic_publish(self):
        self.configure(False)
        stage, destination = self.publish(b"local payload")
        self.assertFalse(stage.exists())
        self.assertEqual(b"local payload", destination.read_bytes())

    def test_provider_create_only_fallback_when_fuse_rejects_rename2(self):
        self.configure(True)
        with patch("openkapsel.files.rename_exclusive.rename_exclusive",
                   side_effect=OSError(errno.EINVAL, "unsupported FUSE flag")):
            stage, destination = self.publish(b"first" * 200000)
        self.assertFalse(stage.exists())
        self.assertEqual(b"first" * 200000, destination.read_bytes())

    def test_provider_rename_noreplace_if_supported(self):
        self.configure(True)
        def move(src, dst, source_fd, destination_fd):
            os.rename(src, dst, src_dir_fd=source_fd, dst_dir_fd=destination_fd)
        with patch("openkapsel.files.rename_exclusive.rename_exclusive", side_effect=move):
            stage, destination = self.publish(b"moved")
        self.assertFalse(stage.exists())
        self.assertEqual(b"moved", destination.read_bytes())

    def test_concurrent_target_never_overwritten_by_fallback(self):
        self.configure(True)
        destination = self.root / "final.bin"
        destination.write_bytes(b"other writer")
        with patch("openkapsel.files.rename_exclusive.rename_exclusive",
                   side_effect=OSError(errno.EINVAL, "unsupported FUSE flag")):
            with self.assertRaises(ApiError) as result:
                self.publish(b"must not overwrite")
        self.assertEqual("path_exists", result.exception.code)
        self.assertEqual(b"other writer", destination.read_bytes())

    def test_bad_source_checksum_does_not_leave_public_target(self):
        self.configure(True)
        with patch("openkapsel.files.rename_exclusive.rename_exclusive",
                   side_effect=OSError(errno.EINVAL, "unsupported FUSE flag")):
            with self.assertRaises(ApiError) as result:
                self.publish(b"some data", digest=hashlib.sha256(b"different").hexdigest())
        self.assertEqual("upload_publish_failed", result.exception.code)
        self.assertFalse((self.root / "final.bin").exists())

    def test_failure_during_publish_unlinks_partial_destination(self):
        self.configure(True)
        with patch("openkapsel.files.rename_exclusive.rename_exclusive",
                   side_effect=OSError(errno.EINVAL, "unsupported FUSE flag")):
            with patch("openkapsel.files.file_handlers.os.fsync",
                       side_effect=OSError(errno.EIO, "write failed")):
                with self.assertRaises(ApiError):
                    self.publish(b"large data")
        self.assertFalse((self.root / "final.bin").exists())


if __name__ == "__main__":
    unittest.main()

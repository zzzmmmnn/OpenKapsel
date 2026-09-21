import io
import stat
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles


class ArchiveTypeMetadataTests(unittest.TestCase):
    def test_tar_regular_file_uses_tarinfo_type_not_permission_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sample.tar"
            with tarfile.open(archive_path, "w") as archive:
                data = b"hello"
                info = tarfile.TarInfo("hello.txt")
                info.mode = 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            files = ClientFiles(root, writable=False)
            try:
                result = files.dispatch("archive_list", {"path": "sample.tar"})
                self.assertEqual(200, result["status"], result)
                entry = next(item for item in result["body"]["entries"] if item["name"] == "hello.txt")
                self.assertEqual("file", entry["type"])
            finally:
                files.close()

    def test_zip_permission_only_mode_defaults_to_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sample.zip"
            info = zipfile.ZipInfo("hello.txt")
            info.create_system = 3
            info.external_attr = 0o600 << 16
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(info, b"hello")
            files = ClientFiles(root, writable=False)
            try:
                result = files.dispatch("archive_list", {"path": "sample.zip"})
                self.assertEqual(200, result["status"], result)
                entry = next(item for item in result["body"]["entries"] if item["name"] == "hello.txt")
                self.assertEqual("file", entry["type"])
            finally:
                files.close()

    def test_zip_explicit_special_type_stays_special(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sample.zip"
            info = zipfile.ZipInfo("fifo")
            info.create_system = 3
            info.external_attr = (stat.S_IFIFO | 0o600) << 16
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(info, b"")
            files = ClientFiles(root, writable=False)
            try:
                result = files.dispatch("archive_list", {"path": "sample.zip"})
                self.assertEqual(200, result["status"], result)
                entry = next(item for item in result["body"]["entries"] if item["name"] == "fifo")
                self.assertEqual("special", entry["type"])
            finally:
                files.close()


if __name__ == "__main__":
    unittest.main()

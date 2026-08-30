from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from openkapsel.tokens import TokenStore
from openkapsel.workspace_images import (
    MIN_IMAGE_BYTES,
    WorkspaceImageEngine,
    WorkspaceImageError,
    validate_image_name,
)


class FakeMountCommands:
    def __init__(self) -> None:
        self.mounts: dict[str, tuple[str, str]] = {}
        self.calls: list[list[str]] = []

    def __call__(self, argv, **_kwargs):
        argv = [str(item) for item in argv]
        self.calls.append(argv)
        command = Path(argv[0]).name
        stdout = ""
        stderr = ""
        returncode = 0
        if command == "mount":
            image, mountpoint = argv[-2:]
            self.mounts[mountpoint] = (image, "/dev/loop7")
        elif command == "umount":
            self.mounts.pop(argv[-1], None)
        elif command == "findmnt":
            mountpoint = argv[-1]
            mounted = self.mounts.get(mountpoint)
            if mounted:
                stdout = f"{mounted[1]} ext4\n"
            else:
                returncode = 1
        elif command == "losetup" and "-j" in argv:
            image = argv[argv.index("-j") + 1]
            loops = [loop for source, loop in self.mounts.values() if source == image]
            stdout = "".join(f"{item}\n" for item in loops)
            returncode = 0 if loops else 1
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class WorkspaceImageTests(unittest.TestCase):
    def test_systemd_helper_keeps_host_mount_namespace_and_fixed_paths(self) -> None:
        project = Path(__file__).resolve().parents[1]
        helper = (project / "systemd" / "openkapsel-images.service").read_text()
        main = (project / "systemd" / "openkapsel.service").read_text()
        self.assertIn("PrivateMounts=false", helper)
        self.assertNotIn("PrivateTmp=true", helper)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", helper)
        self.assertIn("CAP_SYS_RESOURCE", helper)
        self.assertIn("--image-dir /var/lib/openkapsel-images", helper)
        self.assertIn("--workspace-root /var/lib/openkapsel/workspace", helper)
        self.assertIn("Requires=openkapsel-images.service", main)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.workspace = base / "workspace"
        self.images = base / "images"
        self.runner = FakeMountCommands()
        self.engine = WorkspaceImageEngine(
            self.workspace,
            self.images,
            os.getuid(),
            os.getgid(),
            runner=self.runner,
            require_root=False,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_sparse_create_grow_and_delete(self) -> None:
        created = self.engine.create("alpha", MIN_IMAGE_BYTES)
        self.assertEqual(MIN_IMAGE_BYTES, created.size_bytes)
        self.assertTrue(created.mounted)
        self.assertEqual(MIN_IMAGE_BYTES, (self.images / "alpha.img").stat().st_size)
        self.assertTrue((self.workspace / "alpha").is_dir())
        self.assertTrue(any(Path(call[0]).name == "mkfs.ext4" for call in self.runner.calls))

        grown = self.engine.grow("alpha", MIN_IMAGE_BYTES * 2)
        self.assertEqual(MIN_IMAGE_BYTES * 2, grown.size_bytes)
        commands = [Path(call[0]).name for call in self.runner.calls]
        self.assertIn("resize2fs", commands)
        self.assertIn("losetup", commands)
        retried = self.engine.grow("alpha", MIN_IMAGE_BYTES * 2)
        self.assertEqual(MIN_IMAGE_BYTES * 2, retried.size_bytes)
        with self.assertRaisesRegex(WorkspaceImageError, "cannot be shrunk"):
            self.engine.grow("alpha", MIN_IMAGE_BYTES)

        self.engine.delete("alpha")
        self.assertFalse((self.images / "alpha.img").exists())
        self.assertFalse((self.workspace / "alpha").exists())

    def test_create_never_hides_existing_directory(self) -> None:
        (self.workspace / "existing").mkdir()
        (self.workspace / "existing" / "keep.txt").write_text("keep")
        with self.assertRaisesRegex(WorkspaceImageError, "cannot be covered or hidden"):
            self.engine.create("existing", MIN_IMAGE_BYTES)
        self.assertEqual("keep", (self.workspace / "existing" / "keep.txt").read_text())
        self.assertFalse((self.images / "existing.img").exists())

    def test_token_image_binding_is_persistent_and_exact(self) -> None:
        (self.workspace / "volume").mkdir()
        store = TokenStore(self.workspace, Path(self.temp.name) / "tokens.json", None)
        record = store.create(
            name="Image token",
            expires_at=None,
            path_prefix="volume",
            workspace_image="volume",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        self.assertEqual("volume", record.workspace_image)
        reloaded = TokenStore(self.workspace, Path(self.temp.name) / "tokens.json", None)
        self.assertEqual("volume", reloaded.get(record.token).workspace_image)
        with self.assertRaisesRegex(ValueError, "must match"):
            store.update(record.token, workspace_image="different")

    def test_names_are_strict(self) -> None:
        self.assertEqual("site_1", validate_image_name(" site_1 "))
        for invalid in ("../escape", ".hidden", "a/b", "space name", ""):
            with self.subTest(invalid=invalid):
                with self.assertRaises(WorkspaceImageError):
                    validate_image_name(invalid)


if __name__ == "__main__":
    unittest.main()

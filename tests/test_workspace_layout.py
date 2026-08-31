from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openkapsel.workspace_layout import (
    WorkspaceLayoutError,
    ensure_workspace_layout,
)


class WorkspaceLayoutTests(unittest.TestCase):
    def test_new_layout_is_private_versioned_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            first = ensure_workspace_layout(workspace)
            second = ensure_workspace_layout(workspace)

            self.assertEqual(first, second)
            self.assertEqual(workspace.resolve() / ".openkapsel", first.root)
            self.assertEqual("1\n", first.version_file.read_text(encoding="ascii"))
            for path in (
                first.root,
                first.recycle,
                first.sql,
                first.context,
                first.env,
                first.scheduler,
            ):
                self.assertTrue(path.is_dir())
                self.assertEqual(0o700, path.stat().st_mode & 0o777)
            self.assertEqual(0o600, first.version_file.stat().st_mode & 0o777)

    def test_legacy_directories_are_moved_without_changing_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            fixtures = {
                ".recycle": ("old.json", "recycle"),
                ".sql": ("main.sqlite3", "database"),
                ".context": ("context.sqlite3", "context"),
            }
            for name, (filename, content) in fixtures.items():
                root = workspace / name
                root.mkdir()
                (root / filename).write_text(content, encoding="utf-8")

            layout = ensure_workspace_layout(workspace)

            for legacy in fixtures:
                self.assertFalse((workspace / legacy).exists())
            self.assertEqual("recycle", (layout.recycle / "old.json").read_text())
            self.assertEqual("database", (layout.sql / "main.sqlite3").read_text())
            self.assertEqual("context", (layout.context / "context.sqlite3").read_text())

    def test_conflicting_legacy_and_current_data_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            layout = ensure_workspace_layout(workspace)
            (layout.sql / "new.sqlite3").write_text("new", encoding="utf-8")
            legacy = workspace / ".sql"
            legacy.mkdir()
            (legacy / "old.sqlite3").write_text("old", encoding="utf-8")

            with self.assertRaisesRegex(WorkspaceLayoutError, "both contain data"):
                ensure_workspace_layout(workspace)

            self.assertEqual("new", (layout.sql / "new.sqlite3").read_text())
            self.assertEqual("old", (legacy / "old.sqlite3").read_text())

    def test_internal_or_legacy_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as target:
            workspace = Path(directory)
            (workspace / ".context").symlink_to(Path(target), target_is_directory=True)
            with self.assertRaisesRegex(WorkspaceLayoutError, "real directory"):
                ensure_workspace_layout(workspace)


if __name__ == "__main__":
    unittest.main()

"""Regression tests for durable, incremental filename index reconciliation."""
import os
from openkapsel.files.filename_index import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.files.filename_index import FilenameIndex


class IncrementalFilenameIndexTests(unittest.TestCase):
    def test_bundled_sqlite_is_used_when_installed(self):
        import importlib.util
        if importlib.util.find_spec("pysqlite3") is None:
            self.skipTest("pysqlite3-binary not installed on this platform")
        from openkapsel.files import filename_index
        import pysqlite3
        self.assertIs(filename_index.sqlite3, pysqlite3)
        self.assertGreaterEqual(tuple(map(int, pysqlite3.sqlite_version.split(".")[:2])),
                                (3, 34))
        with filename_index.sqlite3.connect(":memory:") as db:
            db.execute(
                "CREATE VIRTUAL TABLE f USING fts5(name, tokenize='trigram')"
            )
            db.execute("INSERT INTO f(name) VALUES('report.filename')")
            self.assertEqual(1, db.execute(
                "SELECT count(*) FROM f WHERE name LIKE '%port%'"
            ).fetchone()[0])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "files"
        self.root.mkdir()
        self.db = self.base / "state" / "index.sqlite3"

    def open_index(self):
        return FilenameIndex(self.root, self.db)

    def test_compatible_restart_keeps_ids_and_scan_does_not_rewrite_unchanged_rows(self):
        (self.root / "stable-report.txt").write_text("a")
        first = self.open_index()
        try:
            first.rebuild()
            entry_id = first._db.execute(
                "SELECT id FROM entries WHERE path='stable-report.txt'"
            ).fetchone()[0]
            changes = first._db.total_changes
            first.reconcile()
            self.assertEqual(changes, first._db.total_changes)
            self.assertEqual(0, first._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
        finally:
            first.close()
        second = self.open_index()
        try:
            self.assertEqual(2, second._db.execute("PRAGMA user_version").fetchone()[0])
            second.reconcile()
            self.assertEqual(entry_id, second._db.execute(
                "SELECT id FROM entries WHERE path='stable-report.txt'"
            ).fetchone()[0])
            self.assertEqual(0, second._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
            second._ready.set()
            self.assertEqual(1, second.search(self.root, "report")["result_count"])
        finally:
            second.close()

    def test_incompatible_schema_is_discarded(self):
        self.db.parent.mkdir()
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE legacy_thing (value TEXT)")
            db.execute("INSERT INTO legacy_thing VALUES ('old')")
            db.execute("PRAGMA user_version=1")
        index = self.open_index()
        try:
            self.assertIsNone(index._db.execute(
                "SELECT name FROM sqlite_master WHERE name='legacy_thing'"
            ).fetchone())
            self.assertEqual(2, index._db.execute("PRAGMA user_version").fetchone()[0])
            index.rebuild()
        finally:
            index.close()

    def test_new_and_deleted_metadata_are_searchable_without_fts_worker(self):
        index = self.open_index()
        try:
            target = self.root / "arrival-example.txt"
            target.write_text("a")
            index.reconcile()
            index._ready.set()
            self.assertEqual(1, index.search(self.root, "arrival")["result_count"])
            self.assertEqual(1, index._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
            self.assertTrue(index._flush_pending())
            target.unlink()
            index.reconcile()
            self.assertEqual(0, index.search(self.root, "arrival")["result_count"])
            self.assertEqual(1, index._db.execute(
                "SELECT COUNT(*) FROM entries WHERE visible=0"
            ).fetchone()[0])
            index._flush_pending()
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM entries"
            ).fetchone()[0])
        finally:
            index.close()

    def test_pending_rename_and_removal_survive_restart(self):
        src = self.root / "old-report.txt"
        src.write_text("data")
        first = self.open_index()
        try:
            first.rebuild()
            src.rename(self.root / "new-report.txt")
            first.reconcile()  # indexer intentionally not running
            self.assertEqual(2, first._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
        finally:
            first.close()
        second = self.open_index()
        try:
            second._ready.set()
            self.assertEqual(1, second.search(self.root, "new-report")["result_count"])
            self.assertEqual(0, second.search(self.root, "old-report")["result_count"])
            while second._flush_pending():
                pass
            self.assertEqual(1, second.search(self.root, "new-report")["result_count"])
            self.assertEqual(0, second.search(self.root, "old-report")["result_count"])
            self.assertEqual(0, second._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
        finally:
            second.close()

    def test_metadata_only_change_never_queues_reindex(self):
        f = self.root / "same-file.txt"
        f.write_text("x")
        index = self.open_index()
        try:
            index.rebuild()
            f.write_text("longer file content")
            index.reconcile()
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
            self.assertEqual(19, index._db.execute(
                "SELECT size_bytes FROM entries WHERE path='same-file.txt'"
            ).fetchone()[0])
            index._ready.set()
            self.assertEqual(1, index.search(self.root, "am")["result_count"])
            self.assertEqual(1, index.search(self.root, "same")["result_count"])
        finally:
            index.close()

    def test_unreadable_subtree_does_not_delete_cached_files(self):
        sub = self.root / "temporarily-unreadable"
        sub.mkdir()
        (sub / "keep-report.txt").write_text("yes")
        index = self.open_index()
        try:
            index.rebuild()
            scandir = os.scandir

            def intermittent(path):
                if Path(path) == sub:
                    raise PermissionError("synthetic scan failure")
                return scandir(path)

            with patch("openkapsel.files.filename_index.os.scandir",
                       side_effect=intermittent):
                index.reconcile()
            index._ready.set()
            self.assertEqual(1, index.search(self.root, "keep-report")["result_count"])
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM entries WHERE visible=0"
            ).fetchone()[0])
        finally:
            index.close()

    def test_missed_event_changes_are_detected_by_periodic_reconcile(self):
        f = self.root / "before-report.txt"
        f.write_text("yes")
        index = self.open_index()
        try:
            index.rebuild()
            f.rename(self.root / "after-report.txt")
            index.reconcile()
            index._ready.set()
            self.assertEqual(1, index.search(self.root, "after-report")["result_count"])
            self.assertEqual(0, index.search(self.root, "before-report")["result_count"])
        finally:
            index.close()


    def test_directory_replaced_by_file_tombstones_old_descendants(self):
        sub = self.root / "tree"
        sub.mkdir()
        (sub / "orphan-child.txt").write_text("data")
        index = self.open_index()
        try:
            index.rebuild()
            (sub / "orphan-child.txt").unlink()
            sub.rmdir()
            sub.write_text("replacement")
            index.reconcile()
            index._ready.set()
            self.assertEqual(0, index.search(self.root, "orphan-child")["result_count"])
            self.assertEqual("file", index._db.execute(
                "SELECT kind FROM entries WHERE path='tree'"
            ).fetchone()[0])
            index._flush_pending()
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM entries WHERE path LIKE 'tree/%'"
            ).fetchone()[0])
        finally:
            index.close()

    def test_later_fts_availability_processes_durable_pending(self):
        class NoTrigram(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if "USING fts5(" in sql:
                    raise sqlite3.OperationalError("no such tokenizer: trigram")
                return super().execute(sql, parameters)

        real_connect = sqlite3.connect
        (self.root / "recovered-report.txt").write_text("data")
        with patch("openkapsel.files.filename_index.sqlite3.connect",
                   side_effect=lambda *args, **kw: real_connect(
                       *args, factory=NoTrigram, **kw)):
            previous = self.open_index()
        try:
            self.assertFalse(previous._fts)
            previous.rebuild()
            self.assertEqual(0, previous._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])  # fallback worker drains tombstones safely
        finally:
            previous.close()
        current = self.open_index()
        try:
            if not current._fts:
                self.skipTest("SQLite FTS5 Trigram is unavailable on this host")
            self.assertTrue(current._flush_pending())
            current._ready.set()
            self.assertEqual(1, current.search(self.root, "recovered")["result_count"])
        finally:
            current.close()

    def test_missing_fts_table_is_repopulated_without_discarding_metadata(self):
        file = self.root / "restored-index.txt"
        file.write_text("data")
        old = self.open_index()
        try:
            if not old._fts:
                self.skipTest("SQLite FTS5 Trigram is unavailable on this host")
            old.rebuild()
            original_id = old._db.execute(
                "SELECT id FROM entries WHERE path='restored-index.txt'"
            ).fetchone()[0]
        finally:
            old.close()
        raw = sqlite3.connect(self.db)
        try:
            raw.execute("DROP TABLE entry_grams")
            raw.execute(
                "INSERT INTO pending_index(entry_id,old_folded) VALUES(?,?)",
                (original_id, "restored-index.txt"),
            )
            raw.commit()
        finally:
            raw.close()
        restored = self.open_index()
        try:
            self.assertEqual(original_id, restored._db.execute(
                "SELECT id FROM entries WHERE path='restored-index.txt'"
            ).fetchone()[0])
            self.assertIsNone(restored._db.execute(
                "SELECT old_folded FROM pending_index WHERE entry_id=?",
                (original_id,),
            ).fetchone()[0])
            self.assertTrue(restored._flush_pending())
            restored._ready.set()
            self.assertEqual(1, restored.search(self.root, "restored")["result_count"])
        finally:
            restored.close()

    def test_no_trigram_fallback_drains_pending_and_preserves_live_entries(self):
        class NoTrigram(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if "USING fts5(" in sql:
                    raise sqlite3.OperationalError("no such tokenizer: trigram")
                return super().execute(sql, parameters)

        real_connect = sqlite3.connect
        path = self.root / "fallback-report.txt"
        path.write_text("before")
        with patch("openkapsel.files.filename_index.sqlite3.connect",
                   side_effect=lambda *args, **kw: real_connect(
                       *args, factory=NoTrigram, **kw)):
            index = self.open_index()
        try:
            self.assertFalse(index._fts)
            index.rebuild()
            index._ready.set()
            self.assertEqual(1, index.search(self.root, "report")["result_count"])
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
            path.unlink()
            index.reconcile()
            self.assertEqual(0, index.search(self.root, "report")["result_count"])
            self.assertEqual(1, index._db.execute(
                "SELECT COUNT(*) FROM entries WHERE visible=0"
            ).fetchone()[0])
            self.assertTrue(index._flush_pending())
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM pending_index"
            ).fetchone()[0])
            self.assertEqual(0, index._db.execute(
                "SELECT COUNT(*) FROM entries"
            ).fetchone()[0])
        finally:
            index.close()


if __name__ == "__main__":
    unittest.main()

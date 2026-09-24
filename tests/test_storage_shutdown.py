import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from openkapsel.storage.storage_shutdown import SafeShutdownError, SafeUpgradeShutdown


def make_db(path: Path, *, writable: bool = True, with_mapping: bool = True) -> str:
    provider_id = "p" * 24
    db = sqlite3.connect(path)
    try:
        db.execute(
            """CREATE TABLE storage_providers (
                id TEXT PRIMARY KEY,
                writable INTEGER NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE storage_provider_mappings (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                workspace TEXT NOT NULL,
                name TEXT NOT NULL
            )"""
        )
        db.execute(
            "INSERT INTO storage_providers(id,writable) VALUES(?,?)",
            (provider_id, int(writable)),
        )
        if with_mapping:
            db.execute(
                "INSERT INTO storage_provider_mappings(id,provider_id,workspace,name) "
                "VALUES(?,?,?,?)",
                ("m" * 24, provider_id, "work", "cloud"),
            )
        db.commit()
    finally:
        db.close()
    return provider_id


class FakeShutdown(SafeUpgradeShutdown):
    def __init__(self, *args, stats=None, monotonic=None, **kwargs):
        self.events = []
        self.active_units = set()
        self.mounts = set()
        self.units = {}
        self.stats = list(stats or [])
        super().__init__(
            *args,
            sleep=lambda _seconds: self.events.append(("sleep",)),
            monotonic=monotonic or (lambda: 0.0),
            command=self._fake_command,
            **kwargs,
        )

    def _fake_command(self, argv, **_kwargs):
        self.events.append(("command", tuple(argv)))
        if argv[0] == "umount":
            target = argv[-1]
            self.mounts.discard(target)
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected command: {argv}")

    def _active(self, unit):
        return unit in self.active_units

    def _stop_service(self, unit):
        self.events.append(("stop", unit))
        self.active_units.discard(unit)
        prefix = "openkapsel-storage-"
        if unit.startswith(prefix) and unit.endswith(".service"):
            provider_id = unit[len(prefix):-len(".service")]
            self.mounts.discard(str(self.storage_root / provider_id / "mount"))

    def _listed_storage_units(self):
        return dict(self.units)

    def _exact_mount(self, path):
        return str(path) in self.mounts

    def _rc_stats(self, provider_id):
        self.events.append(("stats", provider_id))
        if self.stats:
            return self.stats.pop(0)
        return {
            "diskCache": {
                "uploadsQueued": 0,
                "uploadsInProgress": 0,
                "erroredFiles": 0,
            }
        }


class SafeUpgradeShutdownTests(unittest.TestCase):
    def test_waits_for_writes_before_unbinding_and_stopping_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            db_path = base / "storage-providers.sqlite3"
            provider_id = make_db(db_path)
            workspace = base / "workspace"
            storage = base / "providers"
            mapping = workspace / "work" / "cloud"
            provider_mount = storage / provider_id / "mount"
            first = {
                "diskCache": {
                    "uploadsQueued": 2,
                    "uploadsInProgress": 1,
                    "erroredFiles": 0,
                }
            }
            drained = {
                "diskCache": {
                    "uploadsQueued": 0,
                    "uploadsInProgress": 0,
                    "erroredFiles": 0,
                }
            }
            shutdown = FakeShutdown(
                db_path=db_path,
                workspace_root=workspace,
                storage_root=storage,
                timeout_seconds=30,
                stats=[first, drained],
            )
            provider_unit = f"openkapsel-storage-{provider_id}.service"
            shutdown.active_units.update(
                {"openkapsel.service", "openkapsel-images.service", provider_unit}
            )
            shutdown.units[provider_id] = provider_unit
            shutdown.mounts.update({str(mapping), str(provider_mount)})

            shutdown.shutdown()

            self.assertNotIn(str(mapping), shutdown.mounts)
            self.assertNotIn(str(provider_mount), shutdown.mounts)
            self.assertEqual(set(), shutdown.active_units)
            stop_main = shutdown.events.index(("stop", "openkapsel.service"))
            first_stats = shutdown.events.index(("stats", provider_id))
            unmount = next(
                index
                for index, event in enumerate(shutdown.events)
                if event[0] == "command" and event[1][0] == "umount"
            )
            stop_provider = shutdown.events.index(("stop", provider_unit))
            stop_helper = shutdown.events.index(("stop", "openkapsel-images.service"))
            self.assertLess(stop_main, first_stats)
            self.assertLess(first_stats, unmount)
            self.assertLess(unmount, stop_provider)
            self.assertLess(stop_provider, stop_helper)

    def test_timeout_keeps_provider_and_mapping_attached(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            db_path = base / "storage-providers.sqlite3"
            provider_id = make_db(db_path)
            workspace = base / "workspace"
            storage = base / "providers"
            mapping = workspace / "work" / "cloud"
            provider_mount = storage / provider_id / "mount"
            busy = {
                "diskCache": {
                    "uploadsQueued": 1,
                    "uploadsInProgress": 0,
                    "erroredFiles": 0,
                }
            }
            times = iter((0.0, 2.0))
            shutdown = FakeShutdown(
                db_path=db_path,
                workspace_root=workspace,
                storage_root=storage,
                timeout_seconds=1,
                stats=[busy],
                monotonic=lambda: next(times),
            )
            provider_unit = f"openkapsel-storage-{provider_id}.service"
            shutdown.active_units.update(
                {"openkapsel.service", "openkapsel-images.service", provider_unit}
            )
            shutdown.units[provider_id] = provider_unit
            shutdown.mounts.update({str(mapping), str(provider_mount)})

            with self.assertRaisesRegex(SafeShutdownError, "timed out"):
                shutdown.shutdown()

            self.assertNotIn("openkapsel.service", shutdown.active_units)
            self.assertIn(provider_unit, shutdown.active_units)
            self.assertIn("openkapsel-images.service", shutdown.active_units)
            self.assertIn(str(mapping), shutdown.mounts)
            self.assertIn(str(provider_mount), shutdown.mounts)
            self.assertNotIn(("stop", provider_unit), shutdown.events)

    def test_errored_vfs_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            db_path = base / "storage-providers.sqlite3"
            provider_id = make_db(db_path, with_mapping=False)
            storage = base / "providers"
            errored = {
                "diskCache": {
                    "uploadsQueued": 0,
                    "uploadsInProgress": 0,
                    "erroredFiles": 1,
                }
            }
            shutdown = FakeShutdown(
                db_path=db_path,
                workspace_root=base / "workspace",
                storage_root=storage,
                stats=[errored],
            )
            provider_unit = f"openkapsel-storage-{provider_id}.service"
            shutdown.active_units.update(
                {"openkapsel.service", "openkapsel-images.service", provider_unit}
            )
            shutdown.units[provider_id] = provider_unit
            shutdown.mounts.add(str(storage / provider_id / "mount"))

            with self.assertRaisesRegex(SafeShutdownError, "error state"):
                shutdown.shutdown()

            self.assertIn(provider_unit, shutdown.active_units)
            self.assertIn("openkapsel-images.service", shutdown.active_units)

    def test_unknown_active_storage_unit_requires_explicit_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            db_path = base / "storage-providers.sqlite3"
            make_db(db_path, writable=False, with_mapping=False)
            shutdown = FakeShutdown(
                db_path=db_path,
                workspace_root=base / "workspace",
                storage_root=base / "providers",
            )
            unknown = "x" * 24
            unknown_unit = f"openkapsel-storage-{unknown}.service"
            shutdown.active_units.update(
                {"openkapsel.service", "openkapsel-images.service", unknown_unit}
            )
            shutdown.units[unknown] = unknown_unit

            with self.assertRaisesRegex(SafeShutdownError, "missing from the provider database"):
                shutdown.shutdown()

            self.assertIn(unknown_unit, shutdown.active_units)
            self.assertIn("openkapsel-images.service", shutdown.active_units)


if __name__ == "__main__":
    unittest.main()

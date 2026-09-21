"""Native filesystem dependencies for sandboxed API workers, not HTTP requests."""

from __future__ import annotations

import errno
import json
from pathlib import Path

from openkapsel.mapping.mapping_io import WorkspaceFiles
from openkapsel.workspace.workspace_layout import ensure_workspace_layout


class MappingApiMixin:
    def _ensure(self, record, workspace, root_path, worker_key):
        from openkapsel.execution.api_workers import ApiWorkerError
        if self.mappings is None:
            return self._ensure_native(record, workspace, root_path, worker_key)
        scope = self.mappings.root / record.path_prefix
        files = WorkspaceFiles(self.mappings, (scope,))
        names = []
        try:
            with files.open(workspace / "api" / "mappings.json") as handle:
                raw = handle.read(16385)
            if len(raw) > 16384:
                raise ApiWorkerError("api/mappings.json exceeds 16384 bytes")
            manifest = json.loads(raw)
            if not isinstance(manifest, dict) or set(manifest) != {"mount_mappings"}:
                raise ApiWorkerError("api/mappings.json must contain only mount_mappings")
            names = manifest["mount_mappings"]
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise ApiWorkerError("API mapping dependencies are unavailable") from exc
        except (ValueError, UnicodeError) as exc:
            raise ApiWorkerError("api/mappings.json is invalid") from exc
        try:
            rows = self.mappings.execution_mappings(record.path_prefix, workspace, names)
            lease = self.mappings.acquire(rows) if rows else None
        except (OSError, ValueError) as exc:
            raise ApiWorkerError(str(exc)) from exc
        handed_off = False
        try:
            worker = self._ensure_native(record, workspace, root_path, worker_key, mount_lease=lease)
            handed_off = lease is not None and worker.mount_lease is lease
            return worker
        except BaseException as exc:
            if getattr(exc, "retain_mount_lease", False):
                handed_off = True
            raise
        finally:
            if lease is not None and not handed_off:
                lease.close()

    def _mapping_fingerprint(self, lease):
        if self.mappings is None:
            return ()
        with self.mappings.lock:
            return tuple((mid, self.mappings.sessions[mid].generation)
                         for mid in (lease.ids if lease else ()))

    def _app_layout(self, workspace, worker_dir):
        mapped_app = self.mappings is not None and self.mappings.at_path(workspace) is not None
        if mapped_app:
            # A provider intentionally rejects .openkapsel. Store SQL and other
            # private application state on the server, never inside the export.
            state_root = self.worker_root.parent / "mapping-app-state" / worker_dir.name
            state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            return ensure_workspace_layout(state_root), True
        return ensure_workspace_layout(workspace), False

    def _append_mapping_mounts(self, mounts, record, workspace, mapping_ids):
        if self.mappings is None:
            return
        scope_mode = "--bind" if record.can_write else "--ro-bind"
        for row in self.mappings.store.list(record.path_prefix):
            path = self.mappings.mount_path(row)
            if row["id"] in mapping_ids:
                # An app in a mapping gets its app subtree, not the containing
                # export merely because its cwd happens to be inside it.
                if path != workspace and path not in workspace.parents:
                    self._append_parent_dirs(mounts, path.parent)
                    mounts.extend([scope_mode, str(path), str(path)])
            elif workspace in path.parents:
                mounts.extend(["--ro-bind", str(self.mappings.empty_view()), str(path)])

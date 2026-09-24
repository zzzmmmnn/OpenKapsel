"""Lifecycle manager for rclone-backed server storage providers."""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable

from openkapsel.storage.storage_sftp import detect_sftp_host_keys
from openkapsel.storage.storage_store import StorageProviderStore
from openkapsel.workspace.workspace_images import WorkspaceImageClient, WorkspaceImageError


LOG = logging.getLogger("openkapsel.storage")


class StorageProviderDeleteWarning(RuntimeError):
    def __init__(self, provider_id: str, details: dict[str, Any]):
        super().__init__("storage provider may have pending cached writes")
        self.provider_id = provider_id
        self.details = details


class StorageProviderManager:
    def __init__(self, root: Path, state_dir: Path, helper: WorkspaceImageClient):
        self.root = root
        self.store = StorageProviderStore(state_dir / "storage-providers.sqlite3")
        self.helper = helper
        self.workspace_available: Callable[[str], bool] = lambda _workspace: True
        self.client_mapping_reserved: Callable[[str, str], bool] = lambda _workspace, _name: False
        self.lock = threading.RLock()
        self._closing = threading.Event()
        self._reconciler: threading.Thread | None = None

    def start(self) -> None:
        if not self.helper.enabled or self._reconciler is not None:
            return
        self._reconciler = threading.Thread(target=self._startup_reconcile, daemon=True)
        self._reconciler.start()

    def _request(self, action: str, **values: Any) -> dict[str, Any]:
        return self.helper._request(action, **values)

    def probe(self) -> dict[str, Any]:
        if not self.helper.enabled:
            return {"available": False, "reason": "privileged mount helper is unavailable"}
        try:
            result = self._request("storage_probe")
        except WorkspaceImageError as exc:
            return {"available": False, "reason": str(exc)}
        if not result.get("available"):
            reason = result.get("reason")
            if not isinstance(reason, str) or not reason:
                missing = [name for name in ("rclone", "fusermount") if not result.get(name)]
                reason = "missing " + ", ".join(missing)
            return {"available": False, "reason": reason}
        return {"available": True, "reason": ""}

    def detect_sftp_host_keys(self, host: Any, port: Any = 22) -> dict[str, Any]:
        # Detection intentionally runs in the non-root API process. The
        # privileged mount helper is restricted to AF_UNIX and should not gain
        # outbound network access merely to discover public SSH host keys.
        return detect_sftp_host_keys(host, port)

    def _startup_reconcile(self) -> None:
        # openkapsel-images.service is Type=simple, so systemd may start the
        # main service before the helper has created its UNIX socket.  A main
        # process crash can therefore coincide with a helper restart and make
        # a one-shot reconcile lose the startup race.  Wait briefly for the
        # helper RPC endpoint, then retry transient helper failures per
        # provider.  Existing live rclone/FUSE mounts are reused by the host
        # helper, so this does not interrupt queued uploads after a main crash.
        helper_delays = (0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
        for delay in (*helper_delays, None):
            if self._closing.is_set():
                return
            try:
                self._request("storage_probe")
                break
            except WorkspaceImageError:
                if delay is None:
                    LOG.exception("Storage Provider helper did not become ready during startup")
                    return
                if self._closing.wait(delay):
                    return

        retry_delays = (0.25, 0.5, 1.0)
        for provider in self.store.list():
            if self._closing.is_set():
                return
            for attempt, delay in enumerate((*retry_delays, None), start=1):
                try:
                    self.reconcile(provider["id"])
                    break
                except WorkspaceImageError:
                    if delay is None:
                        LOG.exception(
                            "Could not reconcile storage provider %s after %d attempts",
                            provider["id"], attempt,
                        )
                        break
                    if self._closing.wait(delay):
                        return
                except (OSError, ValueError, KeyError, sqlite3.Error):
                    LOG.exception("Could not reconcile storage provider %s", provider["id"])
                    break

    def configure(self, provider_id: str, settings: dict[str, Any]) -> None:
        provider = self.store.get(provider_id)
        self._request("storage_configure", id=provider_id, kind=provider["kind"], settings=settings)

    def create(self, name: str, kind: str, *, settings: dict[str, Any], remote_path: str = "",
               comment: str = "", writable: bool = False, cache_max_bytes: int) -> dict[str, Any]:
        capability = self.probe()
        if not capability["available"]:
            raise ValueError("storage providers are unavailable: " + capability["reason"])
        provider = self.store.create(
            name, kind, remote_path=remote_path, comment=comment,
            writable=writable, cache_max_bytes=cache_max_bytes,
        )
        try:
            self.configure(provider["id"], settings)
            self.reconcile(provider["id"])
        except BaseException:
            try:
                self._request("storage_delete", id=provider["id"])
            except Exception:
                pass
            self.store.delete(provider["id"])
            raise
        return self.get(provider["id"])

    def update(self, provider_id: str, *, credentials: dict[str, Any] | None = None, **values: Any) -> dict[str, Any]:
        with self.lock:
            provider = self.store.get(provider_id)
            mappings = self.store.mappings(provider_id=provider_id)
            for mapping in mappings:
                self._request("storage_unbind", workspace=mapping["workspace"], name=mapping["name"])
            self._request("storage_unmount", id=provider_id)
            provider = self.store.update(provider_id, **values)
            if credentials is not None:
                self.configure(provider_id, credentials)
            self.reconcile(provider_id)
            return self.get(provider_id)

    def delete(self, provider_id: str, *, force: bool = False) -> None:
        with self.lock:
            self.store.get(provider_id)
            if not force:
                pending = self._request("storage_pending", id=provider_id)
                if pending.get("pending") or pending.get("uncertain"):
                    raise StorageProviderDeleteWarning(provider_id, pending)
            for mapping in self.store.mappings(provider_id=provider_id):
                self._request(
                    "storage_unbind",
                    workspace=mapping["workspace"],
                    name=mapping["name"],
                    force=force,
                )
            self._request("storage_delete", id=provider_id)
            self.store.delete(provider_id)

    def add_mapping(self, provider_id: str, workspace: str, name: str) -> dict[str, Any]:
        provider = self.store.get(provider_id)
        if not provider["enabled"]:
            raise ValueError("enable the storage provider before mapping it")
        if not self.workspace_available(workspace):
            raise ValueError("select an active workspace")
        if self.client_mapping_reserved(workspace, name):
            raise ValueError("directory name is already reserved by a client mapping")
        path = self.root / workspace / name
        if path.exists() or path.is_symlink() or os.path.ismount(path):
            raise ValueError("directory name already exists in the workspace")
        mapping = self.store.add_mapping(provider_id, workspace, name)
        try:
            self._request(
                "storage_mount", id=provider_id, remote_path=provider["remote_path"],
                writable=provider["writable"], cache_max_bytes=provider["cache_max_bytes"],
            )
            self._request(
                "storage_bind", id=provider_id, workspace=workspace, name=name,
                writable=provider["writable"],
            )
        except BaseException:
            try:
                self._request("storage_unbind", workspace=workspace, name=name)
            except Exception:
                pass
            self.store.delete_mapping(mapping["id"])
            raise
        return mapping

    def delete_mapping(self, mapping_id: str) -> None:
        mapping = self.store.mapping(mapping_id)
        self._request("storage_unbind", workspace=mapping["workspace"], name=mapping["name"])
        self.store.delete_mapping(mapping_id)

    def reconcile(self, provider_id: str) -> None:
        with self.lock:
            provider = self.store.get(provider_id)
            mappings = self.store.mappings(provider_id=provider_id)
            if not provider["enabled"]:
                for mapping in mappings:
                    self._request("storage_unbind", workspace=mapping["workspace"], name=mapping["name"])
                self._request("storage_unmount", id=provider_id)
                return
            self._request(
                "storage_mount", id=provider_id, remote_path=provider["remote_path"],
                writable=provider["writable"], cache_max_bytes=provider["cache_max_bytes"],
            )
            for mapping in mappings:
                if not self.workspace_available(mapping["workspace"]):
                    continue
                self._request(
                    "storage_bind", id=provider_id, workspace=mapping["workspace"], name=mapping["name"],
                    writable=provider["writable"],
                )

    def get(self, provider_id: str) -> dict[str, Any]:
        provider = self.store.get(provider_id)
        provider["mappings"] = self.store.mappings(provider_id=provider_id)
        try:
            provider["status"] = self._request(
                "storage_status", id=provider_id,
                mappings=[{"id": row["id"], "workspace": row["workspace"], "name": row["name"]}
                          for row in provider["mappings"]],
            )
        except WorkspaceImageError as exc:
            provider["status"] = {"configured": False, "mounted": False, "unit_active": False,
                                  "mappings": {}, "error": str(exc)}
        return provider

    def list(self) -> list[dict[str, Any]]:
        return [self.get(provider["id"]) for provider in self.store.list()]

    def mapping_path(self, mapping: dict[str, Any]) -> Path:
        return self.root / mapping["workspace"] / mapping["name"]

    def mapping_at_path(self, path: Path) -> dict[str, Any] | None:
        try:
            parts = Path(path).relative_to(self.root).parts
        except ValueError:
            return None
        if len(parts) < 2:
            return None
        return next((row for row in self.store.mappings(workspace=parts[0]) if row["name"] == parts[1]), None)

    def is_mapping_root(self, path: Path) -> bool:
        mapping = self.mapping_at_path(path)
        return bool(mapping and self.mapping_path(mapping) == path)

    def path_reserved(self, workspace: str, name: str) -> bool:
        return self.store.reserved(workspace, name)

    def check_path(self, path: Path, *, write: bool = False, protect_root: bool = False) -> None:
        mapping = self.mapping_at_path(path)
        if mapping is None:
            return
        root = self.mapping_path(mapping)
        if not os.path.ismount(root):
            import errno
            raise OSError(errno.EHOSTDOWN, "storage provider mapping is offline", str(root))
        provider = self.store.get(mapping["provider_id"])
        if write and not provider["writable"]:
            import errno
            raise OSError(errno.EROFS, "storage provider is read-only", str(root))
        if protect_root and path == root:
            import errno
            raise OSError(errno.EBUSY, "storage provider mapping root is protected", str(root))

    def close(self) -> None:
        self._closing.set()
        thread = self._reconciler
        if thread is not None and thread.is_alive():
            thread.join(timeout=0.1)

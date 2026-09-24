"""Administration handlers for server-managed storage providers."""

from __future__ import annotations

import sqlite3

from openkapsel.errors import ApiError
from openkapsel.storage.storage_manager import StorageProviderDeleteWarning
from openkapsel.storage.storage_store import DEFAULT_CACHE_MAX_BYTES
from openkapsel.workspace.workspace_images import WorkspaceImageError


class StorageHandlersMixin:
    def _storage_credentials(self, kind: str, form: dict[str, list[str]]) -> dict:
        one = self._form_one
        if kind == "google_drive":
            return {
                "client_id": one(form, "client_id"),
                "client_secret": one(form, "client_secret"),
                "token": one(form, "oauth_token"),
            }
        if kind == "dropbox":
            return {
                "client_id": one(form, "client_id"),
                "client_secret": one(form, "client_secret"),
                "token": one(form, "oauth_token"),
            }
        if kind == "sftp":
            return {
                "host": one(form, "host"),
                "port": one(form, "port"),
                "user": one(form, "user"),
                "password": one(form, "password"),
                "private_key": one(form, "private_key"),
                "known_hosts": one(form, "known_hosts"),
            }
        if kind == "smb":
            return {
                "host": one(form, "host"),
                "port": one(form, "port"),
                "user": one(form, "user"),
                "password": one(form, "password"),
                "domain": one(form, "domain"),
            }
        raise ValueError("unsupported storage provider kind")

    @staticmethod
    def _storage_cache_bytes(value: str) -> int:
        if not value:
            return DEFAULT_CACHE_MAX_BYTES
        try:
            gib = int(value)
        except ValueError:
            raise ValueError("VFS cache GiB must be an integer") from None
        return gib * 1024 * 1024 * 1024

    def _handle_admin_storage_providers(self, method: str) -> None:
        session = self._require_admin_session()
        if session is None:
            return
        message = ""
        delete_warning = None
        manager = self.server.storage_providers
        if method == "POST":
            form = self._read_form()
            if not self._valid_csrf(session, form):
                raise ApiError(403, "csrf", "CSRF validation failed")
            action = self._form_one(form, "action")
            try:
                if action == "create":
                    kind = self._form_one(form, "kind")
                    manager.create(
                        self._form_one(form, "name"),
                        kind,
                        settings=self._storage_credentials(kind, form),
                        remote_path=self._form_one(form, "remote_path"),
                        comment=self._form_one(form, "comment"),
                        writable=self._form_one(form, "writable") == "on",
                        cache_max_bytes=self._storage_cache_bytes(self._form_one(form, "cache_gib")),
                    )
                    message = "Storage provider created and mounted."
                elif action in {"update", "replace_credentials", "reconcile", "delete", "force_delete"}:
                    provider_id = self._form_one(form, "id")
                    provider = manager.store.get(provider_id)
                    if action == "delete":
                        manager.delete(provider_id)
                        message = "Storage provider deleted. Remote data was not deleted."
                    elif action == "force_delete":
                        manager.delete(provider_id, force=True)
                        message = "Storage provider forcibly deleted. Remote data was not deleted; pending local cached writes, if any, were discarded."
                    elif action == "reconcile":
                        manager.reconcile(provider_id)
                        message = "Storage provider reconciled."
                    elif action == "replace_credentials":
                        manager.update(
                            provider_id,
                            credentials=self._storage_credentials(provider["kind"], form),
                        )
                        message = "Storage provider credentials replaced."
                    else:
                        manager.update(
                            provider_id,
                            name=self._form_one(form, "name") or provider["name"],
                            remote_path=self._form_one(form, "remote_path"),
                            comment=self._form_one(form, "comment"),
                            writable=self._form_one(form, "writable") == "on",
                            enabled=self._form_one(form, "enabled") == "on",
                            cache_max_bytes=self._storage_cache_bytes(self._form_one(form, "cache_gib")),
                        )
                        message = "Storage provider updated."
                elif action == "add_mapping":
                    provider_id = self._form_one(form, "provider_id")
                    manager.add_mapping(
                        provider_id,
                        self._form_one(form, "workspace"),
                        self._form_one(form, "mapping_name"),
                    )
                    message = "Storage provider mapped into the workspace."
                elif action == "delete_mapping":
                    manager.delete_mapping(self._form_one(form, "mapping_id"))
                    message = "Storage workspace mapping removed. Remote data was not deleted."
                else:
                    raise ValueError("invalid storage provider action")
            except StorageProviderDeleteWarning as exc:
                delete_warning = {"provider_id": exc.provider_id, **exc.details}
                message = "Storage provider deletion paused: cached writes are pending or their sync state cannot be verified."
            except (ValueError, OSError, KeyError, sqlite3.Error, WorkspaceImageError) as exc:
                message = "Storage provider operation failed: " + str(exc)
        elif method != "GET":
            raise ApiError(405, "method_not_allowed", "use GET or POST")
        self._send_admin_dashboard(
            session,
            active_panel="storage",
            storage_message=message,
            storage_delete_warning=delete_warning,
        )

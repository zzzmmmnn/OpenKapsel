"""Administration handlers for server-managed storage providers."""

from __future__ import annotations

import sqlite3
from urllib.parse import parse_qs

from openkapsel.errors import ApiError
from openkapsel.storage.storage_manager import StorageProviderDeleteWarning
from openkapsel.storage.storage_oauth import StorageOAuthError
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
                if action == "oauth_start":
                    provider_id = self._form_one(form, "id")
                    if provider_id:
                        provider = manager.store.get(provider_id)
                        kind = provider["kind"]
                        create_values = None
                    else:
                        kind = manager.store.validate_kind(self._form_one(form, "kind"))
                        if kind not in {"google_drive", "dropbox"}:
                            raise ValueError("browser OAuth is supported only for Google Drive and Dropbox")
                        create_values = {
                            "name": manager.store.validate_provider_name(
                                self._form_one(form, "name")
                            ),
                            "remote_path": manager.store.validate_remote_path(
                                self._form_one(form, "remote_path")
                            ),
                            "comment": manager.store.validate_comment(
                                self._form_one(form, "comment")
                            ),
                            "writable": self._form_one(form, "writable") == "on",
                            "cache_max_bytes": manager.store.validate_cache_max_bytes(
                                self._storage_cache_bytes(self._form_one(form, "cache_gib"))
                            ),
                        }
                    if kind not in {"google_drive", "dropbox"}:
                        raise ValueError("browser OAuth is supported only for Google Drive and Dropbox")
                    redirect_uri = (
                        self._public_base_url().rstrip("/")
                        + "/admin/storage-providers/oauth/callback"
                    )
                    _flow, authorization_url = self.server.storage_oauth.begin(
                        session_id=session.id,
                        kind=kind,
                        client_id=self._form_one(form, "client_id"),
                        client_secret=self._form_one(form, "client_secret"),
                        redirect_uri=redirect_uri,
                        provider_id=provider_id or None,
                        create_values=create_values,
                    )
                    self._redirect(authorization_url)
                    return
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

    def _handle_admin_storage_oauth_callback(self, method: str, raw_query: str) -> None:
        if method != "GET":
            raise ApiError(405, "method_not_allowed", "use GET")
        session = self._require_admin_session()
        if session is None:
            return
        query = parse_qs(raw_query, keep_blank_values=True)
        state = (query.get("state") or [""])[0]
        try:
            flow = self.server.storage_oauth.consume(state, session.id)
            provider_error = (query.get("error") or [""])[0]
            if provider_error:
                detail = (query.get("error_description") or [provider_error])[0]
                detail = detail[:500]
                raise StorageOAuthError("OAuth authorization was not completed: " + detail)
            code = (query.get("code") or [""])[0]
            token = self.server.storage_oauth.exchange(flow, code)
            credentials = {
                "client_id": flow.client_id,
                "client_secret": flow.client_secret,
                "token": token,
            }
            manager = self.server.storage_providers
            if flow.provider_id:
                provider = manager.store.get(flow.provider_id)
                if provider["kind"] != flow.kind:
                    raise StorageOAuthError("storage provider type changed during OAuth authorization")
                manager.update(flow.provider_id, credentials=credentials)
                message = "Storage provider OAuth credentials connected."
            else:
                values = flow.create_values or {}
                manager.create(
                    values["name"],
                    flow.kind,
                    settings=credentials,
                    remote_path=values["remote_path"],
                    comment=values["comment"],
                    writable=values["writable"],
                    cache_max_bytes=values["cache_max_bytes"],
                )
                message = "Storage provider connected with OAuth and mounted."
        except (
            StorageOAuthError,
            ValueError,
            OSError,
            KeyError,
            sqlite3.Error,
            WorkspaceImageError,
        ) as exc:
            message = "Storage provider OAuth failed: " + str(exc)
        self._send_admin_dashboard(
            session,
            active_panel="storage",
            storage_message=message,
        )

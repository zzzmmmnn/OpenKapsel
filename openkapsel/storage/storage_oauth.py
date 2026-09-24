"""Short-lived administrator OAuth flows for Storage Providers."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from openkapsel.random_ids import token_urlsafe_alnum


_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
_DROPBOX_AUTH_URL = "https://www.dropbox.com/oauth2/authorize"
_DROPBOX_TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"
_KINDS = {"google_drive", "dropbox"}


class StorageOAuthError(ValueError):
    pass


@dataclass(frozen=True)
class StorageOAuthFlow:
    state: str
    session_id: str
    kind: str
    client_id: str
    client_secret: str
    redirect_uri: str
    provider_id: str | None
    create_values: dict[str, Any] | None
    expires_at: float


class StorageOAuthFlows:
    """Keep OAuth secrets only in process memory while a browser flow is pending."""

    def __init__(self, *, ttl_seconds: int = 10 * 60, max_pending: int = 128) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self._flows: dict[str, StorageOAuthFlow] = {}
        self._lock = threading.Lock()

    def begin(
        self,
        *,
        session_id: str,
        kind: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        provider_id: str | None = None,
        create_values: dict[str, Any] | None = None,
    ) -> tuple[StorageOAuthFlow, str]:
        if kind not in _KINDS:
            raise StorageOAuthError("browser OAuth is supported only for Google Drive and Dropbox")
        if not session_id:
            raise StorageOAuthError("administrator session is required")
        client_id = self._credential(client_id, "OAuth client ID")
        client_secret = self._credential(client_secret, "OAuth client secret")
        self._validate_redirect_uri(redirect_uri)
        if bool(provider_id) == bool(create_values):
            raise StorageOAuthError("OAuth flow must create or update exactly one storage provider")

        state = token_urlsafe_alnum(32)
        flow = StorageOAuthFlow(
            state=state,
            session_id=session_id,
            kind=kind,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            provider_id=provider_id,
            create_values=dict(create_values) if create_values is not None else None,
            expires_at=time.time() + self.ttl_seconds,
        )
        with self._lock:
            self._prune_locked()
            if len(self._flows) >= self.max_pending:
                raise StorageOAuthError("too many pending storage OAuth requests")
            self._flows[state] = flow
        return flow, self.authorization_url(flow)

    def consume(self, state: str, session_id: str) -> StorageOAuthFlow:
        if not isinstance(state, str) or not state or len(state) > 256:
            raise StorageOAuthError("invalid OAuth state")
        with self._lock:
            self._prune_locked()
            flow = self._flows.get(state)
            if flow is None:
                raise StorageOAuthError("storage OAuth request is missing, expired, or already used")
            if flow.session_id != session_id:
                raise StorageOAuthError("storage OAuth request belongs to a different administrator session")
            self._flows.pop(state, None)
            return flow

    @staticmethod
    def authorization_url(flow: StorageOAuthFlow) -> str:
        common = {
            "client_id": flow.client_id,
            "redirect_uri": flow.redirect_uri,
            "response_type": "code",
            "state": flow.state,
        }
        if flow.kind == "google_drive":
            params = {
                **common,
                "scope": _GOOGLE_DRIVE_SCOPE,
                "access_type": "offline",
                "prompt": "consent",
                "include_granted_scopes": "true",
            }
            return _GOOGLE_AUTH_URL + "?" + urlencode(params)
        params = {
            **common,
            "token_access_type": "offline",
        }
        return _DROPBOX_AUTH_URL + "?" + urlencode(params)

    @staticmethod
    def exchange(flow: StorageOAuthFlow, code: str) -> str:
        if not isinstance(code, str) or not code or len(code) > 16384 or "\x00" in code:
            raise StorageOAuthError("OAuth provider did not return a valid authorization code")
        if flow.kind == "google_drive":
            token_url = _GOOGLE_TOKEN_URL
        elif flow.kind == "dropbox":
            token_url = _DROPBOX_TOKEN_URL
        else:
            raise StorageOAuthError("unsupported storage OAuth provider")
        data = {
            "client_id": flow.client_id,
            "client_secret": flow.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": flow.redirect_uri,
        }
        try:
            response = httpx.post(
                token_url,
                data=data,
                headers={"Accept": "application/json"},
                timeout=15.0,
                follow_redirects=False,
            )
            response.raise_for_status()
            if len(response.content) > 128 * 1024:
                raise StorageOAuthError("OAuth provider returned an oversized token response")
            payload = response.json()
        except StorageOAuthError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise StorageOAuthError("OAuth token exchange failed") from exc
        return StorageOAuthFlows._rclone_token(payload)

    @staticmethod
    def _rclone_token(payload: Any) -> str:
        if not isinstance(payload, dict):
            raise StorageOAuthError("OAuth provider returned an invalid token response")
        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        token_type = payload.get("token_type") or "Bearer"
        if not isinstance(access_token, str) or not access_token or len(access_token) > 65536:
            raise StorageOAuthError("OAuth provider did not return an access token")
        if not isinstance(refresh_token, str) or not refresh_token or len(refresh_token) > 65536:
            raise StorageOAuthError(
                "OAuth provider did not return a refresh token; revoke the previous grant and authorize again"
            )
        if not isinstance(token_type, str) or not token_type or len(token_type) > 128:
            raise StorageOAuthError("OAuth provider returned an invalid token type")
        try:
            expires_in = int(payload.get("expires_in"))
        except (TypeError, ValueError):
            raise StorageOAuthError("OAuth provider did not return token expiry") from None
        if expires_in <= 0 or expires_in > 366 * 24 * 60 * 60:
            raise StorageOAuthError("OAuth provider returned invalid token expiry")
        expiry = (
            datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")
        return json.dumps(
            {
                "access_token": access_token,
                "token_type": token_type,
                "refresh_token": refresh_token,
                "expiry": expiry,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @staticmethod
    def _credential(value: Any, label: str) -> str:
        if not isinstance(value, str):
            raise StorageOAuthError(f"{label} is required")
        value = value.strip()
        if not value or len(value) > 4096 or "\x00" in value or "\r" in value or "\n" in value:
            raise StorageOAuthError(f"{label} is required")
        return value

    @staticmethod
    def _validate_redirect_uri(value: str) -> None:
        if not isinstance(value, str) or len(value) > 4096:
            raise StorageOAuthError("invalid OAuth redirect URI")
        parsed = urlsplit(value)
        if parsed.fragment or not parsed.hostname or parsed.scheme not in {"http", "https"}:
            raise StorageOAuthError("invalid OAuth redirect URI")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise StorageOAuthError("storage OAuth redirect URI must use HTTPS")

    def _prune_locked(self) -> None:
        now = time.time()
        for state, flow in list(self._flows.items()):
            if flow.expires_at <= now:
                self._flows.pop(state, None)

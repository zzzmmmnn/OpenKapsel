"""Persistent, connection-scoped OAuth grants for remote MCP clients.

Only administrators create connections and approve grants. Public registration
does not confer access or claim a connection. All bearer secrets are hashed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit


ACCESS_SECONDS = 3600
REFRESH_SECONDS = 30 * 86400
REQUEST_SECONDS = 600
SCOPE = "openkapsel"


class OAuthError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


class OAuthStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self.lock = threading.RLock()
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS connections (
                    id TEXT PRIMARY KEY, app_id TEXT NOT NULL, workspace TEXT NOT NULL,
                    comment TEXT NOT NULL, created_at REAL NOT NULL,
                    client_id TEXT, authenticated_at REAL, last_authorized_at REAL,
                    last_used_at REAL
                );
                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY, connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
                    metadata TEXT NOT NULL, secret_hash TEXT, created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS clients_connection ON clients(connection_id);
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
                    client_id TEXT NOT NULL, params TEXT NOT NULL, expires_at REAL NOT NULL,
                    code_hash TEXT UNIQUE
                );
                CREATE TABLE IF NOT EXISTS grants (
                    id TEXT PRIMARY KEY, connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
                    client_id TEXT NOT NULL, expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL, expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS credentials_grant ON credentials(grant_id);
            """)
        os.chmod(path, 0o600)

    @contextmanager
    def _db(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            try:
                with db:
                    yield db
            finally:
                db.close()

    @staticmethod
    def _connection(db, cid):
        row = db.execute("SELECT * FROM connections WHERE id=?", (cid,)).fetchone()
        if row is None:
            raise OAuthError("invalid_request", "Connection does not exist", 404)
        return dict(row)

    @staticmethod
    def _prune(db):
        now = time.time()
        db.execute("DELETE FROM requests WHERE expires_at<=?", (now,))
        db.execute("DELETE FROM grants WHERE expires_at<=?", (now,))
        db.execute("DELETE FROM credentials WHERE kind='access' AND expires_at<=?", (now,))
        db.execute("DELETE FROM clients WHERE created_at<? AND id NOT IN (SELECT client_id FROM connections WHERE client_id IS NOT NULL)", (now - 86400,))

    def create(self, app_id: str, workspace: str, comment: str) -> dict:
        comment = comment.strip()
        if not comment or len(comment) > 200:
            raise OAuthError("invalid_request", "Comment must contain 1 to 200 characters")
        cid = secrets.token_urlsafe(24)
        with self._db() as db:
            db.execute("INSERT INTO connections(id,app_id,workspace,comment,created_at) VALUES(?,?,?,?,?)",
                       (cid, app_id, workspace, comment, time.time()))
            return self._connection(db, cid)

    def get(self, cid: str) -> dict:
        with self._db() as db:
            return self._connection(db, cid)

    def list(self) -> list[dict]:
        with self._db() as db:
            return [dict(row) for row in db.execute("SELECT connections.*, clients.metadata FROM connections LEFT JOIN clients ON clients.id=connections.client_id ORDER BY created_at DESC")]

    def delete(self, cid: str) -> None:
        with self._db() as db:
            self._connection(db, cid)
            db.execute("DELETE FROM connections WHERE id=?", (cid,))

    def register(self, cid: str, metadata: dict) -> dict:
        redirects = metadata.get("redirect_uris")
        if not isinstance(redirects, list) or not 1 <= len(redirects) <= 10:
            raise OAuthError("invalid_redirect_uri", "Provide 1 to 10 redirect URIs")
        for uri in redirects:
            if not isinstance(uri, str) or not uri.isascii() or "#" in uri or len(uri) > 2048 or any(c.isspace() or ord(c) < 32 for c in uri):
                raise OAuthError("invalid_redirect_uri", "Invalid redirect URI")
            try:
                parsed = urlsplit(uri)
                valid = (parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1"}))
                valid = valid and bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.fragment
                valid = valid and bool(re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname or ""))
                parsed.port
            except ValueError:
                valid = False
            if not valid:
                raise OAuthError("invalid_redirect_uri", "Redirects require HTTPS (HTTP loopback IPs are allowed)")
        auth = metadata.get("token_endpoint_auth_method", "client_secret_basic")
        if not isinstance(auth, str) or auth not in {"none", "client_secret_post", "client_secret_basic"}:
            raise OAuthError("invalid_client_metadata", "Unsupported token endpoint authentication method")
        grants = metadata.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grants, list) or not all(isinstance(item, str) for item in grants) or "authorization_code" not in grants or set(grants) - {"authorization_code", "refresh_token"}:
            raise OAuthError("invalid_client_metadata", "Only authorization_code and refresh_token are supported")
        if metadata.get("response_types", ["code"]) != ["code"]:
            raise OAuthError("invalid_client_metadata", "Only response_type code is supported")
        name = metadata.get("client_name", "MCP client")
        if not isinstance(name, str) or len(name) > 200:
            raise OAuthError("invalid_client_metadata", "Invalid client name")
        if metadata.get("scope", SCOPE) != SCOPE:
            raise OAuthError("invalid_scope", "Unsupported scope")
        result = {"client_id": secrets.token_urlsafe(24), "client_name": name,
                  "redirect_uris": redirects, "token_endpoint_auth_method": auth,
                  "grant_types": grants, "response_types": ["code"], "scope": SCOPE}
        secret = secrets.token_urlsafe(32) if auth != "none" else None
        with self._db() as db:
            self._prune(db)
            conn = self._connection(db, cid)
            if conn["client_id"]:
                raise OAuthError("invalid_client_metadata", "Connection is already bound; create a new connection")
            if db.execute("SELECT COUNT(*) FROM clients WHERE connection_id=?", (cid,)).fetchone()[0] >= 32:
                raise OAuthError("temporarily_unavailable", "Registration limit reached; retry later", 429)
            db.execute("INSERT INTO clients VALUES(?,?,?,?,?)", (result["client_id"], cid, json.dumps(result), digest(secret) if secret else None, time.time()))
        result["client_id_issued_at"] = int(time.time())
        if secret:
            result.update(client_secret=secret, client_secret_expires_at=0)
        return result

    @staticmethod
    def _client(db, cid, client_id):
        client = db.execute("SELECT * FROM clients WHERE id=? AND connection_id=?", (client_id, cid)).fetchone()
        if client is None:
            raise OAuthError("invalid_client", "Unknown client", 401)
        conn = OAuthStore._connection(db, cid)
        if conn["client_id"] and conn["client_id"] != client_id:
            raise OAuthError("unauthorized_client", "Connection is bound to another client")
        return client

    def start(self, cid: str, params: dict[str, str], resource: str) -> str:
        with self._db() as db:
            self._prune(db)
            client = self._client(db, cid, params.get("client_id", ""))
            if params.get("redirect_uri") not in json.loads(client["metadata"])["redirect_uris"]:
                raise OAuthError("invalid_request", "Redirect URI is not registered")
            if params.get("response_type") != "code":
                raise OAuthError("unsupported_response_type", "Only authorization code is supported")
            if params.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.get("code_challenge", "")):
                raise OAuthError("invalid_request", "PKCE S256 is required")
            if params.get("resource") != resource:
                raise OAuthError("invalid_target", "Resource must match this connection's MCP URL")
            if params.get("scope", SCOPE) != SCOPE:
                raise OAuthError("invalid_scope", "Unsupported scope")
            if len(params.get("state", "")) > 2048:
                raise OAuthError("invalid_request", "State is too long")
            if db.execute("SELECT COUNT(*) FROM requests WHERE connection_id=?", (cid,)).fetchone()[0] >= 64:
                raise OAuthError("temporarily_unavailable", "Too many pending authorization requests", 429)
            rid = secrets.token_urlsafe(32)
            db.execute("INSERT INTO requests VALUES(?,?,?,?,?,NULL)", (rid, cid, params["client_id"], json.dumps(params), time.time() + REQUEST_SECONDS))
            return rid

    def request(self, rid: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM requests WHERE id=? AND expires_at>? AND code_hash IS NULL", (rid, time.time())).fetchone()
            if row is None:
                raise OAuthError("invalid_request", "Authorization request expired or already used")
            result = dict(row)
            result["params"] = json.loads(row["params"])
            result["connection"] = self._connection(db, row["connection_id"])
            result["client"] = json.loads(self._client(db, row["connection_id"], row["client_id"])["metadata"])
            return result

    def approve(self, rid: str) -> tuple[dict, str]:
        with self.lock:
            request = self.request(rid)
            code = secrets.token_urlsafe(32)
            with self._db() as db:
                db.execute("UPDATE connections SET client_id=? WHERE id=?", (request["client_id"], request["connection_id"]))
                db.execute("UPDATE requests SET code_hash=?,expires_at=? WHERE id=?", (digest(code), time.time() + 120, rid))
            return request["params"], code

    def deny(self, rid: str) -> dict:
        with self.lock:
            request = self.request(rid)
            with self._db() as db:
                db.execute("DELETE FROM requests WHERE id=?", (rid,))
            return request["params"]

    def _issue(self, db, grant_id: str, expiry: float) -> dict:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        now = time.time()
        for raw, kind, end in ((access, "access", now + ACCESS_SECONDS), (refresh, "refresh", expiry)):
            db.execute("INSERT INTO credentials VALUES(?,?,?,?,0)", (digest(raw), grant_id, kind, end))
        return {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_SECONDS,
                "refresh_token": refresh, "scope": SCOPE}

    def exchange(self, cid: str, form: dict[str, str], resource: str, auth_method: str) -> dict:
        failure = None
        result = None
        with self._db() as db:
            self._prune(db)
            client = self._client(db, cid, form.get("client_id", ""))
            metadata = json.loads(client["metadata"])
            if auth_method != metadata["token_endpoint_auth_method"] or (client["secret_hash"] and not hmac.compare_digest(client["secret_hash"], digest(form.get("client_secret", "")))):
                raise OAuthError("invalid_client", "Client authentication failed", 401)
            if form.get("resource") != resource:
                raise OAuthError("invalid_target", "Resource must match this connection's MCP URL")
            now = time.time()
            if form.get("grant_type") == "authorization_code":
                row = db.execute("SELECT * FROM requests WHERE code_hash=? AND connection_id=? AND client_id=? AND expires_at>?", (digest(form.get("code", "")), cid, client["id"], now)).fetchone()
                verifier = form.get("code_verifier", "")
                if row is None or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
                    raise OAuthError("invalid_grant", "Invalid authorization code or verifier")
                params = json.loads(row["params"])
                if form.get("redirect_uri") != params["redirect_uri"] or not hmac.compare_digest(challenge(verifier), params["code_challenge"]):
                    raise OAuthError("invalid_grant", "Authorization code binding mismatch")
                db.execute("DELETE FROM requests WHERE id=?", (row["id"],))
                db.execute("UPDATE grants SET revoked=1 WHERE connection_id=?", (cid,))
                gid = secrets.token_urlsafe(24)
                expiry = now + REFRESH_SECONDS
                db.execute("INSERT INTO grants VALUES(?,?,?,?,0)", (gid, cid, client["id"], expiry))
                db.execute("UPDATE connections SET authenticated_at=COALESCE(authenticated_at,?),last_authorized_at=? WHERE id=?", (now, now, cid))
                result = self._issue(db, gid, expiry)
            elif form.get("grant_type") == "refresh_token":
                row = db.execute("SELECT credentials.*,grants.connection_id,grants.client_id,grants.revoked,grants.expires_at AS grant_expiry FROM credentials JOIN grants ON grants.id=credentials.grant_id WHERE hash=? AND kind='refresh'", (digest(form.get("refresh_token", "")),)).fetchone()
                if row is None or row["connection_id"] != cid or row["client_id"] != client["id"] or row["revoked"] or row["expires_at"] <= now:
                    raise OAuthError("invalid_grant", "Invalid or expired refresh token")
                if row["used"]:
                    db.execute("UPDATE grants SET revoked=1 WHERE id=?", (row["grant_id"],))
                    failure = OAuthError("invalid_grant", "Refresh token reuse detected; authorization revoked")
                else:
                    db.execute("UPDATE credentials SET used=1 WHERE hash=?", (row["hash"],))
                    result = self._issue(db, row["grant_id"], row["grant_expiry"])
            else:
                raise OAuthError("unsupported_grant_type", "Unsupported grant type")
        if failure:
            raise failure
        return result

    def authenticate(self, cid: str, access: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT grants.* FROM credentials JOIN grants ON grants.id=credentials.grant_id WHERE hash=? AND kind='access' AND credentials.expires_at>? AND grants.expires_at>? AND revoked=0 AND connection_id=?", (digest(access), time.time(), time.time(), cid)).fetchone()
            if row is None:
                raise OAuthError("invalid_token", "Invalid or expired access token", 401)
            return self._connection(db, cid)

    def touch(self, cid: str) -> None:
        with self._db() as db:
            db.execute("UPDATE connections SET last_used_at=? WHERE id=? AND (last_used_at IS NULL OR last_used_at<?)", (time.time(), cid, time.time() - 60))

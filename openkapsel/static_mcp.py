"""Administrator-managed, independently expiring static MCP connections."""

import hmac
import os
import secrets
import threading
import time

from .oauth_store import OAuthError, OAuthStore, digest
from .errors import ApiError


EXPIRY_DAYS = (30, 91, 182, 365, 730)


class StaticMcpStore(OAuthStore):
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self.lock = threading.RLock()
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY, app_id TEXT NOT NULL, workspace TEXT NOT NULL,
                comment TEXT NOT NULL, created_at REAL NOT NULL, last_used_at REAL,
                secret TEXT NOT NULL, expires_at REAL NOT NULL
            )""")
        # Re-copying client JSON is an administrator operation, so this database
        # retains the secret under the same file protection as REST credentials.
        os.chmod(path, 0o600)

    def list(self):
        with self._db() as db:
            return [dict(row) for row in db.execute("SELECT * FROM connections ORDER BY created_at DESC")]

    @staticmethod
    def expiry(days):
        try:
            days = int(days)
        except (ValueError, TypeError):
            raise OAuthError("invalid_request", "Invalid expiration duration") from None
        if days not in EXPIRY_DAYS:
            raise OAuthError("invalid_request", "Choose 30, 91, 182, 365, or 730 days")
        return time.time() + days * 86400

    def create(self, app_id, workspace, comment, days=365):
        expiry = self.expiry(days)
        comment = comment.strip()
        if not comment or len(comment) > 200:
            raise OAuthError("invalid_request", "Comment must contain 1 to 200 characters")
        cid = secrets.token_urlsafe(24)
        with self._db() as db:
            db.execute("INSERT INTO connections(id,app_id,workspace,comment,created_at,secret,expires_at) VALUES(?,?,?,?,?,?,?)",
                       (cid, app_id, workspace, comment, time.time(), secrets.token_urlsafe(32), expiry))
            return self._connection(db, cid)

    def update(self, cid, comment, days=None):
        expiry = self.expiry(days) if days is not None else None
        comment = comment.strip()
        if not comment or len(comment) > 200:
            raise OAuthError("invalid_request", "Comment must contain 1 to 200 characters")
        with self._db() as db:
            self._connection(db, cid)
            db.execute("UPDATE connections SET comment=?,expires_at=COALESCE(?,expires_at) WHERE id=?", (comment, expiry, cid))

    def authenticate(self, cid, secret):
        conn = self.get(cid)
        if conn["expires_at"] <= time.time() or not hmac.compare_digest(digest(secret), digest(conn["secret"] or "")):
            raise OAuthError("invalid_token", "Invalid or expired MCP connection credential", 401)
        return conn


class StaticMcpHandlersMixin:
    def _static_mcp_authenticated_route(self, path):
        import re
        match = re.fullmatch(r"/mcp-connect/([A-Za-z0-9_-]{32})/(mcp|transfer/(?:fs/content|uploads/[^/]+(?:/commit)?))", path)
        if not match:
            raise ApiError(404, "not_found", "endpoint does not exist")
        cid, route = match.groups()
        try:
            headers = self.headers.get_all("Authorization") or []
            scheme, _, secret = headers[0].partition(" ") if len(headers) == 1 else ("", "", "")
            if scheme.lower() != "bearer" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", secret):
                raise OAuthError("invalid_token", "MCP connection credential required", 401)
            conn = self.server.static_mcp.authenticate(cid, secret)
            record = self.server.tokens.get_by_app_id(conn["app_id"])
            if record is None or not record.valid or record.path_prefix != conn["workspace"]:
                raise OAuthError("access_denied", "Linked workspace is unavailable or its directory has changed", 403)
            self.token_record = record
            self.token_scope_root = self.server.tokens.scope_root(record)
            self.control_authorized = True
            self.static_mcp_connection_id = cid
            self.server.static_mcp.touch(cid)
        except OAuthError as exc:
            raise ApiError(exc.status, exc.code, str(exc), headers={"WWW-Authenticate": "Bearer"} if exc.status == 401 else None) from None
        except ValueError:
            raise ApiError(403, "access_denied", "Workspace directory is unavailable") from None
        return "/mcp" if route == "mcp" else "/" + route.removeprefix("transfer/")

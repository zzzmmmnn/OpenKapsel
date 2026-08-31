"""Persistent capability-token model for the workspace server."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .environment_store import EnvironmentStore
from .network_proxy import NETWORK_MODES, normalize_domain_rules
from .workspace_layout import ensure_workspace_layout, remove_empty_workspace_layout


SHELL_MODES = {"none", "restricted", "full"}
SANDBOX_BACKENDS = {"auto", "bubblewrap", "podman"}
CONTAINER_IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,511}\Z")
PREVIEW_TOKEN_BYTES = 12
PREVIEW_TOKEN_LENGTH = 16
DEFAULT_SANDBOX_MAX_PROCESSES = 64
DEFAULT_SANDBOX_MEMORY_MB = 256
DEFAULT_SANDBOX_CPU_PERCENT = 100
DEFAULT_CREDENTIAL_TTL_DAYS = 3
MAX_CREDENTIAL_TTL_DAYS = 30
SELF_RENEWAL_WINDOW = timedelta(days=2)
LEGACY_WEB_AUTH_FIELDS = {
    "web_username",
    "web_password_hash",
    "web_session_ttl_seconds",
    "web_auth_version",
}


class CredentialRenewalNotDue(ValueError):
    """Raised when short-lived credentials are still outside the renewal window."""

    def __init__(self, expires_at: str, remaining_seconds: int):
        super().__init__("credentials can be renewed only when less than two days remain")
        self.expires_at = expires_at
        self.remaining_seconds = remaining_seconds


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def credential_expiry(days: int = DEFAULT_CREDENTIAL_TTL_DAYS) -> str:
    if not 1 <= days <= MAX_CREDENTIAL_TTL_DAYS:
        raise ValueError(
            f"credential lifetime must be between 1 and {MAX_CREDENTIAL_TTL_DAYS} days"
        )
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@dataclass(frozen=True)
class PathGrant:
    path: str
    read_only: bool = True

    @classmethod
    def from_data(cls, value: Any) -> "PathGrant":
        if isinstance(value, str):
            return cls(path=value, read_only=True)
        if not isinstance(value, dict):
            raise ValueError("allowed path entries must be objects")
        return cls(
            path=str(value.get("path", "")),
            read_only=bool(value.get("read_only", True)),
        )


@dataclass(frozen=True)
class TokenRecord:
    token: str = field(repr=False)
    name: str
    created_at: str
    preview_token: str = field(default="", repr=False)
    control_token: str = field(default="", repr=False)
    app_id: str = field(default="", repr=False)
    expires_at: str | None = None
    credentials_expires_at: str | None = None
    enabled: bool = True
    path_prefix: str = "."
    workspace_image: str | None = None
    can_read: bool = True
    can_write: bool = True
    can_preview: bool = False
    can_schedule: bool = False
    shell_mode: str = "full"
    sandbox_backend: str = "auto"
    sandbox_image: str | None = None
    network_mode: str = "none"
    allowed_domains: tuple[str, ...] = ()
    allowed_paths: tuple[PathGrant, ...] = ()
    sandbox_max_processes: int = DEFAULT_SANDBOX_MAX_PROCESSES
    sandbox_memory_mb: int = DEFAULT_SANDBOX_MEMORY_MB
    sandbox_cpu_percent: int = DEFAULT_SANDBOX_CPU_PERCENT

    @property
    def actor_id(self) -> str:
        """Stable pseudonymous identity for Context and Memory attribution."""
        material = f"openkapsel-actor:{self.app_id}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    @property
    def expired(self) -> bool:
        expiry = parse_datetime(self.expires_at)
        return expiry is not None and expiry <= datetime.now(timezone.utc)

    @property
    def valid(self) -> bool:
        return self.enabled and not self.expired

    @property
    def credentials_expired(self) -> bool:
        expiry = parse_datetime(self.credentials_expires_at)
        return expiry is not None and expiry <= datetime.now(timezone.utc)

    @property
    def credentials_valid(self) -> bool:
        return self.valid and not self.credentials_expired

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["allowed_paths"] = [asdict(item) for item in self.allowed_paths]
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenRecord":
        return cls(
            token=str(data["token"]),
            name=str(data.get("name") or "Unnamed token"),
            created_at=str(data.get("created_at") or utc_now()),
            preview_token=str(data.get("preview_token") or ""),
            control_token=str(data.get("control_token") or ""),
            app_id=str(data.get("app_id") or ""),
            expires_at=data.get("expires_at"),
            credentials_expires_at=data.get("credentials_expires_at"),
            enabled=bool(data.get("enabled", True)),
            path_prefix=str(data.get("path_prefix") or "."),
            workspace_image=(
                str(data["workspace_image"]) if data.get("workspace_image") else None
            ),
            can_read=bool(data.get("can_read", True)),
            can_write=bool(data.get("can_write", True)),
            can_preview=bool(data.get("can_preview", False)),
            can_schedule=bool(data.get("can_schedule", False)),
            shell_mode=str(data.get("shell_mode", "none")),
            sandbox_backend=str(data.get("sandbox_backend", "auto")),
            sandbox_image=(
                str(data["sandbox_image"]) if data.get("sandbox_image") else None
            ),
            network_mode=str(
                data.get(
                    "network_mode",
                    "full" if data.get("allow_network", False) else "none",
                )
            ),
            allowed_domains=tuple(str(item) for item in data.get("allowed_domains", [])),
            allowed_paths=tuple(PathGrant.from_data(item) for item in data.get("allowed_paths", [])),
            sandbox_max_processes=int(
                data.get("sandbox_max_processes", DEFAULT_SANDBOX_MAX_PROCESSES)
            ),
            sandbox_memory_mb=int(
                data.get("sandbox_memory_mb", DEFAULT_SANDBOX_MEMORY_MB)
            ),
            sandbox_cpu_percent=int(
                data.get("sandbox_cpu_percent", DEFAULT_SANDBOX_CPU_PERCENT)
            ),
        )


class TokenStore:
    """Thread-safe token registry with optional atomic JSON persistence."""

    def __init__(self, root: Path, data_file: Path | None, bootstrap_token: str | None):
        self.root = root.resolve()
        self.data_file = data_file.expanduser().resolve() if data_file is not None else None
        self._lock = threading.RLock()
        self._records: dict[str, TokenRecord] = {}
        self._preview_records: dict[str, TokenRecord] = {}
        self._control_records: dict[str, TokenRecord] = {}
        if self.data_file is not None and self.data_file.exists():
            self._load()
            os.chmod(self.data_file, 0o600)
        if bootstrap_token and bootstrap_token not in self._records:
            if (
                bootstrap_token in self._preview_records
                or bootstrap_token in self._control_records
            ):
                raise ValueError("bootstrap token conflicts with an existing credential")
            preview_token = self._new_preview_token_locked(bootstrap_token)
            control_token = self._new_token_locked(bootstrap_token, preview_token)
            app_id = self._new_app_id_locked()
            record = self._validate(
                TokenRecord(
                    token=bootstrap_token,
                    name="Bootstrap token",
                    created_at=utc_now(),
                    preview_token=preview_token,
                    control_token=control_token,
                    app_id=app_id,
                    credentials_expires_at=credential_expiry(),
                    shell_mode="full",
                )
            )
            self._records[bootstrap_token] = record
            self._preview_records[record.preview_token] = record
            self._control_records[record.control_token] = record
            self._save_locked()
        for path_prefix in {record.path_prefix for record in self._records.values()}:
            ensure_workspace_layout(self.root / path_prefix)

    def authenticate(self, supplied: str) -> TokenRecord | None:
        # Iteration plus constant-time comparison avoids exposing token equality
        # through an ordinary early-exit string comparison.
        with self._lock:
            found = None
            for token, record in self._records.items():
                if secrets.compare_digest(supplied, token):
                    found = record
            return found if found is not None and found.credentials_valid else None

    def authenticate_preview(self, supplied: str) -> TokenRecord | None:
        """Resolve an independent preview token without scanning full tokens."""
        if len(supplied) != PREVIEW_TOKEN_LENGTH:
            return None
        with self._lock:
            record = self._preview_records.get(supplied)
            return record if record is not None and record.valid else None

    def authenticate_control(self, supplied: str) -> TokenRecord | None:
        """Authenticate the high-privilege Bearer credential."""
        with self._lock:
            found = None
            for token, record in self._control_records.items():
                if secrets.compare_digest(supplied, token):
                    found = record
            return found if found is not None and found.credentials_valid else None

    def get(self, token: str) -> TokenRecord:
        with self._lock:
            try:
                return self._records[token]
            except KeyError:
                raise KeyError("token does not exist") from None

    def list(self) -> list[TokenRecord]:
        with self._lock:
            return sorted(
                self._records.values(),
                key=lambda item: (item.credentials_valid, item.valid, item.created_at),
                reverse=True,
            )

    def get_by_app_id(self, app_id: str) -> TokenRecord | None:
        """Resolve a stable app identity independently of rotated credentials."""
        with self._lock:
            for record in self._records.values():
                if secrets.compare_digest(record.app_id, app_id):
                    return record
        return None

    def create(
        self,
        *,
        name: str,
        expires_at: str | None,
        path_prefix: str,
        workspace_image: str | None = None,
        can_read: bool,
        can_write: bool,
        shell_mode: str,
        sandbox_backend: str = "auto",
        sandbox_image: str | None = None,
        can_preview: bool = False,
        can_schedule: bool = False,
        allowed_commands: tuple[str, ...] = (),
        network_mode: str = "none",
        allowed_domains: tuple[str, ...] = (),
        allowed_paths: tuple[PathGrant, ...] = (),
        sandbox_max_processes: int = DEFAULT_SANDBOX_MAX_PROCESSES,
        sandbox_memory_mb: int = DEFAULT_SANDBOX_MEMORY_MB,
        sandbox_cpu_percent: int = DEFAULT_SANDBOX_CPU_PERCENT,
    ) -> TokenRecord:
        with self._lock:
            normalized_prefix, created_workspace = self._prepare_child_workspace(path_prefix)
            token = self._new_token_locked()
            preview_token = self._new_preview_token_locked(token)
            control_token = self._new_token_locked(token, preview_token)
            app_id = self._new_app_id_locked()
            try:
                record = self._validate(
                    TokenRecord(
                        token=token,
                        name=name,
                        created_at=utc_now(),
                        preview_token=preview_token,
                        control_token=control_token,
                        app_id=app_id,
                        expires_at=expires_at,
                        credentials_expires_at=credential_expiry(),
                        path_prefix=normalized_prefix,
                        workspace_image=workspace_image,
                        can_read=can_read,
                        can_write=can_write,
                        can_preview=can_preview,
                        can_schedule=can_schedule,
                        shell_mode=shell_mode,
                        sandbox_backend=sandbox_backend,
                        sandbox_image=sandbox_image,
                        network_mode=network_mode,
                        allowed_domains=allowed_domains,
                        allowed_paths=allowed_paths,
                        sandbox_max_processes=sandbox_max_processes,
                        sandbox_memory_mb=sandbox_memory_mb,
                        sandbox_cpu_percent=sandbox_cpu_percent,
                    )
                )
            except Exception:
                if created_workspace:
                    self._remove_new_workspace(normalized_prefix)
                raise
            self._records[token] = record
            self._preview_records[record.preview_token] = record
            self._control_records[record.control_token] = record
            self._save_locked()
            return record

    def rotate_read_token(self, token: str) -> TokenRecord:
        """Replace only the URL-embedded read token."""
        with self._lock:
            current = self.get(token)
            new_token = self._new_token_locked()
            record = self._validate(replace(current, token=new_token))
            self._records.pop(token)
            self._records[new_token] = record
            self._preview_records[record.preview_token] = record
            self._control_records[record.control_token] = record
            try:
                self._save_locked()
            except Exception:
                self._records.pop(new_token, None)
                self._records[token] = current
                self._preview_records[current.preview_token] = current
                self._control_records[current.control_token] = current
                raise
            return record

    def rotate_control_token(self, token: str) -> TokenRecord:
        """Replace only the high-privilege Bearer credential."""
        with self._lock:
            current = self.get(token)
            control_token = self._new_token_locked()
            record = self._validate(replace(current, control_token=control_token))
            self._records[token] = record
            self._preview_records[record.preview_token] = record
            self._control_records.pop(current.control_token, None)
            self._control_records[control_token] = record
            try:
                self._save_locked()
            except Exception:
                self._records[token] = current
                self._preview_records[current.preview_token] = current
                self._control_records.pop(control_token, None)
                self._control_records[current.control_token] = current
                raise
            return record

    def rotate_token(self, token: str) -> TokenRecord:
        """Backward-compatible alias for rotating the privileged token."""
        return self.rotate_control_token(token)

    def renew_credentials(
        self, token: str, days: int = DEFAULT_CREDENTIAL_TTL_DAYS
    ) -> TokenRecord:
        """Atomically rotate read/control credentials and reset their short expiry."""
        expires_at = credential_expiry(days)
        with self._lock:
            current = self.get(token)
            read_token = self._new_token_locked()
            control_token = self._new_token_locked(read_token, current.preview_token)
            record = self._validate(
                replace(
                    current,
                    token=read_token,
                    control_token=control_token,
                    credentials_expires_at=expires_at,
                )
            )
            self._records.pop(current.token)
            self._records[read_token] = record
            self._preview_records[current.preview_token] = record
            self._control_records.pop(current.control_token, None)
            self._control_records[control_token] = record
            try:
                self._save_locked()
            except Exception:
                self._records.pop(read_token, None)
                self._records[current.token] = current
                self._preview_records[current.preview_token] = current
                self._control_records.pop(control_token, None)
                self._control_records[current.control_token] = current
                raise
            return record

    def renew_credentials_if_due(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> TokenRecord:
        """Self-renew both credentials only inside the final two-day window."""
        requested_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        with self._lock:
            current = self.get(token)
            current_expiry = parse_datetime(current.credentials_expires_at)
            if current_expiry is None:
                raise ValueError("credentials do not have a renewable short expiration")
            remaining = current_expiry - requested_at
            if remaining >= SELF_RENEWAL_WINDOW:
                raise CredentialRenewalNotDue(
                    current_expiry.isoformat(),
                    max(0, int(remaining.total_seconds())),
                )
            if remaining.total_seconds() <= 0:
                raise ValueError("expired credentials must be renewed by an administrator")

            read_token = self._new_token_locked()
            control_token = self._new_token_locked(read_token, current.preview_token)
            expires_at = (
                requested_at + timedelta(days=DEFAULT_CREDENTIAL_TTL_DAYS)
            ).isoformat()
            record = self._validate(
                replace(
                    current,
                    token=read_token,
                    control_token=control_token,
                    credentials_expires_at=expires_at,
                )
            )
            self._records.pop(current.token)
            self._records[read_token] = record
            self._preview_records[current.preview_token] = record
            self._control_records.pop(current.control_token, None)
            self._control_records[control_token] = record
            try:
                self._save_locked()
            except Exception:
                self._records.pop(read_token, None)
                self._records[current.token] = current
                self._preview_records[current.preview_token] = current
                self._control_records.pop(control_token, None)
                self._control_records[current.control_token] = current
                raise
            return record

    def update(self, token: str, **changes: Any) -> TokenRecord:
        with self._lock:
            current = self.get(token)
            if any(key in changes for key in {"token", "preview_token", "control_token", "app_id"}):
                raise ValueError("tokens cannot be changed through update")
            created_workspace = False
            normalized_prefix = None
            if "path_prefix" in changes:
                normalized_prefix, created_workspace = self._prepare_child_workspace(
                    str(changes["path_prefix"])
                )
                changes["path_prefix"] = normalized_prefix
            try:
                record = self._validate(replace(current, **changes))
            except Exception:
                if created_workspace and normalized_prefix is not None:
                    self._remove_new_workspace(normalized_prefix)
                raise
            self._records[token] = record
            self._preview_records[record.preview_token] = record
            self._control_records[record.control_token] = record
            self._save_locked()
            return record

    def rotate_preview_token(self, token: str) -> TokenRecord:
        """Replace only the read-only preview credential for an existing token."""
        with self._lock:
            current = self.get(token)
            preview_token = self._new_preview_token_locked()
            record = self._validate(replace(current, preview_token=preview_token))
            self._records[token] = record
            self._preview_records.pop(current.preview_token, None)
            self._preview_records[preview_token] = record
            self._control_records[record.control_token] = record
            self._save_locked()
            return record

    def _prepare_child_workspace(self, value: str) -> tuple[str, bool]:
        name = value.strip()
        candidate = Path(name)
        if (
            not name
            or name in {".", "..", ".recycle", ".sql", ".context", ".openkapsel"}
            or candidate.is_absolute()
            or len(candidate.parts) != 1
            or "/" in name
            or "\\" in name
        ):
            raise ValueError("workspace path must be a direct child directory name")
        workspace = self.root / name
        if workspace.is_symlink():
            raise ValueError("workspace directory must not be a symbolic link")
        if workspace.exists() and not workspace.is_dir():
            raise ValueError("the workspace path already exists and is not a directory")
        created = not workspace.exists()
        if created:
            workspace.mkdir()
        try:
            ensure_workspace_layout(workspace)
        except Exception:
            if created:
                try:
                    remove_empty_workspace_layout(workspace)
                    workspace.rmdir()
                except OSError:
                    pass
            raise
        return name, created

    def _remove_new_workspace(self, name: str) -> None:
        workspace = self.root / name
        try:
            remove_empty_workspace_layout(workspace)
            workspace.rmdir()
        except OSError:
            # Never remove a directory if another process populated it while
            # token validation was in progress.
            pass

    def delete(self, token: str) -> None:
        with self._lock:
            if token not in self._records:
                raise KeyError("token does not exist")
            record = self._records[token]
            EnvironmentStore(self.root / record.path_prefix).clear(record.app_id)
            self._records.pop(token)
            self._preview_records.pop(record.preview_token, None)
            self._control_records.pop(record.control_token, None)
            self._save_locked()

    def scope_root(self, record: TokenRecord) -> Path:
        # _validate already checks this, but resolving again catches a symlink
        # introduced after the record was saved.
        scoped = (self.root / record.path_prefix).resolve(strict=False)
        try:
            scoped.relative_to(self.root)
        except ValueError:
            raise ValueError("token path scope escapes workspace root") from None
        if not scoped.is_dir():
            raise ValueError("token path scope is not an existing directory")
        return scoped

    def _validate(self, record: TokenRecord) -> TokenRecord:
        if not record.token or "/" in record.token:
            raise ValueError("token must be non-empty and must not contain '/'")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16}", record.preview_token):
            raise ValueError("preview token must contain 16 URL-safe characters")
        if not record.control_token or "/" in record.control_token:
            raise ValueError("control token must be non-empty and must not contain '/'")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16}", record.app_id):
            raise ValueError("app id must contain 16 URL-safe characters")
        if len({record.token, record.preview_token, record.control_token}) != 3:
            raise ValueError("read, control, and preview tokens must be independent")
        name = record.name.strip()
        if not name or len(name) > 200:
            raise ValueError("token name must contain 1 to 200 characters")
        if record.shell_mode not in SHELL_MODES:
            raise ValueError("invalid shell mode")
        if record.can_schedule and record.shell_mode == "none":
            raise ValueError("scheduled tasks require Shell permission")
        if record.sandbox_backend not in SANDBOX_BACKENDS:
            raise ValueError("invalid sandbox backend")
        sandbox_image = (
            record.sandbox_image.strip() if record.sandbox_image is not None else None
        )
        if sandbox_image == "":
            sandbox_image = None
        if sandbox_image is not None and not CONTAINER_IMAGE_RE.fullmatch(sandbox_image):
            raise ValueError("invalid sandbox container image")
        if sandbox_image is not None and record.sandbox_backend != "podman":
            raise ValueError("a sandbox container image requires the Podman backend")
        if record.network_mode not in NETWORK_MODES:
            raise ValueError("invalid network mode")
        allowed_domains = normalize_domain_rules(list(record.allowed_domains))
        if record.network_mode == "domain_allowlist" and not allowed_domains:
            raise ValueError("domain allowlist network mode requires at least one domain")
        if not 1 <= record.sandbox_max_processes <= 4096:
            raise ValueError("sandbox process/thread limit must be between 1 and 4096")
        if not 16 <= record.sandbox_memory_mb <= 1_048_576:
            raise ValueError("sandbox memory limit must be between 16 and 1048576 MiB")
        if not 1 <= record.sandbox_cpu_percent <= 4096:
            raise ValueError("sandbox CPU limit must be between 1% and 4096%")
        expiry = parse_datetime(record.expires_at)
        expires_at = expiry.isoformat() if expiry is not None else None
        credentials_expiry = parse_datetime(record.credentials_expires_at)
        credentials_expires_at = (
            credentials_expiry.isoformat() if credentials_expiry is not None else None
        )
        prefix_path = Path(record.path_prefix or ".")
        if prefix_path.is_absolute():
            raise ValueError("path scope must be relative to workspace root")
        scoped = (self.root / prefix_path).resolve(strict=False)
        try:
            relative = scoped.relative_to(self.root)
        except ValueError:
            raise ValueError("path scope escapes workspace root") from None
        if not scoped.is_dir():
            raise ValueError("path scope must be an existing directory")
        workspace_image = record.workspace_image
        if workspace_image is not None:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", workspace_image):
                raise ValueError("invalid workspace image name")
            if workspace_image != str(relative):
                raise ValueError("workspace image must match the token workspace directory")
        allowed_paths = []
        for grant in record.allowed_paths:
            cleaned = grant.path.strip()
            if not cleaned:
                continue
            candidate = Path(cleaned).expanduser()
            if not candidate.is_absolute():
                raise ValueError("extra accessible paths must be absolute directories")
            resolved_path = candidate.resolve(strict=False)
            if resolved_path == Path("/"):
                raise ValueError("the filesystem root cannot be an extra accessible path")
            if not resolved_path.is_dir():
                raise ValueError(f"extra accessible path is not an existing directory: {resolved_path}")
            try:
                resolved_path.relative_to(self.root)
            except ValueError:
                try:
                    self.root.relative_to(resolved_path)
                except ValueError:
                    pass
                else:
                    raise ValueError("extra accessible paths cannot contain Workspace Root")
            else:
                raise ValueError("extra accessible paths must be outside Workspace Root")
            normalized = str(resolved_path)
            existing = next((item for item in allowed_paths if item.path == normalized), None)
            normalized_grant = PathGrant(path=normalized, read_only=bool(grant.read_only))
            if existing is None:
                allowed_paths.append(normalized_grant)
            elif existing.read_only != normalized_grant.read_only:
                raise ValueError(f"extra accessible path has conflicting modes: {normalized}")
        return replace(
            record,
            name=name,
            expires_at=expires_at,
            credentials_expires_at=credentials_expires_at,
            path_prefix=str(relative) if str(relative) else ".",
            workspace_image=workspace_image,
            can_preview=bool(record.can_preview),
            sandbox_image=sandbox_image,
            network_mode=record.network_mode,
            allowed_domains=allowed_domains,
            allowed_paths=tuple(allowed_paths),
        )

    def _load(self) -> None:
        assert self.data_file is not None
        payload = json.loads(self.data_file.read_text(encoding="utf-8"))
        if payload.get("version") != 1 or not isinstance(payload.get("tokens"), list):
            raise ValueError(f"invalid token data file: {self.data_file}")
        loaded: dict[str, TokenRecord] = {}
        preview_records: dict[str, TokenRecord] = {}
        control_records: dict[str, TokenRecord] = {}
        migrated = False
        migrated_credentials_expires_at = credential_expiry()
        for item in payload["tokens"]:
            record = TokenRecord.from_dict(item)
            if LEGACY_WEB_AUTH_FIELDS.intersection(item):
                migrated = True
            if any(
                key not in item
                for key in (
                    "sandbox_max_processes",
                    "sandbox_memory_mb",
                    "sandbox_cpu_percent",
                    "sandbox_backend",
                    "sandbox_image",
                    "network_mode",
                )
            ):
                migrated = True
            if "credentials_expires_at" not in item:
                record = replace(
                    record,
                    credentials_expires_at=migrated_credentials_expires_at,
                )
                migrated = True
            if not record.preview_token:
                while True:
                    preview_token = secrets.token_urlsafe(PREVIEW_TOKEN_BYTES)
                    if (
                        preview_token != record.token
                        and preview_token != record.control_token
                        and preview_token not in loaded
                        and preview_token not in preview_records
                        and preview_token not in control_records
                    ):
                        break
                record = replace(record, preview_token=preview_token)
                migrated = True
            if not record.control_token:
                while True:
                    control_token = secrets.token_urlsafe(32)
                    if (
                        control_token not in {record.token, record.preview_token}
                        and control_token not in loaded
                        and control_token not in preview_records
                        and control_token not in control_records
                    ):
                        break
                record = replace(record, control_token=control_token)
                migrated = True
            if not record.app_id:
                while True:
                    app_id = secrets.token_hex(8)
                    if all(item.app_id != app_id for item in loaded.values()):
                        break
                record = replace(record, app_id=app_id)
                migrated = True
            record = self._validate(record)
            if record.token in loaded:
                raise ValueError(f"duplicate token in data file: {record.token}")
            if record.preview_token in preview_records:
                raise ValueError(
                    f"duplicate preview token in data file: {record.preview_token}"
                )
            if record.control_token in control_records:
                raise ValueError(
                    f"duplicate control token in data file: {record.control_token}"
                )
            if (
                record.token in preview_records
                or record.token in control_records
                or record.preview_token in loaded
                or record.preview_token in control_records
                or record.control_token in loaded
                or record.control_token in preview_records
            ):
                raise ValueError("read, control, and preview token namespaces conflict")
            loaded[record.token] = record
            preview_records[record.preview_token] = record
            control_records[record.control_token] = record
        self._records = loaded
        self._preview_records = preview_records
        self._control_records = control_records
        if migrated:
            self._save_locked()

    def _new_preview_token_locked(self, *excluded: str) -> str:
        while True:
            preview_token = secrets.token_urlsafe(PREVIEW_TOKEN_BYTES)
            if (
                preview_token not in excluded
                and preview_token not in self._preview_records
                and preview_token not in self._records
                and preview_token not in self._control_records
            ):
                return preview_token

    def _new_token_locked(self, *excluded: str) -> str:
        while True:
            token = secrets.token_urlsafe(32)
            if (
                token not in excluded
                and token not in self._records
                and token not in self._preview_records
                and token not in self._control_records
            ):
                return token

    def _new_app_id_locked(self) -> str:
        existing = {item.app_id for item in self._records.values()}
        while True:
            app_id = secrets.token_hex(8)
            if app_id not in existing:
                return app_id

    def _save_locked(self) -> None:
        if self.data_file is None:
            return
        parent_was_missing = not self.data_file.parent.exists()
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        if parent_was_missing:
            os.chmod(self.data_file.parent, 0o700)
        temp_name: str | None = None
        payload = {"version": 1, "tokens": [item.to_dict() for item in self._records.values()]}
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.data_file.parent,
                prefix=f".{self.data_file.name}.",
                delete=False,
            ) as handle:
                temp_name = handle.name
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.data_file)
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass

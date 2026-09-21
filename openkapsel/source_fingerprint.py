"""Deterministic source fingerprints for mapping server/client reload decisions."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

FINGERPRINT_FORMAT = 1
_FORMAT_MARKER = f"openkapsel-source-fingerprint-v{FINGERPRINT_FORMAT}\0".encode("ascii")
_VERSION_RE = re.compile(rb'^__version__\s*=\s*["\']([0-9]+(?:\.[0-9]+){2})["\']\s*$', re.M)

SHARED_FILES = (
    "openkapsel/__init__.py",
    "openkapsel/source_fingerprint.py",
    "openkapsel/mapping_transport.py",
    "openkapsel/mapping_capabilities.py",
)

SERVER_FILES = (
    "openkapsel/server.py",
    "openkapsel/mapping_api.py",
    "openkapsel/mapping_fuse.py",
    "openkapsel/mapping_handlers.py",
    "openkapsel/mapping_host.py",
    "openkapsel/mapping_io.py",
    "openkapsel/mapping_leases.py",
    "openkapsel/mapping_manager.py",
    "openkapsel/mapping_process.py",
    "openkapsel/mapping_queries.py",
    "openkapsel/mapping_shares.py",
    "openkapsel/mapping_store.py",
    "openkapsel/mapping_transfers.py",
    "openkapsel/mapping_ui.py",
    "openkapsel/mapping_uploads.py",
    "openkapsel/shell_routing.py",
)

CLIENT_FILES = (
    "openkapsel/client.py",
    "openkapsel/client_reload.py",
    "openkapsel/client_file_api.py",
    "openkapsel/client_files.py",
    "openkapsel/client_tasks.py",
    "openkapsel/client_windows.py",
    "openkapsel/git_operations.py",
    "openkapsel/git_read.py",
    "openkapsel/git_write.py",
    "openkapsel/rename_exclusive.py",
    "openkapsel/safe_paths.py",
    "openkapsel/text_encoding.py",
    "openkapsel/rpc_plugins/__init__.py",
    "openkapsel/rpc_plugins/_data.py",
    "openkapsel/rpc_plugins/registry.py",
    "openkapsel/rpc_plugins/archive/__init__.py",
    "openkapsel/rpc_plugins/git/__init__.py",
    "openkapsel/rpc_plugins/structured/__init__.py",
    "openkapsel/rpc_plugins/tabular/__init__.py",
    "openkapsel/rpc_plugins/tabular/csv_stream.py",
    "openkapsel/rpc_plugins/tabular/excel.py",
)


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _manifest(side: str) -> tuple[str, ...]:
    if side == "server":
        specific = SERVER_FILES
    elif side == "client":
        specific = CLIENT_FILES
    else:
        raise ValueError("fingerprint side must be server or client")
    files = SHARED_FILES + specific
    if len(files) != len(set(files)):
        raise ValueError("fingerprint manifest contains duplicate paths")
    return files


def source_fingerprint(root: str | Path, side: str) -> str:
    root = Path(root).expanduser().resolve()
    manifest = _manifest(side)
    digest = hashlib.sha256()
    digest.update(_FORMAT_MARKER)
    digest.update(side.encode("ascii") + b"\0")
    # Explicitly bind the ordered manifest in addition to hashing the module
    # which contains it. This makes membership/order part of the format.
    for relative in manifest:
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    digest.update(b"\0files\0")
    for relative in manifest:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"fingerprint source file is missing or invalid: {relative}")
        data = path.read_bytes()
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return base64.b64encode(digest.digest()).decode("ascii")


def running_fingerprint(side: str) -> str:
    return source_fingerprint(project_root(), side)


def source_version(root: str | Path) -> str:
    data = (Path(root).expanduser().resolve() / "openkapsel" / "__init__.py").read_bytes()
    match = _VERSION_RE.search(data)
    if not match:
        raise ValueError("OpenKapsel source version is missing or invalid")
    return match.group(1).decode("ascii")


def parse_release_version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError("version must be numeric MAJOR.MINOR.PATCH")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def version_at_least(value: str, minimum: str) -> bool:
    return parse_release_version(value) >= parse_release_version(minimum)


def guarded_source_files(root: str | Path, side: str) -> set[str]:
    """Files expected to be represented by a manifest; used by tests/CI."""
    root = Path(root).expanduser().resolve()
    result = set(SHARED_FILES)
    if side == "server":
        result.update(
            path.relative_to(root).as_posix()
            for path in (root / "openkapsel").glob("mapping_*.py")
        )
        result.add("openkapsel/server.py")
        result.add("openkapsel/shell_routing.py")
    elif side == "client":
        result.update(
            path.relative_to(root).as_posix()
            for path in (root / "openkapsel").glob("client*.py")
        )
        result.update(
            path.relative_to(root).as_posix()
            for path in (root / "openkapsel" / "rpc_plugins").rglob("*.py")
        )
        result.update({
            "openkapsel/git_operations.py", "openkapsel/git_read.py",
            "openkapsel/git_write.py", "openkapsel/rename_exclusive.py",
            "openkapsel/safe_paths.py", "openkapsel/text_encoding.py",
        })
    else:
        raise ValueError("fingerprint side must be server or client")
    return result

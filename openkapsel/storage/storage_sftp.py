"""SFTP host-key discovery helpers for administrator confirmation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import shutil
import subprocess
from typing import Any, Callable


RunCommand = Callable[..., subprocess.CompletedProcess[str]]


def _host(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("SFTP host is required")
    host = value.strip()
    if not host or len(host) > 253:
        raise ValueError("SFTP host must be between 1 and 253 characters")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in host):
        raise ValueError("SFTP host must not contain whitespace or control characters")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ValueError("SFTP host is required")
    return host


def _port(value: Any) -> int:
    if value in (None, ""):
        return 22
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("SFTP port must be an integer") from None
    if not 1 <= port <= 65535:
        raise ValueError("SFTP port must be between 1 and 65535")
    return port


def _fingerprint_sha256(key_blob: str) -> str:
    try:
        raw = base64.b64decode(key_blob.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise ValueError("ssh-keyscan returned an invalid SSH host key") from None
    if not raw or len(raw) > 16384:
        raise ValueError("ssh-keyscan returned an invalid SSH host key")
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + digest


def detect_sftp_host_keys(
    host: Any,
    port: Any = 22,
    *,
    runner: RunCommand = subprocess.run,
    executable: str | None = None,
) -> dict[str, Any]:
    """Retrieve public SSH host keys without authenticating or trusting them.

    The returned material is only a candidate for administrator verification.
    Callers must never treat discovery itself as proof of host identity.
    """

    host = _host(host)
    port = _port(port)
    keyscan = executable or shutil.which("ssh-keyscan")
    if not keyscan:
        raise ValueError(
            "ssh-keyscan is not installed; install OpenSSH client tools or paste known_hosts manually"
        )

    try:
        result = runner(
            [
                keyscan,
                "-T",
                "5",
                "-p",
                str(port),
                "-t",
                "ed25519,ecdsa,rsa",
                "-f",
                "-",
            ],
            input=host + "\n",
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ValueError("timed out while detecting the SFTP SSH host key") from None
    except OSError as exc:
        raise ValueError("could not run ssh-keyscan: " + str(exc)) from None

    stdout = result.stdout or ""
    if len(stdout) > 65536:
        raise ValueError("ssh-keyscan returned too much host-key data")

    keys: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    known_host = host if port == 22 else f"[{host}]:{port}"
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3:
            continue
        _reported_host, key_type, key_blob = fields
        if len(key_type) > 64 or not key_type.startswith(("ssh-", "ecdsa-")):
            continue
        pair = (key_type, key_blob)
        if pair in seen:
            continue
        fingerprint = _fingerprint_sha256(key_blob)
        seen.add(pair)
        keys.append(
            {
                "type": key_type,
                "fingerprint_sha256": fingerprint,
                "known_hosts": f"{known_host} {key_type} {key_blob}",
            }
        )

    if not keys:
        detail = (result.stderr or "").strip().splitlines()
        suffix = ""
        if detail:
            suffix = ": " + detail[-1][:300]
        raise ValueError("no SSH host key was returned for the SFTP server" + suffix)

    return {
        "host": host,
        "port": port,
        "known_hosts": "\n".join(item["known_hosts"] for item in keys),
        "keys": keys,
    }

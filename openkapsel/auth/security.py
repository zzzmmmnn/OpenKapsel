"""Password hashing helpers shared by the server and password tool."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets


PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_SALT_BYTES = 16
PASSWORD_DIGEST_BYTES = 32


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def _parse_pbkdf2(encoded: str) -> tuple[int, bytes, bytes] | None:
    parts = encoded.split("$")
    if len(parts) != 4 or parts[0] != PASSWORD_HASH_ALGORITHM:
        return None
    try:
        iterations = int(parts[1])
        salt = _decode(parts[2])
        digest = _decode(parts[3])
    except (ValueError, binascii.Error):
        return None
    if not 1 <= iterations <= 10_000_000:
        return None
    if len(salt) < PASSWORD_SALT_BYTES or len(digest) != PASSWORD_DIGEST_BYTES:
        return None
    return iterations, salt, digest


def is_password_hash_supported(encoded: str) -> bool:
    """Only explicitly encoded, per-password-salted PBKDF2 is accepted."""
    return isinstance(encoded, str) and _parse_pbkdf2(encoded) is not None


def password_hash_needs_upgrade(encoded: str) -> bool:
    parsed = _parse_pbkdf2(encoded)
    return parsed is None or parsed[0] < PASSWORD_HASH_ITERATIONS


def hash_password(password: str, *, min_length: int = 12) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and a per-password salt."""
    if len(password) < min_length:
        raise ValueError(f"password must contain at least {min_length} characters")
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
        dklen=PASSWORD_DIGEST_BYTES,
    )
    return "$".join(
        (
            PASSWORD_HASH_ALGORITHM,
            str(PASSWORD_HASH_ITERATIONS),
            _encode(salt),
            _encode(digest),
        )
    )


def verify_password(password: str, expected_hash: str) -> bool:
    parsed = _parse_pbkdf2(expected_hash)
    if parsed is not None:
        iterations, salt, expected = parsed
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)

    # Keep invalid configuration checks expensive enough not to become a
    # distinct, cheap timing path at the login endpoint.
    hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        b"invalid-openkapsel",
        PASSWORD_HASH_ITERATIONS,
        dklen=PASSWORD_DIGEST_BYTES,
    )
    return False

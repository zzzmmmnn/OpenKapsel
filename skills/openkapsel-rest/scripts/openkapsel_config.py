#!/usr/bin/env python3
"""Directory-scoped credential loading for the OpenKapsel REST helpers."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit


ENV_FILENAME = ".openkapsel.env"
BASE_URL_KEY = "OPENKAPSEL_BASE_URL"
CONTROL_TOKEN_KEY = "OPENKAPSEL_CONTROL_TOKEN"
EXPIRY_KEY = "OPENKAPSEL_CREDENTIALS_EXPIRES_AT"
KNOWN_KEYS = frozenset({BASE_URL_KEY, CONTROL_TOKEN_KEY, EXPIRY_KEY})


@dataclass(frozen=True)
class Credentials:
    base_url: str | None
    control_token: str | None
    credentials_expires_at: str | None = None
    env_file: Path | None = None

    def updated(self, **changes: object) -> "Credentials":
        return replace(self, **changes)


def find_env_file(start: Path | None = None) -> Path | None:
    current = (start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    while True:
        candidate = current / ENV_FILENAME
        if candidate.exists():
            return candidate
        if (current / ".git").exists() or current.parent == current:
            return None
        current = current.parent


def _unquote(value: str, line_number: int) -> str:
    if not value:
        return ""
    if value[0] not in {"'", '"'}:
        return value
    if len(value) < 2 or value[-1] != value[0]:
        raise ValueError(f"unterminated quoted value on line {line_number}")
    inner = value[1:-1]
    if value[0] == "'":
        return inner
    output: list[str] = []
    escaped = False
    for char in inner:
        if escaped:
            output.append({"n": "\n", "r": "\r", "t": "\t"}.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            output.append(char)
    if escaped:
        raise ValueError(f"unterminated escape on line {line_number}")
    return "".join(output)


def read_env_file(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"credential file must be a regular non-symlink file: {path}")
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise ValueError(f"credential file must have mode 0600: {path}")
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        key, separator, value = stripped.partition("=")
        key = key.strip()
        if not separator or key not in KNOWN_KEYS:
            raise ValueError(f"unsupported credential entry on line {line_number}: {key or raw}")
        if key in values:
            raise ValueError(f"duplicate credential entry on line {line_number}: {key}")
        values[key] = _unquote(value.strip(), line_number)
    return values


def resolve_credentials(
    *,
    base_url: str | None = None,
    control_token: str | None = None,
    env_file: str | Path | None = None,
    cwd: Path | None = None,
) -> Credentials:
    requested_file = env_file or os.environ.get("OPENKAPSEL_ENV_FILE")
    path = Path(requested_file).expanduser() if requested_file else find_env_file(cwd)
    if requested_file and (path is None or not path.exists()):
        raise ValueError(f"credential file does not exist: {path}")
    file_values = read_env_file(path) if path is not None else {}

    resolved_base = base_url or file_values.get(BASE_URL_KEY) or os.environ.get(BASE_URL_KEY)
    resolved_control = (
        control_token
        or file_values.get(CONTROL_TOKEN_KEY)
        or os.environ.get(CONTROL_TOKEN_KEY)
    )
    expiry = file_values.get(EXPIRY_KEY) or os.environ.get(EXPIRY_KEY)
    persist_path = (
        path
        if path is not None
        and base_url is None
        and control_token is None
        and file_values.get(BASE_URL_KEY) == resolved_base
        and file_values.get(CONTROL_TOKEN_KEY) == resolved_control
        else None
    )
    return Credentials(
        base_url=resolved_base,
        control_token=resolved_control,
        credentials_expires_at=expiry,
        env_file=persist_path,
    )


def update_env_file(path: Path, credentials: Credentials) -> None:
    if not credentials.base_url or not credentials.control_token:
        raise ValueError("cannot persist incomplete OpenKapsel credentials")
    current = read_env_file(path)
    current.update(
        {
            BASE_URL_KEY: credentials.base_url,
            CONTROL_TOKEN_KEY: credentials.control_token,
        }
    )
    if credentials.credentials_expires_at:
        current[EXPIRY_KEY] = credentials.credentials_expires_at
    else:
        current.pop(EXPIRY_KEY, None)
    _atomic_write_env(path, current)


def _atomic_write_env(path: Path, values: dict[str, str]) -> None:
    lines = [
        f"{key}={values[key]}"
        for key in (BASE_URL_KEY, CONTROL_TOKEN_KEY, EXPIRY_KEY)
        if key in values
    ]
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _normalize_workspace_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
        or len(parts) < 2
        or parts[-2] != "w"
        or not parts[-1]
    ):
        raise ValueError("workspace URL must be an HTTP(S) URL ending in /w/<READ_TOKEN>")
    return normalized


def initialize_env_file(
    workspace_url: str,
    control_token: str,
    *,
    directory: Path | None = None,
    force: bool = False,
) -> tuple[Path, str]:
    base_url = _normalize_workspace_url(workspace_url)
    control = control_token.strip()
    if not control or any(char.isspace() for char in control):
        raise ValueError("control token must be non-empty and contain no whitespace")
    target = (directory or Path.cwd()).resolve() / ENV_FILENAME
    if target.is_symlink():
        raise ValueError(f"credential file must not be a symlink: {target}")
    desired = {
        BASE_URL_KEY: base_url,
        CONTROL_TOKEN_KEY: control,
    }
    if target.exists():
        current = read_env_file(target)
        if (
            current.get(BASE_URL_KEY) == base_url
            and current.get(CONTROL_TOKEN_KEY) == control
        ):
            return target, "unchanged"
        if not force:
            raise ValueError(f"credential file already exists; pass --force to replace it: {target}")
        action = "replaced"
    else:
        action = "created"
    _atomic_write_env(target, desired)
    return target, action


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Manage directory-scoped OpenKapsel credentials")
    subcommands = result.add_subparsers(dest="command", required=True)
    initialize = subcommands.add_parser(
        "init",
        help="write .openkapsel.env in the current directory",
    )
    initialize.add_argument("workspace_url")
    initialize.add_argument("control_token")
    initialize.add_argument(
        "--force",
        action="store_true",
        help="replace an existing configuration with different credentials",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command != "init":
            raise ValueError("unknown command")
        path, action = initialize_env_file(
            args.workspace_url,
            args.control_token,
            force=args.force,
        )
        print(json.dumps({"action": action, "path": str(path), "mode": "0600"}))
        return 0
    except (OSError, ValueError) as exc:
        print(f"openkapsel_config.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

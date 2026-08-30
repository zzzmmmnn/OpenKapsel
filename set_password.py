#!/usr/bin/env python3
"""Set the administration password hash in an OpenKapsel config file."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from openkapsel.security import PASSWORD_HASH_ALGORITHM, PASSWORD_HASH_ITERATIONS, hash_password


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    original_stat = path.stat() if path.exists() else None
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temp_name = handle.name
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        if original_stat is not None and hasattr(os, "chown"):
            temporary_stat = os.stat(temp_name)
            if (temporary_stat.st_uid, temporary_stat.st_gid) != (
                original_stat.st_uid,
                original_stat.st_gid,
            ):
                os.chown(temp_name, original_stat.st_uid, original_stat.st_gid)
        os.replace(temp_name, path)
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Set the admin password in config.json")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--username", help="also update the admin username")
    parser.add_argument(
        "--generate-username",
        action="store_true",
        help="generate an eight-character administrator username; prints it once",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="generate a strong password instead of prompting; prints it once",
    )
    args = parser.parse_args()
    if args.username and args.generate_username:
        parser.error("--username and --generate-username are mutually exclusive")

    config_path = Path(args.config).expanduser().resolve()
    if not config_path.is_file():
        parser.error(f"config file does not exist: {config_path}")
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"cannot read config: {exc}")
    if not isinstance(payload, dict):
        parser.error("config root must be a JSON object")
    admin = payload.setdefault("admin", {})
    if not isinstance(admin, dict):
        parser.error("config field admin must be an object")

    if args.generate:
        password = secrets.token_urlsafe(12)
    else:
        password = getpass.getpass("New admin password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            parser.error("passwords do not match")
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        parser.error(str(exc))

    if args.generate_username:
        admin["username"] = secrets.token_urlsafe(6)
    elif args.username:
        admin["username"] = args.username
    if not admin.get("username"):
        parser.error("admin.username is missing; pass --username")
    admin["password_hash"] = password_hash
    admin.pop("password_sha256", None)
    atomic_write(config_path, payload)
    print(
        f"Updated {config_path} using {PASSWORD_HASH_ALGORITHM} "
        f"with {PASSWORD_HASH_ITERATIONS} iterations."
    )
    if args.generate_username:
        print(f"Generated admin username (shown once): {admin['username']}")
    if args.generate:
        print(f"Generated admin password (shown once): {password}")


if __name__ == "__main__":
    main()

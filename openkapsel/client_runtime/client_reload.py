"""Persistent client reload state and trusted local-source re-exec helpers."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from openkapsel.source_fingerprint import project_root, source_fingerprint, source_version, version_at_least

STATE_VERSION = 1
LOCAL_REFRESH_SECONDS = 24 * 60 * 60
REQUIRED_RELOAD_DELAYS = (0, 60, 120, 300)


class ClientReloadState:
    def __init__(self, config_path: Path):
        self.path = config_path.with_name(config_path.name + ".state.json")
        self.data = self._load()
        if not self.data.get("last_reload_at"):
            self.data["last_reload_at"] = time.time()
            self.save()

    def _load(self):
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": STATE_VERSION, "required_reload_attempts": 0}
        except (OSError, ValueError, TypeError):
            return {"version": STATE_VERSION, "required_reload_attempts": 0}
        if not isinstance(raw, dict) or raw.get("version") != STATE_VERSION:
            return {"version": STATE_VERSION, "required_reload_attempts": 0}
        try:
            last_reload_at = float(raw.get("last_reload_at", 0) or 0)
            attempts = max(0, int(raw.get("required_reload_attempts", 0) or 0))
        except (TypeError, ValueError, OverflowError):
            return {"version": STATE_VERSION, "required_reload_attempts": 0}
        return {
            "version": STATE_VERSION,
            "last_reload_at": last_reload_at,
            "last_successful_server_fingerprint": (
                raw.get("last_successful_server_fingerprint")
                if isinstance(raw.get("last_successful_server_fingerprint"), str)
                else None
            ),
            "required_reload_attempts": attempts,
        }

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(self.data, version=STATE_VERSION)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=str(self.path.parent))
        try:
            fchmod = getattr(os, "fchmod", None)
            if callable(fchmod):
                fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
            chmod = getattr(os, "chmod", None)
            if callable(chmod):
                try:
                    chmod(self.path, 0o600)
                except (OSError, NotImplementedError):
                    pass
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    @property
    def last_reload_at(self) -> float:
        return float(self.data.get("last_reload_at", 0) or 0)

    @property
    def last_server_fingerprint(self) -> str | None:
        value = self.data.get("last_successful_server_fingerprint")
        return value if isinstance(value, str) and value else None

    @property
    def required_reload_attempts(self) -> int:
        return int(self.data.get("required_reload_attempts", 0) or 0)

    def mark_process_reload(self):
        self.data["last_reload_at"] = time.time()
        self.save()

    def mark_ready(self, server_fingerprint: str):
        self.data["last_successful_server_fingerprint"] = server_fingerprint
        self.data["required_reload_attempts"] = 0
        self.save()

    def next_required_delay(self) -> int:
        attempt = self.required_reload_attempts
        delay = REQUIRED_RELOAD_DELAYS[min(attempt, len(REQUIRED_RELOAD_DELAYS) - 1)]
        self.data["required_reload_attempts"] = attempt + 1
        self.save()
        return delay


class LocalSource:
    def __init__(self, root: Path, version: str, fingerprint: str):
        self.root = root
        self.version = version
        self.fingerprint = fingerprint


def inspect_local_source(config: dict) -> LocalSource | None:
    if config.get("auto_reload") is not True:
        return None
    raw = config.get("source_root")
    root = (
        Path(raw).expanduser().resolve()
        if isinstance(raw, str) and raw.strip()
        else project_root()
    )
    try:
        return LocalSource(root, source_version(root), source_fingerprint(root, "client"))
    except (OSError, ValueError):
        return None


def local_source_can_satisfy(source: LocalSource | None, minimum_version: str) -> bool:
    return bool(source is not None and version_at_least(source.version, minimum_version))


def exec_local_source(source: LocalSource, config_path: Path):
    import sys
    env = os.environ.copy()
    source_path = str(source.root)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = source_path + (os.pathsep + existing if existing else "")
    env["OPENKAPSEL_CLIENT_RELOADED"] = "1"
    # python -m can place an old checkout's working directory ahead of
    # PYTHONPATH. Bootstrap with an explicit sys.path insertion before importing
    # any OpenKapsel module from the configured trusted source root.
    bootstrap = (
        "import runpy,sys;"
        f"sys.path.insert(0,{source_path!r});"
        "runpy.run_module('openkapsel.client',run_name='__main__')"
    )
    argv = [sys.executable, "-c", bootstrap, "--config", str(config_path)]
    os.execve(sys.executable, argv, env)

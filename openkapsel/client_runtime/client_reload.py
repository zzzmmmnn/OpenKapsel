"""Persistent client reload state and trusted local-source re-exec helpers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from openkapsel.client_runtime.client_config import REEXEC_CONFIG_FD_ENV, REEXEC_CONFIG_SHA256_ENV
from openkapsel.source_fingerprint import (
    project_root,
    source_fingerprint,
    source_mapping_handshake_version,
    source_version,
    version_at_least,
)

STATE_VERSION = 1
LOCAL_REFRESH_SECONDS = 24 * 60 * 60
REQUIRED_RELOAD_DELAYS = (0, 60, 120, 300)
GIT_PULL_RETRY_SECONDS = 30
GIT_PULL_TIMEOUT_SECONDS = 90


class ClientReloadState:
    def __init__(self, config_path: Path):
        self.path = config_path.with_name(config_path.name + ".state.json")
        self.data = self._load()
        if not self.data.get("last_reload_at"):
            now = time.time()
            self.data["last_reload_at"] = now
            self.data["last_source_check_at"] = now
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
            last_source_check_at = float(
                raw.get("last_source_check_at", last_reload_at) or last_reload_at
            )
            attempts = max(0, int(raw.get("required_reload_attempts", 0) or 0))
        except (TypeError, ValueError, OverflowError):
            return {"version": STATE_VERSION, "required_reload_attempts": 0}
        return {
            "version": STATE_VERSION,
            "last_reload_at": last_reload_at,
            "last_source_check_at": last_source_check_at,
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
    def last_source_check_at(self) -> float:
        return float(self.data.get("last_source_check_at", self.last_reload_at) or 0)

    @property
    def last_server_fingerprint(self) -> str | None:
        value = self.data.get("last_successful_server_fingerprint")
        return value if isinstance(value, str) and value else None

    @property
    def required_reload_attempts(self) -> int:
        return int(self.data.get("required_reload_attempts", 0) or 0)

    def mark_process_reload(self):
        now = time.time()
        self.data["last_reload_at"] = now
        self.data["last_source_check_at"] = now
        self.save()

    def mark_source_checked(self):
        self.data["last_source_check_at"] = time.time()
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


def pull_trusted_source(root: Path) -> None:
    """Fast-forward the selected checkout as the Client operator, not an RPC.

    Only an opt-in trusted Git root may be updated. No interactive credential
    prompt, shell interpolation, submodule recursion or unbounded Git command.
    """
    git = shutil.which("git")
    if not git:
        raise OSError("git executable is unavailable")
    root = root.resolve()
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    def run(*args, capture=False):
        result = subprocess.run(
            [git, "-C", str(root), *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=env,
            timeout=GIT_PULL_TIMEOUT_SECONDS, check=False,
        )
        if result.returncode:
            raise OSError(f"git {args[0]} exited {result.returncode}")
        if capture:
            if len(result.stdout) > 4096:
                raise OSError("unexpectedly long Git repository path")
            return result.stdout.decode("utf-8", errors="replace").strip()
        return ""
    # Never accidentally pull an enclosing checkout via Git's upward search.
    top = Path(run("rev-parse", "--show-toplevel", capture=True)).resolve()
    if os.path.normcase(str(top)) != os.path.normcase(str(root)):
        raise OSError("source_root must be the Git worktree root")
    run("-c", "submodule.recurse=false", "pull", "--ff-only", "--no-recurse-submodules")


class GitPullGate:
    """Retry Git while the current Client connection stays alive.

    A successful pull is only a *permission to inspect/reload*; the caller
    still checks the source fingerprint, protocol, and active jobs.
    """
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.thread = None

    def start(self):
        if self.thread is None:
            self.thread = threading.Thread(
                target=self._run, name="openkapsel-git-pull", daemon=True)
            self.thread.start()
        return self.ready.is_set()

    def reset(self):
        # Called after a successful pull that did not need a reload.
        if self.thread is not None and self.thread.is_alive():
            return
        self.thread = None
        self.ready.clear()

    def close(self):
        self.stop.set()

    def _run(self):
        import logging
        log = logging.getLogger("openkapsel.client")
        while not self.stop.is_set():
            try:
                pull_trusted_source(self.root)
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                log.warning(
                    "Client Git pull failed (%s); retrying in %ss without disconnecting",
                    type(exc).__name__, GIT_PULL_RETRY_SECONDS,
                )
                if self.stop.wait(GIT_PULL_RETRY_SECONDS):
                    return
            else:
                if not self.stop.is_set():
                    log.info("Client Git pull succeeded; checking source for reload")
                    self.ready.set()
                return


class LocalSource:
    def __init__(self, root: Path, version: str, fingerprint: str, handshake_version: int):
        self.root = root
        self.version = version
        self.fingerprint = fingerprint
        self.handshake_version = handshake_version


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
        return LocalSource(
            root,
            source_version(root),
            source_fingerprint(root, "client"),
            source_mapping_handshake_version(root),
        )
    except (OSError, ValueError):
        return None


def local_source_can_satisfy(
    source: LocalSource | None,
    minimum_version: str,
    handshake_version: int,
) -> bool:
    return bool(
        source is not None
        and version_at_least(source.version, minimum_version)
        and source.handshake_version == handshake_version
    )


def exec_local_source(
    source: LocalSource,
    config_path: Path,
    *,
    config_sha256: str | None = None,
    config_fd: int | None = None,
):
    import sys
    env = os.environ.copy()
    source_path = str(source.root)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = source_path + (os.pathsep + existing if existing else "")
    env["OPENKAPSEL_CLIENT_RELOADED"] = "1"
    if config_sha256 is not None:
        env[REEXEC_CONFIG_SHA256_ENV] = config_sha256
    else:
        env.pop(REEXEC_CONFIG_SHA256_ENV, None)
    if config_fd is not None and os.name != "nt":
        env[REEXEC_CONFIG_FD_ENV] = str(config_fd)
    else:
        env.pop(REEXEC_CONFIG_FD_ENV, None)
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

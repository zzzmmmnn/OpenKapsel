"""Bounded read-only Git queries directly in the original repository.

The repository worktree and object database are never copied. Before launching
Git, validate its metadata/configuration with the same safe-read policy used
by Git mutations; commands run without a shell, external helpers, network,
system/user Git configuration, or optional Git maintenance.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from openkapsel.errors import ApiError
from openkapsel.files.git_operations import git_arguments
from openkapsel.files.git_write import _git_env, _validate_git_metadata

MAX_OUTPUT_BYTES = 65536
_SLOTS = threading.BoundedSemaphore(4)


def _check_local_config(executable, config, env, root, seconds):
    """Git's own parser recognizes hostile subsections even with odd whitespace."""
    try:
        parsed = subprocess.run(
            [executable, "config", "--null", "--list", "--no-includes", "--file", "-"],
            input=config.encode("utf-8"), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, cwd=root,
            shell=False, timeout=max(.01, seconds),
        )
    except subprocess.TimeoutExpired as exc:
        raise ApiError(504, "git_timeout", "Git config validation timed out") from exc
    if parsed.returncode or len(parsed.stdout) > 262144:
        raise ApiError(409, "git_unsafe_config", "repository Git config cannot be validated")
    filters = set()
    for record in parsed.stdout.split(b"\0"):
        if not record:
            continue
        key = record.split(b"\n", 1)[0].decode("utf-8", errors="replace").lower()
        if key.startswith(("include.", "includeif.")) or key == "extensions.worktreeconfig":
            raise ApiError(409, "git_unsafe_config",
                           "repository config redirects to external Git configuration")
        if key.startswith("filter.") and "." in key[7:]:
            filters.add(key.rsplit(".", 1)[0])
    # Git status/diff can run user-configured clean/process filters even with
    # --no-ext-diff. Shadow the repository's filter command keys for THIS
    # subprocess, retaining the rest of the genuine local Git configuration.
    overrides = []
    for prefix in sorted(filters):
        for suffix, value in (("clean", ""), ("smudge", ""), ("process", ""),
                              ("required", "false")):
            overrides.extend(["-c", f"{prefix}.{suffix}={value}"])
    return overrides


def inspect_git(access, root, operation, options, timeout=15):
    argv = git_arguments(operation, options)
    if type(timeout) is not int or not 1 <= timeout <= 20:
        raise ApiError(400, "invalid_request", "timeout_seconds must be between 1 and 20")
    if not _SLOTS.acquire(blocking=False):
        raise ApiError(429, "git_busy", "all Git inspection slots are in use")
    deadline = time.monotonic() + timeout

    def check():
        if time.monotonic() >= deadline:
            raise ApiError(504, "git_timeout", "Git inspection deadline exceeded")

    try:
        executable = shutil.which("git")
        if not executable:
            raise ApiError(503, "git_unavailable", "Git is not installed on the execution host")

        # The controlled Git subprocess reads the real repo. Reject alternate
        # object stores, linked Git directories and configurations capable of
        # redirecting IO or calling arbitrary external helpers.
        gitdir, config = _validate_git_metadata(
            SimpleNamespace(paths=access), Path(root), check_config=False)
        check()
        if (gitdir / "config.worktree").exists():
            raise ApiError(409, "git_unsupported_layout",
                           "per-worktree Git configuration is not supported")
        with tempfile.TemporaryDirectory(prefix="openkapsel-git-read-") as temporary:
            home = Path(temporary)
            env = _git_env(Path(root), gitdir, home, {})
            env.update(
                GIT_OPTIONAL_LOCKS="0",
                GIT_ALLOW_PROTOCOL="",
            )
            filter_overrides = _check_local_config(
                executable, config, env, root, deadline - time.monotonic())
            check()
            # No shell or external helpers, and no system/user Git config.
            # Local Git config is validated before use. Git receives its
            # real worktree and index, so ignored files and symlinks behave
            # as they do in normal Git.
            process = subprocess.Popen(
                [executable, "-c", "core.attributesFile=" + os.devnull,
                 "-c", "core.excludesFile=" + os.devnull,
                 *filter_overrides, *argv[1:]],
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            buffers = [bytearray(), bytearray()]
            dropped = [False, False]

            def collect(stream, index):
                with stream:
                    while data := stream.read(8192):
                        room = MAX_OUTPUT_BYTES - len(buffers[index])
                        buffers[index].extend(data[:room])
                        dropped[index] |= len(data) > room

            readers = [
                threading.Thread(target=collect, args=(stream, i), daemon=True)
                for i, stream in enumerate((process.stdout, process.stderr))
            ]
            for reader in readers:
                reader.start()
            try:
                process.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise ApiError(504, "git_timeout", "Git inspection deadline exceeded") from None
            finally:
                for reader in readers:
                    reader.join()
            result = {
                "operation": operation,
                "running": False,
                "exit_code": process.returncode,
                "output": buffers[0].decode("utf-8", errors="replace"),
                "stderr": buffers[1].decode("utf-8", errors="replace"),
                "output_truncated": dropped[0],
                "stderr_truncated": dropped[1],
            }
            if process.returncode:
                # Do not return absolute local paths from Git diagnostics.
                result["stderr"] = result["stderr"].replace(str(root), "<repository>")
                result["stderr"] = result["stderr"].replace(str(home), "<git-private>")
                raise ApiError(422, "git_failed", "Git inspection failed", result)
            return result
    except OSError as exc:
        raise ApiError(409, "git_read_unavailable", "repository could not be read safely") from exc
    finally:
        _SLOTS.release()

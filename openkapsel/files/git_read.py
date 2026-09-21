"""Read-only Git queries over a bounded, sanitized private snapshot.

The Git subprocess never receives a source-workspace path or its configuration.
No shell/task permission is involved and there is no unsafe execution fallback.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from openkapsel.errors import ApiError
from openkapsel.files.git_operations import git_arguments

MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_NODES = 100000
MAX_OUTPUT_BYTES = 65536
_SLOTS = threading.BoundedSemaphore(4)


def inspect_git(access, root, operation, options, timeout=15):
    argv = git_arguments(operation, options)
    if type(timeout) is not int or not 1 <= timeout <= 20:
        raise ApiError(400, "invalid_request", "timeout_seconds must be between 1 and 20")
    if not _SLOTS.acquire(blocking=False):
        raise ApiError(429, "git_busy", "all Git inspection slots are in use")
    deadline = time.monotonic() + timeout
    size = nodes = 0

    def check():
        if time.monotonic() >= deadline:
            raise ApiError(504, "git_timeout", "Git inspection deadline exceeded")

    def entries(path, *, metadata=False):
        check()
        def collect_entries(it):
            result = []
            for entry in it:
                check()
                # Git maintenance and writers create transient lock files.
                # They are not repository data and can vanish before stat().
                if metadata and entry.name.endswith(".lock"):
                    continue
                if len(result) >= MAX_SNAPSHOT_NODES:
                    raise ApiError(413, "git_snapshot_limit", "too many directory entries")
                result.append((entry.name, entry.stat(follow_symlinks=False)))
            return result
        if os.name == "nt":
            with access.guard(path, include_final=True):
                with os.scandir(path) as it:
                    return collect_entries(it)
        fd = access.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            with os.scandir(fd) as it:
                return collect_entries(it)
        finally:
            os.close(fd)

    def copy(source, target, details, *, metadata=False):
        nonlocal size, nodes
        check()
        nodes += 1
        if nodes > MAX_SNAPSHOT_NODES:
            raise ApiError(413, "git_snapshot_limit", "Git snapshot node limit exceeded")
        if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
            raise ApiError(409, "git_unsupported_layout", "Git snapshots do not follow symlinks or reparse points")
        if stat.S_ISDIR(details.st_mode):
            target.mkdir()
            for name, child in entries(source, metadata=metadata):
                if name == ".openkapsel" or (not metadata and name == ".git"):
                    continue
                if metadata and name in {"alternates", "http-alternates"}:
                    raise ApiError(409, "git_unsupported_layout", "external object stores are not supported")
                if metadata and name.endswith(".promisor"):
                    continue
                copy(source / name, target / name, child, metadata=metadata)
        elif stat.S_ISREG(details.st_mode):
            fd = access.open(source, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as src, target.open("xb") as dst:
                before = os.fstat(src.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ApiError(409, "git_unsupported_layout", "only regular files are supported")
                if size + before.st_size > MAX_SNAPSHOT_BYTES:
                    raise ApiError(413, "git_snapshot_limit", "Git snapshot exceeds 128 MiB")
                while chunk := src.read(1024 * 1024):
                    check()
                    size += len(chunk)
                    if size > MAX_SNAPSHOT_BYTES:
                        raise ApiError(413, "git_snapshot_limit", "Git snapshot exceeds 128 MiB")
                    dst.write(chunk)
                after = os.fstat(src.fileno())
                if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                    raise ApiError(409, "path_changed", "file changed while creating Git snapshot")
            target.chmod(0o700 if before.st_mode & 0o111 else 0o600)
        else:
            raise ApiError(409, "git_unsupported_layout", "special files cannot be inspected")

    try:
        executable = shutil.which("git")
        if not executable:
            raise ApiError(503, "git_unavailable", "Git is not installed on the execution host")
        with tempfile.TemporaryDirectory(prefix="openkapsel-git-") as temporary:
            base = Path(temporary)
            home = base / "home"
            home.mkdir()
            repo = base / "repo"
            repo.mkdir()
            gitdir = repo / ".git"
            gitdir.mkdir()
            children = entries(root)
            original_git = next((st for name, st in children if name == ".git"), None)
            if original_git is None or not stat.S_ISDIR(original_git.st_mode) or getattr(original_git, "st_file_attributes", 0) & 0x400:
                raise ApiError(409, "git_unsupported_layout", "path must be a repository root with an ordinary .git directory")
            for name, details in entries(root / ".git", metadata=True):
                if name == "commondir":
                    raise ApiError(409, "git_unsupported_layout", "linked worktrees are not supported")
                if name in {"HEAD", "index", "packed-refs", "shallow", "objects", "refs"} or name.startswith("sharedindex."):
                    copy(root / ".git" / name, gitdir / name, details, metadata=True)
            # Never read or interpret source config, hooks, info/attributes, or
            # include files. Only SHA-1 repositories are supported in this version.
            (gitdir / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\n", encoding="ascii")
            needs_worktree = operation == "status" or (operation in {"diff", "diff_stat"} and not options.get("staged") and not options.get("to_revision"))
            if needs_worktree:
                for name, details in children:
                    if name not in {".git", ".openkapsel"}:
                        copy(root / name, repo / name, details)
            env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR") if key in os.environ}
            env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), TMPDIR=str(base), TMP=str(base), TEMP=str(base),
                       GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", LC_ALL="C")
            check()
            process = subprocess.Popen([executable, *argv[1:]], cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            buffers = [bytearray(), bytearray()]
            dropped = [False, False]
            def collect(stream, index):
                with stream:
                    while data := stream.read(8192):
                        room = MAX_OUTPUT_BYTES - len(buffers[index])
                        buffers[index].extend(data[:room])
                        dropped[index] |= len(data) > room
            readers = [threading.Thread(target=collect, args=(stream, i), daemon=True)
                       for i, stream in enumerate((process.stdout, process.stderr))]
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
            result = {"operation": operation, "running": False, "exit_code": process.returncode,
                      "output": buffers[0].decode("utf-8", errors="replace"),
                      "stderr": buffers[1].decode("utf-8", errors="replace"),
                      "output_truncated": dropped[0], "stderr_truncated": dropped[1],
                      "snapshot_bytes": size}
            if process.returncode:
                # Never disclose private snapshot paths in diagnostics.
                result["stderr"] = result["stderr"].replace(str(base), "<git-snapshot>")
                raise ApiError(422, "git_failed", "Git inspection failed", result)
            return result
    except OSError as exc:
        # Keep the cause for local debugging; API serialization exposes only
        # the sanitized message, never the native path from the exception.
        raise ApiError(409, "git_snapshot_unavailable", "repository could not be read safely") from exc
    finally:
        _SLOTS.release()

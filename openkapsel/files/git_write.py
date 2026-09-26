"""Cancellable fixed Git mutations for server and client RPC tasks.

The operation set is intentionally small. Complex Git invocations belong in
Shell. Hooks/signing/global config are disabled and network operations accept
HTTPS remotes only under an explicit token network policy.
"""

from __future__ import annotations

import configparser
import errno
import os
import shutil
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from openkapsel.errors import ApiError
from openkapsel.execution.network_proxy import domain_allowed, normalize_domain_rules


MAX_GIT_METADATA_NODES = 100_000
_UNSAFE_CONFIG_MARKERS = (
    "[include",
    "[filter ",
    '[filter "',
    "[url ",
    '[url "',
    "[merge ",
    '[merge "',
    "[credential",
    "[http",
    "sshcommand",
    "uploadpack",
    "receivepack",
)


def _read_file(files, path: Path, limit: int = 256 * 1024) -> bytes:
    fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_size > limit:
            raise ApiError(409, "git_unsafe_config", "Git metadata is not a bounded regular file")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ApiError(409, "git_unsafe_config", "Git metadata exceeds its safety limit")
        return data


def _path_exists(files, path: Path) -> bool:
    try:
        fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return False
        raise
    else:
        os.close(fd)
        return True


def _metadata_entries(files, path: Path):
    guard = getattr(files.paths, "guard", None)
    if guard is not None:
        with guard(path, include_final=True):
            with os.scandir(path) as items:
                return [(item.name, item.stat(follow_symlinks=False)) for item in items]
    fd = files.paths.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with os.scandir(fd) as items:
            return [(item.name, item.stat(follow_symlinks=False)) for item in items]
    finally:
        os.close(fd)


def _validate_git_metadata(files, root: Path):
    gitdir = root / ".git"
    try:
        fd = files.paths.open(gitdir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise ApiError(409, "git_unsupported_layout", "path must contain an ordinary .git directory") from exc
    try:
        details = os.fstat(fd)
        if not stat.S_ISDIR(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
            raise ApiError(409, "git_unsupported_layout", "path must contain an ordinary .git directory")
    finally:
        os.close(fd)

    if _path_exists(files, gitdir / "commondir") or _path_exists(files, gitdir / "objects" / "info" / "alternates"):
        raise ApiError(409, "git_unsupported_layout", "linked worktrees and alternate object stores are not supported")

    config = ""
    try:
        config = _read_file(files, gitdir / "config").decode("utf-8", errors="replace")
    except FileNotFoundError:
        pass
    lowered = config.lower()
    if any(marker in lowered for marker in _UNSAFE_CONFIG_MARKERS):
        raise ApiError(
            409,
            "git_unsafe_config",
            "repository configuration contains an external-helper or redirection feature",
        )

    nodes = 0
    stack = [gitdir]
    while stack:
        directory = stack.pop()
        for name, child in _metadata_entries(files, directory):
            nodes += 1
            if nodes > MAX_GIT_METADATA_NODES:
                raise ApiError(413, "git_metadata_limit", "Git metadata contains too many entries")
            if stat.S_ISLNK(child.st_mode) or getattr(child, "st_file_attributes", 0) & 0x400:
                raise ApiError(409, "git_unsupported_layout", "Git metadata cannot contain links or reparse points")
            if stat.S_ISDIR(child.st_mode):
                stack.append(directory / name)
            elif not stat.S_ISREG(child.st_mode):
                raise ApiError(409, "git_unsupported_layout", "Git metadata contains a special file")
    return gitdir, config


def _paths(value, *, required=False):
    if value is None:
        value = []
    if (
        not isinstance(value, list)
        or len(value) > 100
        or any(
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or "\x00" in path
            or "\\" in path
            or ":" in path
            or path.startswith("/")
            or ".." in path.split("/")
            or ".openkapsel" in path.split("/")
            for path in value
        )
        or sum(map(len, value)) > 16_000
        or (required and not value)
    ):
        raise ApiError(400, "invalid_request", "paths must be bounded repository-relative paths")
    return value


def _revision(value, key="revision"):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or value.startswith("-")
        or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        raise ApiError(400, "invalid_request", f"{key} must be a bounded revision")
    return value


def _branch(value):
    value = _revision(value, "new_branch")
    if (
        value.startswith((".", "/"))
        or value.endswith((".", "/", ".lock"))
        or ".." in value
        or "@{" in value
        or any(char in value for char in "~^:?*[")
    ):
        raise ApiError(400, "invalid_request", "new_branch is not a safe branch name")
    return value


def _identity(value, key):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 200
        or "\x00" in value
        or any(ord(char) < 32 for char in value)
    ):
        raise ApiError(400, "invalid_request", f"{key} is invalid")
    return value.strip()


def _remote(value):
    if value is None:
        return "origin"
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or value.startswith(("-", "."))
        or value.endswith(".")
        or any(ord(char) < 33 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
        or any(char in value for char in '\\"[]{}:;')
    ):
        raise ApiError(400, "invalid_request", "remote must be a simple bounded remote name")
    return value


def _network_policy(args):
    mode = args.get("_network_mode", "none")
    if mode not in {"none", "domain_allowlist", "full"}:
        raise ApiError(400, "invalid_request", "invalid Git network policy")
    if mode == "none":
        raise ApiError(403, "git_network_denied", "Git network access is not granted")
    raw = args.get("_allowed_domains", [])
    if not isinstance(raw, (list, tuple)) or any(not isinstance(item, str) for item in raw):
        raise ApiError(400, "invalid_request", "invalid Git network domain policy")
    rules = normalize_domain_rules(list(raw)) if mode == "domain_allowlist" else ()
    if mode == "domain_allowlist" and not rules:
        raise ApiError(403, "git_network_denied", "Git network domain allowlist is empty")
    return mode, rules


def _validate_https_url(value, args):
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ApiError(400, "invalid_request", "Git remote URL must be a bounded HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ApiError(400, "git_remote_unsupported", "Git network operations require a plain HTTPS URL without embedded credentials, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ApiError(400, "git_remote_unsupported", "Git remote URL contains an invalid port") from exc
    if port not in {None, 443}:
        raise ApiError(400, "git_remote_unsupported", "Git HTTPS remotes must use port 443")
    mode, rules = _network_policy(args)
    if mode == "domain_allowlist" and not domain_allowed(parsed.hostname, rules):
        raise ApiError(403, "git_network_denied", "Git remote host is not in the token network allowlist")
    return value


def _remote_url(config_text: str, remote: str, args) -> str:
    parser = configparser.RawConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(config_text)
    except configparser.Error as exc:
        raise ApiError(409, "git_unsafe_config", "repository Git config cannot be parsed safely") from exc
    section = f'remote "{remote}"'
    if not parser.has_section(section):
        raise ApiError(409, "git_remote_missing", f"Git remote does not exist: {remote}")
    value = parser.get(section, "url", fallback=None)
    if value is None:
        raise ApiError(409, "git_remote_missing", f"Git remote has no URL: {remote}")
    return _validate_https_url(value.strip(), args)


def _base_env(home: Path, args):
    env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "LANG") if key in os.environ}
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_ATTR_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="",
        GIT_NO_LAZY_FETCH="1",
        GIT_ALLOW_PROTOCOL="https",
        LC_ALL="C",
    )
    name = _identity(args.get("author_name"), "author_name")
    email = _identity(args.get("author_email"), "author_email")
    if name is not None:
        env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = name
    if email is not None:
        env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = email
    return env


def _git_env(root: Path, gitdir: Path, home: Path, args):
    env = _base_env(home, args)
    env.update(GIT_DIR=str(gitdir), GIT_WORK_TREE=str(root))
    return env


def _common(executable: str, hooks: Path):
    return [
        executable,
        "--no-pager",
        "--literal-pathspecs",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=" + str(hooks),
        "-c", "commit.gpgSign=false",
        "-c", "tag.gpgSign=false",
        "-c", "submodule.recurse=false",
        "-c", "maintenance.auto=false",
        "-c", "gc.auto=0",
        "-c", "color.ui=false",
        "-c", "credential.helper=",
        "-c", "core.askPass=",
        "-c", "http.proxy=",
        "-c", "http.sslVerify=true",
        "-c", "http.extraHeader=",
        "-c", "http.cookieFile=",
        "-c", "http.saveCookies=false",
        "-c", "http.followRedirects=false",
    ]


def _run_git(files, root: Path, args, task):
    executable = shutil.which("git")
    if not executable:
        raise ApiError(503, "git_unavailable", "Git is not installed on the execution host")
    operation = args["_operation"]
    with tempfile.TemporaryDirectory(prefix="openkapsel-git-write-") as temporary:
        base = Path(temporary)
        hooks = base / "hooks"
        home = base / "home"
        hooks.mkdir()
        home.mkdir()
        common = _common(executable, hooks)

        if operation == "clone":
            source = _validate_https_url(args.get("source"), args)
            if root == files.root or ".openkapsel" in root.relative_to(files.root).parts:
                raise ApiError(403, "reserved_path", "clone destination is protected")
            if _path_exists(files, root):
                raise ApiError(409, "path_exists", "clone destination already exists")
            try:
                parent_fd = files.paths.open(root.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            except OSError as exc:
                raise ApiError(400, "parent_not_found", "clone destination parent does not exist") from exc
            else:
                os.close(parent_fd)
            env = _base_env(home, args)
            argv = [*common, "clone", "--no-recurse-submodules", "--", source, root.name]
            cwd = root.parent
        else:
            gitdir, config_text = _validate_git_metadata(files, root)
            env = _git_env(root, gitdir, home, args)
            cwd = root
            if operation == "add":
                paths = _paths(args.get("paths"), required=True)
                argv = [*common, "add", "--", *paths]
            elif operation == "commit":
                message = args.get("message")
                if not isinstance(message, str) or not message.strip() or len(message) > 10_000 or "\x00" in message:
                    raise ApiError(400, "invalid_request", "message must be a bounded non-empty commit message")
                amend = args.get("amend", False)
                if not isinstance(amend, bool):
                    raise ApiError(400, "invalid_request", "amend must be boolean")
                argv = [*common, "commit", "--no-verify", "--no-gpg-sign", "-m", message]
                if amend:
                    argv.append("--amend")
            elif operation == "restore":
                paths = _paths(args.get("paths"), required=True)
                staged = args.get("staged", False)
                worktree = args.get("worktree", True)
                if not isinstance(staged, bool) or not isinstance(worktree, bool) or not (staged or worktree):
                    raise ApiError(400, "invalid_request", "restore must target staged and/or worktree state")
                argv = [*common, "restore"]
                if staged:
                    argv.append("--staged")
                if worktree:
                    argv.append("--worktree")
                if args.get("source") is not None:
                    argv += ["--source", _revision(args["source"], "source")]
                argv += ["--", *paths]
            elif operation == "checkout":
                revision = _revision(args.get("revision"))
                argv = [*common, "checkout", "--no-recurse-submodules"]
                if args.get("new_branch") is not None:
                    argv += ["-b", _branch(args["new_branch"])]
                argv += [revision]
            elif operation in {"fetch", "pull"}:
                remote = _remote(args.get("remote"))
                remote_url = _remote_url(config_text, remote, args)
                common = [*common, "-c", f"remote.{remote}.url={remote_url}"]
                if operation == "fetch":
                    argv = [*common, "fetch", "--no-recurse-submodules", remote]
                else:
                    argv = [*common, "pull", "--ff-only", "--no-recurse-submodules", remote]
            else:
                raise ApiError(400, "invalid_git_operation", "unsupported Git write operation")

        task.write(f"git {operation} started\n")
        returncode = task.run_process(argv, cwd=cwd, env=env)
        if returncode:
            raise ApiError(
                422,
                "git_failed",
                "Git write operation failed",
                {"operation": operation, "exit_code": returncode},
            )
        task.write(f"git {operation} completed\n")
        try:
            display_cwd = root.relative_to(files.root).as_posix() or "."
        except ValueError:
            display_cwd = str(root)
        return {
            "operation": operation,
            "cwd": display_cwd,
            "exit_code": 0,
        }


def mutate_git(files, operation: str, args, task):
    if not isinstance(args, dict):
        raise ApiError(400, "invalid_request", "Git arguments must be an object")
    root = files.path(args.get("cwd", "."))
    payload = dict(args, _operation=operation)
    return _run_git(files, root, payload, task)

"""Per-job filesystem and network sandbox launch policy for shared Job Manager.

Only an explicit sandbox JSON request enables this path. Missing sandbox is
intentionally kept as current-user execution for existing Clients.
"""
from __future__ import annotations

import os
import platform
import shlex
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from openkapsel.auth.tokens import PathGrant
from openkapsel.execution.cgroups import SandboxLimits
from openkapsel.execution.network_proxy import DomainProxy, normalize_domain_rules
from openkapsel.execution.sandbox_backends import (
    BubblewrapBackend, SandboxSpec,
)
from openkapsel.execution.tasks import RESOLVER_FD_MARKER

MODES = {"none", "full", "domain_allowlist"}
TYPES = {"bubblewrap", "seatbelt", "srt_windows"}
MAX_PATHS = 32
# Runtime libraries are readable, but nothing under the host user's home is.
MACOS_SYSTEM_READ = (
    "/System", "/usr", "/bin", "/sbin", "/Library",
    "/private/etc", "/dev", "/opt/homebrew",
)


@dataclass
class PreparedJob:
    argv: list[str]
    environment: dict[str, str]
    controller: object | None = None
    resolver: IO[bytes] | None = None
    temp_dir: Path | None = None

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self.resolver.fileno(),) if self.resolver is not None else ()

    def launched(self) -> None:
        if self.resolver is not None:
            self.resolver.close()
            self.resolver = None

    def cleanup(self) -> None:
        self.launched()
        if self.controller is not None:
            if isinstance(self.controller, DomainProxy):
                self.controller.close()
            else:
                self.controller.cleanup()
            self.controller = None
        if self.temp_dir is not None:
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None


def _real_dir(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("sandbox path must be a non-empty absolute directory")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("sandbox path must be absolute")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or resolved == Path(resolved.anchor):
        raise ValueError("sandbox must use a non-root directory")
    return resolved


def _contains(root: Path, child: Path) -> bool:
    return child == root or root in child.parents


def _sb_quote(value: Path | str) -> str:
    # Seatbelt profile string quoting is not shell quoting.
    raw = str(value)
    return '"' + raw.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def prepare_job(
    specification: dict, argv: list[str], cwd: str, environment: dict[str, str],
    home: Path,
) -> PreparedJob:
    if not isinstance(specification, dict) or set(specification) - {
        "type", "root", "writable", "network_mode", "allowed_domains",
        "allowed_paths", "hidden_paths",
    }:
        raise ValueError("unknown sandbox environment options")
    kind = specification.get("type")
    if not isinstance(kind, str) or kind not in TYPES:
        raise ValueError("unsupported sandbox type")
    if kind == "bubblewrap" and platform.system() != "Linux":
        raise ValueError("bubblewrap sandbox requires Linux")
    if kind == "seatbelt" and platform.system() != "Darwin":
        raise ValueError("Seatbelt sandbox requires macOS")
    if kind == "srt_windows" and platform.system() != "Windows":
        raise ValueError("sandbox-runtime requires Windows")
    root = _real_dir(specification.get("root"))
    work = Path(cwd).resolve(strict=True)
    if not _contains(root, work):
        raise ValueError("sandbox cwd must be inside sandbox root")
    # Never expose the Manager's state database and spool in the sandbox.
    state_root = home.resolve()
    if _contains(root, state_root) or _contains(state_root, root):
        raise ValueError("sandbox workspace overlaps Manager state")
    writable = specification.get("writable", False)
    if type(writable) is not bool:
        raise ValueError("sandbox writable must be boolean")
    mode = specification.get("network_mode", "none")
    if not isinstance(mode, str) or mode not in MODES:
        raise ValueError("unsupported sandbox network mode")
    domains = specification.get("allowed_domains", [])
    if not isinstance(domains, list) or len(domains) > 128 or not all(
        isinstance(item, str) for item in domains
    ):
        raise ValueError("invalid sandbox allowed_domains")
    if mode == "domain_allowlist":
        domains = list(normalize_domain_rules(domains))
        if not domains:
            raise ValueError("domain_allowlist requires allowed_domains")
    elif domains:
        raise ValueError("allowed_domains requires domain_allowlist mode")
    extras = specification.get("allowed_paths", [])
    hidden = specification.get("hidden_paths", [])
    if (not isinstance(extras, list) or len(extras) > MAX_PATHS
            or not isinstance(hidden, list) or len(hidden) > MAX_PATHS):
        raise ValueError("invalid sandbox path grants")
    grants: list[PathGrant] = []
    for item in extras:
        if not isinstance(item, dict) or set(item) != {"path", "read_only"} or type(item["read_only"]) is not bool:
            raise ValueError("allowed_paths entries require path and read_only")
        directory = _real_dir(item["path"])
        if _contains(directory, root):
            raise ValueError("sandbox grant must not enclose workspace root")
        if _contains(directory, state_root) or _contains(state_root, directory):
            raise ValueError("sandbox grant overlaps Manager state")
        if any(directory == Path(grant.path) or
               directory in Path(grant.path).parents or
               Path(grant.path) in directory.parents for grant in grants):
            raise ValueError("overlapping sandbox path grants are ambiguous")
        grants.append(PathGrant(str(directory), item["read_only"]))
    excluded: list[Path] = []
    for item in hidden:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise ValueError("invalid hidden path")
        value = Path(item)
        if not value.is_absolute():
            raise ValueError("hidden path must be absolute")
        path = value.resolve(strict=True)
        if not _contains(root, path):
            raise ValueError("hidden path must be inside workspace root")
        if path == root:
            raise ValueError("cannot hide the sandbox root")
        excluded.append(path)
    for grant in grants:
        directory = Path(grant.path)
        if any(_contains(directory, item) or _contains(item, directory)
               for item in excluded):
            raise ValueError("sandbox grant overlaps a hidden path")

    sandbox_home = home / "sandboxes"
    sandbox_home.mkdir(mode=0o700, exist_ok=True)
    job_dir = Path(tempfile.mkdtemp(prefix="job-", dir=sandbox_home)).resolve()
    controller: object | None = None
    try:
        if kind == "srt_windows":
            from openkapsel.windows_srt import launch_windows_srt
            command, env = launch_windows_srt(
                argv=argv, environment=environment, job_dir=job_dir,
                root=root, writable=writable, grants=grants, hidden=excluded,
                mode=mode, domains=domains,
            )
            return PreparedJob(command, env, temp_dir=job_dir)
        if kind == "bubblewrap":
            bwrap = Path(shutil.which("bwrap") or "/usr/bin/bwrap")
            rootlesskit = Path(shutil.which("rootlesskit") or "/usr/bin/rootlesskit")
            backend = BubblewrapBackend(bwrap, rootlesskit, aggregate_resources=False)
            spec = SandboxSpec(
                command=shlex.join(argv), cwd=work, scope_root=root,
                can_write=writable, network_mode=mode,
                allowed_domains=tuple(domains), proxy_root=job_dir,
                allowed_paths=tuple(grants), hidden_paths=tuple(excluded),
                limits=SandboxLimits(64, 256 * 1024 * 1024, 100),
                owner_token="job-manager",
                allow_grant_writes_when_scope_readonly=True,
            )
            launch = backend.build_shell(spec)
            controller = launch.controller
            result = PreparedJob(list(launch.argv), dict(environment), controller, temp_dir=job_dir)
            # Directory masks are handled by the shared backend. Files need a
            # read-only /dev/null bind instead of a tmpfs mount (which fails
            # on regular-file destinations).
            file_masks = [path for path in excluded if path.is_file()]
            if file_masks:
                # Remove these from the backend's --tmpfs list, then place
                # regular-file masks after the workspace bind and path grants.
                for path in file_masks:
                    marker = ["--tmpfs", str(path)]
                    index = next(
                        (i for i in range(len(result.argv) - 1)
                         if result.argv[i:i + 2] == marker), None
                    )
                    if index is None:
                        raise RuntimeError("file mask not found in Bubblewrap launch")
                    del result.argv[index:index + 2]
                for path in file_masks:
                    index = result.argv.index("--clearenv")
                    result.argv[index:index] = ["--ro-bind", "/dev/null", str(path)]
            if launch.stdin_data is not None:
                fd = tempfile.TemporaryFile()
                fd.write(launch.stdin_data)
                fd.seek(0)
                result.resolver = fd
                result.argv = [
                    str(fd.fileno()) if arg == RESOLVER_FD_MARKER else arg
                    for arg in result.argv
                ]
            return result

        executable = shutil.which("sandbox-exec")
        if not executable or not Path(executable).is_file():
            raise RuntimeError("sandbox-exec is not available on this macOS host")
        profile = [
            "(version 1)", "(deny default)",
            "(allow process*)", "(allow sysctl-read)",
            "(allow file-read-metadata)", '(allow file-read-data (literal "/"))',
        ]
        for system_path in MACOS_SYSTEM_READ:
            if Path(system_path).exists():
                profile.append(f"(allow file-read* (subpath {_sb_quote(Path(system_path).resolve())}))")
        for directory in (root, *(Path(item.path) for item in grants)):
            profile.append(f"(allow file-read* (subpath {_sb_quote(directory)}))")
        if writable:
            profile.append(f"(allow file-write* (subpath {_sb_quote(root)}))")
        for grant in grants:
            if not grant.read_only:
                profile.append(f"(allow file-write* (subpath {_sb_quote(grant.path)}))")
            else:
                # A read-only path inside a writable workspace (or another
                # writable ancestor) needs a deny override, not just the
                # absence of an extra allow.
                profile.append(f"(deny file-write* (subpath {_sb_quote(grant.path)}))")
        profile.append(f"(allow file-read* (subpath {_sb_quote(job_dir)}))")
        profile.append(f"(allow file-write* (subpath {_sb_quote(job_dir)}))")
        for directory in excluded:
            operation = "subpath" if directory.is_dir() else "literal"
            profile.append(f"(deny file-read* ({operation} {_sb_quote(directory)}))")
            profile.append(f"(deny file-write* ({operation} {_sb_quote(directory)}))")
        env = dict(environment)
        env.update(TMPDIR=str(job_dir), TMP=str(job_dir), TEMP=str(job_dir), HOME=str(root))
        if mode == "full":
            profile.append("(allow network*)")
        elif mode == "domain_allowlist":
            proxy, port = DomainProxy.start_loopback(job_dir, tuple(domains))
            controller = proxy
            profile.append(f'(allow network-outbound (remote ip "localhost:{port}"))')
            url = f"http://127.0.0.1:{port}"
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                env[name] = url
            env["NO_PROXY"] = env["no_proxy"] = ""
        # Everything else, including outgoing sockets, is denied by default.
        rules = "\n".join(profile)
        if len(rules) > 32000:
            raise ValueError("Seatbelt profile exceeds size limit")
        return PreparedJob([executable, "-p", rules, *argv], env, controller, temp_dir=job_dir)
    except BaseException:
        if controller is not None:
            if isinstance(controller, DomainProxy):
                controller.close()
            else:
                controller.cleanup()
        shutil.rmtree(job_dir)
        raise

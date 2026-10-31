"""Per-job filesystem and network sandbox launch policy for shared Job Manager.

Only an explicit sandbox JSON request enables this path. Missing sandbox is
intentionally kept as current-user execution for existing Clients.
"""
from __future__ import annotations

import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
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
from openkapsel.execution.tasks import RESOLVER_FD_MARKER, _injected_file_descriptor

MODES = {"none", "full", "domain_allowlist"}
TYPES = {"bubblewrap", "seatbelt"}
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


def _seatbelt_named_rules(root: Path, grants: list[PathGrant],
                          patterns: list[PathGrant]) -> list[str]:
    """Compile prefix-ignored rules to *dynamic* macOS path regexes.

    A per-job os.walk is required for Bubblewrap bind masks, but creates
    hundreds of redundant rules for Seatbelt and misses paths created after
    launch. Positive pattern grants are scoped to already-authorized concrete
    directories, so a suffix pattern cannot grant access to unrelated HOME.
    """
    from openkapsel.auth.path_access import (
        DEFAULT_ACCESS_RULES, _FOLDED_PROTECTED_NAMES, _rule_parts,
    )

    scopes = [root, *(Path(item.path) for item in grants
                       if item.access in {"rw", "ro"} and Path(item.path).is_dir())]
    # An encompassing grant already covers all its nested roots.
    scopes = [path for path in dict.fromkeys(scopes)
              if not any(path != parent and _contains(parent, path)
                         for parent in scopes)]
    prefix = "^(" + "|".join(re.escape(str(path)) for path in scopes) + ")/(.*/)?"

    explicit = {item.path: item.access for item in patterns}
    effective = [(raw, access) for raw, access in DEFAULT_ACCESS_RULES
                 if raw not in explicit]
    effective += list(explicit.items())
    # An allow must not accidentally cancel an unrelated protected suffix;
    # caller-emitted concrete exceptions are handled after these regex rules.
    priority = {"rw": 0, "ro": 1, "protect": 2, "deny": 3}
    rules = []
    for raw, access in sorted(effective, key=lambda x: priority[x[1]]):
        _suffix, directory, name = _rule_parts(raw)
        folded = name.casefold() in _FOLDED_PROTECTED_NAMES
        name_regex = "".join(
            "[" + c.lower() + c.upper() + "]"
            if folded and c.isascii() and c.isalpha() else re.escape(c)
            for c in name
        )
        expression = prefix + name_regex + ("(/.*)?$" if directory else "$")
        scope = f"(regex {_sb_quote(expression)})"
        if access in {"ro", "rw"}:
            rules.append(f"(allow file-read* {scope})")
            if access == "rw":
                rules.append(f"(allow file-write* {scope})")
            else:
                rules.append(f"(deny file-write* {scope})")
        else:
            rules.append(f"(deny file-read* {scope})")
            rules.append(f"(deny file-write* {scope})")
    return rules


def _seatbelt_inside_named_protection(path: Path,
                                        patterns: list[PathGrant]) -> bool:
    """Whether a concrete exception needs reapplying after named denies."""
    from openkapsel.auth.path_access import DEFAULT_ACCESS_RULES, _rule_parts
    overrides = {item.path: item.access for item in patterns}
    effective = [(raw, access) for raw, access in DEFAULT_ACCESS_RULES
                 if raw not in overrides] + list(overrides.items())
    protected = {name.casefold() for raw, access in effective
                 if access in {"protect", "deny", "ro"}
                 for _suffix, _directory, name in (_rule_parts(raw),)}
    return any(part.casefold() in protected for part in path.parts)



def _seatbelt_same_anchor_access(directory: Path, access: str,
                                 patterns: list[PathGrant]) -> str:
    """Two explicit rules at the same anchor compete by strictness.

    An explicit literal permit replaces a DEFAULT name rule, but does not
    override a separately configured explicit */name rule at that anchor.
    Deeper literal rules may still open an ordinary protect/ro ancestor.
    """
    from openkapsel.auth.path_access import _literal_name_matches, _rule_parts
    strength = {"rw": 0, "ro": 1, "protect": 2, "deny": 3}
    for pattern in patterns:
        _suffix, is_directory, name = _rule_parts(pattern.path)
        if is_directory == directory.is_dir() and _literal_name_matches(
                directory.name, name):
            if strength[pattern.access] > strength[access]:
                access = pattern.access
    return access


def _trusted_macos_xcode_developer_dir(path: Path) -> bool:
    """Only a system-installed Xcode.app Developer root, not arbitrary apps.

    Do not grant /Applications itself (or an environment-selected user tree)
    access to sensitive data merely because /usr/bin/python3 uses xcrun.
    """
    parts = path.parts
    return (
        len(parts) == 5
        and parts[:2] == ("/", "Applications")
        and bool(re.fullmatch(r"Xcode(?:[._-][A-Za-z0-9._-]+)?\.app", parts[2]))
        and parts[3:] == ("Contents", "Developer")
    )


def _macos_xcode_developer_dir(environment: dict[str, str]) -> Path | None:
    """Resolve the selected Apple developer toolchain outside the sandbox.

    GitHub-hosted macOS may select /Applications/Xcode_<version>.app. Apple's
    /usr/bin/python3 loads libxcrun.dylib from Developer/usr/lib, then may
    launch xcodebuild which requires sibling Contents/SharedFrameworks and
    Contents/Frameworks. The CLT variant under /Library is already covered
    by system read roots.
    """
    selected = environment.get("DEVELOPER_DIR")
    if not selected:
        try:
            result = subprocess.run(
                ["/usr/bin/xcode-select", "-p"],
                capture_output=True, text=True, check=True, timeout=5,
                env={key: value for key, value in os.environ.items()
                     if key != "DEVELOPER_DIR"},
            )
            selected = result.stdout.strip()
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
    if not selected:
        return None
    candidate = Path(selected)
    if candidate.suffix == ".app":
        candidate = candidate / "Contents" / "Developer"
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if _trusted_macos_xcode_developer_dir(resolved) and resolved.is_dir() else None


def prepare_job(
    specification: dict, argv: list[str], cwd: str, environment: dict[str, str],
    home: Path,
) -> PreparedJob:
    if not isinstance(specification, dict) or set(specification) - {
        "type", "root", "writable", "network_mode", "allowed_domains",
        "allowed_paths", "hidden_paths", "pattern_rules",
    }:
        raise ValueError("unknown sandbox environment options")
    kind = specification.get("type")
    if not isinstance(kind, str) or kind not in TYPES:
        raise ValueError("unsupported sandbox type")
    if kind == "bubblewrap" and platform.system() != "Linux":
        raise ValueError("bubblewrap sandbox requires Linux")
    if kind == "seatbelt" and platform.system() != "Darwin":
        raise ValueError("Seatbelt sandbox requires macOS")
    root = _real_dir(specification.get("root"))
    work = Path(cwd).resolve(strict=True)
    if not _contains(root, work):
        raise ValueError("sandbox cwd must be inside sandbox root")
    # Never expose the Manager's state database and spool in the sandbox.
    state_root = home.resolve()
    # An exported root may CONTAIN the Manager's state: mask that private
    # subtree rather than rejecting an otherwise legitimate workspace.
    # Only a root INSIDE private Manager state is fundamentally unsafe.
    if _contains(state_root, root):
        raise ValueError("sandbox workspace is inside Manager state")
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
    patterns = specification.get("pattern_rules", [])
    if (not isinstance(extras, list) or len(extras) > MAX_PATHS
            or not isinstance(hidden, list) or len(hidden) > MAX_PATHS
            or not isinstance(patterns, list) or len(patterns) > MAX_PATHS):
        raise ValueError("invalid sandbox path grants")
    from openkapsel.auth.path_access import _rule_parts, existing_pattern_masks
    pattern_grants = []
    for item in patterns:
        if (not isinstance(item, dict) or set(item) != {"path", "access"}
                or item["access"] not in {"rw", "ro", "r", "protect", "deny"}):
            raise ValueError("invalid name-pattern sandbox rule")
        suffix, _directory, _name = _rule_parts(item["path"])
        if not suffix:
            raise ValueError("pattern rules must start with */")
        pattern_grants.append(PathGrant(
            item["path"], access="ro" if item["access"] == "r" else item["access"]))
    grants: list[PathGrant] = []
    for item in extras:
        if not isinstance(item, dict) or set(item) != {"path", "access"}:
            raise ValueError("allowed_paths entries require path and access")
        access = item["access"]
        if access == "r":
            access = "ro"
        if access not in {"rw", "ro", "protect", "deny"}:
            raise ValueError("allowed_paths entries require rw, ro, protect or deny access")
        # Only concrete mount paths belong in allowed_paths. Prefix-ignored
        # rules were checked above and will expand from the *actual* root.
        if access in {"protect", "deny"}:
            value = Path(item["path"].rstrip("/"))
            if not value.is_absolute():
                raise ValueError("deny path must be absolute")
            directory = value.resolve(strict=True)
            if not (directory.is_file() or directory.is_dir()):
                raise ValueError("deny sandbox path must exist")
        else:
            literal = Path(item["path"].rstrip("/"))
            if (not item["path"].endswith("/") and literal.is_file()):
                directory = literal.resolve(strict=True)
            else:
                directory = _real_dir(item["path"].rstrip("/"))
        # Parent grants are valid for Shell, provided the backend reapplies
        # the exported root's stricter access after the broader grant.
        # Parent grants are fine: the Manager state subtree is excluded below.
        # Do not grant a directory that lies inside Manager private state.
        if _contains(state_root, directory):
            raise ValueError("sandbox grant is inside Manager state")
        grants.append(PathGrant(str(directory), access=access))
    excluded: list[Path] = []
    # Filesystem sandbox backends require concrete mount paths. Discover
    # current named sensitive paths at launch, not merely at Client startup.
    # New paths created AFTER launch still require process isolation.
    try:
        if kind == "bubblewrap":
            roots = [root, *(
                Path(grant.path) for grant in grants
                if grant.access in {"ro", "rw"} and Path(grant.path).is_dir())]
            named_masks = tuple(
                item for base in dict.fromkeys(roots)
                for item in existing_pattern_masks(
                    base, writable, (*grants, *pattern_grants)))
        else:
            # Seatbelt has dynamic regex filters; no filesystem walk needed.
            named_masks = ()
    except (OSError, ValueError) as exc:
        raise ValueError("cannot apply named sandbox path protections") from exc
    for item in named_masks:
        if item.access == "deny":
            excluded.append(Path(item.path))
        else:
            grants.append(item)
    for item in hidden:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise ValueError("invalid hidden path")
        value = Path(item)
        if not value.is_absolute():
            raise ValueError("hidden path must be absolute")
        path = value.resolve(strict=True)
        if path == root:
            raise ValueError("cannot hide the sandbox root")
        if not (_contains(root, path) or any(
                _contains(Path(grant.path), path) for grant in grants)):
            raise ValueError("hidden path must be within an allowed directory")
        excluded.append(path)
    # A broad workspace or extra Shell grant may include the Manager's
    # private state. Hide it at the sandbox boundary instead of failing the
    # entire grant (deny has precedence over every RO/RW bind).
    if any(_contains(base, state_root) for base in
           (root, *(Path(grant.path) for grant in grants))):
        excluded.append(state_root)
    # More-specific rules override parent rules, including ro and deny.
    # The Manager's private state, IPC socket, and hidden configuration
    # remain unconditional exclusions applied after all configured grants.
    # The Manager's AF_UNIX socket is in the OS temp dir, not under the
    # private state directory. Mask it even if a broad sandbox grant could
    # otherwise include that directory. The Manager additionally authenticates
    # every connection independently of filesystem visibility.
    ipc_parent = None
    if os.name != "nt":
        from openkapsel.job_manager import endpoint
        address, family = endpoint(state_root)
        if family == "AF_UNIX":
            ipc_parent = Path(address).parent.resolve()
            if any(_contains(base, ipc_parent)
                   for base in (root, *(Path(item.path) for item in grants))):
                excluded.append(ipc_parent)
    # Merge explicit and automatic exclusions into non-overlapping mounts.
    # An explicit deny of Manager state is valid, not a fatal overlap.
    reduced = []
    for path in sorted(set(excluded), key=lambda p: (len(p.parts), str(p))):
        if not any(parent == path or parent in path.parents for parent in reduced):
            reduced.append(path)
    excluded = reduced
    # Drop grants inside system-protected hidden locations, not inside
    # ordinary configured deny ancestors: a child may override those.
    grants = [grant for grant in grants if not any(
        _contains(path, Path(grant.path)) for path in excluded
    )]
    sandbox_home = home / "sandboxes"
    sandbox_home.mkdir(mode=0o700, exist_ok=True)
    job_dir = Path(tempfile.mkdtemp(prefix="job-", dir=sandbox_home)).resolve()
    controller: object | None = None
    try:
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
            if launch.stdin_data is not None:
                fd = tempfile.TemporaryFile()
                try:
                    fd.write(launch.stdin_data)
                    fd.seek(0)
                    # RootlessKit reserves FD 3 for its control channel. As in
                    # Server Shell's sandbox launcher, duplicate a resolver
                    # tempfile allocated at FD 3 before entering RootlessKit.
                    descriptor, duplicate = _injected_file_descriptor(fd)
                    if duplicate is not None:
                        try:
                            replacement = os.fdopen(duplicate, "rb")
                        except BaseException:
                            os.close(duplicate)
                            raise
                        fd.close()
                        fd = replacement
                    result.resolver = fd
                    result.argv = [
                        str(descriptor) if arg == RESOLVER_FD_MARKER else arg
                        for arg in result.argv
                    ]
                except BaseException:
                    fd.close()
                    raise
            return result

        executable = shutil.which("sandbox-exec")
        if not executable or not Path(executable).is_file():
            raise RuntimeError("sandbox-exec is not available on this macOS host")
        profile = [
            "(version 1)", "(deny default)",
            "(allow process*)", "(allow sysctl-read)",
            "(allow file-read-metadata)", '(allow file-read-data (literal "/"))',
            # Shell tools routinely redirect diagnostics to /dev/null, even
            # with a read-only workspace. This grants only the null device,
            # not file writes elsewhere under /dev.
            '(allow file-write* (literal "/dev/null"))',
        ]
        # Hosted CI and source checkouts can use Python outside Apple's
        # /usr and Homebrew roots (e.g. /Users/runner/hostedtoolcache/Python).
        # Grant only the interpreter's installed runtime prefix, never HOME.
        read_roots = [Path(path) for path in MACOS_SYSTEM_READ]
        for interpreter_prefix in (sys.base_prefix, sys.exec_prefix):
            prefix = Path(interpreter_prefix).resolve()
            if prefix != Path(prefix.anchor):
                read_roots.append(prefix)
        for system_path in dict.fromkeys(read_roots):
            if system_path.exists():
                profile.append(f"(allow file-read* (subpath {_sb_quote(system_path.resolve())}))")
        developer = _macos_xcode_developer_dir(environment)
        if developer is not None:
            # The resolver checked the exact Xcode.app/Contents/Developer
            # layout. xcrun requires Developer/usr/lib, but the delegated
            # xcodebuild process loads libraries from *sibling* trees,
            # notably Contents/SharedFrameworks. Restrict this read-only
            # exception to the selected Xcode.app, never /Applications.
            xcode_app = developer.parent.parent
            profile.append(f"(allow file-read* (subpath {_sb_quote(xcode_app)}))")
        # 1. Baseline grants: parents first so a narrower concrete rule wins.
        # 2. Dynamic name protections (including paths created after launch).
        # 3. Deliberate concrete exceptions *inside* protected names.
        # 4. Absolute denies and hard-private state masks, always last.
        entries = [(root, "rw" if writable else "ro"), *(
            (Path(grant.path), grant.access) for grant in grants
            if grant.access != "deny")]
        strength = {"rw": 0, "ro": 1, "protect": 2, "deny": 3}

        def append_concrete(directory: Path, access: str) -> None:
            scope = "subpath" if directory.is_dir() else "literal"
            match = f"({scope} {_sb_quote(directory)})"
            if access in {"rw", "ro"}:
                profile.append(f"(allow file-read* {match})")
            if access == "rw":
                profile.append(f"(allow file-write* {match})")
            elif access in {"ro", "protect", "deny"}:
                profile.append(f"(deny file-write* {match})")
            if access in {"protect", "deny"}:
                profile.append(f"(deny file-read* {match})")

        for directory, access in sorted(
                entries, key=lambda entry: (len(entry[0].parts),
                                            strength[entry[1]])):
            append_concrete(directory, access)
        profile.extend(_seatbelt_named_rules(root, grants, pattern_grants))
        for directory, access in sorted(
                entries[1:], key=lambda entry: (len(entry[0].parts),
                                                strength[entry[1]])):
            if _seatbelt_inside_named_protection(directory, pattern_grants):
                access = _seatbelt_same_anchor_access(
                    directory, access, pattern_grants)
                append_concrete(directory, access)
                if directory.is_dir() and access in {"rw", "ro"}:
                    # Reopening .git/public must not also reopen a NEW
                    # nested .git, .ssh or .openkapsel under that exception.
                    # The next (deeper) concrete exception can still win.
                    profile.extend(_seatbelt_named_rules(
                        directory, [], pattern_grants))
        # Private .openkapsel-* staging names are always hard-denied, even
        # inside deliberately reopened protected directories.
        scopes = [root, *(Path(g.path) for g in grants
                          if g.access in {"rw", "ro"} and Path(g.path).is_dir())]
        scopes = [path for path in dict.fromkeys(scopes)
                  if not any(path != parent and _contains(parent, path)
                             for parent in scopes)]
        private = "^(" + "|".join(re.escape(str(path)) for path in scopes)
        private += r")/(.*/)?[.]openkapsel-.*$"
        profile.append(f"(deny file-read* (regex {_sb_quote(private)}))")
        profile.append(f"(deny file-write* (regex {_sb_quote(private)}))")
        # Explicit literal deny cannot be reopened by narrower grants.
        for grant in grants:
            if grant.access == "deny":
                append_concrete(Path(grant.path), "deny")
        for directory in excluded:
            operation = "subpath" if directory.is_dir() else "literal"
            profile.append(f"(deny file-read* ({operation} {_sb_quote(directory)}))")
            profile.append(f"(deny file-write* ({operation} {_sb_quote(directory)}))")
        # Deny the entire Manager state even when an unrelated system-level
        # runtime-read grant reaches it. Seatbelt evaluates later matching
        # rules last, so the one per-job scratch directory may be re-allowed
        # without exposing the manager database, spool or IPC secret.
        if state_root not in excluded:
            profile.append(f"(deny file-read* (subpath {_sb_quote(state_root)}))")
            profile.append(f"(deny file-write* (subpath {_sb_quote(state_root)}))")
        profile.append(f"(allow file-read* (subpath {_sb_quote(job_dir)}))")
        profile.append(f"(allow file-write* (subpath {_sb_quote(job_dir)}))")
        # Deny IPC key explicitly as well as the parent state subtree.
        credential = state_root / "ipc.key"
        profile.append(f"(deny file-read* (literal {_sb_quote(credential)}))")
        profile.append(f"(deny file-write* (literal {_sb_quote(credential)}))")
        if ipc_parent is not None:
            profile.append(f"(deny file-read* (subpath {_sb_quote(ipc_parent)}))")
            profile.append(f"(deny file-write* (subpath {_sb_quote(ipc_parent)}))")
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
        # In full mode, (allow network*) includes AF_UNIX and would allow
        # connecting to Manager's same-UID IPC socket despite file-read denies.
        # The command-facing sandbox has no reason to connect to ANY host
        # AF_UNIX socket (the domain proxy uses loopback TCP on macOS).
        profile.append("(deny network-outbound (remote unix-socket))")
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

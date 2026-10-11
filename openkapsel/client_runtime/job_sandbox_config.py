"""Client-owned configuration for Job Manager sandboxed Mapping Shell.

The Client chooses the native sandbox and sends a fully normalized specification
per invocation. A Manager never guesses an isolation policy.
"""
from __future__ import annotations

import platform
from pathlib import Path

from openkapsel.execution.network_proxy import normalize_domain_rules


def make_job_sandbox(config, files, *, protected_paths=()):
    """Return a Manager sandbox specification, or None for legacy execution."""
    if "job_sandbox" not in config:
        return None
    options = config["job_sandbox"]
    if not isinstance(options, dict) or set(options) - {"paths", "network"}:
        raise ValueError("job_sandbox must be an object with only paths and network")
    system = platform.system()
    if system == "Linux":
        kind = "bubblewrap"
    elif system == "Darwin":
        kind = "seatbelt"
    elif system == "Windows":
        kind = "srt_windows"
    else:
        raise ValueError("job_sandbox requires Linux, macOS or Windows")
    # "root" is the Client's exported workspace; no redundant, mutable config.
    root = files.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("job_sandbox root must be an existing directory")
    paths = options.get("paths", [])
    if not isinstance(paths, list) or len(paths) > 32:
        raise ValueError("job_sandbox.paths must be a list of up to 32 path rules")
    protected = [Path(value).expanduser().resolve(strict=False)
                 for value in protected_paths]
    grants = []
    denied = []
    used = {}
    raw_permits = []
    for item in paths:
        if not isinstance(item, dict) or set(item) != {"path", "access"}:
            raise ValueError("job_sandbox.paths entries require path and access")
        access = item["access"]
        if access == "r":
            access = "ro"
        if access not in {"rw", "ro", "deny"}:
            raise ValueError("job_sandbox.paths access must be rw, ro/r or deny")
        value = item["path"]
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("job_sandbox path must be an absolute path")
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError("job_sandbox path must be absolute")
        resolved = path.resolve(strict=True)
        if resolved == Path(resolved.anchor):
            raise ValueError("job_sandbox cannot authorize filesystem root")
        if access != "deny" and not resolved.is_dir():
            raise ValueError("rw/ro sandbox paths must be directories")
        if access == "deny" and not (resolved.is_dir() or resolved.is_file()):
            raise ValueError("deny sandbox path must be a file or directory")
        if access in {"rw", "ro"}:
            raw_permits.append(resolved)
        if resolved in used:
            priority = {"rw": 0, "ro": 1, "deny": 2}
            access = max((access, used[resolved]), key=lambda x: priority[x])
        used[resolved] = access
    # An explicit permit cannot grant a protected secret path itself. A
    # writable parent is fine because its protected contents are auto-denied.
    for resolved, access in used.items():
        if access == "deny":
            denied.append(resolved)
            continue
        if resolved == root or resolved in root.parents:
            raise ValueError("job_sandbox additional permits must not enclose root")
        for secret in protected:
            if secret == resolved or secret in resolved.parents:
                raise ValueError("job_sandbox path would expose protected Client configuration")
        grants.append({"path": str(resolved), "access": access})
    permitted = [root, *(Path(g["path"]) for g in grants)]
    all_denied = tuple(denied)
    for denied_path in all_denied:
        if denied_path == root or denied_path in root.parents:
            raise ValueError("cannot deny the sandbox root or its ancestors")
        if any(denied_path == base or base in denied_path.parents for base in permitted):
            continue
        # Deny the very same path as an earlier rw/ro entry, or deny
        # an ancestor of an extra grant: the now-shadowed permit need not
        # be mounted at all, so no filesystem mask is needed.
        if any(denied_path == base or denied_path in base.parents for base in raw_permits):
            denied.remove(denied_path)
            continue
        raise ValueError("deny path must be inside root or another permitted directory")
    grants = [grant for grant in grants if not any(
        denied_path == Path(grant["path"]) or
        denied_path in Path(grant["path"]).parents for denied_path in all_denied
    )]
    permitted = [root, *(Path(g["path"]) for g in grants)]
    # Automatic deny applies to the workspace metadata and direct .openkapsel
    # subdirectory of each extra grant; also hide any Client config under a
    # permitted parent. Deny is never canceled by a more specific permit.
    for base in permitted:
        internal = base / ".openkapsel"
        if internal.exists():
            denied.append(internal.resolve(strict=True))
    for secret in protected:
        if secret.exists() and any(secret == base or base in secret.parents for base in permitted):
            denied.append(secret.resolve(strict=True))
    network = options.get("network", {"mode": "none"})
    if (not isinstance(network, dict) or set(network) - {"mode", "domains"}):
        raise ValueError("job_sandbox.network must be an object with mode and domains")
    mode = network.get("mode", "none")
    if not isinstance(mode, str) or mode not in {"none", "full", "domain_allowlist"}:
        raise ValueError("job_sandbox.network.mode must be none, full or domain_allowlist")
    if kind == "srt_windows" and mode == "full":
        raise ValueError(
            "Windows SRT does not support job_sandbox.network.mode=full; "
            "use none or domain_allowlist"
        )
    domains = network.get("domains", [])
    if not isinstance(domains, list) or len(domains) > 128 or not all(
        isinstance(item, str) for item in domains
    ):
        raise ValueError("job_sandbox.network.domains must be a list of domain rules")
    if mode == "domain_allowlist":
        domains = list(normalize_domain_rules(domains))
        if not domains:
            raise ValueError("job_sandbox.domain_allowlist requires domains")
    elif domains:
        raise ValueError("job_sandbox.network.domains requires domain_allowlist mode")
    reduced = []
    for path in sorted(set(denied), key=lambda p: (len(p.parts), str(p))):
        if not any(parent == path or parent in path.parents for parent in reduced):
            reduced.append(path)
    hidden = [str(path) for path in reduced]
    if len(hidden) > 32:
        raise ValueError("too many sandbox hidden paths (max 32)")
    return {
        "type": kind,
        "root": str(root),
        "writable": bool(files.writable),
        "allowed_paths": grants,
        "hidden_paths": hidden,
        "network_mode": mode,
        "allowed_domains": domains,
    }

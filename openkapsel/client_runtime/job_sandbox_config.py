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
    else:
        raise ValueError("job_sandbox is supported only on Linux and macOS")
    # "root" is the Client's exported workspace; no redundant, mutable config.
    root = files.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("job_sandbox root must be an existing directory")
    paths = options.get("paths", [])
    if not isinstance(paths, list) or len(paths) > 32:
        raise ValueError("job_sandbox.paths must be a list of up to 32 directories")
    protected = [Path(value).expanduser().resolve(strict=False)
                 for value in protected_paths]
    grants = []
    used = set()
    for item in paths:
        if (not isinstance(item, dict) or set(item) != {"path", "read_only"}
                or type(item["read_only"]) is not bool):
            raise ValueError("job_sandbox.paths entries require path and boolean read_only")
        value = item["path"]
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("job_sandbox path must be an absolute directory")
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError("job_sandbox path must be absolute")
        resolved = path.resolve(strict=True)
        if not resolved.is_dir() or resolved == Path("/"):
            raise ValueError("job_sandbox path must be a non-root directory")
        if resolved == root or resolved in root.parents:
            raise ValueError("job_sandbox path must not enclose the workspace root")
        internal = (root / ".openkapsel").resolve(strict=False)
        if resolved == internal or resolved in internal.parents or internal in resolved.parents:
            raise ValueError("job_sandbox path overlaps protected workspace metadata")
        if any(secret == resolved or resolved in secret.parents
               for secret in protected):
            raise ValueError("job_sandbox path would expose protected Client configuration")
        if resolved in used:
            raise ValueError("duplicate job_sandbox path")
        if any(resolved in existing.parents or existing in resolved.parents for existing in used):
            raise ValueError("overlapping job_sandbox.paths grants are ambiguous")
        used.add(resolved)
        grants.append({"path": str(resolved), "read_only": item["read_only"]})
    network = options.get("network", {"mode": "none"})
    if (not isinstance(network, dict) or set(network) - {"mode", "domains"}):
        raise ValueError("job_sandbox.network must be an object with mode and domains")
    mode = network.get("mode", "none")
    if not isinstance(mode, str) or mode not in {"none", "full", "domain_allowlist"}:
        raise ValueError("job_sandbox.network.mode must be none, full or domain_allowlist")
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
    hidden = []
    # Keep the Client's internal metadata out of Shell. If this directory
    # does not exist, the sandbox already cannot reach it outside the root.
    for protected in [*protected_paths, root / ".openkapsel"]:
        path = Path(protected).expanduser().resolve(strict=False)
        if path != root and root in path.parents and path.exists():
            hidden.append(str(path))
    return {
        "type": kind,
        "root": str(root),
        "writable": bool(files.writable),
        "allowed_paths": grants,
        "hidden_paths": sorted(set(hidden)),
        "network_mode": mode,
        "allowed_domains": domains,
    }

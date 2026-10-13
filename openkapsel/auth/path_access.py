"""Effective path policy for Server Token Shell and File APIs.

Rules compose by strict priority: deny > ro > rw, regardless of depth or
configuration ordering. The workspace's default access is implicit.
"""
from __future__ import annotations
from pathlib import Path


def effective_path_access(path: Path, root: Path, writable: bool, grants) -> str | None:
    # macOS may expose the same path through /tmp and /private/tmp;
    # compare canonical locations, including symlink targets.
    path = Path(path).resolve(strict=False)
    roots = [(Path(root), "rw" if writable else "ro")]
    roots.extend((Path(rule.path).resolve(strict=False), rule.access) for rule in grants)
    matches = [(base, mode) for base, mode in roots
               if path == base or base in path.parents]
    permitted = [base for base, mode in matches if mode != "deny"]
    if not permitted:
        return None
    # Paths named .openkapsel are not exported even under extra grants.
    if any(".openkapsel" in path.relative_to(base).parts for base in permitted):
        return "deny"
    modes = {mode for _, mode in matches}
    if "deny" in modes:
        return "deny"
    if "ro" in modes:
        return "ro"
    return "rw"

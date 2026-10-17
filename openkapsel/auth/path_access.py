"""Effective path policy for Server Token Shell and File APIs.

Rules compose by strict priority: deny > ro > rw, regardless of depth or
configuration ordering. The workspace's default access is implicit.
"""
from __future__ import annotations
from pathlib import Path


def effective_path_access(path: Path, root: Path, writable: bool, grants,
                          *, resolve_symlinks: bool = True) -> str | None:
    # Server paths resolve on this host; Mapping external paths have already
    # been resolved on the CLIENT and must not be resolved again on Server.
    normalize = (lambda raw: Path(raw).resolve(strict=False)) if resolve_symlinks else Path
    path = normalize(path)
    roots = [(Path(root), "rw" if writable else "ro")]
    roots.extend((normalize(rule.path), rule.access) for rule in grants)
    matches = [(base, mode) for base, mode in roots
               if path == base or base in path.parents]
    # A deny-only match outside the export root must still be a deny. This
    # matters for aliases pointing into an approved canonical scope: the
    # lexical spelling may match only an explicit deny rule.
    modes = {mode for _, mode in matches}
    if "deny" in modes:
        return "deny"
    permitted = [base for base, mode in matches if mode != "deny"]
    if not permitted:
        return None
    # Paths named .openkapsel are not exported even under extra grants.
    if any(".openkapsel" in path.relative_to(base).parts for base in permitted):
        return "deny"
    if "ro" in modes:
        return "ro"
    return "rw"

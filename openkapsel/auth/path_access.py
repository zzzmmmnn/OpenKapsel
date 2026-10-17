"""Effective path policy for Server Token Shell and File APIs.

The most-specific matching path wins, independent of configuration order.
An absolute deny wins at any ancestor depth. Other rules resolve by deepest
path, with protect > ro > rw at identical depth. System metadata stays denied.
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
    if not matches:
        return None
    # Metadata hiding is a system boundary, not a configured path rule.
    if any(part == ".openkapsel" or part.startswith(".openkapsel-")
           for part in path.parts):
        return "deny"
    # Absolute deny cannot be escaped through child grants or Approval.
    if any(mode == "deny" for _, mode in matches):
        return "deny"
    deepest = max(len(base.parts) for base, _ in matches)
    modes = {mode for base, mode in matches if len(base.parts) == deepest}
    if "protect" in modes:
        return "protect"
    if "ro" in modes:
        return "ro"
    return "rw"

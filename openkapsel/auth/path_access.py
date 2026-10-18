"""Effective path policy for Server Token Shell and File APIs.

The most-specific matching path wins, independent of configuration order.
An absolute deny wins at any ancestor depth. Other rules resolve by deepest
path, with protect > ro > rw at identical depth. System metadata stays denied.
"""
from __future__ import annotations
from pathlib import Path
import re


def is_private_name(name: str) -> bool:
    """Reserved metadata names, regardless of host filesystem case rules."""
    folded = name.casefold()
    return folded == ".openkapsel" or folded.startswith(".openkapsel-")


def has_private_component(path) -> bool:
    """Check lexical path components before and after filesystem resolution."""
    return any(is_private_name(part) for part in Path(path).parts)


_STAGING_COMPONENT = re.compile(
    r"\.openkapsel-(?:share-[0-9a-f]{24}|transfer-[A-Za-z0-9_-]{24})\Z"
)


def is_internal_transfer_stage(path: Path, root: Path) -> bool:
    """Recognize only exact Server-owned staging spellings, never metadata aliases.

    This exception is for low-level Mapping transport only. Public File APIs,
    approvals, listings, and searches must still reject all reserved names.
    """
    root, path = Path(root), Path(path)
    if has_private_component(root):
        return False
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    private = [part for part in relative.parts if is_private_name(part)]
    return len(private) == 1 and _STAGING_COMPONENT.fullmatch(private[0]) is not None


def effective_path_access(path: Path, root: Path, writable: bool, grants,
                          *, resolve_symlinks: bool = True,
                          internal_transfer: bool = False) -> str | None:
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
    if has_private_component(path) and not (
            internal_transfer and is_internal_transfer_stage(path, root)):
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

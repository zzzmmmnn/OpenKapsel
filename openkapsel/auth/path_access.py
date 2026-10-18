"""Effective path policy for Server Token Shell and File APIs.

The most-specific matching path wins, independent of configuration order.
An absolute deny wins at any ancestor depth. Other rules resolve by deepest
path, with protect > ro > rw at identical depth. System metadata stays denied.
"""
from __future__ import annotations
from pathlib import Path
import os
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


def _rule_parts(raw: str) -> tuple[bool, bool, str]:
    """Return (any-prefix, directory, target); '*' has no glob semantics."""
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("invalid path rule")
    suffix = raw.startswith("*/")
    directory = raw.endswith("/")
    target = raw[2:] if suffix else raw
    if suffix:
        name = target[:-1] if directory else target
        if (not name or name in {".", ".."} or "/" in name or "\\" in name
                or "*" in name or "?" in name or "[" in name):
            raise ValueError("prefix-ignored rules match one literal name")
        return True, directory, name
    if "*" in target or "?" in target or "[" in target:
        raise ValueError("wildcards are permitted only as an initial */")
    body = (target.rstrip("/") or "/") if directory else target
    if not Path(body).is_absolute() or ".." in Path(body).parts:
        raise ValueError("path rules must use absolute paths")
    return False, directory, body


# These are FALLBACK rules. An administrator's rule with the exact same key
# replaces the fallback, including its deny mode. System credentials and
# transport secrets still have their independent, non-overridable boundaries.
DEFAULT_ACCESS_RULES: tuple[tuple[str, str], ...] = (
    ("*/.git/", "protect"),
    ("*/.git", "protect"),  # Git submodule/worktree metadata pointer file
    ("*/.config/", "protect"),
    ("*/.ssh/", "protect"),
    ("*/.openkapsel/", "deny"),
    ("*/.gitconfig", "protect"),
    ("*/.gitattributes", "protect"),
    ("*/.gitmodules", "protect"),
)


# System metadata spellings were historically reserved case-insensitively.
# Retain that property on case-insensitive host filesystems even when path
# presentation preserves caller-controlled letter case.
_FOLDED_PROTECTED_NAMES = frozenset({
    ".git", ".config", ".ssh", ".openkapsel", ".gitconfig",
    ".gitattributes", ".gitmodules",
})


def _literal_name_matches(name: str, configured: str) -> bool:
    return name == configured or (
        configured.casefold() in _FOLDED_PROTECTED_NAMES
        and name.casefold() == configured.casefold()
    )


def _matching_anchor(path: Path, raw: str) -> tuple[Path, bool] | None:
    suffix, directory, target = _rule_parts(raw)
    if suffix:
        # Match an entire path component, never a substring.
        matches = [ancestor for ancestor in (path, *path.parents)
                   if _literal_name_matches(ancestor.name, target)]
        if not matches:
            return None
        anchor = matches[0]
        if not directory and (anchor != path or anchor.is_dir()):
            return None
        return anchor, suffix
    anchor = Path(target)
    if path != anchor and (not directory or anchor not in path.parents):
        return None
    if not directory and anchor.is_dir():
        return None
    return anchor, suffix


def normalized_explicit_rule(item) -> str:
    """Preserve historical directory PathGrants without changing typed files."""
    raw = item.path
    if (not raw.endswith("/") and not raw.startswith("*/")
            and not getattr(item, "strict_file", False)
            and (getattr(item, "legacy_directory", False) or Path(raw).is_dir())):
        return raw + "/"
    return raw


def effective_path_access(path: Path, root: Path, writable: bool, grants,
                          *, resolve_symlinks: bool = True,
                          internal_transfer: bool = False) -> str | None:
    """Evaluate literal/suffix rules, with inherited scope and defaults.

    A literal and a suffix rule at the SAME matching directory compete by
    strictness for the directory AND all its descendants. A genuinely deeper
    matching rule overrides the ancestor, except for an explicit literal deny.
    Explicit rules replace default rules with the exact same spelling.
    """
    normalize = (lambda p: Path(p).resolve(strict=False)) if resolve_symlinks else (
        lambda p: Path(os.path.abspath(p)))
    path, root = normalize(path), normalize(root)
    # Legacy PathGrant instances denoted existing directories without a
    # terminal slash; preserve old tokens while new configuration requires
    # an explicit '/' to declare a directory.
    explicit = tuple((normalized_explicit_rule(item), item.access)
                     for item in grants)
    # A deliberate rule for the same concrete file/directory replaces an
    # implicit fallback; this is distinct from TWO explicit overlapping
    # rules, which compete by strictness over the entire matched subtree.
    matched_explicit = [(raw, mode, _matching_anchor(path, raw))
                        for raw, mode in explicit]
    matched_anchors = {anchor for raw, _mode, result in matched_explicit
                       if result is not None for anchor, _suffix in (result,)}
    rules = [(raw, mode, False) for raw, mode in DEFAULT_ACCESS_RULES
             if (result := _matching_anchor(path, raw)) is not None
             and result[0] not in matched_anchors]
    rules.extend((raw, mode, True) for raw, mode in explicit)

    # The workspace itself is the fallback; outside requires an explicit
    # literal grant. Suffix patterns by themselves do not open new roots.
    within = path == root or root in path.parents
    if not within and not any(
        not _rule_parts(raw)[0] and _matching_anchor(path, raw) is not None
        for raw, _mode in explicit
    ):
        return None
    if internal_transfer and is_internal_transfer_stage(path, root):
        return "rw" if writable else "ro"

    matches: list[tuple[int, bool, bool, str, Path]] = []
    for raw, access, configured in rules:
        match = _matching_anchor(path, raw)
        if match is None:
            continue
        anchor, suffix = match
        # A user-configured literal deny is absolute; default deny remains
        # replaceable, including by a more specific explicit rule.
        if configured and not suffix and access == "deny":
            return "deny"
        matches.append((len(anchor.parts), not suffix, configured,
                        access, anchor))
    if not matches:
        return ("rw" if writable else "ro") if within else None
    deepest = max(item[0] for item in matches)
    matches = [item for item in matches if item[0] == deepest]
    weight = {"rw": 0, "ro": 1, "protect": 2, "deny": 3}
    return max((item[3] for item in matches), key=weight.__getitem__)


def existing_pattern_masks(root: Path, writable: bool, rules,
                           *, limit: int = 8192):
    """Return static sandbox masks for currently existing named paths.

    Filesystem sandboxes consume concrete paths, not suffix patterns.
    This is an enforcement aid for EXISTING entries, not a guarantee
    against creating/renaming new matching paths after shell startup.
    """
    from openkapsel.auth.tokens import PathGrant
    root = Path(root)
    named = {target for pattern, _mode in DEFAULT_ACCESS_RULES
             if (parts := _rule_parts(pattern))[0]
             for target in (parts[2],)}
    named.update(_rule_parts(rule.path)[2] for rule in rules
                 if _rule_parts(rule.path)[0])
    masks = []
    for parent, directories, files in os.walk(root, followlinks=False):
        directory = Path(parent)
        # Do not follow symlinks; they must be evaluated at their lexical
        # spelling and via their canonical destination independently.
        for name in tuple(directories):
            path = directory / name
            if path.is_symlink():
                directories.remove(name)
                continue
            if not any(_literal_name_matches(name, item) for item in named):
                continue
            mode = effective_path_access(path, root, writable, rules,
                                         resolve_symlinks=False)
            if mode in {"protect", "deny", "ro"}:
                masks.append(PathGrant(str(path), access=mode))
                directories.remove(name)
        for name in files:
            if not any(_literal_name_matches(name, item) for item in named):
                continue
            path = directory / name
            if path.is_symlink():
                continue
            mode = effective_path_access(path, root, writable, rules,
                                         resolve_symlinks=False)
            if mode in {"protect", "deny", "ro"}:
                masks.append(PathGrant(str(path), access=mode))
        if len(masks) > limit:
            raise ValueError("too many hidden path rules for static sandbox masking")
    return tuple(masks)

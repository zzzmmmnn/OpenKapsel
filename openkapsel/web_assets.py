"""Bundled web UI assets."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib.resources import files


_BUILTIN_FAVICONS = frozenset({"favicon.svg", "favicon.ico"})


@lru_cache(maxsize=2)
def builtin_favicon(name: str) -> bytes:
    """Return a bundled OpenKapsel favicon asset."""
    if name not in _BUILTIN_FAVICONS:
        raise ValueError(f"unsupported favicon asset: {name}")
    return files("openkapsel").joinpath("static", name).read_bytes()


@lru_cache(maxsize=2)
def builtin_favicon_asset_etag(name: str) -> str:
    """Return a stable strong ETag for a bundled favicon asset."""
    return f'"{hashlib.sha256(builtin_favicon(name)).hexdigest()}"'


def builtin_favicon_svg() -> bytes:
    """Return the bundled OpenKapsel SVG favicon."""
    return builtin_favicon("favicon.svg")


def builtin_favicon_etag() -> str:
    """Return the stable ETag for the bundled SVG favicon."""
    return builtin_favicon_asset_etag("favicon.svg")

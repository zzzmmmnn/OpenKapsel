"""Bundled web UI assets."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def builtin_favicon_svg() -> bytes:
    """Return the bundled OpenKapsel favicon SVG."""
    return files("openkapsel").joinpath("static/favicon.svg").read_bytes()


@lru_cache(maxsize=1)
def builtin_favicon_etag() -> str:
    """Return a stable strong ETag for the bundled favicon."""
    return f'"{hashlib.sha256(builtin_favicon_svg()).hexdigest()}"'

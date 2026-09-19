"""URL-safe random identifiers with an ASCII-alphanumeric leading character."""

from __future__ import annotations

import secrets
import string


_LEADING_ALNUM = frozenset(string.ascii_letters + string.digits)


def token_urlsafe_alnum(nbytes: int) -> str:
    """Return a token_urlsafe value whose first character is ASCII alphanumeric."""
    if isinstance(nbytes, bool) or not isinstance(nbytes, int) or nbytes <= 0:
        raise ValueError("nbytes must be a positive integer")
    while True:
        value = secrets.token_urlsafe(nbytes)
        if value and value[0] in _LEADING_ALNUM:
            return value

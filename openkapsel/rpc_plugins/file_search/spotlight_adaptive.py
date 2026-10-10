"""Disjoint Spotlight metadata windows for bounded ordered file searches.

Each step widens coverage without rescanning earlier windows. A query may stop
after enough accessible/exactly matched candidates have been collected because
later windows cannot contain an item with a *better primary sort value*.
Equal timestamp/size ties are contained within the same window.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import datetime, timezone

_DAY = 86_400
_YEAR = 365 * _DAY
_GIB = 1024 ** 3
_SIZE_START = 200 * _GIB
_SIZE_ASC_START = 256
# The final open-ended window includes historical/future dates and very large
# files. Never silently stop when expanding windows finds too few matches.
_SIZE_MAX = (1 << 63) - 1


def _iso_utc(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _time_bound(operator: str, timestamp: int) -> str:
    return f"kMDItemFSContentChangeDate {operator} $time.iso({_iso_utc(timestamp)})"


def _size_bound(operator: str, size: int) -> str:
    return f"kMDItemFSSize {operator} {size}"


def metadata_windows(sort_by: str, order: str, *, now_seconds: int | None = None
                     ) -> Iterator[tuple[tuple[str, ...], bool]]:
    """Yield (AND predicates, exhaustive_last_window) in best-first order.

    'exhaustive_last_window' signals that the windows have covered the entire
    nonnegative size domain / all feasible UTC modification timestamps.
    """
    if sort_by == "modified":
        now = int(time.time()) if now_seconds is None else int(now_seconds)
        if order == "desc":
            span = _DAY
            lower = now - span
            yield (_time_bound(">=", lower),), False
            while lower > -_YEAR:
                earlier = now - span * 2
                if earlier <= -_YEAR:
                    yield (_time_bound("<", lower),), True
                    return
                yield (_time_bound(">=", earlier), _time_bound("<", lower)), False
                lower = earlier
                span *= 2
            yield (_time_bound("<", lower),), True
            return
        if order == "asc":
            span = _YEAR
            upper = span
            yield (_time_bound("<", upper),), False
            while upper <= now + _YEAR:
                next_upper = span * 2
                if next_upper > now + _YEAR:
                    yield (_time_bound(">=", upper),), True
                    return
                yield (_time_bound(">=", upper), _time_bound("<", next_upper)), False
                upper = next_upper
                span *= 2
            yield (_time_bound(">=", upper),), True
            return
    if sort_by == "size":
        if order == "desc":
            lower = _SIZE_START
            yield (_size_bound(">=", lower),), False
            while lower > 1:
                next_lower = max(1, lower // 2)
                yield (_size_bound(">=", next_lower), _size_bound("<", lower)), False
                lower = next_lower
            yield (_size_bound("<", 1),), True  # zero-byte files
            return
        if order == "asc":
            yield (_size_bound("==", 0),), False
            upper = _SIZE_ASC_START
            yield (_size_bound(">", 0), _size_bound("<=", upper)), False
            while upper < _SIZE_MAX:
                next_upper = min(_SIZE_MAX, upper * 2)
                yield (_size_bound(">", upper), _size_bound("<=", next_upper)), False
                upper = next_upper
            yield (_size_bound(">", upper),), True
            return
    raise ValueError("adaptive Spotlight windows require size or modified sorting")

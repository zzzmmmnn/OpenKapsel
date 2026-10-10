"""Shared bounded result ordering for native indexes and recursive/mapped searches."""
from __future__ import annotations

import heapq
from pathlib import Path

SORT_FIELDS = ("name", "path", "size", "modified")
SORT_ORDERS = ("asc", "desc")
FILE_TYPES = ("all", "file", "directory")


def sort_key(item: dict, field: str):
    path = item["path"]
    value = {
        "name": Path(path).name,
        "path": path,
        "size": item.get("size_bytes"),
        "modified": item.get("modified_utc_ns"),
    }[field]
    # Metadata is optional on a remote mount; keep unknown values last for
    # desc and first for asc, consistently with SQLite's NULL ordering.
    if field in {"size", "modified"}:
        return (value is not None, value if value is not None else 0, path)
    return (value, path)


class _Reverse:
    def __init__(self, value):
        self.value = value

    def __lt__(self, other):
        return self.value > other.value


class TopResults:
    """Bounded top N; examines all candidates before declaring their ranking."""

    def __init__(self, limit: int, field: str, order: str):
        self.limit = limit
        self.field = field
        self.order = order
        self.heap = []
        self.seen = 0

    def add(self, item: dict):
        self.seen += 1
        key = sort_key(item, self.field)
        # Worst-ranked candidate at the heap root.
        score = (_Reverse(key) if self.order == "asc" else key)
        entry = (score, self.seen, item)
        if len(self.heap) < self.limit:
            heapq.heappush(self.heap, entry)
        elif score > self.heap[0][0]:
            heapq.heapreplace(self.heap, entry)

    def results(self):
        return sorted((entry[2] for entry in self.heap),
                      key=lambda item: sort_key(item, self.field),
                      reverse=self.order == "desc")

    @property
    def truncated(self):
        return self.seen > self.limit


def stat_item(path: str, kind: str, details) -> dict:
    result = {"path": path, "type": kind,
              "size_bytes": details.st_size,
              "modified_utc_ns": details.st_mtime_ns}
    birth = getattr(details, "st_birthtime_ns", None)
    if birth is None:
        birth_seconds = getattr(details, "st_birthtime", None)
        birth = int(birth_seconds * 1_000_000_000) if birth_seconds is not None else None
    result["created_utc_ns"] = birth
    return result

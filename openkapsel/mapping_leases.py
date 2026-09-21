"""Idempotent native mount ownership, independent of provider connections."""

import threading


class MountLease:
    def __init__(self, manager, ids):
        self.manager = manager
        self.ids = tuple(ids)
        self._lock = threading.Lock()
        self._closed = False

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self.manager.release(self.ids)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

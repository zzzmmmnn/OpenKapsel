"""Windows pathname components prohibited in unprivileged Client file access.

These checks run before any Win32 path resolution or file operation.  The
caller must still enforce its export root, reparse-point and access-mode policy.
"""

from __future__ import annotations

import errno
import re
from collections.abc import Iterable


_DEVICE_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"})
_DEVICE_PORT = re.compile(r"(?:COM|LPT)[0-9\u00b9\u00b2\u00b3]\Z", re.IGNORECASE)
_INVALID = frozenset('<>:"/\\|?*')


def check_windows_filename_parts(parts: Iterable[str]) -> None:
    """Reject DOS devices, NTFS ADS, and ambiguous Win32 components.

    Device names are reserved even before an extension (NUL.txt), and Windows
    also recognizes the superscript digits ¹²³ for COM/LPT device names.
    This intentionally rejects a few exotic valid NTFS names: the approval-
    free file subset must not rely on device/stream normalization behavior.
    """
    for part in parts:
        if part == ".":
            continue
        if not part:
            raise OSError(errno.EACCES, "empty Windows filename component")
        if (
            part == ".."
            or part.endswith((" ", "."))
            or any(char in _INVALID or ord(char) < 32 for char in part)
        ):
            raise OSError(errno.EACCES, "invalid Windows filename")
        stem = part.split(".", 1)[0].rstrip(" ").upper()
        if stem in _DEVICE_NAMES or _DEVICE_PORT.fullmatch(stem):
            raise OSError(errno.EACCES, "reserved Windows device filename")

"""Atomic no-replacement rename for transfer publication."""

import ctypes
import errno
import os
import sys


def rename_exclusive(source, destination, source_fd, destination_fd):
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        function = getattr(libc, "renameat2", None)
        flag = 1
    elif sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 4
    else:
        function = None
    if function is None:
        raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), flag):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))

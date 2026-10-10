"""Native Windows Everything QUERY2 IPC without es.exe, ETP, or SDK DLLs."""

from __future__ import annotations

import fnmatch
import os
import struct
import threading
import time
from collections.abc import Iterator


WM_COPYDATA = 0x004A
COPYDATA_QUERY2W = 18
MATCH_CASE = 0x01
MATCH_PATH = 0x04
MATCH_REGEX = 0x08
REQUEST_FULL_PATH = 0x00000004
SORT_NAME_ASCENDING = 1
SORT_NAME_DESCENDING = 2
SORT_PATH_ASCENDING = 3
SORT_PATH_DESCENDING = 4
SORT_SIZE_ASCENDING = 5
SORT_SIZE_DESCENDING = 6
SORT_DATE_MODIFIED_ASCENDING = 13
SORT_DATE_MODIFIED_DESCENDING = 14
_SORT_TYPES = {
    ("name", "asc"): SORT_NAME_ASCENDING,
    ("name", "desc"): SORT_NAME_DESCENDING,
    ("path", "asc"): SORT_PATH_ASCENDING,
    ("path", "desc"): SORT_PATH_DESCENDING,
    ("size", "asc"): SORT_SIZE_ASCENDING,
    ("size", "desc"): SORT_SIZE_DESCENDING,
    ("modified", "asc"): SORT_DATE_MODIFIED_ASCENDING,
    ("modified", "desc"): SORT_DATE_MODIFIED_DESCENDING,
}
MAX_REPLY_BYTES = 8 * 1024 * 1024
_BASE_WINDOW_CLASS = "EVERYTHING_TASKBAR_NOTIFICATION"
_KNOWN_WINDOW_CLASSES = (
    _BASE_WINDOW_CLASS + "_(1.5a)",
    _BASE_WINDOW_CLASS + "_(1.5)",
    _BASE_WINDOW_CLASS + "_(1.4)",
    _BASE_WINDOW_CLASS,
)
_QUERY_LOCK = threading.Lock()
_REGEX_META = frozenset(r"\.^$|?*+()[]{}")


class EverythingIpcError(RuntimeError):
    pass


def _handle_value(value) -> int:
    if isinstance(value, int):
        return value
    raw = getattr(value, "value", None)
    return int(raw) if raw is not None else 0


def _escape_regex_literal(value: str) -> str:
    return "".join(("\\" + char) if char in _REGEX_META else char for char in value)


def build_scope_regex(scope: str, query: str, *, mode: str = "literal") -> str:
    """Native Everything regex for basename matching inside one directory."""
    import ntpath

    normalized = ntpath.normpath(scope)
    prefix = normalized.rstrip("\\/") + "\\"
    beginning = "^" + _escape_regex_literal(prefix) + r"(.*\\)?"
    if mode == "glob":
        # fnmatch generates PCRE-compatible (?s:...) and end anchor.
        # Safe extra candidates are rejected by the exact basename filter.
        return beginning + fnmatch.translate(query)
    return beginning + r"[^\\]*" + _escape_regex_literal(query) + r"[^\\]*$"


def build_query2(
    reply_hwnd: int,
    search: str,
    *,
    search_flags: int,
    offset: int,
    max_results: int,
    request_flags: int = REQUEST_FULL_PATH,
    sort_type: int = SORT_NAME_ASCENDING,
    reply_message: int = 0x4F4B0001,
) -> bytes:
    encoded = search.encode("utf-16-le") + b"\x00\x00"
    return struct.pack(
        "<IIIIIII",
        reply_hwnd & 0xFFFFFFFF,
        reply_message & 0xFFFFFFFF,
        search_flags & 0xFFFFFFFF,
        offset & 0xFFFFFFFF,
        max_results & 0xFFFFFFFF,
        request_flags & 0xFFFFFFFF,
        sort_type & 0xFFFFFFFF,
    ) + encoded


def _read_wstring(data: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset + 4 > len(data):
        raise EverythingIpcError("Everything returned an invalid string offset")
    length = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    end = start + length * 2
    if end + 2 > len(data):
        raise EverythingIpcError("Everything returned a truncated string")
    if data[end : end + 2] != b"\x00\x00":
        raise EverythingIpcError("Everything returned an unterminated string")
    try:
        value = data[start:end].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise EverythingIpcError("Everything returned invalid UTF-16") from exc
    return value, end + 2


def parse_list2(data: bytes) -> tuple[list[str], int]:
    """Parse a QUERY2 response containing FULL_PATH_AND_FILE_NAME."""
    if len(data) < 20:
        raise EverythingIpcError("Everything returned a truncated result header")
    total, count, _offset, request_flags, _sort_type = struct.unpack_from("<IIIII", data, 0)
    if count > 100_000 or 20 + count * 8 > len(data):
        raise EverythingIpcError("Everything returned an invalid result count")
    if not request_flags & REQUEST_FULL_PATH:
        raise EverythingIpcError("Everything omitted the requested full path field")

    results: list[str] = []
    for index in range(count):
        _item_flags, data_offset = struct.unpack_from("<II", data, 20 + index * 8)
        if data_offset >= len(data):
            raise EverythingIpcError("Everything returned an invalid item offset")
        position = data_offset
        full_path = None
        for flag in (0x00000001, 0x00000002, REQUEST_FULL_PATH):
            if request_flags & flag:
                value, position = _read_wstring(data, position)
                if flag == REQUEST_FULL_PATH:
                    full_path = value
        if full_path is None:
            raise EverythingIpcError("Everything result has no full path")
        results.append(full_path)
    return results, total


def _windows_libraries():
    if os.name != "nt":
        raise EverythingIpcError("Everything IPC is only available on Windows")
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return ctypes, wintypes, user32, kernel32


def _find_everything_window() -> tuple[int, str]:
    ctypes, wt, user32, _kernel32 = _windows_libraries()
    user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
    user32.FindWindowW.restype = wt.HWND
    for class_name in _KNOWN_WINDOW_CLASSES:
        hwnd = user32.FindWindowW(class_name, None)
        if hwnd:
            return _handle_value(hwnd), class_name

    user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    enum_proc_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    found: list[tuple[int, str]] = []

    @enum_proc_type
    def enum_proc(hwnd, _lparam):
        buffer = ctypes.create_unicode_buffer(512)
        if user32.GetClassNameW(hwnd, buffer, len(buffer)):
            class_name = buffer.value
            if class_name.startswith(_BASE_WINDOW_CLASS + "_("):
                found.append((_handle_value(hwnd), class_name))
                return False
        return True

    user32.EnumWindows.argtypes = [enum_proc_type, wt.LPARAM]
    user32.EnumWindows.restype = wt.BOOL
    user32.EnumWindows(enum_proc, 0)
    if found:
        return found[0]
    raise EverythingIpcError("Everything IPC window was not found")


def status() -> dict[str, object]:
    try:
        _hwnd, class_name = _find_everything_window()
    except EverythingIpcError:
        return {"running": False}
    instance = "default"
    if class_name != _BASE_WINDOW_CLASS and class_name.startswith(_BASE_WINDOW_CLASS + "_("):
        instance = class_name[len(_BASE_WINDOW_CLASS) + 2 : -1]
    return {"running": True, "instance": instance}


def _query_page(
    search: str,
    *,
    match_case: bool,
    offset: int,
    max_results: int,
    timeout_seconds: float,
    sort_type: int = SORT_NAME_ASCENDING,
) -> tuple[list[str], int]:
    ctypes, wt, user32, kernel32 = _windows_libraries()
    everything_hwnd, _class_name = _find_everything_window()

    wndproc_type = ctypes.WINFUNCTYPE(
        ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM
    )

    class CopyDataStruct(ctypes.Structure):
        _fields_ = [
            ("dwData", ctypes.c_size_t),
            ("cbData", wt.DWORD),
            ("lpData", ctypes.c_void_p),
        ]

    class WndClassW(ctypes.Structure):
        _fields_ = [
            ("style", wt.UINT),
            ("lpfnWndProc", wndproc_type),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wt.HINSTANCE),
            ("hIcon", wt.HICON),
            ("hCursor", wt.HANDLE),
            ("hbrBackground", wt.HANDLE),
            ("lpszMenuName", wt.LPCWSTR),
            ("lpszClassName", wt.LPCWSTR),
        ]

    class Msg(ctypes.Structure):
        _fields_ = [
            ("hwnd", wt.HWND),
            ("message", wt.UINT),
            ("wParam", wt.WPARAM),
            ("lParam", wt.LPARAM),
            ("time", wt.DWORD),
            ("pt", wt.POINT),
        ]

    user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.RegisterClassW.argtypes = [ctypes.POINTER(WndClassW)]
    user32.RegisterClassW.restype = wt.ATOM
    user32.UnregisterClassW.argtypes = [wt.LPCWSTR, wt.HINSTANCE]
    user32.UnregisterClassW.restype = wt.BOOL
    user32.CreateWindowExW.argtypes = [
        wt.DWORD,
        wt.LPCWSTR,
        wt.LPCWSTR,
        wt.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wt.HWND,
        wt.HANDLE,
        wt.HINSTANCE,
        wt.LPVOID,
    ]
    user32.CreateWindowExW.restype = wt.HWND
    user32.DestroyWindow.argtypes = [wt.HWND]
    user32.DestroyWindow.restype = wt.BOOL
    user32.PeekMessageW.argtypes = [
        ctypes.POINTER(Msg), wt.HWND, wt.UINT, wt.UINT, wt.UINT
    ]
    user32.PeekMessageW.restype = wt.BOOL
    user32.TranslateMessage.argtypes = [ctypes.POINTER(Msg)]
    user32.TranslateMessage.restype = wt.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(Msg)]
    user32.DispatchMessageW.restype = ctypes.c_ssize_t
    kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wt.HMODULE

    reply_tag = 0x4F4B0001
    state: dict[str, object] = {"received": False, "data": None, "error": None}

    @wndproc_type
    def wndproc(hwnd, message, wparam, lparam):
        if message == WM_COPYDATA:
            cds = ctypes.cast(lparam, ctypes.POINTER(CopyDataStruct)).contents
            if int(cds.dwData) == reply_tag:
                size = int(cds.cbData)
                if size > MAX_REPLY_BYTES:
                    state["error"] = "Everything reply exceeded the IPC size limit"
                elif size and cds.lpData:
                    state["data"] = ctypes.string_at(cds.lpData, size)
                else:
                    state["data"] = b""
                state["received"] = True
                return 1
        return user32.DefWindowProcW(hwnd, message, wparam, lparam)

    hinstance = kernel32.GetModuleHandleW(None)
    class_name = (
        f"OpenKapselEverythingReply_{os.getpid()}_"
        f"{threading.get_ident()}_{time.monotonic_ns()}"
    )
    window_class = WndClassW()
    window_class.lpfnWndProc = wndproc
    window_class.hInstance = hinstance
    window_class.lpszClassName = class_name
    atom = user32.RegisterClassW(ctypes.byref(window_class))
    if not atom:
        raise EverythingIpcError("could not register the Everything reply window")

    hwnd = None
    try:
        hwnd = user32.CreateWindowExW(
            0,
            class_name,
            None,
            0,
            0,
            0,
            0,
            0,
            ctypes.c_void_p(-3),
            None,
            hinstance,
            None,
        )
        if not hwnd:
            raise EverythingIpcError("could not create the Everything reply window")

        flags = MATCH_PATH | MATCH_REGEX
        if match_case:
            flags |= MATCH_CASE
        query = build_query2(
            _handle_value(hwnd),
            search,
            search_flags=flags,
            offset=offset,
            max_results=max_results,
            sort_type=sort_type,
            reply_message=reply_tag,
        )
        buffer = ctypes.create_string_buffer(query)
        copy_data = CopyDataStruct(
            COPYDATA_QUERY2W,
            len(query),
            ctypes.cast(buffer, ctypes.c_void_p),
        )

        user32.SendMessageTimeoutW.argtypes = [
            wt.HWND,
            wt.UINT,
            wt.WPARAM,
            wt.LPARAM,
            wt.UINT,
            wt.UINT,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
        send_result = ctypes.c_size_t()
        sent = user32.SendMessageTimeoutW(
            everything_hwnd,
            WM_COPYDATA,
            _handle_value(hwnd),
            ctypes.addressof(copy_data),
            0x0002,
            max(1, int(timeout_seconds * 1000)),
            ctypes.byref(send_result),
        )
        if not sent:
            raise EverythingIpcError("Everything did not accept the IPC query")

        message = Msg()
        deadline = time.monotonic() + timeout_seconds
        while not state["received"]:
            if time.monotonic() >= deadline:
                raise EverythingIpcError("timed out waiting for Everything IPC")
            if user32.PeekMessageW(ctypes.byref(message), hwnd, 0, 0, 0x0001):
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
            else:
                time.sleep(0.001)

        if state["error"]:
            raise EverythingIpcError(str(state["error"]))
        payload = state["data"]
        if not isinstance(payload, bytes):
            raise EverythingIpcError("Everything returned no IPC payload")
        return parse_list2(payload)
    finally:
        if hwnd:
            user32.DestroyWindow(hwnd)
        user32.UnregisterClassW(class_name, hinstance)


def query_paths(
    scope: str,
    query: str,
    *,
    case_sensitive: bool = False,
    timeout_seconds: float = 10.0,
    batch_size: int = 256,
    sort_by: str = "path",
    sort_order: str = "asc",
    mode: str = "literal",
) -> Iterator[str]:
    """Yield Everything-indexed paths in native sort order, fetched by pages."""
    search = build_scope_regex(scope, query, mode=mode)
    sort_type = _SORT_TYPES[(sort_by, sort_order)]
    with _QUERY_LOCK:
        offset = 0
        while True:
            page, total = _query_page(
                search,
                match_case=case_sensitive,
                offset=offset,
                max_results=batch_size,
                timeout_seconds=timeout_seconds,
                sort_type=sort_type,
            )
            if not page:
                break
            yield from page
            offset += len(page)
            if offset >= total:
                break

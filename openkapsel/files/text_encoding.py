"""Explicit, portable text codecs; no locale fallback or lossy conversion."""
import codecs
from openkapsel.errors import ApiError

ENCODINGS = ("utf-8", "utf-8-sig", "utf-16-le", "utf-16-be", "ascii",
             "iso8859-1", "cp1252", "gbk", "gb18030", "big5", "shift_jis")


def text_encoding(value="utf-8"):
    try:
        encoding = codecs.lookup(value).name if isinstance(value, str) and len(value) <= 64 and value.isascii() else None
    except (LookupError, ValueError):
        encoding = None
    if encoding not in ENCODINGS:
        raise ApiError(400, "invalid_encoding", "choose a supported explicit text encoding", {"supported": list(ENCODINGS)})
    return encoding


def encode_text(content, encoding):
    try:
        return content.encode(encoding, errors="strict")
    except UnicodeEncodeError:
        raise ApiError(400, "text_encode_error", "content cannot be represented in the requested encoding") from None


def decode_error(encoding):
    return ApiError(415, "not_utf8_text" if encoding == "utf-8" else "text_decode_error",
                    "file is not valid text in the requested encoding")

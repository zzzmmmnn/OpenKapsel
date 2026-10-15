"""Conservative Windows PowerShell *file-command* interpreter.

A recognized command is NEVER passed to a command shell.  Unknown syntax
requires normal Shell approval.  An identified path outside the export or an
access-mode violation is denied, not reinterpreted as an unrestricted command.
"""
from __future__ import annotations

import errno
import os
import re
from dataclasses import dataclass
from pathlib import Path


# Reject expansion, redirection, chaining, wildcards and any multiline script.
_UNSAFE = frozenset(";\u0026|$\x60><(){}[]*?%\r\n\x00")
_READ_COMMANDS = {
    "get-childitem": "list", "gci": "list", "ls": "list", "dir": "list",
    "get-item": "stat", "gi": "stat",
    "get-content": "read", "gc": "read", "cat": "read", "type": "read",
    "test-path": "exists",
    "get-location": "pwd", "pwd": "pwd",
}
_WRITE_COMMANDS = {
    "set-content": "write", "add-content": "append",
    "new-item": "mkdir", "remove-item": "remove",
}


@dataclass(frozen=True)
class SimplePowerShell:
    operation: str
    path: str = "."
    value: str = ""

    @property
    def write(self) -> bool:
        return self.operation in {"write", "append", "mkdir", "remove"}


def _words(command: str) -> list[str] | None:
    """Small literal-only subset of PowerShell lexical rules, no escapes."""
    if not isinstance(command, str) or not command or len(command) > 8192:
        return None
    if any(c in _UNSAFE for c in command):
        return None
    words = []
    position = 0
    while position < len(command):
        if command[position].isspace():
            position += 1
            continue
        quote = command[position] if command[position] in ("'", '"') else ""
        if quote:
            end = command.find(quote, position + 1)
            if end < 0 or end == position + 1:
                return None
            words.append(command[position + 1:end])
            position = end + 1
            if position < len(command) and not command[position].isspace():
                return None
        else:
            end = position
            while end < len(command) and not command[end].isspace():
                if command[end] in ("'", '"'):
                    return None
                end += 1
            words.append(command[position:end])
            position = end
        if len(words) > 8:
            return None
    return words or None


def parse_simple_powershell(command: str) -> SimplePowerShell | None:
    """Recognize only literal, single-operation PowerShell file commands."""
    words = _words(command)
    if words is None:
        return None
    # Optional explicit interpreter is accepted only with a literal -Command,
    # never -EncodedCommand, -File, profile scripts or interpreter options.
    if words[0].casefold() in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        prefix = [part.casefold() for part in words[1:-1]]
        if not prefix or prefix[-1] not in {"-command", "-c"}:
            return None
        if any(x not in {"-noprofile", "-noninteractive"} for x in prefix[:-1]):
            return None
        return parse_simple_powershell(words[-1])
    kind = _READ_COMMANDS.get(words[0].casefold()) or _WRITE_COMMANDS.get(words[0].casefold())
    if kind is None:
        return None
    args = words[1:]
    if kind == "pwd":
        return SimplePowerShell(kind) if not args else None
    if kind == "mkdir":
        # New-Item -ItemType Directory -LiteralPath foo
        if len(args) != 4 or [args[0].casefold(), args[1].casefold(),
                             args[2].casefold()] != ["-itemtype", "directory", "-literalpath"]:
            return None
        return SimplePowerShell(kind, args[3]) if args[3] else None
    if kind in {"write", "append"}:
        # Only literal content: no expressions, variables, stream pipeline,
        # encoded/scriptblock content or optional PowerShell behaviors.
        if len(args) != 4 or args[0].casefold() != "-literalpath" or args[2].casefold() != "-value":
            return None
        return SimplePowerShell(kind, args[1], args[3]) if args[1] else None
    if args and args[0].casefold() == "-literalpath":
        args = args[1:]
    if not args and kind == "list":
        return SimplePowerShell(kind)
    if len(args) != 1 or not args[0] or args[0].startswith("-"):
        return None
    return SimplePowerShell(kind, args[0])


def _checked_path(files, cwd: Path, value: str, *, write: bool,
                  rules=()) -> tuple[Path, str]:
    """Enforce the existing Client File RPC path guard and protected paths."""
    # Windows uses case-insensitive NTFS path semantics.  pathlib on the Client
    # is native WindowsPath; the lexically scoped relative path uses the same
    # WindowsPaths reparse-point guards as ordinary File RPC operations.
    candidate = Path(value)
    if ".." in candidate.parts or any(
        part.casefold() == ".openkapsel"
        or part.casefold().startswith(".openkapsel-")
        for part in candidate.parts
    ):
        raise OSError(errno.EACCES, "path is not permitted")
    target = candidate if candidate.is_absolute() else cwd / candidate
    try:
        relative = target.relative_to(files.root).as_posix()
    except ValueError:
        raise OSError(errno.EACCES, "path is outside exported files") from None
    resolved = files.path(relative)
    from openkapsel.auth.path_access import effective_path_access
    access = effective_path_access(resolved, files.root, files.writable,
                                   rules, resolve_symlinks=False)
    if access in {None, "deny"}:
        raise OSError(errno.EACCES, "path is denied")
    if write:
        if access != "rw":
            raise OSError(errno.EROFS, "path is read-only")
        files.ensure_mutable_path(resolved)
    # A Windows junction/shortcut must not be used to escape the exported
    # tree.  The actual I/O still runs under WindowsPaths.guard.
    if resolved.resolve(strict=False) != resolved:
        raise OSError(errno.EACCES, "reparse or symbolic-link path is not allowed")
    return resolved, relative


def execute_simple_powershell(files, cwd: Path, parsed: SimplePowerShell,
                              *, rules=()) -> str:
    """Execute the identified file operation without invoking PowerShell."""
    if parsed.operation == "pwd":
        return str(cwd) + "\n"
    path, relative = _checked_path(files, cwd, parsed.path, write=parsed.write,
                                   rules=rules)
    with files.lock:
        if parsed.operation == "list":
            result = files._dispatch("list", {"path": relative})
            return "".join(name + "\n" for name in result["names"])
        if parsed.operation == "stat":
            st = files._dispatch("stat", {"path": relative})
            return f"{path.name}\t{st['st_size']}\n"
        if parsed.operation == "exists":
            try:
                if hasattr(files.paths, "guard"):
                    with files.paths.guard(path, include_final=True):
                        return ("True" if path.exists() else "False") + "\n"
                descriptor = files.paths.open(path, os.O_RDONLY)
                os.close(descriptor)
                return "True\n"
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    return "False\n"
                raise
        if parsed.operation == "read":
            fd = files.paths.open(path, os.O_RDONLY)
            try:
                with os.fdopen(fd, "rb") as stream:
                    data = stream.read(1024 * 1024 + 1)
            except BaseException:
                # fdopen owns/closed fd when enter succeeded.
                raise
            if len(data) > 1024 * 1024:
                raise OSError(errno.EFBIG, "safe file read exceeds 1 MiB")
            return data.decode("utf-8", errors="replace")
        if parsed.operation in {"write", "append"}:
            # WindowsPaths.open uses CREATE_NEW for O_CREAT.  Open existing
            # files first; create exclusively only for a missing destination.
            flags = os.O_WRONLY
            if parsed.operation == "write":
                flags |= os.O_TRUNC
            try:
                fd = files.paths.open(path, flags)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
                fd = files.paths.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            if parsed.operation == "append":
                os.lseek(fd, 0, os.SEEK_END)
            with os.fdopen(fd, "ab" if parsed.operation == "append" else "wb") as stream:
                stream.write((parsed.value + "\n").encode("utf-8"))
            return ""
        if parsed.operation == "mkdir":
            files.paths.mkdir(path, parents=False, exist_ok=False)
            return str(path) + "\n"
        if parsed.operation == "remove":
            files._dispatch("unlink", {"path": relative})
            return ""
    raise OSError(errno.EACCES, "unsupported PowerShell operation")

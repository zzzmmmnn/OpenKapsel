"""Move a task into a prepared cgroup before executing untrusted code."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit("usage: cgroup_exec.py <cgroup.procs> <command> [args...]")
    procs_file = Path(sys.argv[1])
    command = sys.argv[2:]
    try:
        procs_file.write_text(f"{os.getpid()}\n", encoding="ascii")
    except OSError as exc:
        raise SystemExit(f"OpenKapsel could not enter the token cgroup: {exc}") from None
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()

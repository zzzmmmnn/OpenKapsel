"""Wait for the managed process group before releasing a native mapping lease."""

import os
import signal
import time
from pathlib import Path


def group_alive(process):
    if process.poll() is None:
        return True
    # Ignore orphan zombies: their file descriptors have already been closed.
    proc = Path("/proc")
    if proc.is_dir():
        for path in proc.iterdir():
            if not path.name.isdecimal():
                continue
            try:
                fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
                if int(fields[2]) == process.pid and fields[0] not in {"Z", "X"}:
                    return True
            except (OSError, ValueError, IndexError):
                continue
        return False
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False


def signal_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def wait_for_native_task(task, process):
    deadline = None if task.timeout_seconds is None else time.monotonic() + task.timeout_seconds
    kill_at = None
    while group_alive(process):
        now = time.monotonic()
        if deadline is not None and now >= deadline and not task.timed_out:
            task.timed_out = True
            task.stderr.append(b"\n[workspace] command timed out; terminating process group\n")
        if task.force_killed or (kill_at is not None and now >= kill_at):
            signal_group(process, signal.SIGKILL)
        elif (task.interrupted or task.timed_out) and kill_at is None:
            signal_group(process, signal.SIGTERM)
            kill_at = now + 2
        time.sleep(.05)
    return process.wait()


def release_native_task(task):
    if task.mount_lease is None:
        return True
    process = task.process
    if process is not None and group_alive(process):
        signal_group(process, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while group_alive(process) and time.monotonic() < deadline:
            time.sleep(.05)
        if group_alive(process):
            return False  # Retain the lease rather than unmount under a live process.
    task.mount_lease.close()
    return True

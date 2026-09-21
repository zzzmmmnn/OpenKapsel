"""Opt-in dense CSV benchmark, not part of unittest discovery.

Run: python tests/benchmark_tabular_csv.py --gib 2 10
Creates one temporary file, validates scans in fresh child processes, and deletes
it on normal completion or errors. Requires at least max(size)+2 GiB free disk.
No FUSE, database index, dataframe or remote provider is involved.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

WORKER = r'''
import json, resource, sys, time
from pathlib import Path
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.rpc_plugins.tabular import plugin
class Task:
    def check_cancelled(self): pass
    def write(self, value): pass
path = Path(sys.argv[1])
files = ClientFiles(path.parent, writable=False)
start = time.monotonic()
preview = plugin.dispatch(files, "inspect", {"path": path.name, "sample_rows": 2})
assert preview["status"] == 200, preview
preview_seconds = time.monotonic() - start
assert preview["body"]["total_rows"] is None
start = time.monotonic()
cursor, rows, segments = None, 0, 0
while True:
    args = {"path": path.name, "scan_bytes": 512 * 1024 * 1024,
            "time_budget_seconds": 120, "scan_rows": 1000000000}
    if cursor is not None: args["cursor"] = cursor
    reply = plugin.dispatch_task(files, "scan", args, Task())
    assert reply["status"] == 200, reply
    result = reply["body"]
    assert result["start_row_exclusive"] == rows, result
    assert result["matched_rows"] == result["rows_scanned"], result
    rows += result["rows_scanned"]
    segments += 1
    if result["complete"]: break
    cursor = result["next_cursor"]
    assert cursor and segments < 1000, result
elapsed = time.monotonic() - start
expected = (path.stat().st_size - len(b"id,text\n")) // 4096
assert rows == expected, (rows, expected)
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
peak_bytes = peak if sys.platform == "darwin" else peak * 1024
print(json.dumps({"file_bytes": path.stat().st_size, "records": rows, "segments": segments,
                  "inspect_seconds": round(preview_seconds, 6), "scan_seconds": round(elapsed, 3),
                  "scan_mib_per_second": round(path.stat().st_size / 1024**2 / elapsed, 2),
                  "peak_rss_mib": round(peak_bytes / 1024**2, 2)}))
files.close()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gib", type=int, nargs="+", default=[2, 10])
    args = parser.parse_args()
    sizes = sorted(set(args.gib))
    if not sizes or min(sizes) < 1 or max(sizes) > 32:
        parser.error("sizes must be integers between 1 and 32 GiB")
    if os.name == "nt":
        parser.error("this benchmark uses POSIX resource.getrusage; ordinary reader tests support Windows")
    if shutil.disk_usage(tempfile.gettempdir()).free < (max(sizes) + 2) * 1024**3:
        parser.error("not enough temporary disk space; leave at least 2 GiB free")
    project = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(project) + os.pathsep + os.environ.get("PYTHONPATH", ""), PYTHONDONTWRITEBYTECODE="1")
    row = b"1," + b"x" * 4093 + b"\n"
    assert len(row) == 4096
    block = row * 256
    with tempfile.TemporaryDirectory(prefix="openkapsel-csv-benchmark-") as directory:
        path = Path(directory) / "dense.csv"
        with path.open("wb") as stream:
            stream.write(b"id,text\n")
        written = 0
        for gib in sizes:
            required = gib * 1024**3
            started = time.monotonic()
            with path.open("ab") as stream:
                while written < required:
                    stream.write(block)
                    written += len(block)
                stream.flush()
                os.fsync(stream.fileno())
            print(json.dumps({"phase": "generated", "gib": gib, "seconds": round(time.monotonic() - started, 3)}), flush=True)
            run = subprocess.run([sys.executable, "-B", "-c", WORKER, str(path)], cwd=project,
                                 env=env, capture_output=True, text=True, timeout=480)
            if run.returncode:
                raise RuntimeError(run.stderr[-4000:] + run.stdout[-4000:])
            print(run.stdout.strip(), flush=True)
    print("Temporary dense CSV removed", flush=True)


if __name__ == "__main__":
    main()

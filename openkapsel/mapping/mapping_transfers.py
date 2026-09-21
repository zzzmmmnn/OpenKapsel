"""Bounded, resumable cross-root transfers over local I/O or direct client RPC."""

from __future__ import annotations

import hashlib
import errno
import json
import os
import stat
import threading
import time
from pathlib import Path

from openkapsel.random_ids import token_urlsafe_alnum
from openkapsel.mapping.mapping_io import WorkspaceFiles, stream_stat, sync_stream


class FileTransferManager:
    def __init__(self, directory, mappings, recycle_for, slots):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.mappings, self.recycle_for, self.slots = mappings, recycle_for, slots
        self.lock = threading.RLock()
        self.jobs = {}
        self.stopped = False

    def _save(self, job):
        payload = {key: value for key, value in job.items() if key not in {"cancel", "thread"}}
        path = self.directory / (job["id"] + ".json")
        temporary = path.with_suffix(".tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def get(self, tid, scope):
        if not isinstance(tid, str) or len(tid) != 24 or not all(c.isalnum() or c in "_-" for c in tid):
            raise KeyError("transfer not found")
        with self.lock:
            job = self.jobs.get(tid)
            if job is None:
                try:
                    job = json.loads((self.directory / (tid + ".json")).read_text())
                except (OSError, ValueError):
                    raise KeyError("transfer not found") from None
                if job["state"] == "running":
                    job["state"] = "interrupted"
                job["cancel"] = threading.Event()
                self.jobs[tid] = job
            if job["scope"] != str(scope):
                raise KeyError("transfer not found")
            return job

    @staticmethod
    def public(job):
        return {key: job[key] for key in ("id", "source", "destination", "move", "state", "bytes_copied", "files_copied", "error", "created_at", "updated_at")}

    def _mapping_id(self, path):
        row = self.mappings.at_path(Path(path))
        return row["id"] if row else None

    def start(self, source, destination, scope, *, move=False, max_nodes=5000):
        with self.lock:
            if sum(j["state"] == "running" for j in self.jobs.values()) >= 4:
                raise ValueError("transfer concurrency limit reached")
            tid = token_urlsafe_alnum(18)
            job = {"id": tid, "source": str(source), "destination": str(destination), "scope": str(scope),
                   "stage": str(destination.with_name(".openkapsel-transfer-" + tid)), "move": move,
                   "state": "pending", "bytes_copied": 0, "files_copied": 0, "error": None,
                   "created_at": time.time(), "updated_at": time.time(), "manifest": None,
                   "max_nodes": max_nodes, "cancel": threading.Event(), "published": False,
                   "mapping_ids": [self._mapping_id(source), self._mapping_id(destination)]}
            self.jobs[tid] = job
            self.resume(job)
            return self.public(job)

    def resume(self, job):
        with self.lock:
            if job["state"] in {"running", "completed"}:
                return
            if self.stopped or not self.slots.acquire(blocking=False):
                raise ValueError("transfer concurrency limit reached")
            job["state"], job["error"] = "running", None
            job["cancel"].clear()
            self._save(job)
            worker = threading.Thread(target=self._run, args=(job,), daemon=True)
            job["thread"] = worker
            worker.start()

    def _check(self, job, path, write=False):
        if job["cancel"].is_set() or self.stopped:
            raise InterruptedError("transfer cancelled")
        current = [self._mapping_id(job["source"]), self._mapping_id(job["destination"])]
        if current != job.get("mapping_ids", [None, None]):
            raise ValueError("transfer mapping identity changed; start a new transfer")
        self.mappings.check_path(path, write=write)

    @staticmethod
    def fingerprint(details):
        return [details.st_size, details.st_mtime_ns, details.st_ino, stat.S_IFMT(details.st_mode)]

    def _manifest(self, job, paths, source):
        result = []
        def walk(path, relative, depth):
            self._check(job, path)
            if depth > 32 or len(result) >= job["max_nodes"]:
                raise ValueError("transfer tree exceeds configured limits")
            details = paths.stat(path)
            is_dir = stat.S_ISDIR(details.st_mode)
            if not is_dir and not stat.S_ISREG(details.st_mode):
                raise ValueError("only files and directories can be transferred")
            result.append({"path": relative, "directory": is_dir, "fingerprint": self.fingerprint(details)})
            if is_dir:
                for name, _ in sorted(paths.entries(path), key=lambda item: item[0]):
                    from openkapsel.files.file_support import FileOperationSupportMixin
                    if name == ".openkapsel" or FileOperationSupportMixin._is_internal_transfer_name(name):
                        raise ValueError("transfer source contains private storage or another transfer")
                    walk(path / name, (Path(relative) / name).as_posix(), depth + 1)
        walk(source, ".", 0)
        return result

    def _copy_file(self, job, paths, source, destination, expected):
        src = paths.open(source, os.O_RDONLY)
        dst = None
        try:
            if self.fingerprint(stream_stat(src)) != expected:
                raise ValueError("source changed; transfer cannot resume")
            try:
                dst = paths.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                dst = paths.open(destination, os.O_RDWR)
            target_details = stream_stat(dst)
            if not stat.S_ISREG(target_details.st_mode) or target_details.st_size > expected[0]:
                raise ValueError("partial destination changed")
            offset = 0
            digest = hashlib.sha256()
            while offset < expected[0]:
                self._check(job, source)
                self._check(job, destination, write=True)
                chunk = src.read(min(128 * 1024, expected[0] - offset))
                if not chunk:
                    raise ValueError("source shortened during copy")
                digest.update(chunk)
                if offset < target_details.st_size:
                    previous = dst.read(min(len(chunk), target_details.st_size - offset))
                    if previous != chunk[:len(previous)]:
                        raise ValueError("partial destination content differs from source")
                    chunk_to_write = chunk[len(previous):]
                else:
                    chunk_to_write = chunk
                while chunk_to_write:
                    written = dst.write(chunk_to_write)
                    if written <= 0:
                        raise OSError("short transfer write")
                    chunk_to_write = chunk_to_write[written:]
                offset += len(chunk)
                job["bytes_copied"] += len(chunk)
                job["updated_at"] = time.time()
            sync_stream(dst)
            if self.fingerprint(stream_stat(src)) != expected:
                raise ValueError("source changed during copy")
            if stream_stat(dst).st_size != expected[0]:
                raise ValueError("destination size changed")
            dst.seek(0)
            verification = hashlib.sha256()
            remaining = expected[0]
            while remaining:
                self._check(job, destination, write=True)
                chunk = dst.read(min(128 * 1024, remaining))
                if not chunk:
                    raise ValueError("destination shortened during verification")
                verification.update(chunk)
                remaining -= len(chunk)
            if verification.digest() != digest.digest() or dst.read(1):
                raise ValueError("destination verification failed")
            job["files_copied"] += 1
        finally:
            src.close()
            if dst is not None:
                dst.close()

    def _run(self, job):
        source, destination, stage = map(Path, (job["source"], job["destination"], job["stage"]))
        scope = Path(job["scope"])
        paths = WorkspaceFiles(self.mappings, (scope,))
        try:
            if not job["published"]:
                self._check(job, source)
                self._check(job, destination, write=True)
                if paths.exists(destination):
                    raise FileExistsError("destination exists; recycle it before copying")
                if job["manifest"] is None:
                    job["manifest"] = self._manifest(job, paths, source)
                    self._save(job)
                job["bytes_copied"], job["files_copied"] = 0, 0
                for entry in job["manifest"]:
                    src, dst = source / entry["path"], stage / entry["path"]
                    if entry["path"] == ".":
                        src, dst = source, stage
                    if entry["directory"]:
                        paths.mkdir(dst, parents=False, exist_ok=True)
                    else:
                        self._copy_file(job, paths, src, dst, entry["fingerprint"])
                if self._manifest(job, paths, source) != job["manifest"]:
                    raise ValueError("source tree changed during transfer")
                paths.rename(stage, destination, overwrite=False)
                job["published"] = True
                self._save(job)
            if job["move"]:
                if self._manifest(job, paths, source) != job["manifest"]:
                    raise ValueError("destination copied; source changed and was retained")
                row = self.mappings.at_path(source)
                if row:
                    paths.call(row, "recycle", {"path": paths.relative(row, source)})
                else:
                    self.recycle_for(scope).recycle(source)
            job["state"] = "completed"
        except Exception as exc:
            job["state"] = "copied_source_retained" if job["published"] else "cancelled" if job["cancel"].is_set() else "interrupted"
            job["error"] = type(exc).__name__ + ": " + str(exc)[:300]
        finally:
            job["updated_at"] = time.time()
            with self.lock:
                self._save(job)
            self.slots.release()

    def close(self):
        self.stopped = True
        for job in list(self.jobs.values()):
            job["cancel"].set()
        for job in list(self.jobs.values()):
            thread = job.get("thread")
            if thread:
                thread.join(timeout=2)

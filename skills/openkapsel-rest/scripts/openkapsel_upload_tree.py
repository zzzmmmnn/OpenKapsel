#!/usr/bin/env python3
"""Upload files or directory trees with filtering and resumable batch state."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import posixpath
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from openkapsel_upload import UploadClient, sha256_file
from openkapsel_config import resolve_credentials
from openkapsel_http import ensure_fresh_credentials


STATE_VERSION = 1
DEFAULT_STATE_DIRECTORY = ".openkapsel-upload-state"
DEFAULT_PRIVATE_EXCLUDES = (".openkapsel.env",)


@dataclass(frozen=True)
class LocalFile:
    source: Path
    destination: str
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class ScanResult:
    directories: tuple[str, ...]
    files: tuple[LocalFile, ...]
    filtered: tuple[str, ...]
    symlinks: tuple[str, ...]


class UploadFilter:
    def __init__(self, includes: Iterable[str], excludes: Iterable[str]):
        self.includes = tuple(self._normalize(pattern) for pattern in includes if pattern.strip())
        self.excludes = tuple(self._normalize(pattern) for pattern in excludes if pattern.strip())

    @staticmethod
    def _normalize(pattern: str) -> str:
        return pattern.strip().replace("\\", "/").removeprefix("./").rstrip("/")

    @staticmethod
    def _matches(path: str, pattern: str, *, any_segment: bool) -> bool:
        if not pattern:
            return False
        normalized = path.removeprefix("./").strip("/")
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
        if fnmatch.fnmatchcase(normalized, pattern):
            return True
        if "/" not in pattern:
            if any_segment:
                return any(
                    fnmatch.fnmatchcase(part, pattern)
                    for part in PurePosixPath(normalized).parts
                )
            return fnmatch.fnmatchcase(PurePosixPath(normalized).name, pattern)
        return False

    def excluded(self, relative_path: str) -> bool:
        if any(part == ".openkapsel.env" for part in PurePosixPath(relative_path).parts):
            return True
        return any(
            self._matches(relative_path, pattern, any_segment=True)
            for pattern in self.excludes
        )

    @staticmethod
    def _hidden(relative_path: str) -> bool:
        return any(
            part.startswith(".") and part not in {".", ".."}
            for part in PurePosixPath(relative_path).parts
        )

    def hidden_allowed(self, relative_path: str, *, directory: bool = False) -> bool:
        if not self._hidden(relative_path):
            return True
        normalized = relative_path.removeprefix("./").strip("/")
        prefixes = [
            "/".join(PurePosixPath(normalized).parts[:index])
            for index in range(1, len(PurePosixPath(normalized).parts) + 1)
        ]
        for pattern in self.includes:
            if not any(part.startswith(".") for part in PurePosixPath(pattern).parts):
                continue
            if any(
                self._matches(prefix, pattern, any_segment=True)
                for prefix in prefixes
            ):
                return True
            if directory and pattern.startswith(normalized + "/"):
                return True
        return False

    def included_file(self, relative_path: str, *, explicit_source: bool = False) -> bool:
        if not explicit_source and not self.hidden_allowed(relative_path):
            return False
        return not self.includes or any(
            self._matches(relative_path, pattern, any_segment=False)
            for pattern in self.includes
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Upload multiple files or directory trees to a OpenKapsel workspace"
    )
    result.add_argument("sources", nargs="+", type=Path)
    result.add_argument(
        "--destination",
        required=True,
        help="remote parent directory; each source keeps its basename",
    )
    result.add_argument("--base-url")
    result.add_argument("--control-token")
    result.add_argument("--env-file", help="credential file; defaults to nearest .openkapsel.env")
    result.add_argument("--plan-id", required=True, type=int)
    result.add_argument("--taskname", required=True)
    result.add_argument("--message", required=True)
    result.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="GLOB",
        help="include matching files; an explicit hidden path pattern opts it in",
    )
    result.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    result.add_argument(
        "--exclude-from",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="read newline-separated exclude globs; blank lines and # comments are ignored",
    )
    result.add_argument(
        "--overwrite",
        action="store_true",
        help="recycle each existing destination before replacing it",
    )
    result.add_argument("--force-resumable", action="store_true")
    result.add_argument("--state-file", type=Path)
    result.add_argument("--keep-state", action="store_true")
    result.add_argument("--retries", type=int, default=3)
    result.add_argument("--retry-delay", type=float, default=2.0)
    result.add_argument("--timeout", type=float, default=120.0)
    return result


def _remote_path(parent: str, child: str) -> str:
    normalized_parent = parent.replace("\\", "/")
    if any(part == ".." for part in PurePosixPath(normalized_parent).parts):
        raise ValueError("destination must not contain '..'")
    joined = posixpath.normpath(posixpath.join(normalized_parent or ".", child))
    if joined == ".." or joined.startswith("../"):
        raise ValueError("destination escapes the requested remote directory")
    return joined


def _pattern_file(path: Path) -> list[str]:
    patterns: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped)
    return patterns


def scan_sources(
    sources: Iterable[Path],
    destination: str,
    upload_filter: UploadFilter,
    *,
    ignored_paths: Iterable[Path] = (),
) -> ScanResult:
    directories: set[str] = set()
    files: dict[str, LocalFile] = {}
    filtered: list[str] = []
    symlinks: list[str] = []
    ignored = {path.resolve(strict=False) for path in ignored_paths}
    remote_roots: dict[str, Path] = {}

    def add_file(
        source: Path,
        remote: str,
        relative: str,
        *,
        explicit_source: bool = False,
    ) -> None:
        if source.resolve(strict=False) in ignored:
            filtered.append(str(source))
            return
        if upload_filter.excluded(relative) or not upload_filter.included_file(
            relative, explicit_source=explicit_source
        ):
            filtered.append(str(source))
            return
        stat_result = source.stat()
        item = LocalFile(source.resolve(), remote, stat_result.st_size, stat_result.st_mtime_ns)
        previous = files.get(remote)
        if previous is not None and previous.source != item.source:
            raise ValueError(
                f"multiple local files map to the same destination {remote!r}: "
                f"{previous.source} and {item.source}"
            )
        files[remote] = item

    for original in sources:
        if original.is_symlink():
            raise ValueError(f"top-level source must not be a symlink: {original}")
        source = original.resolve(strict=True)
        remote_base = _remote_path(destination, source.name)
        previous_root = remote_roots.get(remote_base)
        if previous_root is not None and previous_root != source:
            raise ValueError(
                f"multiple sources map to the same destination root {remote_base!r}: "
                f"{previous_root} and {source}"
            )
        remote_roots[remote_base] = source
        if source.is_file():
            add_file(source, remote_base, source.name, explicit_source=True)
            continue
        if not source.is_dir():
            raise ValueError(f"source is not a regular file or directory: {original}")

        directories.add(remote_base)
        for root_text, directory_names, file_names in os.walk(source, followlinks=False):
            root = Path(root_text)
            relative_root = root.relative_to(source)
            retained_directories: list[str] = []
            for name in sorted(directory_names):
                child = root / name
                relative = (relative_root / name).as_posix()
                if child.is_symlink():
                    symlinks.append(str(child))
                elif (
                    child.resolve(strict=False) in ignored
                    or upload_filter.excluded(relative)
                    or not upload_filter.hidden_allowed(relative, directory=True)
                ):
                    filtered.append(str(child))
                else:
                    retained_directories.append(name)
                    directories.add(_remote_path(remote_base, relative))
            directory_names[:] = retained_directories

            for name in sorted(file_names):
                child = root / name
                relative = (relative_root / name).as_posix()
                if child.is_symlink():
                    symlinks.append(str(child))
                    continue
                add_file(child, _remote_path(remote_base, relative), relative)

    ordered_directories = tuple(sorted(directories, key=lambda value: (value.count("/"), value)))
    ordered_files = tuple(files[key] for key in sorted(files))
    return ScanResult(
        directories=ordered_directories,
        files=ordered_files,
        filtered=tuple(filtered),
        symlinks=tuple(symlinks),
    )


def _workspace_fingerprint(base_url: str) -> str:
    return hashlib.sha256(base_url.rstrip("/").encode("utf-8")).hexdigest()


def _batch_key(
    base_url: str,
    sources: Iterable[Path],
    destination: str,
    includes: Iterable[str],
    excludes: Iterable[str],
    overwrite: bool,
) -> str:
    payload = {
        "workspace": _workspace_fingerprint(base_url),
        "sources": [str(path.resolve(strict=False)) for path in sources],
        "destination": destination,
        "includes": list(includes),
        "excludes": list(excludes),
        "overwrite": overwrite,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


def default_state_path(batch_key: str) -> Path:
    return Path.cwd() / DEFAULT_STATE_DIRECTORY / f"{batch_key}.json"


def load_state(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION:
        raise ValueError(f"unsupported upload state file: {path}")
    return payload


def save_state(path: Path, payload: dict[str, Any]) -> None:
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed:
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _build_state(
    *,
    batch_key: str,
    workspace_fingerprint: str,
    scan: ScanResult,
    previous: dict[str, Any] | None,
    options: dict[str, Any],
) -> dict[str, Any]:
    previous_files = previous.get("files", {}) if previous else {}
    files: dict[str, dict[str, Any]] = {}
    for item in scan.files:
        old = previous_files.get(item.destination)
        unchanged = bool(
            isinstance(old, dict)
            and old.get("source") == str(item.source)
            and old.get("size") == item.size
            and old.get("mtime_ns") == item.mtime_ns
            and isinstance(old.get("sha256"), str)
        )
        digest = str(old["sha256"]) if unchanged else sha256_file(item.source)
        entry: dict[str, Any] = {
            "source": str(item.source),
            "destination": item.destination,
            "size": item.size,
            "mtime_ns": item.mtime_ns,
            "sha256": digest,
            "status": "pending",
            "upload_id": None,
            "offset": 0,
            "attempted": False,
            "conflict": False,
            "last_error": None,
        }
        if unchanged:
            for key in (
                "status", "upload_id", "offset", "attempted", "conflict", "last_error"
            ):
                entry[key] = old.get(key, entry[key])
        files[item.destination] = entry
    return {
        "version": STATE_VERSION,
        "batch_key": batch_key,
        "workspace_fingerprint": workspace_fingerprint,
        "options": options,
        "directories": list(scan.directories),
        "files": files,
    }


def directories_requiring_creation(
    directories: Iterable[str], file_destinations: Iterable[str]
) -> tuple[str, ...]:
    """Return only empty-tree leaves; file uploads create their own parents."""
    ordered = tuple(directories)
    files = tuple(file_destinations)
    empty_tree = tuple(
        directory
        for directory in ordered
        if not any(path.startswith(directory.rstrip("/") + "/") for path in files)
    )
    return tuple(
        directory
        for directory in empty_tree
        if not any(
            other != directory
            and other.startswith(directory.rstrip("/") + "/")
            for other in empty_tree
        )
    )


def apply_manifest_preflight(
    client: UploadClient,
    state: dict[str, Any],
    discovery: dict[str, object],
    *,
    overwrite: bool,
) -> tuple[set[str], set[str], list[dict[str, str]]]:
    """Use the optional native manifest route to skip matches and flag conflicts."""
    if not client.endpoint_available(discovery, "fs_manifest"):
        return set(), set(), []
    discovery_limits = discovery.get("limits")
    if not isinstance(discovery_limits, dict):
        raise RuntimeError("file Discovery does not publish limits")
    maximum = int(discovery_limits.get("max_batch_file_operations", 1000))
    if maximum <= 0:
        raise RuntimeError("file Discovery publishes an invalid batch operation limit")

    destinations = [
        destination
        for destination, entry in state["files"].items()
        if not entry.get("upload_id")
    ]
    already_present: set[str] = set()
    blocked: set[str] = set()
    failures: list[dict[str, str]] = []
    for start in range(0, len(destinations), maximum):
        selected = destinations[start : start + maximum]
        requested = [
            {
                "path": destination,
                "size": state["files"][destination]["size"],
                "sha256": state["files"][destination]["sha256"],
            }
            for destination in selected
        ]
        response = client.manifest(requested)
        results = response["items"]
        if len(results) != len(selected):
            raise RuntimeError("file manifest response length does not match the request")
        for expected_index, (destination, result) in enumerate(zip(selected, results)):
            if not isinstance(result, dict) or result.get("index") != expected_index:
                raise RuntimeError("file manifest response order is invalid")
            entry = state["files"][destination]
            status = result.get("status")
            if status == "same":
                entry["status"] = "complete"
                entry["upload_id"] = None
                entry["offset"] = entry["size"]
                entry["conflict"] = False
                entry["last_error"] = None
                already_present.add(destination)
            elif status == "missing":
                entry["status"] = "pending"
                entry["upload_id"] = None
                entry["offset"] = 0
                entry["conflict"] = False
                entry["last_error"] = None
            elif status == "conflict":
                entry["upload_id"] = None
                entry["offset"] = 0
                if overwrite:
                    entry["status"] = "pending"
                    entry["conflict"] = False
                    entry["last_error"] = None
                else:
                    message = "destination exists with different content"
                    entry["status"] = "failed"
                    entry["conflict"] = True
                    entry["last_error"] = message
                    blocked.add(destination)
                    failures.append({"path": destination, "error": message})
            else:
                raise RuntimeError(
                    f"file manifest returned unexpected status {status!r} for {destination}"
                )
    return already_present, blocked, failures


def run_batch(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    if not args.base_url:
        raise ValueError("set OPENKAPSEL_BASE_URL or pass --base-url")
    if not args.control_token:
        raise ValueError("set OPENKAPSEL_CONTROL_TOKEN or pass --control-token")
    exclude_patterns = list(args.exclude)
    for filename in args.exclude_from:
        exclude_patterns.extend(_pattern_file(filename))
    exclude_patterns.extend(
        (*DEFAULT_PRIVATE_EXCLUDES, DEFAULT_STATE_DIRECTORY, f"{DEFAULT_STATE_DIRECTORY}/**")
    )
    upload_filter = UploadFilter(args.include, exclude_patterns)
    key = _batch_key(
        args.base_url,
        args.sources,
        args.destination,
        args.include,
        exclude_patterns,
        args.overwrite,
    )
    state_path = (args.state_file or default_state_path(key)).resolve(strict=False)
    scan = scan_sources(
        args.sources,
        args.destination,
        upload_filter,
        ignored_paths=(state_path, Path.cwd() / DEFAULT_STATE_DIRECTORY),
    )
    previous = load_state(state_path)
    workspace_fingerprint = _workspace_fingerprint(args.base_url)
    if previous is not None and (
        previous.get("batch_key") != key
        or previous.get("workspace_fingerprint") != workspace_fingerprint
    ):
        raise ValueError("upload state belongs to different sources, options, or workspace")
    options = {
        "destination": args.destination,
        "includes": list(args.include),
        "excludes": exclude_patterns,
        "overwrite": args.overwrite,
        "force_resumable": args.force_resumable,
    }
    state = _build_state(
        batch_key=key,
        workspace_fingerprint=workspace_fingerprint,
        scan=scan,
        previous=previous,
        options=options,
    )
    save_state(state_path, state)

    client = UploadClient(
        base_url=args.base_url,
        control_token=args.control_token,
        plan_id=args.plan_id,
        taskname=args.taskname,
        message=args.message,
        retries=args.retries,
        retry_delay=args.retry_delay,
        timeout=args.timeout,
    )
    discovery = client.discover_files()
    limits = client.upload_limits_from_discovery(discovery)
    manifest_matches, preflight_blocked, failures = apply_manifest_preflight(
        client,
        state,
        discovery,
        overwrite=args.overwrite,
    )
    save_state(state_path, state)
    directory_requests = directories_requiring_creation(
        state["directories"], state["files"]
    )
    for directory in directory_requests:
        if directory in {"", ".", "/"}:
            continue
        try:
            client.ensure_directory(directory)
        except (OSError, ValueError, RuntimeError) as exc:
            failures.append({"path": directory, "error": str(exc)})

    uploaded = 0
    resumed = 0
    already_complete = 0
    for destination, entry in state["files"].items():
        if destination in preflight_blocked:
            continue
        if entry["status"] == "complete":
            if destination not in manifest_matches:
                already_complete += 1
            continue
        source = Path(entry["source"])
        current = source.stat()
        if current.st_size != entry["size"] or current.st_mtime_ns != entry["mtime_ns"]:
            entry["status"] = "failed"
            entry["last_error"] = "local file changed after batch scanning"
            save_state(state_path, state)
            failures.append({"path": destination, "error": entry["last_error"]})
            continue

        resume_upload_id = entry.get("upload_id")
        was_attempted = bool(entry.get("attempted"))
        entry["status"] = "uploading"
        entry["attempted"] = True
        entry["last_error"] = None
        save_state(state_path, state)

        def progress(upload_id: str | None, offset: int, *, item: dict[str, Any] = entry) -> None:
            item["upload_id"] = upload_id
            item["offset"] = offset
            save_state(state_path, state)

        try:
            client.upload_file(
                source,
                destination,
                limits=limits,
                digest=entry["sha256"],
                create_parents=True,
                force_resumable=args.force_resumable,
                overwrite=args.overwrite,
                resume_upload_id=resume_upload_id,
                allow_existing_match=was_attempted and not bool(entry.get("conflict")),
                progress=progress,
            )
            entry["status"] = "complete"
            entry["upload_id"] = None
            entry["offset"] = entry["size"]
            entry["conflict"] = False
            entry["last_error"] = None
            save_state(state_path, state)
            uploaded += 1
            if resume_upload_id:
                resumed += 1
            print(f"uploaded {source} -> {destination}", file=sys.stderr)
        except (OSError, ValueError, RuntimeError) as exc:
            message = str(exc)
            entry["status"] = "failed"
            entry["conflict"] = "path_exists" in message or "not_a_file" in message
            entry["last_error"] = message
            save_state(state_path, state)
            failures.append({"path": destination, "error": message})

    summary: dict[str, Any] = {
        "state_file": str(state_path),
        "directories": len(state["directories"]),
        "directory_requests": len(directory_requests),
        "files": len(state["files"]),
        "uploaded": uploaded,
        "resumed": resumed,
        "already_complete": already_complete,
        "already_present": len(manifest_matches),
        "filtered": len(scan.filtered),
        "symlinks_skipped": len(scan.symlinks),
        "failures": failures,
    }
    if not failures and all(
        entry["status"] == "complete" for entry in state["files"].values()
    ):
        summary["complete"] = True
        if not args.keep_state:
            state_path.unlink(missing_ok=True)
            try:
                state_path.parent.rmdir()
            except OSError:
                pass
            summary["state_file"] = None
    else:
        summary["complete"] = False
    return (0 if summary["complete"] else 1), summary


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        credentials = ensure_fresh_credentials(
            resolve_credentials(
                base_url=args.base_url,
                control_token=args.control_token,
                env_file=args.env_file,
            )
        )
        args.base_url = credentials.base_url
        args.control_token = credentials.control_token
        status, summary = run_batch(args)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return status
    except KeyboardInterrupt:
        print("openkapsel_upload_tree.py: interrupted; rerun the same command to resume", file=sys.stderr)
        return 130
    except (KeyError, OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"openkapsel_upload_tree.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

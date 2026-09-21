"""Token-scoped cgroup v2 resource controls and process inspection."""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_CONTROLLERS = {"cpu", "memory", "pids"}
CPU_PERIOD_US = 100_000
MAX_CMDLINE_BYTES = 8192
BUBBLEWRAP_PROCESS_OVERHEAD = 16


@dataclass(frozen=True)
class SandboxLimits:
    max_processes: int
    memory_bytes: int
    cpu_percent: int
    process_overhead: int = 0

    @property
    def effective_max_processes(self) -> int:
        return self.max_processes + max(0, self.process_overhead)

    def public(self) -> dict[str, int]:
        return {
            "max_processes": self.max_processes,
            "process_overhead": max(0, self.process_overhead),
            "effective_max_processes": self.effective_max_processes,
            "memory_bytes": self.memory_bytes,
            "cpu_percent": self.cpu_percent,
        }


class TokenCgroupManager:
    """Own a delegated cgroup subtree while leaving the API process unlimited."""

    def __init__(
        self,
        *,
        enabled: bool,
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        proc_root: Path = Path("/proc"),
    ) -> None:
        self.enabled = enabled
        self.cgroup_root = cgroup_root
        self.proc_root = proc_root
        self.available = False
        self.unavailable_reason = "disabled by server configuration"
        self.delegated_root: Path | None = None
        self.manager_cgroup: Path | None = None
        self._lock = threading.RLock()
        if enabled:
            self._initialize()

    def _initialize(self) -> None:
        try:
            if not (self.cgroup_root / "cgroup.controllers").is_file():
                raise RuntimeError("the host is not using cgroup v2")
            relative = self._self_cgroup_path()
            delegated = self.cgroup_root / relative.relative_to("/")
            available_controllers = set(
                (delegated / "cgroup.controllers").read_text(encoding="ascii").split()
            )
            missing = REQUIRED_CONTROLLERS - available_controllers
            if missing:
                raise RuntimeError(
                    "the delegated cgroup is missing controllers: " + ", ".join(sorted(missing))
                )
            manager = delegated / "openkapsel-manager"
            manager.mkdir(exist_ok=True)
            (manager / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="ascii")
            (delegated / "cgroup.subtree_control").write_text(
                "+cpu +memory +pids\n", encoding="ascii"
            )
            self.delegated_root = delegated
            self.manager_cgroup = manager
            self.available = True
            self.unavailable_reason = ""
        except (OSError, RuntimeError, ValueError) as exc:
            self.available = False
            self.unavailable_reason = str(exc)

    def _self_cgroup_path(self) -> Path:
        data = (self.proc_root / "self/cgroup").read_text(encoding="ascii")
        for line in data.splitlines():
            if line.startswith("0::"):
                value = line.removeprefix("0::").strip()
                if value.startswith("/"):
                    return Path(value)
        raise RuntimeError("cannot find the process cgroup v2 path")

    @staticmethod
    def token_key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]

    def configure(self, token: str, limits: SandboxLimits) -> Path:
        if not self.available or self.delegated_root is None:
            raise RuntimeError(self.unavailable_reason or "cgroup controls are unavailable")
        with self._lock:
            group = self.delegated_root / f"openkapsel-token-{self.token_key(token)}"
            group.mkdir(exist_ok=True)
            self._write(group / "pids.max", str(limits.effective_max_processes))
            self._write(group / "memory.max", str(limits.memory_bytes))
            swap_max = group / "memory.swap.max"
            if swap_max.exists():
                self._write(swap_max, "0")
            oom_group = group / "memory.oom.group"
            if oom_group.exists():
                self._write(oom_group, "1")
            quota = max(1, CPU_PERIOD_US * limits.cpu_percent // 100)
            self._write(group / "cpu.max", f"{quota} {CPU_PERIOD_US}")
            return group / "cgroup.procs"

    @staticmethod
    def _write(path: Path, value: str) -> None:
        path.write_text(value + "\n", encoding="ascii")

    def ensure_capacity(self, token: str, limits: SandboxLimits) -> Path:
        procs_file = self.configure(token, limits)
        current = self._read_int(procs_file.parent / "pids.current", default=0)
        if current >= limits.effective_max_processes:
            raise ProcessLookupError(
                "token sandbox process capacity reached "
                f"({current}/{limits.effective_max_processes}; "
                f"configured limit {limits.max_processes} plus "
                f"{max(0, limits.process_overhead)} internal overhead)"
            )
        return procs_file

    def inspect(
        self,
        token: str,
        limits: SandboxLimits,
        *,
        task_roots: dict[int, str],
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        if not self.available:
            return {
                "available": False,
                "reason": self.unavailable_reason,
                "limits": limits.public(),
                "usage": None,
                "processes": [],
                "offset": offset,
                "limit": limit,
                "total": 0,
                "truncated": False,
            }
        procs_file = self.configure(token, limits)
        group = procs_file.parent
        pids = self._read_descendant_pids(group)
        process_rows = []
        for pid in pids:
            row = self._process_info(pid)
            if row is not None:
                process_rows.append(row)
        process_rows.sort(key=lambda item: item["pid"])
        self._assign_task_ids(process_rows, task_roots)
        total = len(process_rows)
        selected = process_rows[offset : offset + limit]
        return {
            "available": True,
            "reason": None,
            "limits": limits.public(),
            "usage": {
                "processes_current": self._read_int(group / "pids.current", default=0),
                "memory_current_bytes": self._read_int(group / "memory.current", default=0),
                "memory_peak_bytes": self._read_int(group / "memory.peak", default=None),
                "cpu": self._read_key_values(group / "cpu.stat"),
                "memory_events": self._read_key_values(group / "memory.events"),
            },
            "processes": selected,
            "offset": offset,
            "limit": limit,
            "total": total,
            "truncated": offset + len(selected) < total,
        }

    @staticmethod
    def _assign_task_ids(rows: list[dict[str, Any]], task_roots: dict[int, str]) -> None:
        parents = {int(row["pid"]): int(row["ppid"]) for row in rows}
        for row in rows:
            current = int(row["pid"])
            seen: set[int] = set()
            task_id = None
            while current > 0 and current not in seen:
                seen.add(current)
                task_id = task_roots.get(current)
                if task_id is not None:
                    break
                current = parents.get(current, 0)
            row["task_id"] = task_id

    def _process_info(self, pid: int) -> dict[str, Any] | None:
        directory = self.proc_root / str(pid)
        try:
            status_values: dict[str, str] = {}
            for line in (directory / "status").read_text(errors="replace").splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    status_values[key] = value.strip()
            raw_stat = (directory / "stat").read_text(encoding="ascii")
            closing = raw_stat.rfind(")")
            stat_fields = raw_stat[closing + 2 :].split()
            with (directory / "cmdline").open("rb") as handle:
                command_window = handle.read(MAX_CMDLINE_BYTES + 1)
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError, ValueError):
            return None
        if len(stat_fields) < 20:
            return None
        clock_ticks = os.sysconf("SC_CLK_TCK")
        start_ticks = int(stat_fields[19])
        boot_time = self._boot_time()
        started_at = datetime.fromtimestamp(
            boot_time + start_ticks / clock_ticks, tz=timezone.utc
        ).isoformat()
        rss_value = status_values.get("VmRSS", "0 kB").split()[0]
        try:
            rss_bytes = int(rss_value) * 1024
        except ValueError:
            rss_bytes = 0
        command_truncated = len(command_window) > MAX_CMDLINE_BYTES
        command_data = command_window[:MAX_CMDLINE_BYTES].rstrip(b"\0")
        command = [
            item.decode("utf-8", errors="replace")
            for item in command_data.split(b"\0")
            if item
        ]
        return {
            "pid": pid,
            "ppid": int(stat_fields[1]),
            "name": status_values.get("Name", ""),
            "state": status_values.get("State", stat_fields[0]),
            "command": command,
            "command_truncated": command_truncated,
            "rss_bytes": rss_bytes,
            "cpu_time_seconds": (int(stat_fields[11]) + int(stat_fields[12])) / clock_ticks,
            "started_at": started_at,
        }

    def _boot_time(self) -> int:
        try:
            for line in (self.proc_root / "stat").read_text(encoding="ascii").splitlines():
                if line.startswith("btime "):
                    return int(line.split()[1])
        except (OSError, ValueError):
            pass
        return 0

    @staticmethod
    def _read_pid_list(path: Path) -> list[int]:
        try:
            return [int(value) for value in path.read_text(encoding="ascii").split()]
        except (OSError, ValueError):
            return []

    def _read_descendant_pids(self, group: Path) -> list[int]:
        """Include processes that a container runtime placed in child cgroups."""
        pids: set[int] = set(self._read_pid_list(group / "cgroup.procs"))
        try:
            children = group.rglob("cgroup.procs")
            for path in children:
                pids.update(self._read_pid_list(path))
        except OSError:
            pass
        return sorted(pids)

    @staticmethod
    def _read_int(path: Path, *, default: int | None) -> int | None:
        try:
            value = path.read_text(encoding="ascii").strip()
            return int(value) if value != "max" else None
        except (OSError, ValueError):
            return default

    @staticmethod
    def _read_key_values(path: Path) -> dict[str, int]:
        result: dict[str, int] = {}
        try:
            for line in path.read_text(encoding="ascii").splitlines():
                key, value = line.split(None, 1)
                result[key] = int(value)
        except (OSError, ValueError):
            return result
        return result

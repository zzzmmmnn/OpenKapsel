"""Pluggable restricted-shell sandbox backends."""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .api_workers import apparmor_restricts_user_namespaces
from .cgroups import SandboxLimits
from .network_proxy import DomainProxy, PROXY_MOUNT, PROXY_PORT
from .tasks import RESOLVER_FD_MARKER
from .tokens import PathGrant


ENVIRONMENT_MOUNT = "/run/openkapsel-environment.rc"


@dataclass(frozen=True)
class SandboxCapabilities:
    filesystem_isolation: bool = True
    pid_isolation: bool = True
    network_isolation: bool = True
    resource_limits: bool = False
    aggregate_resource_limits: bool = False
    process_listing: bool = False
    api_workers: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "filesystem_isolation": self.filesystem_isolation,
            "pid_isolation": self.pid_isolation,
            "network_isolation": self.network_isolation,
            "resource_limits": self.resource_limits,
            "aggregate_resource_limits": self.aggregate_resource_limits,
            "process_listing": self.process_listing,
            "api_workers": self.api_workers,
        }


class SandboxController(Protocol):
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def cleanup(self) -> None: ...


@dataclass(frozen=True)
class SandboxLaunch:
    backend: str
    argv: tuple[str, ...]
    stdin_data: bytes | None = None
    controller: SandboxController | None = None


@dataclass(frozen=True)
class SandboxSpec:
    command: str
    cwd: Path
    scope_root: Path
    can_write: bool
    network_mode: str
    allowed_domains: tuple[str, ...]
    proxy_root: Path
    allowed_paths: tuple[PathGrant, ...]
    hidden_paths: tuple[Path, ...]
    limits: SandboxLimits
    owner_token: str
    sandbox_image: str | None = None
    environment_file: Path | None = None


class SandboxBackend(Protocol):
    name: str
    capabilities: SandboxCapabilities

    def available(self) -> tuple[bool, str]: ...
    def build_shell(self, spec: SandboxSpec) -> SandboxLaunch: ...


def _executable_available(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


class BubblewrapBackend:
    name = "bubblewrap"

    def __init__(self, executable: Path, rootlesskit: Path, *, aggregate_resources: bool):
        self.executable = executable
        self.rootlesskit = rootlesskit
        self.capabilities = SandboxCapabilities(
            resource_limits=aggregate_resources,
            aggregate_resource_limits=aggregate_resources,
            process_listing=aggregate_resources,
            api_workers=True,
        )

    def available(self) -> tuple[bool, str]:
        if not _executable_available(self.executable):
            return False, f"Bubblewrap is not available at {self.executable}"
        if apparmor_restricts_user_namespaces() and not _executable_available(self.rootlesskit):
            return False, f"RootlessKit is required but is not available at {self.rootlesskit}"
        return True, "available"

    def build_shell(self, spec: SandboxSpec) -> SandboxLaunch:
        available, reason = self.available()
        if not available:
            raise RuntimeError(reason)
        use_rootlesskit = spec.network_mode == "full" or apparmor_restricts_user_namespaces()
        if use_rootlesskit and not _executable_available(self.rootlesskit):
            raise RuntimeError(
                f"RootlessKit is required for this sandbox but is not available at {self.rootlesskit}"
            )
        scope = str(spec.scope_root)
        path_value = os.environ.get(
            "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
        argv = [
            str(self.executable), "--die-with-parent", "--new-session", "--unshare-user",
            "--unshare-ipc", "--unshare-uts", "--unshare-pid", "--unshare-cgroup-try",
            "--cap-drop", "ALL",
        ]
        if spec.network_mode != "full":
            argv.append("--unshare-net")
        argv.extend(
            [
                "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
                "--symlink", "usr/sbin", "/sbin", "--symlink", "usr/lib", "/lib",
                "--symlink", "usr/lib64", "/lib64", "--dev", "/dev", "--dir", "/etc",
                "--dir", "/var", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp",
                "--tmpfs", "/run", "--proc", "/proc",
            ]
        )
        for host_path in (
            "/etc/ssl", "/etc/ca-certificates", "/etc/ld.so.conf.d", "/etc/passwd",
            "/etc/group", "/etc/nsswitch.conf", "/etc/hosts", "/etc/services",
            "/etc/protocols", "/etc/gai.conf", "/etc/localtime", "/etc/timezone",
            "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/fonts", "/etc/gitconfig",
            "/etc/ssh/ssh_config",
        ):
            if Path(host_path).exists():
                self._append_parent_dirs(argv, Path(host_path).parent)
                argv.extend(["--ro-bind", host_path, host_path])
        resolver_data = None
        if spec.network_mode == "full":
            resolver_data = b"nameserver 10.0.2.3\noptions timeout:2 attempts:2\n"
            argv.extend(["--file", RESOLVER_FD_MARKER, "/etc/resolv.conf"])
        self._append_parent_dirs(argv, spec.scope_root.parent)
        argv.extend(["--bind" if spec.can_write else "--ro-bind", scope, scope])
        if spec.environment_file is not None:
            argv.extend(
                ["--ro-bind", str(spec.environment_file), ENVIRONMENT_MOUNT]
            )
        for hidden in spec.hidden_paths:
            argv.extend(["--tmpfs", str(hidden)])
        for grant in sorted(spec.allowed_paths, key=lambda item: len(Path(item.path).parts)):
            mode = "--ro-bind" if not spec.can_write or grant.read_only else "--bind"
            self._append_parent_dirs(argv, Path(grant.path).parent)
            argv.extend([mode, grant.path, grant.path])
        controller = None
        shell_command = spec.command
        if spec.environment_file is not None:
            shell_command = f". {ENVIRONMENT_MOUNT}\n{shell_command}"
        command = ["/bin/sh", "-c", shell_command]
        proxy = None
        try:
            if spec.network_mode == "domain_allowlist":
                proxy = DomainProxy.start(spec.proxy_root, spec.allowed_domains)
                relay = Path(__file__).with_name("proxy_relay.py").resolve()
                argv.extend(["--ro-bind", str(proxy.directory), PROXY_MOUNT])
                argv.extend(["--ro-bind", str(relay), "/run/openkapsel-proxy-relay.py"])
                proxy_url = f"http://127.0.0.1:{PROXY_PORT}"
                command = [
                    "/usr/bin/python3", "/run/openkapsel-proxy-relay.py",
                    "--socket", f"{PROXY_MOUNT}/proxy.sock", "--port", str(PROXY_PORT),
                    "--", "/bin/sh", "-c", shell_command,
                ]
                controller = ProxyController(proxy)
            argv.extend(
                [
                    "--clearenv", "--setenv", "PATH", path_value, "--setenv", "HOME", scope,
                    "--setenv", "TMPDIR", "/tmp", "--setenv", "OPENKAPSEL_WORKSPACE", scope,
                ]
            )
            if spec.network_mode == "domain_allowlist":
                for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                    argv.extend(["--setenv", name, proxy_url])
                argv.extend(["--setenv", "NO_PROXY", "", "--setenv", "no_proxy", ""])
            argv.extend(["--chdir", str(spec.cwd), "--", *command])
        except Exception:
            if proxy is not None:
                proxy.close()
            raise
        if use_rootlesskit:
            argv = [
                str(self.rootlesskit), "--copy-up=/etc", "--net=slirp4netns",
                "--disable-host-loopback", "--", *argv,
            ]
        return SandboxLaunch(self.name, tuple(argv), resolver_data, controller)

    @staticmethod
    def _append_parent_dirs(argv: list[str], path: Path) -> None:
        current = Path("/")
        existing = {argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--dir"}
        for part in path.parts[1:]:
            current /= part
            value = str(current)
            if value not in existing:
                argv.extend(["--dir", value])
                existing.add(value)


class PodmanController:
    def __init__(self, executable: Path, container_name: str):
        self.executable = executable
        self.container_name = container_name

    def _run(self, *arguments: str) -> None:
        try:
            subprocess.run(
                (str(self.executable), *arguments, self.container_name),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def terminate(self) -> None:
        self._run("stop", "--time", "2")

    def kill(self) -> None:
        self._run("kill")

    def cleanup(self) -> None:
        self._run("rm", "--force")


class ProxyController:
    def __init__(
        self,
        proxy: DomainProxy,
        backend: SandboxController | None = None,
    ):
        self.proxy = proxy
        self.backend = backend

    def terminate(self) -> None:
        if self.backend is not None:
            self.backend.terminate()

    def kill(self) -> None:
        if self.backend is not None:
            self.backend.kill()

    def cleanup(self) -> None:
        try:
            if self.backend is not None:
                self.backend.cleanup()
        finally:
            self.proxy.close()


class PodmanBackend:
    name = "podman"

    def __init__(
        self, executable: Path, image: str, runtime: str, *, aggregate_resources: bool
    ):
        self.executable = executable
        self.image = image.strip()
        self.runtime = runtime.strip()
        self.host_is_macos = platform.system() == "Darwin"
        self.capabilities = SandboxCapabilities(
            network_isolation=not self.host_is_macos,
            resource_limits=True,
            aggregate_resource_limits=aggregate_resources,
            process_listing=aggregate_resources,
            api_workers=False,
        )

    def available(self) -> tuple[bool, str]:
        if not _executable_available(self.executable):
            return False, f"Podman is not available at {self.executable}"
        if not self.image:
            return False, "podman_image is not configured"
        if not self.runtime:
            return False, "podman_runtime is not configured"
        try:
            result = subprocess.run(
                (
                    str(self.executable), f"--runtime={self.runtime}", "info",
                    "--format", "{{.Host.OCIRuntime.Name}}",
                ),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False, text=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"Podman probe failed: {exc}"
        if result.returncode != 0:
            lines = result.stderr.strip().splitlines()
            return False, lines[-1] if lines else "Podman service is unavailable"
        return True, "available"

    def installed_images(self) -> tuple[str, ...]:
        available, _reason = self.available()
        if not available:
            return ()
        try:
            result = subprocess.run(
                (
                    str(self.executable), f"--runtime={self.runtime}", "images",
                    "--filter", "dangling=false", "--format", "{{.Repository}}:{{.Tag}}",
                ),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, check=False, text=True,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ()
        if result.returncode != 0:
            return ()
        return tuple(
            sorted(
                {
                    line.strip()
                    for line in result.stdout.splitlines()
                    if line.strip() and "<none>" not in line
                }
            )
        )

    def image_available(self, image: str) -> bool:
        try:
            result = subprocess.run(
                (
                    str(self.executable), f"--runtime={self.runtime}",
                    "image", "exists", image,
                ),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def build_shell(self, spec: SandboxSpec) -> SandboxLaunch:
        available, reason = self.available()
        if not available:
            raise RuntimeError(reason)
        if self.host_is_macos and spec.network_mode != "full":
            raise RuntimeError(
                "Podman on macOS uses a remote Linux VM and cannot guarantee --network=none; "
                "use full network mode for this token or run OpenKapsel inside Linux"
            )
        image = (spec.sandbox_image or self.image).strip()
        if not image:
            raise RuntimeError("no Podman image is configured for this token")
        if not self.image_available(image):
            raise RuntimeError(f"Podman image is not installed: {image}")
        token_label = hashlib.sha256(spec.owner_token.encode("utf-8")).hexdigest()[:24]
        container_name = f"openkapsel-{token_label[:8]}-{secrets.token_hex(6)}"
        argv = [str(self.executable), f"--runtime={self.runtime}"]
        if not self.host_is_macos:
            argv.append("--cgroup-manager=cgroupfs")
        argv.extend([
            "run", "--rm", "--name", container_name,
            "--label", f"io.openkapsel.token={token_label}", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--userns=keep-id",
            "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit", str(spec.limits.max_processes),
            "--memory", str(spec.limits.memory_bytes), "--cpus", str(spec.limits.cpu_percent / 100),
            "--pid=private", "--ipc=private", "--uts=private",
            "--network", "slirp4netns:allow_host_loopback=false" if spec.network_mode == "full" else "none",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777",
            "--tmpfs", "/run:rw,nosuid,nodev,noexec,mode=755",
            "--volume", f"{spec.scope_root}:{spec.scope_root}:{'rw' if spec.can_write else 'ro'}",
        ])
        if spec.environment_file is not None:
            argv.extend(
                ["--volume", f"{spec.environment_file}:{ENVIRONMENT_MOUNT}:ro"]
            )
        for hidden in spec.hidden_paths:
            argv.extend(["--tmpfs", f"{hidden}:rw,nosuid,nodev,noexec,mode=700"])
        for grant in sorted(spec.allowed_paths, key=lambda item: len(Path(item.path).parts)):
            mode = "ro" if not spec.can_write or grant.read_only else "rw"
            argv.extend(["--volume", f"{grant.path}:{grant.path}:{mode}"])
        podman_controller = PodmanController(self.executable, container_name)
        proxy = None
        try:
            shell_command = spec.command
            if spec.environment_file is not None:
                shell_command = f". {ENVIRONMENT_MOUNT}\n{shell_command}"
            command = ["/bin/sh", "-c", shell_command]
            if spec.network_mode == "domain_allowlist":
                proxy = DomainProxy.start(spec.proxy_root, spec.allowed_domains)
                relay = Path(__file__).with_name("proxy_relay.py").resolve()
                argv.extend(["--volume", f"{proxy.directory}:{PROXY_MOUNT}:ro"])
                argv.extend(["--volume", f"{relay}:/run/openkapsel-proxy-relay.py:ro"])
                proxy_url = f"http://127.0.0.1:{PROXY_PORT}"
                for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                    argv.extend(["--env", f"{name}={proxy_url}"])
                argv.extend(["--env", "NO_PROXY=", "--env", "no_proxy="])
                command = [
                    "python3", "/run/openkapsel-proxy-relay.py",
                    "--socket", f"{PROXY_MOUNT}/proxy.sock", "--port", str(PROXY_PORT),
                    "--", "/bin/sh", "-c", shell_command,
                ]
            argv.extend(
                [
                    "--workdir", str(spec.cwd), "--env", f"HOME={spec.scope_root}",
                    "--env", "TMPDIR=/tmp", "--env", f"OPENKAPSEL_WORKSPACE={spec.scope_root}",
                    "--pull=never", image, *command,
                ]
            )
            controller: SandboxController = podman_controller
            if proxy is not None:
                controller = ProxyController(proxy, podman_controller)
            return SandboxLaunch(self.name, tuple(argv), controller=controller)
        except Exception:
            if proxy is not None:
                proxy.close()
            raise


class SandboxRegistry:
    def __init__(
        self, *, enabled: tuple[str, ...], default: str, bubblewrap_path: Path,
        rootlesskit_path: Path, podman_path: Path, podman_image: str,
        podman_runtime: str,
        aggregate_resources: bool,
    ):
        self.enabled = enabled
        self.default = default
        all_backends: dict[str, SandboxBackend] = {
            "bubblewrap": BubblewrapBackend(
                bubblewrap_path, rootlesskit_path, aggregate_resources=aggregate_resources
            ),
            "podman": PodmanBackend(
                podman_path, podman_image, podman_runtime,
                aggregate_resources=aggregate_resources
            ),
        }
        self.backends = {name: all_backends[name] for name in enabled}

    def resolve(self, requested: str) -> SandboxBackend:
        name = self.default if requested == "auto" else requested
        backend = self.backends.get(name)
        if backend is None:
            raise LookupError(f"sandbox backend {name!r} is not enabled")
        available, reason = backend.available()
        if not available:
            raise RuntimeError(reason)
        return backend

    def status(self) -> dict[str, dict[str, object]]:
        payload: dict[str, dict[str, object]] = {}
        for name, backend in self.backends.items():
            available, reason = backend.available()
            payload[name] = {
                "available": available,
                "reason": reason,
                "capabilities": backend.capabilities.to_dict(),
            }
            if isinstance(backend, PodmanBackend):
                payload[name]["default_image"] = backend.image
                payload[name]["installed_images"] = list(backend.installed_images())
        return payload

    def podman_images(self) -> tuple[str, ...]:
        backend = self.backends.get("podman")
        if not isinstance(backend, PodmanBackend):
            return ()
        return backend.installed_images()

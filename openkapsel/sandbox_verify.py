"""Linux installation probe for API worker mount and PID isolation."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .api_workers import ApiWorkerManager
from .cgroups import SandboxLimits, TokenCgroupManager
from .sandbox_backends import BubblewrapBackend, SandboxSpec
from .tokens import TokenRecord, utc_now


def verify_api_worker_isolation(
    workspace_root: Path,
    worker_root: Path,
    bubblewrap_path: Path,
    rootlesskit_path: Path,
) -> None:
    workspace_root = workspace_root.resolve(strict=True)
    worker_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    manager = ApiWorkerManager(
        worker_root=worker_root,
        bubblewrap_path=bubblewrap_path.resolve(strict=True),
        rootlesskit_path=rootlesskit_path.resolve(strict=True),
        cgroups=TokenCgroupManager(enabled=False),
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix=".sandbox-isolation-",
            dir=workspace_root,
        ) as temporary_root, tempfile.TemporaryDirectory(
            prefix="sandbox-isolation-",
            dir=worker_root,
        ) as temporary_worker:
            test_root = Path(temporary_root)
            own_workspace = test_root / "own"
            other_workspace = test_root / "other"
            own_workspace.mkdir(mode=0o700)
            other_workspace.mkdir(mode=0o700)
            own_marker = own_workspace / "visible.txt"
            other_marker = other_workspace / "secret.txt"
            context_marker = own_workspace / ".openkapsel" / "context" / "private.txt"
            own_marker.write_text("own-workspace", encoding="utf-8")
            other_marker.write_text("other-workspace", encoding="utf-8")
            context_marker.parent.mkdir(mode=0o700, parents=True)
            context_marker.write_text("private-context", encoding="utf-8")
            worker_dir = Path(temporary_worker)
            host_pid = os.getpid()
            probe = f"""
from pathlib import Path
own = Path({json.dumps(str(own_marker))})
other = Path({json.dumps(str(other_marker))})
host_pid = {host_pid}
assert own.read_text(encoding='utf-8') == 'own-workspace'
assert not other.exists(), other
assert not Path({json.dumps(str(context_marker))}).exists()
assert Path('/opt/openkapsel/venv/bin/python').is_file()
assert not Path('/opt/openkapsel/README.md').exists()
assert not Path('/opt/openkapsel/openkapsel').exists()
assert Path('/proc/self/status').is_file()
assert not Path(f'/proc/{{host_pid}}').exists(), host_pid
assert not (Path('/proc/1/root') / str(other).lstrip('/')).exists()
import PIL, bs4, cryptography, fastapi, httpx, jinja2, lxml, matplotlib, numba, numpy, pandas, scipy, sqlalchemy, openkapsel_runtime, yaml
from matplotlib import font_manager
assert Path(font_manager.findfont('DejaVu Sans')).is_file()
print('API worker isolation probe passed')
"""
            record = TokenRecord(
                token="sandbox-isolation-token",
                name="Sandbox isolation probe",
                created_at=utc_now(),
                preview_token="sandbox-preview",
                control_token="sandbox-control",
                app_id="sandbox-isolation-app",
                can_preview=True,
                shell_mode="restricted",
            )
            python = "/opt/openkapsel/venv/bin/python"
            argv = manager._sandbox_argv(
                record,
                own_workspace,
                worker_dir,
                worker_dir / "probe.sock",
                "/sandbox/api",
                command=[python, "-I", "-c", probe],
            )
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
                raise RuntimeError(
                    "API worker isolation probe failed "
                    f"with exit code {completed.returncode}: {stderr}"
                )
            if b"API worker isolation probe passed" not in completed.stdout:
                raise RuntimeError("API worker isolation probe returned no success marker")
    finally:
        manager.close()


def verify_domain_network_isolation(
    workspace_root: Path,
    worker_root: Path,
    bubblewrap_path: Path,
    rootlesskit_path: Path,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=".network-isolation-",
        dir=workspace_root,
    ) as temporary_workspace:
        workspace = Path(temporary_workspace)
        probe = """
import os
import socket

assert os.environ['HTTPS_PROXY'] == 'http://127.0.0.1:18080'
direct = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
direct.settimeout(1)
try:
    direct.connect(('1.1.1.1', 443))
except OSError:
    pass
else:
    raise AssertionError('direct Internet connection bypassed the domain proxy')
finally:
    direct.close()

proxy = socket.create_connection(('127.0.0.1', 18080), timeout=3)
proxy.sendall(b'CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n')
response = proxy.recv(1024)
proxy.close()
assert response.startswith(b'HTTP/1.1 403'), response
print('Domain network isolation probe passed')
"""
        backend = BubblewrapBackend(
            bubblewrap_path.resolve(strict=True),
            rootlesskit_path.resolve(strict=True),
            aggregate_resources=False,
        )
        spec = SandboxSpec(
            command=f"python3 -c {shlex.quote(probe)}",
            cwd=workspace,
            scope_root=workspace,
            can_write=True,
            network_mode="domain_allowlist",
            allowed_domains=("github.com",),
            proxy_root=worker_root / "network-proxies",
            allowed_paths=(),
            hidden_paths=(),
            limits=SandboxLimits(16, 64 * 1024 * 1024, 100),
            owner_token="network-isolation-probe",
        )
        launch = backend.build_shell(spec)
        try:
            completed = subprocess.run(
                launch.argv,
                input=launch.stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
        finally:
            if launch.controller is not None:
                launch.controller.cleanup()
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
            raise RuntimeError(
                "Domain network isolation probe failed "
                f"with exit code {completed.returncode}: {stderr}"
            )
        if b"Domain network isolation probe passed" not in completed.stdout:
            raise RuntimeError("Domain network isolation probe returned no success marker")


def verify_allowed_git_access(
    workspace_root: Path,
    worker_root: Path,
    bubblewrap_path: Path,
    rootlesskit_path: Path,
    repository_url: str,
) -> None:
    parsed = urlsplit(repository_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("allowed Git probe URL must be an HTTPS repository URL")
    with tempfile.TemporaryDirectory(
        prefix=".network-git-",
        dir=workspace_root,
    ) as temporary_workspace:
        workspace = Path(temporary_workspace)
        backend = BubblewrapBackend(
            bubblewrap_path.resolve(strict=True),
            rootlesskit_path.resolve(strict=True),
            aggregate_resources=False,
        )
        spec = SandboxSpec(
            command=f"git ls-remote {shlex.quote(repository_url)} HEAD",
            cwd=workspace,
            scope_root=workspace,
            can_write=True,
            network_mode="domain_allowlist",
            allowed_domains=(parsed.hostname,),
            proxy_root=worker_root / "network-proxies",
            allowed_paths=(),
            hidden_paths=(),
            limits=SandboxLimits(16, 64 * 1024 * 1024, 100),
            owner_token="allowed-git-probe",
        )
        launch = backend.build_shell(spec)
        try:
            completed = subprocess.run(
                launch.argv,
                input=launch.stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
        finally:
            if launch.controller is not None:
                launch.controller.cleanup()
        if completed.returncode != 0 or b"\tHEAD" not in completed.stdout:
            stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
            raise RuntimeError(
                "Allowed-domain Git probe failed "
                f"with exit code {completed.returncode}: {stderr}"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--worker-root", type=Path, required=True)
    parser.add_argument("--bubblewrap", type=Path, required=True)
    parser.add_argument("--rootlesskit", type=Path, required=True)
    parser.add_argument("--allowed-git-url")
    args = parser.parse_args()
    verify_api_worker_isolation(
        args.workspace_root,
        args.worker_root,
        args.bubblewrap,
        args.rootlesskit,
    )
    verify_domain_network_isolation(
        args.workspace_root,
        args.worker_root,
        args.bubblewrap,
        args.rootlesskit,
    )
    if args.allowed_git_url:
        verify_allowed_git_access(
            args.workspace_root,
            args.worker_root,
            args.bubblewrap,
            args.rootlesskit,
            args.allowed_git_url,
        )


if __name__ == "__main__":
    main()

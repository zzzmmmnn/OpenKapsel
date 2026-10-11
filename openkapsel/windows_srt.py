"""Windows Anthropic Sandbox Runtime (SRT) Job Manager integration.

This adapter uses the globally installed npm package's Node CLI directly
rather than launching a .cmd wrapper through a host shell. SRT's Windows
implementation uses a dedicated local account, ACLs and a WFP egress fence.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path


_PACKAGE = "@anthropic-ai/sandbox-runtime"
_NODE_MINIMUM = (22, 12, 0)
_SRT_MINIMUM = (0, 0, 79)


def _version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", value.strip())
    if match is None:
        raise RuntimeError(f"invalid runtime version: {value!r}")
    return tuple(int(match.group(i)) for i in (1, 2, 3))


def _resolve_global_cli(*, writable_dirs: tuple[Path, ...]) -> tuple[str, str]:
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        raise RuntimeError(
            "Windows sandbox requires Node.js >=22.12 and npm; "
            "install Node.js and npm before enabling job_sandbox"
        )
    try:
        node_version = subprocess.run(
            [node, "--version"], capture_output=True, text=True,
            check=True, timeout=10,
        )
        if _version(node_version.stdout) < _NODE_MINIMUM:
            raise RuntimeError(
                f"Windows sandbox requires Node.js >=22.12; found {node_version.stdout.strip()}"
            )
        global_root = subprocess.run(
            [npm, "root", "--global"], capture_output=True, text=True,
            check=True, timeout=15,
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError("cannot locate Windows sandbox-runtime npm installation") from exc
    if not global_root:
        raise RuntimeError("npm root --global returned an empty directory")
    package_dir = (Path(global_root) / "@anthropic-ai" / "sandbox-runtime").resolve()
    entrypoint = (package_dir / "dist" / "cli.js").resolve()
    manifest = package_dir / "package.json"
    try:
        package = json.loads(manifest.read_text(encoding="utf-8"))
        if package.get("name") != _PACKAGE:
            raise ValueError("unexpected npm package")
        if _version(package.get("version", "")) < _SRT_MINIMUM:
            raise ValueError("sandbox-runtime requires version 0.0.79 or later")
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Windows sandbox-runtime is missing/incompatible: "
            "npm install -g @anthropic-ai/sandbox-runtime"
        ) from exc
    if not entrypoint.is_file():
        raise RuntimeError(
            "Windows sandbox-runtime CLI not found; "
            "npm install -g @anthropic-ai/sandbox-runtime"
        )
    # Executing a launcher from a sandbox-writable tree would let a job
    # replace it and execute the substituted code on the host next time.
    for binary in (Path(node).resolve(), entrypoint, manifest):
        if any(binary == root or root in binary.parents for root in writable_dirs):
            raise RuntimeError("Windows sandbox runtime lives inside a writable sandbox path")
    return str(Path(node).resolve()), str(entrypoint)


def srt_settings(*, root: Path, writable: bool, grants, hidden: list[Path],
                 mode: str, domains: list[str]) -> dict:
    """Translate the Manager's normalized policy to SRT 0.0.79 settings.

    SRT's wildcard syntax differs: *.host does NOT match host itself,
    whereas OpenKapsel's .host matches both. Explicitly emit both.
    """
    if mode == "full":
        # SRT's Windows WFP fence always blocks direct connections, while
        # allowedDomains rejects '*'. Do not pretend this enables full egress.
        raise ValueError(
            "Windows sandbox-runtime 0.0.79 cannot enforce "
            "job_sandbox.network.mode=full; use none or domain_allowlist"
        )
    if mode not in {"none", "domain_allowlist"}:
        raise ValueError("unsupported Windows sandbox network mode")
    allowed = []
    for domain in domains if mode == "domain_allowlist" else ():
        rules = (domain[1:], "*." + domain[1:]) if domain.startswith(".") else (domain,)
        for rule in rules:
            if rule not in allowed:
                allowed.append(rule)
    reads = [str(root)]
    writes = [str(root)] if writable else []
    denied_writes = []
    for item in grants:
        path = str(item.path)
        if path not in reads:
            reads.append(path)
        if item.access == "ro":
            denied_writes.append(path)
        else:
            writes.append(path)
    # Deny hidden metadata/secret paths even when they lie within a
    # writable/readable root (ACL deny overlays).
    hidden_paths = [str(p) for p in hidden]
    denied_writes.extend(hidden_paths)
    return {
        "network": {
            "allowedDomains": allowed,
            "deniedDomains": [],
        },
        "filesystem": {
            "allowRead": reads,
            "allowWrite": writes,
            "denyRead": hidden_paths,
            "denyWrite": list(dict.fromkeys(denied_writes)),
        },
    }


def launch_windows_srt(*, argv: list[str], environment: dict[str, str],
                       job_dir: Path, root: Path, writable: bool, grants,
                       hidden: list[Path], mode: str, domains: list[str]) -> tuple[list[str], dict[str, str]]:
    """Build a fail-closed Node CLI launch and a private per-Job settings file."""
    settings = srt_settings(
        root=root, writable=writable, grants=grants,
        hidden=hidden, mode=mode, domains=domains,
    )
    node, cli = _resolve_global_cli(
        writable_dirs=tuple(
            [root] * int(writable) +
            [Path(item.path) for item in grants if item.access == "rw"]
        ),
    )
    settings_path = job_dir / "srt-settings.json"
    # Per-job config lives in the Manager's private state, never the Mapping.
    # A named --settings file is mandatory; missing/invalid config makes
    # upstream SRT exit instead of silently falling back to defaults.
    with settings_path.open("x", encoding="utf-8") as file:
        json.dump(settings, file, ensure_ascii=False, separators=(",", ":"))
    # These are host-side launcher variables. The Windows SRT runner creates
    # a separate fresh child environment for the srt-sandbox account.
    whitelist = (
        "SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "PATH", "APPDATA",
        "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "PROGRAMDATA", "TEMP", "TMP",
    )
    env = {name: os.environ[name] for name in whitelist if name in os.environ}
    env.update(environment)
    # Do not carry arbitrary host proxy variables into the Node broker.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        env.pop(name, None)
    # The argv is turned into one cmd.exe command inside SRT. It is never
    # parsed by the host shell (subprocess.Popen(shell=False)).
    command = subprocess.list2cmdline(argv)
    return [node, cli, "--settings", str(settings_path), "-c", command], env

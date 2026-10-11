#!/usr/bin/env python3
"""Create or repair the OpenKapsel Client virtual environment.

No third-party modules are needed by the launcher. Dependency declarations
come directly from pyproject.toml, including all Client RPC optional extras.
Existing distributions that satisfy their version requirements are never
reinstalled or upgraded merely because this script was run again.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.parse
from collections import deque
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTRAS = ("client", "data-rpc", "ssh-rpc")
SUPPORTED_SYSTEMS = {"Linux", "Darwin", "Windows"}


def platform_name() -> str:
    system = platform.system()
    if system not in SUPPORTED_SYSTEMS:
        raise RuntimeError(f"unsupported Client OS: {system}")
    return {"Darwin": "macOS"}.get(system, system)


def venv_interpreter(directory: Path) -> Path:
    if sys.platform == "win32":
        return directory / "Scripts" / "python.exe"
    return directory / "bin" / "python"


def run_command(argv: list[str], *, cwd: Path = PROJECT_ROOT) -> None:
    print("+", " ".join(str(s) for s in argv), flush=True)
    subprocess.run([str(s) for s in argv], cwd=str(cwd), check=True)


def ensure_virtualenv(directory: Path, *, check_only: bool) -> Path:
    path = venv_interpreter(directory)
    if directory.exists():
        if not (directory / "pyvenv.cfg").is_file() or not path.is_file():
            raise RuntimeError(
                f"{directory} exists but is not a healthy venv; "
                "move it aside before recreating (it will not be overwritten)"
            )
    elif check_only:
        raise RuntimeError(f"venv not found: {directory}")
    else:
        directory.parent.mkdir(parents=True, exist_ok=True)
        run_command([sys.executable, "-m", "venv", str(directory)])
    # A broken launch shim must never cause pip to run against the host Python.
    check = subprocess.run(
        [str(path), "-I", "-c",
         "import json,sys;print(json.dumps({'prefix':sys.prefix,'version':list(sys.version_info[:2])}))"],
        cwd=str(PROJECT_ROOT), capture_output=True, text=True, check=True,
    )
    info = json.loads(check.stdout)
    if Path(info["prefix"]).resolve() != directory.resolve():
        raise RuntimeError(f"venv interpreter does not point to {directory}")
    if info["version"] < [3, 10]:
        raise RuntimeError("Client requires Python >=3.10")
    try:
        subprocess.run(
            [str(path), "-I", "-m", "pip", "--version"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        if check_only:
            raise RuntimeError(
                f"pip is missing in {directory}; rerun without --check to repair it"
            ) from None
        run_command([str(path), "-m", "ensurepip", "--upgrade"])
    return path


def load_toml():
    try:
        import tomllib
        return tomllib
    except ModuleNotFoundError:
        # Python 3.10 has no tomllib; pip (installed in the target venv)
        # vendors the same TOML parser. No extra bootstrap package needed.
        from pip._vendor import tomli
        return tomli


def load_requirements(project_root: Path):
    project = load_toml().loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extras = project.get("optional-dependencies", {})
    missing = set(DEFAULT_EXTRAS) - set(extras)
    if missing:
        raise RuntimeError(f"missing Client dependency groups: {sorted(missing)}")
    return list(project["dependencies"]) + [
        requirement for group in DEFAULT_EXTRAS for requirement in extras[group]
    ]


def editable_installed(project_root: Path) -> bool:
    try:
        distribution = importlib.metadata.distribution("openkapsel")
    except importlib.metadata.PackageNotFoundError:
        return False
    raw = distribution.read_text("direct_url.json")
    if not raw:
        return False
    try:
        data = json.loads(raw)
        if data.get("dir_info", {}).get("editable") is not True:
            return False
        url = urllib.parse.urlsplit(data["url"])
        if url.scheme != "file":
            return False
        from urllib.request import url2pathname
        path = Path(url2pathname(urllib.parse.unquote(url.path))).resolve()
        return path == project_root.resolve()
    except (KeyError, TypeError, ValueError, OSError):
        return False


def audit_requirements(requirements: list[str]) -> list[str]:
    """Return only unsatisfied direct/transitive requirements.

    Uses pip's vendored packaging on fresh venvs, so this also works when the
    separately installable 'packaging' distribution is not yet available.
    """
    try:
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
    except ImportError:
        from pip._vendor.packaging.requirements import Requirement
        from pip._vendor.packaging.utils import canonicalize_name

    pending = deque((Requirement(text), frozenset()) for text in requirements)
    examined = set()
    unsatisfied = {}
    while pending:
        req, parent_extras = pending.popleft()
        if req.marker is not None and not any(
            req.marker.evaluate({"extra": extra})
            for extra in (parent_extras or frozenset({""}))
        ):
            continue
        key = canonicalize_name(req.name)
        marker_key = (str(req), parent_extras)
        if marker_key in examined:
            continue
        examined.add(marker_key)
        # The parent extra/OS marker has *already* been evaluated. Installing
        # it as a top-level pip requirement with that marker intact would cause
        # pip to skip it (the top-level "extra" environment is always empty).
        install_req = Requirement(str(req))
        install_req.marker = None
        install_spec = str(install_req)
        try:
            dist = importlib.metadata.distribution(req.name)
        except importlib.metadata.PackageNotFoundError:
            unsatisfied.setdefault(key, install_spec)
            continue
        if req.specifier and not req.specifier.contains(dist.version, prereleases=True):
            unsatisfied.setdefault(key, install_spec)
            continue
        # An installed package can be used with different extras in different
        # places. Traverse once for each distinct requirement+extras context.
        for dependency in dist.requires or ():
            pending.append((Requirement(dependency), frozenset(req.extras)))
    return list(unsatisfied.values())


def environment_audit(project_root: Path) -> dict:
    required = load_requirements(project_root)
    missing = audit_requirements(required)
    return {
        "editable": editable_installed(project_root),
        "missing": missing,
        "requirements": len(required),
    }


def audit_in_venv(python: Path) -> dict:
    proc = subprocess.run(
        [str(python), "-I", str(Path(__file__).resolve()), "--internal-audit",
         "--project-root", str(PROJECT_ROOT)],
        cwd=str(PROJECT_ROOT), capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)


def install_missing(python: Path, missing: list[str]) -> None:
    if missing:
        print(f"Installing {len(missing)} missing/incompatible requirements...", flush=True)
        run_command([str(python), "-m", "pip", "install",
                     "--disable-pip-version-check", "--upgrade-strategy",
                     "only-if-needed", *missing])


def windows_sandbox_diagnostic() -> str:
    """Inspect (without installing) the future Windows sandbox prerequisites.

    npm list reads the local global package inventory; no registry query or
    installation takes place. Runtime integration will do its own hard checks.
    """
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        missing = [tool for tool, path in (("node", node), ("npm", npm)) if not path]
        return f"Windows sandbox runtime prerequisite missing: {', '.join(missing)}"
    try:
        result = subprocess.run(
            [npm, "list", "--global", "--depth=0", "--json",
             "@anthropic-ai/sandbox-runtime"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        packages = json.loads(result.stdout or "{}").get("dependencies", {})
        if isinstance(packages, dict) and "@anthropic-ai/sandbox-runtime" in packages:
            return "Windows sandbox-runtime npm package: installed globally (not yet integrated)"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "Windows sandbox-runtime npm package: status unavailable"
    return ("Windows sandbox-runtime npm package: not found globally; "
            "future backend prerequisite is npm install -g @anthropic-ai/sandbox-runtime")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--venv", type=Path, default=PROJECT_ROOT / ".venv",
        help="venv directory (default: repository .venv)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="report missing dependencies without installing anything",
    )
    parser.add_argument("--internal-audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.internal_audit:
        print(json.dumps(environment_audit(args.project_root)))
        return 0

    if sys.version_info < (3, 10):
        raise RuntimeError("Python >=3.10 is required to set up the Client")
    name = platform_name()
    directory = args.venv.expanduser().resolve()
    print(f"Platform: {name}; Client environment: {directory}", flush=True)
    if name == "Windows":
        print(windows_sandbox_diagnostic(), flush=True)
    python = ensure_virtualenv(directory, check_only=args.check)
    audit = audit_in_venv(python)
    print(f"Checking {audit['requirements']} Client requirements...", flush=True)
    if args.check:
        print(f"Local editable OpenKapsel: {'OK' if audit['editable'] else 'MISSING'}")
        for requirement in audit["missing"]:
            print(f"  Missing/incompatible: {requirement}")
        if not audit["editable"] or audit["missing"]:
            return 1
    else:
        if not audit["editable"]:
            # Only install the current checkout once; don't reinstall an
            # already-correct editable distribution on every invocation.
            run_command([str(python), "-m", "pip", "install",
                         "--disable-pip-version-check", "--no-deps",
                         "--editable", str(PROJECT_ROOT)])
        install_missing(python, audit["missing"])
        verified = audit_in_venv(python)
        if not verified["editable"] or verified["missing"]:
            raise RuntimeError(f"Client environment verification failed: {verified}")
    print(f"Client environment ready: {python}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"Client setup failed: {exc}", file=sys.stderr)
        sys.exit(1)

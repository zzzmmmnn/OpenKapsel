"""Public discovery and download endpoints for the bundled REST skill."""

from __future__ import annotations

import hashlib
import io
import zipfile
from functools import lru_cache
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .errors import ApiError


SKILL_NAME = "openkapsel-rest"
SKILL_DESCRIPTION = (
    "Operate OpenKapsel workspace REST, reliable file-transfer, sharing, preview, "
    "and FastAPI HTTP surfaces without loading the full Discovery document."
)


def _skill_root() -> Path:
    return Path(__file__).resolve().parent.parent / "skills" / SKILL_NAME


def _public_paths() -> tuple[str, ...]:
    root = _skill_root()
    paths = ["SKILL.md"]
    for directory, suffixes in (
        ("agents", {".yaml", ".yml"}),
        ("references", {".md", ".json"}),
        ("scripts", {".py"}),
    ):
        base = root / directory
        if not base.is_dir():
            continue
        paths.extend(
            str(path.relative_to(root))
            for path in sorted(base.rglob("*"))
            if path.is_file() and not path.is_symlink() and path.suffix in suffixes
        )
    return tuple(paths)


@lru_cache(maxsize=1)
def skill_bundle() -> tuple[dict[str, bytes], bytes, str]:
    root = _skill_root()
    files: dict[str, bytes] = {}
    for relative in _public_paths():
        path = root / relative
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root.resolve(strict=True))
        except (OSError, ValueError):
            raise RuntimeError(f"bundled skill file is unavailable: {relative}") from None
        files[relative] = resolved.read_bytes()
    if "SKILL.md" not in files:
        raise RuntimeError("bundled skill entrypoint is unavailable")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, content in sorted(files.items()):
            info = zipfile.ZipInfo(f"{SKILL_NAME}/{relative}", (1980, 1, 1, 0, 0, 0))
            mode = 0o755 if relative.startswith("scripts/") else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    bundle = output.getvalue()
    return files, bundle, hashlib.sha256(bundle).hexdigest()


def skill_discovery(public_base_url: str) -> dict[str, Any]:
    _files, bundle, bundle_sha256 = skill_bundle()
    base = f"{public_base_url.rstrip('/')}/skills/{SKILL_NAME}"
    return {
        "name": SKILL_NAME,
        "description": SKILL_DESCRIPTION,
        "scope": "OpenKapsel workspace HTTP interfaces except MCP and administration",
        "authentication": "none",
        "manifest_url": base,
        "entrypoint_url": f"{base}/SKILL.md",
        "archive_url": f"{base}/archive.zip?sha256={bundle_sha256}",
        "archive_sha256": bundle_sha256,
        "archive_bytes": len(bundle),
        "install_directory": SKILL_NAME,
    }


class SkillHandlersMixin:
    """Serve the built-in skill without exposing any workspace credential."""

    def _dispatch_skill(self, method: str, request_path: str) -> None:
        if method not in {"GET", "HEAD"}:
            self._discard_request_body()
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        self._discard_request_body()
        base_path = f"/skills/{SKILL_NAME}"
        if request_path in {base_path, base_path + "/"}:
            discovery = skill_discovery(self._public_base_url())
            discovery.update(
                {
                    "format": "Codex skill directory",
                    "files": [
                        {
                            "path": relative,
                            "url": f"{discovery['manifest_url']}/{relative}",
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "bytes": len(content),
                        }
                        for relative, content in sorted(skill_bundle()[0].items())
                    ],
                    "installation": (
                        "Download archive_url, verify archive_sha256, extract the "
                        "openkapsel-rest directory into the AI client's skills directory, "
                        "then load SKILL.md. The files may also be read directly by URL."
                    ),
                }
            )
            self._send_json(HTTPStatus.OK, discovery)
            return

        encoded_relative = request_path.removeprefix(base_path + "/")
        relative = unquote(encoded_relative)
        if relative == "archive.zip":
            _files, content, digest = skill_bundle()
            self._send_skill_content(
                content,
                'application/zip',
                f'"{digest}"',
                content_disposition=f'attachment; filename="{SKILL_NAME}.zip"',
            )
            return
        files, _bundle, _digest = skill_bundle()
        content = files.get(relative)
        if content is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "skill_file_not_found", "skill file does not exist")
        content_type = (
            "text/markdown; charset=utf-8"
            if relative.endswith(".md")
            else "application/yaml; charset=utf-8"
            if relative.endswith((".yaml", ".yml"))
            else "text/x-python; charset=utf-8"
            if relative.endswith(".py")
            else "application/json; charset=utf-8"
        )
        digest = hashlib.sha256(content).hexdigest()
        self._send_skill_content(content, content_type, f'"{digest}"')

    def _send_skill_content(
        self,
        content: bytes,
        content_type: str,
        etag: str,
        *,
        content_disposition: str | None = None,
    ) -> None:
        if self.headers.get("If-None-Match") == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("Content-Length", "0")
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("X-Content-Type-Options", "nosniff")
        if content_disposition is not None:
            self.send_header("Content-Disposition", content_disposition)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

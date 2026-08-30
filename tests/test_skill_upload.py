from __future__ import annotations

import hashlib
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIRECTORY = (
    Path(__file__).resolve().parents[1] / "skills" / "openkapsel-rest" / "scripts"
)
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import openkapsel_upload  # noqa: E402
import openkapsel_upload_tree  # noqa: E402
from openkapsel_http import HttpResult  # noqa: E402


class SkillUploadScriptTests(unittest.TestCase):
    def test_state_file_is_private_without_changing_an_existing_parent_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "existing"
            parent.mkdir()
            parent.chmod(0o755)
            state = parent / "batch.json"
            openkapsel_upload_tree.save_state(
                state,
                {"version": openkapsel_upload_tree.STATE_VERSION},
            )
            self.assertEqual(0o755, stat.S_IMODE(parent.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(state.stat().st_mode))

    def test_single_file_automatically_selects_direct_or_resumable_upload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            small = root / "small.bin"
            large = root / "large.bin"
            small.write_bytes(b"1234")
            large.write_bytes(b"1234567")
            calls: list[tuple[str, str, int]] = []
            expected_digest = hashlib.sha256(large.read_bytes()).hexdigest()

            def fake_request(method: str, endpoint: str, **kwargs) -> HttpResult:
                data = kwargs.get("data") or b""
                calls.append((method, endpoint, len(data)))
                if method == "PUT" and endpoint == "fs/content":
                    return HttpResult(
                        201,
                        {"Content-Type": "application/json"},
                        json.dumps({"created": True}).encode(),
                    )
                if method == "POST" and endpoint == "uploads":
                    body = json.loads(data)
                    self.assertEqual(len(large.read_bytes()), body["size"])
                    self.assertEqual(expected_digest, body["sha256"])
                    return HttpResult(
                        201,
                        {"Content-Type": "application/json"},
                        json.dumps(
                            {
                                "upload_id": "upload_test",
                                "offset": 0,
                                "size": body["size"],
                                "sha256": body["sha256"],
                            }
                        ).encode(),
                    )
                if method == "PATCH" and endpoint == "uploads/upload_test":
                    offset = int(kwargs["headers"]["Upload-Offset"])
                    return HttpResult(
                        200,
                        {"Content-Type": "application/json"},
                        json.dumps({"offset": offset + len(data)}).encode(),
                    )
                if method == "POST" and endpoint == "uploads/upload_test/commit":
                    return HttpResult(
                        201,
                        {"Content-Type": "application/json"},
                        json.dumps({"created": True, "sha256": expected_digest}).encode(),
                    )
                raise AssertionError(f"unexpected request: {method} {endpoint}")

            client = openkapsel_upload.UploadClient(
                base_url="https://workspace.invalid/w/read",
                control_token="control",
                plan_id=1,
                taskname="upload",
                message="Upload test files",
                retries=0,
                retry_delay=0,
            )
            limits = openkapsel_upload.UploadLimits(
                direct_bytes=4,
                request_bytes=3,
                chunk_bytes=3,
            )
            with patch.object(openkapsel_upload, "api_request", side_effect=fake_request):
                client.upload_file(small, "small.bin", limits=limits)
                client.upload_file(large, "large.bin", limits=limits)

            self.assertEqual(("PUT", "fs/content", 4), calls[0])
            large_calls = calls[1:]
            self.assertEqual(("POST", "uploads"), large_calls[0][:2])
            self.assertEqual([3, 3, 1], [size for method, _path, size in large_calls if method == "PATCH"])
            self.assertEqual(("POST", "uploads/upload_test/commit"), large_calls[-1][:2])

    def test_directory_scan_applies_filters_before_hashing_and_rejects_root_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "site"
            (source / "src").mkdir(parents=True)
            (source / "docs").mkdir()
            (source / "node_modules").mkdir()
            (source / "src" / "main.py").write_text("print('ok')", encoding="utf-8")
            (source / "src" / "scratch.tmp").write_text("skip", encoding="utf-8")
            (source / "docs" / "readme.md").write_text("skip", encoding="utf-8")
            (source / "node_modules" / "package.py").write_text("skip", encoding="utf-8")

            result = openkapsel_upload_tree.scan_sources(
                [source],
                "release",
                openkapsel_upload_tree.UploadFilter(["*.py"], ["*.tmp", "node_modules"]),
            )
            self.assertEqual(
                ["release/site/src/main.py"],
                [item.destination for item in result.files],
            )
            self.assertIn("release/site/docs", result.directories)
            self.assertNotIn("release/site/node_modules", result.directories)
            self.assertEqual(
                ("release/site/docs",),
                openkapsel_upload_tree.directories_requiring_creation(
                    result.directories,
                    [item.destination for item in result.files],
                ),
            )

            first = root / "first" / "same"
            second = root / "second" / "same"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "same destination root"):
                openkapsel_upload_tree.scan_sources(
                    [first, second],
                    "release",
                    openkapsel_upload_tree.UploadFilter([], []),
                )

    def test_directory_scan_hides_dotfiles_unless_explicitly_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "site"
            (source / ".github" / "workflows").mkdir(parents=True)
            (source / "src" / ".cache").mkdir(parents=True)
            (source / "src").mkdir(exist_ok=True)
            (source / ".gitignore").write_text("cache\n", encoding="utf-8")
            (source / ".openkapsel.env").write_text("secret\n", encoding="utf-8")
            (source / ".github" / "workflows" / "ci.yml").write_text("ci\n", encoding="utf-8")
            (source / "src" / ".cache" / "item.bin").write_bytes(b"cache")
            (source / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")

            default = openkapsel_upload_tree.scan_sources(
                [source], "release", openkapsel_upload_tree.UploadFilter([], [])
            )
            self.assertEqual(
                ["release/site/src/main.py"],
                [item.destination for item in default.files],
            )

            selected = openkapsel_upload_tree.scan_sources(
                [source],
                "release",
                openkapsel_upload_tree.UploadFilter([".gitignore", ".github/**"], []),
            )
            self.assertEqual(
                [
                    "release/site/.github/workflows/ci.yml",
                    "release/site/.gitignore",
                ],
                [item.destination for item in selected.files],
            )

            explicit = openkapsel_upload_tree.scan_sources(
                [source / ".gitignore"],
                "release",
                openkapsel_upload_tree.UploadFilter([], []),
            )
            self.assertEqual(
                ["release/.gitignore"],
                [item.destination for item in explicit.files],
            )
            protected = openkapsel_upload_tree.scan_sources(
                [source / ".openkapsel.env"],
                "release",
                openkapsel_upload_tree.UploadFilter([".openkapsel.env"], []),
            )
            self.assertEqual((), protected.files)


if __name__ == "__main__":
    unittest.main()

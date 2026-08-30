from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from openkapsel.cgroups import SandboxLimits, TokenCgroupManager
from openkapsel.security import (
    LEGACY_PASSWORD_SALT,
    PASSWORD_HASH_ITERATIONS,
    hash_password,
    password_hash_needs_upgrade,
    verify_password,
)
from openkapsel.server import ServerConfig, TaskRegistry, load_config


class ConfigurationTests(unittest.TestCase):
    def test_cgroup_v2_configuration_and_process_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cgroup_root = base / "cgroup"
            service = cgroup_root / "service"
            proc_root = base / "proc"
            (proc_root / "self").mkdir(parents=True)
            service.mkdir(parents=True)
            (cgroup_root / "cgroup.controllers").write_text(
                "cpu memory pids\n", encoding="ascii"
            )
            (service / "cgroup.controllers").write_text(
                "cpu memory pids\n", encoding="ascii"
            )
            (proc_root / "self/cgroup").write_text("0::/service\n", encoding="ascii")
            (proc_root / "stat").write_text("btime 1000\n", encoding="ascii")

            manager = TokenCgroupManager(
                enabled=True,
                cgroup_root=cgroup_root,
                proc_root=proc_root,
            )
            self.assertTrue(manager.available, manager.unavailable_reason)
            limits = SandboxLimits(max_processes=32, memory_bytes=256 * 1024 * 1024, cpu_percent=150)
            procs_file = manager.configure("secret-token", limits)
            group = procs_file.parent
            self.assertNotIn("secret-token", group.name)
            self.assertEqual("32", (group / "pids.max").read_text().strip())
            self.assertEqual(str(256 * 1024 * 1024), (group / "memory.max").read_text().strip())
            self.assertEqual("150000 100000", (group / "cpu.max").read_text().strip())

            bubblewrap_limits = SandboxLimits(
                max_processes=32,
                memory_bytes=256 * 1024 * 1024,
                cpu_percent=150,
                process_overhead=16,
            )
            manager.configure("bubblewrap-token", bubblewrap_limits)
            bubblewrap_group = (
                service
                / f"openkapsel-token-{manager.token_key('bubblewrap-token')}"
            )
            self.assertEqual("48", (bubblewrap_group / "pids.max").read_text().strip())
            self.assertEqual(32, bubblewrap_limits.public()["max_processes"])
            self.assertEqual(16, bubblewrap_limits.public()["process_overhead"])
            self.assertEqual(
                48, bubblewrap_limits.public()["effective_max_processes"]
            )

            process = proc_root / "123"
            process.mkdir()
            (process / "status").write_text(
                "Name:\tpython3\nState:\tS (sleeping)\nPPid:\t1\nVmRSS:\t2048 kB\n",
                encoding="ascii",
            )
            stat_fields = [
                "S", "1", "123", "123", "0", "0", "0", "0", "0", "0", "0",
                "50", "25", "0", "0", "20", "0", "1", "0", "100",
            ]
            (process / "stat").write_text(
                "123 (python3) " + " ".join(stat_fields) + "\n", encoding="ascii"
            )
            (process / "cmdline").write_bytes(b"python3\0worker.py\0")
            procs_file.write_text("123\n", encoding="ascii")
            (group / "pids.current").write_text("1\n", encoding="ascii")
            (group / "memory.current").write_text("2097152\n", encoding="ascii")
            (group / "memory.peak").write_text("3145728\n", encoding="ascii")
            (group / "cpu.stat").write_text("usage_usec 9000\n", encoding="ascii")
            (group / "memory.events").write_text("oom_kill 0\n", encoding="ascii")

            payload = manager.inspect(
                "secret-token",
                limits,
                task_roots={123: "task_example"},
                offset=0,
                limit=10,
            )
            self.assertTrue(payload["available"])
            self.assertEqual(1, payload["usage"]["processes_current"])
            self.assertEqual(2 * 1024 * 1024, payload["usage"]["memory_current_bytes"])
            self.assertEqual("task_example", payload["processes"][0]["task_id"])
            self.assertEqual(["python3", "worker.py"], payload["processes"][0]["command"])

            workspace = base / "workspace"
            workspace.mkdir()
            registry = TaskRegistry(
                ServerConfig(root=workspace, sandbox_cgroup_enabled=True),
                manager,
            )
            task = registry.start(
                "printf cgroup-launcher-ok",
                workspace,
                5,
                owner_token="secret-token",
                argv=("/bin/sh", "-c", "printf cgroup-launcher-ok"),
                sandboxed=True,
                sandbox_backend="podman",
                resource_limits=limits,
            )
            deadline = time.monotonic() + 5
            while task.status != "finished" and time.monotonic() < deadline:
                time.sleep(0.01)
            result = task.serialize()
            self.assertEqual("finished", result["status"])
            self.assertEqual(0, result["exit_code"])
            self.assertEqual("cgroup-launcher-ok", result["stdout"])
            self.assertTrue(result["resource_limited"])
            self.assertEqual("podman", result["sandbox_backend"])
            registry.close()

    def test_pbkdf2_hash_legacy_compatibility_and_config_loading(self) -> None:
        encoded = hash_password("correct-horse-battery")
        self.assertTrue(encoded.startswith(f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}$"))
        self.assertTrue(verify_password("correct-horse-battery", encoded))
        self.assertFalse(verify_password("wrong-password", encoded))
        self.assertNotEqual(encoded, hash_password("correct-horse-battery"))
        self.assertFalse(password_hash_needs_upgrade(encoded))
        legacy_hash = hashlib.sha256(
            f"{LEGACY_PASSWORD_SALT}\0correct-horse-battery".encode("utf-8")
        ).hexdigest()
        self.assertTrue(verify_password("correct-horse-battery", legacy_hash))
        self.assertTrue(password_hash_needs_upgrade(legacy_hash))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            workspace.mkdir()
            defaults = ServerConfig(root=workspace)
            self.assertEqual(16, defaults.max_concurrent_shell_tasks)
            self.assertEqual(8, defaults.max_concurrent_shell_tasks_per_token)
            self.assertEqual(60 * 60, defaults.finished_task_retention_seconds)
            self.assertEqual(4, defaults.max_finished_tasks_per_token)
            self.assertEqual(24 * 60 * 60, defaults.share_ttl_seconds)
            self.assertEqual(10, defaults.max_share_entries)
            self.assertEqual(256 * 1024 * 1024, defaults.max_share_bytes)
            self.assertIn("github.com", defaults.default_network_domains)
            self.assertIn("npm.pkg.github.com", defaults.default_network_domains)
            self.assertIn("pypi.org", defaults.default_network_domains)
            self.assertIn("files.pythonhosted.org", defaults.default_network_domains)
            self.assertIn("registry.npmjs.org", defaults.default_network_domains)
            self.assertIn("registry.yarnpkg.com", defaults.default_network_domains)
            self.assertIn("nodejs.org", defaults.default_network_domains)
            self.assertEqual(
                (base / "network-proxies").resolve(),
                defaults.network_proxy_dir,
            )
            config_path = base / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "workspace_name": "Configured Workspace",
                        "workspace_root": "workspace",
                        "listen_host": "127.0.0.1",
                        "listen_port": 9010,
                        "url_base_path": "/agent",
                        "preview_base_url": "https://preview.example.test",
                        "token_data_file": "state/tokens.json",
                        "upload_state_dir": "state/uploads",
                        "share_dir": "state/shares",
                        "task_history_dir": "state/tasks",
                        "workspace_image_socket": "state/images.sock",
                        "finished_task_retention_minutes": 30,
                        "max_finished_tasks_per_token": 3,
                        "bubblewrap_path": "/custom/bin/bwrap",
                        "podman_path": "/custom/bin/podman",
                        "podman_image": "registry.example.test/runtime@sha256:" + "a" * 64,
                        "podman_runtime": "crun",
                        "sandbox_backends": ["bubblewrap", "podman"],
                        "sandbox_default_backend": "podman",
                        "max_direct_upload_mb": 16,
                        "max_file_size_gb": 5,
                        "rest_chunk_size_mb": 2,
                        "mcp_binary_chunk_kb": 128,
                        "upload_ttl_hours": 12,
                        "max_incomplete_upload_gb": 8,
                        "max_text_replace_mb": 10,
                        "max_concurrent_transfers": 3,
                        "max_concurrent_shell_tasks": 6,
                        "max_concurrent_shell_tasks_per_token": 4,
                        "sandbox_cgroup_enabled": True,
                        "max_search_results": 250,
                        "max_search_file_mb": 6,
                        "max_tree_nodes": 1200,
                        "max_batch_file_operations": 125,
                        "share_ttl_hours": 36,
                        "max_share_entries": 7,
                        "max_share_mb": 192,
                        "max_recursion_depth": 12,
                        "admin": {
                            "username": "operator",
                            "password_sha256": legacy_hash,
                        },
                    }
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config_path),
                host=None,
                port=None,
                root=None,
                token=None,
                name=None,
                token_data_file=None,
                public_base_url=None,
            )
            host, port, config = load_config(args)
            self.assertEqual("127.0.0.1", host)
            self.assertEqual(9010, port)
            self.assertEqual(workspace.resolve(), config.root)
            self.assertEqual("/agent", config.url_base_path)
            self.assertEqual("https://preview.example.test", config.preview_base_url)
            self.assertEqual((base / "state" / "tokens.json").resolve(), config.token_data_file)
            self.assertEqual((base / "state" / "uploads").resolve(), config.upload_state_dir)
            self.assertEqual((base / "state" / "shares").resolve(), config.share_dir)
            self.assertEqual((base / "state" / "tasks").resolve(), config.task_history_dir)
            self.assertEqual((base / "state" / "images.sock").resolve(), config.workspace_image_socket)
            self.assertEqual(30 * 60, config.finished_task_retention_seconds)
            self.assertEqual(3, config.max_finished_tasks_per_token)
            self.assertEqual(Path("/custom/bin/bwrap"), config.bubblewrap_path)
            self.assertEqual(Path("/custom/bin/podman"), config.podman_path)
            self.assertEqual(("bubblewrap", "podman"), config.sandbox_backends)
            self.assertEqual("podman", config.sandbox_default_backend)
            self.assertEqual("crun", config.podman_runtime)
            self.assertEqual(16 * 1024 * 1024, config.max_direct_upload_bytes)
            self.assertEqual(5 * 1024 * 1024 * 1024, config.max_file_bytes)
            self.assertEqual(2 * 1024 * 1024, config.upload_chunk_bytes)
            self.assertEqual(128 * 1024, config.mcp_binary_chunk_bytes)
            self.assertEqual(12 * 60 * 60, config.upload_ttl_seconds)
            self.assertEqual(8 * 1024 * 1024 * 1024, config.max_incomplete_upload_bytes)
            self.assertEqual(10 * 1024 * 1024, config.max_text_replace_bytes)
            self.assertEqual(3, config.max_concurrent_transfers)
            self.assertEqual(6, config.max_concurrent_shell_tasks)
            self.assertEqual(4, config.max_concurrent_shell_tasks_per_token)
            self.assertTrue(config.sandbox_cgroup_enabled)
            self.assertEqual(250, config.max_search_results)
            self.assertEqual(6 * 1024 * 1024, config.max_search_file_bytes)
            self.assertEqual(1200, config.max_tree_nodes)
            self.assertEqual(125, config.max_batch_file_operations)
            self.assertEqual(36 * 60 * 60, config.share_ttl_seconds)
            self.assertEqual(7, config.max_share_entries)
            self.assertEqual(192 * 1024 * 1024, config.max_share_bytes)
            self.assertEqual(12, config.max_recursion_depth)
            self.assertEqual("operator", config.admin_username)

    def test_password_script_generates_and_saves_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(
                json.dumps({"admin": {"username": "admin", "password_sha256": "unset"}}),
                encoding="utf-8",
            )
            original_owner = (config_path.stat().st_uid, config_path.stat().st_gid)
            script = Path(__file__).resolve().parent.parent / "set_password.py"
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--config",
                    str(config_path),
                    "--generate-username",
                    "--generate",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            generated = result.stdout.split("Generated admin password (shown once): ", 1)[1].strip()
            generated_username = result.stdout.split(
                "Generated admin username (shown once): ", 1
            )[1].splitlines()[0]
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(16, len(generated))
            self.assertEqual(8, len(generated_username))
            self.assertRegex(generated, r"^[A-Za-z0-9_-]{16}$")
            self.assertRegex(generated_username, r"^[A-Za-z0-9_-]{8}$")
            self.assertEqual(generated_username, payload["admin"]["username"])
            self.assertTrue(verify_password(generated, payload["admin"]["password_hash"]))
            self.assertNotIn("password_sha256", payload["admin"])
            self.assertNotIn(generated, config_path.read_text(encoding="utf-8"))
            self.assertEqual(0o600, config_path.stat().st_mode & 0o777)
            self.assertEqual(original_owner, (config_path.stat().st_uid, config_path.stat().st_gid))

if __name__ == "__main__":
    unittest.main()

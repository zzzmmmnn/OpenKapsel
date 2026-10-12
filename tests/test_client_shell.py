"""Native client command and stdin behavior on Linux, macOS, and Windows."""

import base64
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks


class ClientCommandTests(unittest.TestCase):
    def test_disabled_client_accepts_only_explicit_unsandboxed_short_and_long_shell(self):
        from openkapsel.client_runtime.shared_job_tasks import SharedClientTasks
        from openkapsel.job_manager import shutdown
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "export"
            root.mkdir()
            home = Path(directory) / "manager"
            file_class = ClientFiles
            if os.name == "nt":
                from openkapsel.client_runtime.client_windows import WindowsClientFiles
                file_class = WindowsClientFiles
            files = file_class(root, writable=True)
            legacy = ClientTasks(files, enabled=False, sandbox=True)
            tasks = SharedClientTasks(legacy, url="ws://localhost/mapping-connect/" + "A" * 24,
                                      home=home, job_sandbox={"type": "current_user"})
            try:
                for flag in (False, None, "true", 1):
                    with self.subTest(flag=flag), self.assertRaises(OSError):
                        tasks.dispatch("task_start", {"task_id": "&Ab12&", "command": "echo denied", "unsandboxed": flag})
                with self.assertRaises(OSError):
                    tasks.dispatch("task_start", {"task_id": "rpcjob123", "rpc": {}, "unsandboxed": True})
                for tid, timeout in (("&Ab12&", 120), ("&Ab13&", 121)):
                    with self.subTest(timeout=timeout):
                        tasks.dispatch("task_start", {"task_id": tid, "command": "echo approved", "timeout_seconds": timeout, "unsandboxed": True})
                        until = time.monotonic() + 10
                        while time.monotonic() < until:
                            result = tasks.dispatch("task_get", {"task_id": tid})
                            if not result["running"]:
                                break
                            time.sleep(.02)
                        self.assertFalse(result["running"])
                        self.assertEqual(0, result["exit_code"])
                        self.assertIn(b"approved", base64.b64decode(result["output"]))
                self.assertTrue(legacy.sandbox)
                self.assertFalse(legacy.enabled)
            finally:
                tasks.close()
                files.close()
                try:
                    shutdown(home, force=True)
                except (OSError, ConnectionError):
                    pass
                if os.name != "nt":
                    from openkapsel.job_manager import endpoint
                    socket_path, _ = endpoint(home)
                    until = time.monotonic() + 5
                    while Path(socket_path).exists() and time.monotonic() < until:
                        time.sleep(.02)

    def test_command_and_combined_input_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            file_class = ClientFiles
            if os.name == "nt":
                from openkapsel.client_runtime.client_windows import WindowsClientFiles
                file_class = WindowsClientFiles
            files = file_class(Path(directory), writable=True)
            tasks = ClientTasks(files, enabled=True, sandbox=False)
            try:
                tasks.dispatch("task_start", {"task_id": "command123", "command": "echo unified"})
                tasks.tasks["command123"]["done"].wait(10)
                result = tasks.dispatch("task_get", {"task_id": "command123"})
                self.assertFalse(result["running"])
                self.assertIn(b"unified", base64.b64decode(result["output"]))
                if os.name == "nt":
                    tasks.dispatch("task_start", {"task_id": "quotes5678", "command": f'"{sys.executable}" -c "print(12345)"'})
                    tasks.tasks["quotes5678"]["done"].wait(10)
                    quoted = tasks.dispatch("task_get", {"task_id": "quotes5678"})
                    self.assertEqual(0, quoted["exit_code"])
                    self.assertIn(b"12345", base64.b64decode(quoted["output"]))
                with self.assertRaises(OSError):
                    tasks.dispatch("task_stdin", {"task_id": "command123", "data": ""})
                tasks.dispatch("task_start", {"task_id": "stdin12345", "argv": [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"]})
                data = b"final chunk\r\n"
                tasks.dispatch("task_stdin", {"task_id": "stdin12345", "data": base64.b64encode(data).decode(), "eof": True})
                tasks.tasks["stdin12345"]["done"].wait(10)
                result = tasks.dispatch("task_get", {"task_id": "stdin12345"})
                self.assertEqual(data, base64.b64decode(result["output"]))
                self.assertTrue(tasks.capabilities()["shell_command"])
            finally:
                tasks.close()
                files.close()


if __name__ == "__main__":
    unittest.main()

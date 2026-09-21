"""Native client command and stdin behavior on Linux, macOS, and Windows."""

import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.client_tasks import ClientTasks


class ClientCommandTests(unittest.TestCase):
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

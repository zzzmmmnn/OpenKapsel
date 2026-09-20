from __future__ import annotations

import base64
import errno
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from openkapsel.client import proxy_options, run_once
from openkapsel.client_files import ClientFiles
from openkapsel.client_tasks import ClientTasks
from openkapsel.mapping_manager import MappingManager
from openkapsel.mapping_store import MappingStore
from openkapsel.mapping_transport import ProviderSession
from openkapsel.mapping_transfers import FileTransferManager


@unittest.skipIf(os.name == "nt", "POSIX descriptor tests; see test_client_windows")
class MappingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.export = self.root / "export"
        self.export.mkdir()
        self.files = ClientFiles(self.export, writable=True)

    def tearDown(self):
        self.files.close()
        self.temp.cleanup()

    def test_registry_credential_rotation_and_workspace_binding(self):
        store = MappingStore(self.root / "state" / "mappings.sqlite3")
        row, key = store.create("project", "laptop", writable=True)
        self.assertEqual(store.authenticate(row["id"], key)["workspace"], "project")
        self.assertNotIn("secret_hash", store.list()[0])
        _, replacement = store.update(row["id"], rotate=True)
        with self.assertRaises(PermissionError):
            store.authenticate(row["id"], key)
        store.authenticate(row["id"], replacement)
        store.update(row["id"], enabled=False)
        with self.assertRaises(PermissionError):
            store.authenticate(row["id"], replacement)

    def test_containment_and_no_symlink_following(self):
        outside = self.root / "outside"
        outside.write_text("private")
        (self.export / "link").symlink_to(outside)
        for path in ("../outside", "/etc/passwd", "a\x00b", "C:\\secret", ".openkapsel/context/data"):
            with self.subTest(path=path), self.assertRaises(OSError):
                self.files.dispatch("stat", {"path": path})
        with self.assertRaises(OSError):
            self.files.dispatch("open", {"path": "link"})
        self.assertEqual(self.files.dispatch("list", {})["names"], [])

    def test_directory_replacement_cannot_escape(self):
        (self.export / "sub").mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "private").write_text("secret")
        with self.files.paths.parent(self.export / "sub" / "new") as anchored:
            (self.export / "sub").rename(self.export / "old")
            (self.export / "sub").symlink_to(outside, target_is_directory=True)
            fd = anchored.open(os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, b"safe")
            os.close(fd)
        self.assertFalse((outside / "new").exists())
        self.assertEqual((self.export / "old" / "new").read_text(), "safe")

    def test_read_write_rename_and_readonly(self):
        handle = self.files.dispatch("create", {"path": "a", "mode": "rw"})
        self.files.dispatch("write", {"handle": handle, "data": base64.b64encode(b"hello").decode()})
        self.assertEqual(base64.b64decode(self.files.dispatch("read", {"handle": handle, "size": 10})), b"hello")
        self.files.dispatch("close", {"handle": handle})
        self.files.dispatch("rename", {"path": "a", "destination": "b"})
        self.files.writable = False
        for operation, args in (("unlink", {"path": "b"}), ("open", {"path": "b", "mode": "w"}),
                                ("open", {"path": "b", "mode": "r", "truncate": True})):
            with self.subTest(operation=operation), self.assertRaises(OSError):
                self.files.dispatch(operation, args)
        self.assertEqual((self.export / "b").read_text(), "hello")

    def test_recycle_lives_on_client_and_can_be_restored(self):
        (self.export / "sample").write_text("recover me")
        record = self.files.dispatch("recycle", {"path": "sample"})
        self.assertFalse((self.export / "sample").exists())
        result = self.files.dispatch("recycle_list", {})
        self.assertEqual(result["total"], 1)
        self.assertTrue((self.export / ".openkapsel" / "recycle").is_dir())
        self.files.dispatch("recycle_restore", {"recycle_id": record["recycle_id"]})
        self.assertEqual((self.export / "sample").read_text(), "recover me")
        record = self.files.dispatch("recycle", {"path": "sample"})
        self.assertTrue(self.files.dispatch("recycle_purge", {"recycle_id": record["recycle_id"]})["purged"])
        self.assertEqual(self.files.dispatch("recycle_list", {})["total"], 0)

    def test_proxy_schemes_and_no_credentials_in_options_errors(self):
        for scheme in ("socks4", "socks5", "http"):
            options = proxy_options(f"{scheme}://user:secret@127.0.0.1:21080")
            self.assertEqual(options["proxy_type"], scheme)
            self.assertEqual(options["http_proxy_port"], 21080)
        with self.assertRaises(ValueError):
            proxy_options("ftp://127.0.0.1:1")

    def test_shell_private_scan_does_not_walk_remote_exports(self):
        from openkapsel.shell_execution import sandbox_hidden_paths
        remote = self.export / "remote"
        remote.mkdir()
        (remote / "project").mkdir()
        (remote / "project" / ".openkapsel").mkdir()
        hidden = sandbox_hidden_paths(self.export, mapping_roots=(remote,))
        self.assertEqual(hidden, (self.export / ".openkapsel",))

    def test_execution_requires_explicit_policy_and_no_sandbox_fallback(self):
        tasks = ClientTasks(self.files)
        with self.assertRaises(OSError):
            tasks.dispatch("task_start", {"task_id": "a" * 24, "argv": [sys.executable, "-V"]})
        with patch("shutil.which", return_value=None), self.assertRaises(ValueError):
            ClientTasks(self.files, enabled=True)

    def test_native_task_output_is_bounded_and_retrievable(self):
        tasks = ClientTasks(self.files, enabled=True, sandbox=False)
        args = {"task_id": "a" * 24, "argv": [sys.executable, "-c", "print('from-client')"], "cwd": "."}
        try:
            first = tasks.dispatch("task_start", args)
            self.assertEqual(first["location"], "client")
            self.assertEqual(tasks.dispatch("task_start", args)["task_id"], first["task_id"])
            for _ in range(100):
                result = tasks.dispatch("task_get", {"task_id": first["task_id"]})
                if result["finished_at"]:
                    break
                time.sleep(.02)
            self.assertEqual(result["exit_code"], 0)
            self.assertIn(b"from-client", base64.b64decode(result["output"]))
        finally:
            tasks.close()

    def test_offline_and_stale_handles_fail_closed(self):
        workspace = self.root / "workspaces"
        workspace.mkdir()
        (workspace / "project").mkdir()
        manager = MappingManager(workspace, self.root / "state")
        row, _ = manager.store.create("project", "laptop")
        with self.assertRaises(OSError) as error:
            manager.call(row["id"], "stat", {"path": "."})
        self.assertEqual(error.exception.errno, errno.EHOSTDOWN)
        class Session:
            generation = "new"
            closed = False
        manager.sessions[row["id"]] = Session()
        with self.assertRaises(OSError) as error:
            manager.call(row["id"], "read", {"handle": "old:1", "size": 1})
        self.assertEqual(error.exception.errno, errno.ESTALE)

    def test_rename_preserves_identity_rejects_collisions_and_rolls_back(self):
        workspace = self.root / "workspaces"
        (workspace / "project").mkdir(parents=True)
        manager = MappingManager(workspace, self.root / "state")
        row, key = manager.store.create("project", "before", writable=True)
        original = workspace / "project" / "before"
        original.mkdir()
        with patch.object(manager, "mount"), patch.object(manager, "unmount"):
            changed = manager.rename(row["id"], "after")
            self.assertEqual(changed["id"], row["id"])
            self.assertEqual(manager.store.authenticate(row["id"], key)["name"], "after")
            self.assertFalse(original.exists())
            occupied = workspace / "project" / "occupied"
            occupied.mkdir()
            (occupied / "keep").write_text("unchanged")
            with self.assertRaises(FileExistsError):
                manager.rename(row["id"], "occupied")
            self.assertEqual((occupied / "keep").read_text(), "unchanged")
            with self.assertRaises(ValueError):
                manager.rename(row["id"], "../escape")
        with patch.object(manager, "unmount"), patch.object(manager, "mount", side_effect=[OSError("mount failed"), None]):
            with self.assertRaises(OSError):
                manager.rename(row["id"], "failed")
        self.assertEqual(manager.store.authenticate(row["id"], key)["name"], "after")
        self.assertTrue((workspace / "project" / "after").is_dir())
        self.assertFalse((workspace / "project" / "failed").exists())

    def test_task_deadline_covers_descendants_after_leader_exit(self):
        tasks = ClientTasks(self.files, enabled=True, sandbox=False, max_tasks=1)
        try:
            result = tasks.dispatch("task_start", {"task_id": "descendant-test", "timeout_seconds": .5,
                "argv": [sys.executable, "-c", "import os,time; pid=os.fork(); time.sleep(30) if pid == 0 else None"]})
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = tasks.dispatch("task_get", {"task_id": result["task_id"]})
                if result["finished_at"]:
                    break
                time.sleep(.02)
            self.assertIsNotNone(result["finished_at"])
            self.assertFalse(result["running"])
        finally:
            tasks.close()

    def test_host_helper_only_launches_fixed_unprivileged_worker(self):
        from openkapsel.mapping_host import HostMappingMounts
        from openkapsel.workspace_images import WorkspaceImageError
        root = self.root / "workspace"
        root.mkdir()
        parent = root / "project space"
        parent.mkdir()
        (parent / "laptop").mkdir()
        broker = self.root / "mapping-run"
        broker.mkdir()
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(broker / "broker.sock"))
        helper = HostMappingMounts(root, os.getuid(), os.getgid())
        request = {"action": "mapping_mount", "id": "a" * 24, "workspace": parent.name, "name": "laptop"}
        try:
            with patch.object(helper, "mounted", side_effect=[False, True]), patch.object(helper, "run") as run:
                self.assertTrue(helper.dispatch(request)["mounted"])
                argv = run.call_args.args[0]
                self.assertEqual(argv[argv.index("--uid") + 1], str(os.getuid()))
                self.assertIn("openkapsel.mapping_fuse", argv)
                self.assertEqual(argv[-1], str(parent / "laptop"))
            for field, value in (("workspace", "../outside"), ("workspace", "/root"),
                                 ("id", "--evil"), ("name", "../outside"), ("action", "arbitrary")):
                with self.subTest(field=field, value=value), patch.object(helper, "run") as run:
                    with self.assertRaises(WorkspaceImageError):
                        helper.dispatch(dict(request, **{field: value}))
                    run.assert_not_called()
            # A stopped worker must never trigger root umount against a path
            # which the unprivileged owner could have swapped concurrently.
            with patch.object(helper, "mounted", return_value=True), patch.object(helper, "run") as run:
                with self.assertRaises(WorkspaceImageError):
                    helper.dispatch(dict(request, action="mapping_unmount"))
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0][0], "systemctl")
        finally:
            sock.close()


class MappingTransportTests(unittest.TestCase):
    def test_real_websocket_client_roundtrip(self):
        self._roundtrip(False)
        self._roundtrip(True)

    def _roundtrip(self, writable):
        try:
            import websocket
        except ImportError:
            self.skipTest("install client extras for transport integration tests")
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "hello.txt").write_text("hello")
            connected = threading.Event()
            sessions = []
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    session = ProviderSession(self)
                    sessions.append(session)
                    connected.set()
                    session.run(lambda: None)
                def log_message(self, *args):
                    pass
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client = threading.Thread(target=run_once, args=({"url": f"ws://127.0.0.1:{server.server_port}/provider",
                                                              "token": "testing", "root": directory,
                                                              "writable": writable, "allow_exec": writable, "sandbox": False},), daemon=True)
            client.start()
            try:
                self.assertTrue(connected.wait(5))
                result = sessions[0].call("stat", {"path": "hello.txt"})
                self.assertEqual(result["st_size"], 5)
                result = sessions[0].call("list", {"path": "."})
                self.assertEqual(result["names"], ["hello.txt"])
                self.assertEqual(sessions[0].capabilities["file_api"]["version"], 3)
                self.assertEqual(sessions[0].capabilities["git_api"], {"version": 2, "read_only": True})
                self.assertEqual(sessions[0].capabilities["rpc"]["file"]["state"], "available")
                self.assertEqual(sessions[0].capabilities["rpc"]["git"]["state"], "available")
                self.assertEqual(sessions[0].capabilities["rpc"]["archive"]["state"], "available")
                self.assertFalse(sessions[0].capabilities["rpc"]["archive"]["read_only"])
                self.assertIn("archive", sessions[0].capabilities["rpc"]["archive"]["description"].lower())
                archive_specs = sessions[0].capabilities["rpc"]["archive"]["operation_specs"]
                self.assertEqual(
                    ["path", "member"],
                    archive_specs["read"]["input_schema"]["required"],
                )
                self.assertFalse(archive_specs["read"]["write"])
                self.assertEqual("sync", archive_specs["read"]["execution"])
                self.assertTrue(archive_specs["create"]["write"])
                self.assertEqual("task", archive_specs["create"]["execution"])
                result = sessions[0].call("api_fs_stat", {"query": {"path": ["hello.txt"], "fields": ["sha256,size"]}, "display_root": "/workspace/client"})
                self.assertEqual(result["status"], 200)
                self.assertEqual(result["body"]["size"], 5)
                self.assertEqual(result["body"]["path"], "/workspace/client/hello.txt")
                self.assertEqual(len(result["body"]["sha256"]), 64)
                result = sessions[0].call("api_fs_read", {"query": {"path": ["missing"]}})
                self.assertEqual(result["status"], 404)
                import shutil
                if shutil.which("git"):
                    from tests.test_git_operations import make_repo
                    repo = Path(directory) / "repo"
                    repo.mkdir()
                    make_repo(repo)
                    result = sessions[0].call("git_log", {"cwd": "repo", "options": {"limit": 1}})
                    self.assertEqual(200, result["status"], result)
                    result = result["body"]
                    self.assertFalse(result["running"], result)
                    self.assertEqual(0, result["exit_code"], result)
                    self.assertIn("Initial fixture", result["output"])
                if not writable:
                    with self.assertRaises(OSError):
                        sessions[0].call("api_fs_write", {"body": {"path": "no-write", "content": "no"}})
                    self.assertFalse((Path(directory) / "no-write").exists())
            finally:
                for session in sessions:
                    session.close()
                client.join(5)
                server.shutdown()
                server.server_close()
                thread.join(5)


@unittest.skipIf(os.name == "nt", "server-side transfers require Linux/POSIX")
class FileTransferTests(unittest.TestCase):
    def test_copy_move_and_no_overwrite(self):
        from openkapsel.recycle import RecycleBin
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory).resolve() / "project"
            scope.mkdir()
            source = scope / "source"
            source.mkdir()
            (source / "file").write_bytes(b"a" * 400000)
            mappings = MappingManager(scope.parent, scope.parent / "state")
            transfers = FileTransferManager(scope.parent / "transfers", mappings, RecycleBin, threading.BoundedSemaphore(2))
            try:
                result = transfers.start(source, scope / "copy", scope)
                job = transfers.get(result["id"], scope)
                job["thread"].join(5)
                self.assertEqual(job["state"], "completed", job["error"])
                self.assertEqual((scope / "copy" / "file").read_bytes(), b"a" * 400000)
                moved = transfers.start(source, scope / "moved", scope, move=True)
                job = transfers.get(moved["id"], scope)
                job["thread"].join(5)
                self.assertEqual(job["state"], "completed", job["error"])
                self.assertFalse(source.exists())
                self.assertEqual(RecycleBin(scope).list_items(0, 10)[1], 1)
                conflict = transfers.start(scope / "moved", scope / "copy", scope)
                job = transfers.get(conflict["id"], scope)
                job["thread"].join(5)
                self.assertEqual(job["state"], "interrupted")
                self.assertEqual((scope / "copy" / "file").read_bytes(), b"a" * 400000)
            finally:
                transfers.close()

    def test_resume_after_cancel_and_detect_changed_source(self):
        from openkapsel.recycle import RecycleBin
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory).resolve() / "project"
            scope.mkdir()
            (scope / "source").write_bytes(b"x" * 300000)
            mappings = MappingManager(scope.parent, scope.parent / "state")
            transfers = FileTransferManager(scope.parent / "transfers", mappings, RecycleBin, threading.BoundedSemaphore(2))
            original = transfers._copy_file
            def interrupt(job, *args):
                job["cancel"].set()
                return original(job, *args)
            with patch.object(transfers, "_copy_file", side_effect=interrupt):
                result = transfers.start(scope / "source", scope / "copy", scope)
                job = transfers.get(result["id"], scope)
                job["thread"].join(5)
            self.assertEqual(job["state"], "cancelled")
            transfers.resume(job)
            job["thread"].join(5)
            self.assertEqual(job["state"], "completed", job["error"])
            self.assertEqual((scope / "copy").read_bytes(), b"x" * 300000)
            transfers.close()

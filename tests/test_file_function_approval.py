"""Shared File function policy: scopes are merged and interpreted by Client."""
import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.file_approval import FileApproval, register_file_functions
from openkapsel.execution.function_registry import FunctionRegistry
from openkapsel.errors import ApiError


class FileFunctionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'workspace'
        self.root.mkdir()
        factory = ClientFiles
        if os.name == "nt":
            from openkapsel.client_runtime.client_windows import WindowsClientFiles
            factory = WindowsClientFiles
        self.files = factory(self.root, writable=True)
        self.addCleanup(self.files.close)
        self.functions = FunctionRegistry()
        register_file_functions(self.functions, self.files)

    def grant(self, path=None, old=None, access='read'):
        return self.functions.grant('files.' + access, old_auth=old,
            request={} if path is None else {'path': str(path)})

    def execute(self, auth, operation, body=None, query=None, access='read', **arguments):
        arguments.update(body=body or {}, query=query or {})
        return self.functions.execute('files.' + access,
            {'operation': operation, 'arguments': arguments}, auth=auth)

    def test_prepare_does_not_stat_or_resolve_any_path(self):
        with patch.object(Path, 'resolve', side_effect=AssertionError('must not resolve')), patch.object(
                Path, 'stat', side_effect=AssertionError('must not stat')):
            prepared = self.functions.prepare('files.read', {'path': str(self.base / 'unknown')})
        self.assertTrue(prepared['confirmation_required'])
        self.assertEqual(str(self.base / 'unknown'), prepared['request']['path'])

    def test_two_scopes_are_merged_by_client_and_execute_independently(self):
        first, second = self.base / 'one', self.base / 'two'
        for directory, content in ((first, 'ONE'), (second, 'TWO')):
            directory.mkdir(); (directory / 'text.txt').write_text(content)
        one = self.grant(first)
        two = self.grant(second, old=one)
        self.assertEqual([str(first)], one['paths'])
        self.assertEqual([str(first), str(second)], two['paths'])
        for directory, text in ((first, 'ONE'), (second, 'TWO')):
            result = self.execute(two, 'fs_read_files', {'paths': [str(directory / 'text.txt')]})
            self.assertEqual(200, result['status'], result)
            self.assertEqual(text, result['body']['items'][0]['content'])
        result = self.execute(one, 'fs_read_files', {'paths': [str(second / 'text.txt')]})
        self.assertEqual(404, result['status'])
        self.assertNotIn('TWO', str(result))

    def test_unscoped_grant_cannot_read_external_path(self):
        secret = self.base / 'secret'; secret.write_text('PRIVATE')
        result = self.execute(self.grant(), 'fs_read_files', {'paths': [str(secret)]})
        self.assertEqual(404, result['status'])
        self.assertNotIn('PRIVATE', str(result))

    def test_grant_to_parent_coalesces_child_without_expanding_to_host(self):
        parent = self.base / 'parent'; child = parent / 'child'; child.mkdir(parents=True)
        result = self.grant(parent, old=self.grant(child))
        self.assertEqual([str(parent)], result['paths'])
        with self.assertRaises(ApiError):
            self.grant(Path(self.base.anchor))

    def test_write_requires_write_function_and_preserves_atomic_preconditions(self):
        outside = self.base / 'outside'; outside.mkdir()
        read = self.grant(outside)
        with self.assertRaises(OSError) as raised:
            self.execute(read, 'fs_mkdir', {'path': str(outside / 'forbidden')})
        self.assertEqual(errno.EACCES, raised.exception.errno)
        write = self.grant(outside, access='write')
        target = outside / 'created.txt'
        result = self.execute(write, 'fs_mutate', {'items': [
            {'op': 'file.create', 'path': str(target), 'content': 'FIRST'}]}, access='write')
        self.assertEqual(200, result['status'], result)
        failed = self.execute(write, 'fs_mutate', {'items': [
            {'op': 'file.replace', 'path': str(target), 'content': 'WRONG', 'expected_etag': 'stale'},
            {'op': 'file.create', 'path': str(outside / 'never.txt'), 'content': 'NEVER'}]}, access='write')
        self.assertEqual(412, failed['status'], failed)
        self.assertEqual('FIRST', target.read_text())
        self.assertFalse((outside / 'never.txt').exists())

    def test_protected_config_outside_export_is_hidden_and_not_readable(self):
        outside = self.base / 'outside'; outside.mkdir()
        secret = outside / 'config.json'; secret.write_text('SECRET_CONFIGURATION')
        self.files.global_protected_paths = (*self.files.global_protected_paths, secret)
        auth = self.grant(outside)
        result = self.execute(auth, 'fs_list', query={'path': [str(outside)]})
        self.assertEqual(200, result['status'], result)
        self.assertNotIn('config.json', str(result))
        result = self.execute(auth, 'fs_read_files', {'paths': [str(secret)]})
        self.assertEqual(404, result['status'])
        self.assertNotIn('SECRET_CONFIGURATION', str(result))
        write = self.grant(outside, access='write')
        blocked = self.execute(write, 'fs_mutate', {'items': [
            {'op': 'file.replace', 'path': str(secret),
             'content': 'OVERWRITE', 'expected_etag': '"stale"'}]}, access='write')
        self.assertIn(blocked['status'], (403, 404), blocked)
        self.assertEqual('SECRET_CONFIGURATION', secret.read_text())

    def test_approved_write_elevates_readonly_but_never_explicit_deny(self):
        outside = self.base / 'outside'; outside.mkdir()
        auth = self.grant(outside, access='write')
        readonly = [{'path': str(outside), 'access': 'ro'}]
        allowed = self.execute(auth, 'fs_mkdir', {'path': str(outside / 'created')},
                               access='write', rules=readonly)
        self.assertEqual(201, allowed['status'], allowed)
        self.assertTrue((outside / 'created').is_dir())
        denied = self.execute(auth, 'fs_mkdir', {'path': str(outside / 'blocked')},
                              access='write', rules=[{'path': str(outside), 'access': 'deny'}])
        self.assertEqual(403, denied['status'], denied)
        self.assertFalse((outside / 'blocked').exists())
        # A denied descendant cannot be deleted by mutating its ancestor.
        secret = outside / 'protected'; secret.mkdir()
        denied_descendant = [{'path': str(secret), 'access': 'deny'}]
        denied = self.execute(auth, 'fs_mutate', {'items': [
            {'op': 'path.delete', 'path': str(outside), 'expected_etag': '"unknown"'},
        ]}, access='write', rules=denied_descendant)
        self.assertEqual(403, denied['status'], denied)

    def test_client_readonly_and_external_deny_policy_survives_approval(self):
        from types import SimpleNamespace
        outside = self.base / 'outside'; outside.mkdir()
        protected = outside / 'private'; protected.mkdir()
        (protected / 'secret.txt').write_text('PRIVATE')
        self.files.sandbox_path_rules = (SimpleNamespace(path=str(outside), access='ro'),)
        self.files.sandbox_denied_paths = frozenset({protected})
        auth = self.grant(outside, access='write')
        # Without approved File API the original sandbox read-only policy
        # continues rejecting exactly the same path.
        with self.assertRaises(OSError) as denial:
            self.files.ensure_mutable_path(outside / 'created')
        self.assertEqual(errno.EACCES, denial.exception.errno)
        result = self.execute(auth, 'fs_mkdir', {'path': str(outside / 'created')}, access='write')
        self.assertEqual(201, result['status'], result)
        self.assertTrue((outside / 'created').exists())
        result = self.execute(auth, 'fs_mkdir', {'path': str(protected / 'blocked')}, access='write')
        self.assertEqual(404, result['status'], result)
        self.assertFalse((protected / 'blocked').exists())
        read = self.grant(outside)
        result = self.execute(read, 'fs_list', query={'path': [str(outside)]})
        self.assertEqual(200, result['status'], result)
        self.assertNotIn('private', [entry['name'] for entry in result['body']['entries']])
        hidden = self.execute(read, 'fs_read_files', {'paths': [str(protected / 'secret.txt')]})
        self.assertEqual(404, hidden['status'], hidden)
        self.assertNotIn('PRIVATE', str(hidden))

    def test_descriptor_stream_rechecks_scope_and_read_function_cannot_write(self):
        outside, other = self.base / 'outside', self.base / 'other'
        outside.mkdir(); other.mkdir()
        target = outside / 'text.txt'; target.write_text('STREAM_SECRET')
        auth, different = self.grant(outside), self.grant(other)
        def stream(operation, args, authorization=auth):
            return self.functions.execute('files.read', {'operation': 'file_stream',
                'arguments': {'operation': operation, 'args': args, 'rules': []}}, auth=authorization)
        handle = stream('open', {'path': str(target), 'mode': 'r'})
        self.assertIsInstance(handle, str)
        try:
            with self.assertRaises(ApiError):
                stream('read', {'handle': handle, 'offset': 0, 'size': 32}, different)
            with self.assertRaises(OSError) as denied:
                stream('write', {'handle': handle, 'offset': 0, 'data': 'Tk8='})
            self.assertEqual(errno.EACCES, denied.exception.errno)
            import base64
            content = stream('read', {'handle': handle, 'offset': 0, 'size': 32})
            self.assertEqual(b'STREAM_SECRET', base64.b64decode(content))
        finally:
            stream('close', {'handle': handle})
        self.assertEqual({}, self.files.handles)
        self.assertEqual('STREAM_SECRET', target.read_text())

    def test_symlink_retarget_and_traversal_cannot_change_authorized_directory(self):
        import subprocess
        def link(alias, target):
            if os.name == 'nt':
                subprocess.run(['cmd', '/c', 'mklink', '/J', str(alias), str(target)],
                               check=True, capture_output=True)
            else:
                alias.symlink_to(target, target_is_directory=True)
        one, two = self.base / 'one', self.base / 'two'
        one.mkdir(); two.mkdir()
        (one / 'visible.txt').write_text('VISIBLE'); (two / 'secret.txt').write_text('PRIVATE')
        alias = self.base / 'alias'; link(alias, one)
        auth = self.grant(alias)
        write = self.grant(alias, access='write')
        self.assertEqual([str(one)], auth['paths'])
        self.assertEqual(200, self.execute(auth, 'fs_read_files', {'paths': [str(alias / 'visible.txt')]})['status'])
        created = self.execute(write, 'fs_mutate', {'items': [
            {'op': 'file.create', 'path': str(alias / 'allowed.txt'), 'content': 'APPROVED'}]}, access='write')
        self.assertEqual(200, created['status'], created)
        self.assertEqual('APPROVED', (one / 'allowed.txt').read_text())
        # An explicit deny on the alias spelling cannot be bypassed by
        # following the canonical symlink inside an approved scope.
        denied = self.execute(write, 'fs_mutate', {'items': [
            {'op': 'file.create', 'path': str(alias / 'denied.txt'), 'content': 'BLOCKED'}]},
            access='write', rules=[{'path': str(alias), 'access': 'deny'}])
        self.assertEqual(403, denied['status'], denied)
        self.assertFalse((one / 'denied.txt').exists())
        alias.rmdir() if os.name == 'nt' else alias.unlink()
        link(alias, two)
        failed = self.execute(auth, 'fs_read_files', {'paths': [str(alias / 'secret.txt')]})
        self.assertEqual(404, failed['status'])
        self.assertNotIn('PRIVATE', str(failed))
        failed_write = self.execute(write, 'fs_mutate', {'items': [
            {'op': 'file.create', 'path': str(alias / 'redirected.txt'), 'content': 'LEAK'}]},
            access='write')
        self.assertIn(failed_write['status'], (403, 404), failed_write)
        self.assertFalse((two / 'redirected.txt').exists())
        with self.assertRaises(ApiError):
            self.execute(auth, 'fs_read_files', {'paths': [str(one) + '/../two/secret.txt']})

    def test_write_stream_stat_unlink_and_recycle_use_native_provider(self):
        outside = self.base / 'outside'; outside.mkdir()
        target = outside / 'text.txt'; target.write_text('DATA')
        auth = self.grant(outside, access='write')
        def stream(operation, args):
            return self.functions.execute('files.write', {'operation': 'file_stream',
                'arguments': {'operation': operation, 'args': args, 'rules': []}}, auth=auth)
        self.assertEqual(4, stream('stat', {'path': str(target)})['st_size'])
        stream('unlink', {'path': str(target)})
        self.assertFalse(target.exists())
        # Recoverable delete retains the existing workspace-only contract.
        target = self.root / 'recycle.txt'
        auth = self.grant(access='write')
        target.write_text('RECYCLE')
        # Recycle enters ClientFiles._dispatch directly. Its sandbox ro
        # must not undo an explicitly approved files.write grant.
        from types import SimpleNamespace
        self.files.sandbox_path_rules = (SimpleNamespace(path=str(self.root), access='ro'),)
        with self.assertRaises(OSError):
            self.files.ensure_mutable_path(target)
        details = self.execute(auth, 'fs_stat', query={'path': [str(target)], 'fields': ['etag']}, access='write')
        self.assertEqual(200, details['status'], details)
        result = self.execute(auth, 'fs_mutate', {'items': [
            {'op': 'path.delete', 'path': str(target), 'expected_etag': details['body']['etag']}]}, access='write')
        self.assertEqual(200, result['status'], result)
        self.assertFalse(target.exists())
        self.assertTrue(any((self.root / '.openkapsel' / 'recycle').iterdir()))

    @unittest.skipUnless(os.name == 'nt', 'Windows native junction race')
    def test_windows_scope_ancestor_junction_swap_cannot_redirect_io(self):
        import subprocess
        from openkapsel.client_runtime.approved_file_api import ApprovedFiles
        parent = self.base / 'parent'; scope = parent / 'scope'; scope.mkdir(parents=True)
        other = self.base / 'other'; (other / 'scope').mkdir(parents=True)
        (scope / 'text.txt').write_text('AUTHORIZED')
        (other / 'scope' / 'text.txt').write_text('PRIVATE')
        provider = ApprovedFiles(self.files, self.grant(scope), False, ())
        target = provider.path(str(scope / 'text.txt'))
        parent.rename(self.base / 'saved')
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(parent), str(other)],
                       check=True, capture_output=True)
        # Simulate the swap after policy resolution but before opening.
        with self.assertRaises(OSError):
            descriptor = provider.paths.open(target)
            os.close(descriptor)

    @unittest.skipUnless(os.name == 'nt', 'Windows device and ADS paths')
    def test_windows_approved_paths_reject_devices_and_ads_before_resolution(self):
        auth = self.grant()
        for name in ('NUL', 'con.txt', 'COM¹', 'LPT³.log', 'text.txt:stream', 'bad. '):
            with self.subTest(name=name), patch.object(Path, 'resolve',
                    side_effect=AssertionError('invalid path reached filesystem resolution')):
                with self.assertRaises(ApiError):
                    FileApproval.check(str(self.root / name), self.root, auth)
                with self.assertRaises(ApiError):
                    self.functions.prepare('files.read', {'path': str(self.root / name)})


if __name__ == '__main__':
    unittest.main()

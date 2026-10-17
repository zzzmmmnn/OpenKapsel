"""Real HTTP/browser and WebSocket acceptance tests for function approvals."""
import json
import os
import tempfile
import time
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests import test_capability_http as capability_fixture
from tests import test_shell_routing as shell_fixture


@unittest.skipIf(os.name == 'nt', 'HTTP server is POSIX-only')
class FunctionApprovalHTTPTests(unittest.TestCase):
    setUp = shell_fixture.UnifiedShellHTTPTests.setUp
    tearDown = shell_fixture.UnifiedShellHTTPTests.tearDown
    request = shell_fixture.UnifiedShellHTTPTests.request
    api = shell_fixture.UnifiedShellHTTPTests.api
    form = shell_fixture.UnifiedShellHTTPTests.form
    ownership = capability_fixture.CapabilityHTTPTests.ownership
    configure = capability_fixture.CapabilityHTTPTests.configure
    approval = capability_fixture.CapabilityHTTPTests.approval
    approve = capability_fixture.CapabilityHTTPTests.approve
    request_file_approval = capability_fixture.CapabilityHTTPTests.request_file_approval
    request_approval = capability_fixture.CapabilityHTTPTests.request_approval
    PASSWORD = capability_fixture.CapabilityHTTPTests.PASSWORD

    def request_function(self, name, arguments, **extra):
        return self.api('/function/approval/request', dict(
            function=name, target='server', args=arguments,
            writer_nonce=self.ownership()[1], **extra))

    def confirm(self, pending):
        location, headers, form, _ = self.approval({'error': {'details': pending}})
        status, _, body = self.form(location, form, headers)
        self.assertEqual(200, status, body)
        return location

    def test_no_prepare_callback_and_opaque_client_merge_over_real_http(self):
        self.configure()
        calls = []
        def grant(old, request, seconds):
            calls.append((old, request, seconds))
            return {'grants': [*(old or {}).get('grants', []),
                    {'resource': request['resource'], 'expires_at': time.time() + seconds}],
                    'client_only': 'SECRET_AUTH'}
        functions = self.server.local_client.functions
        functions.register('demo.write', execute=lambda args, auth: auth, approval_grant=grant)
        for resource in ('first', 'second'):
            status, pending = self.request_function('demo.write', {'resource': resource})
            self.assertEqual(200, status, pending)
            self.assertEqual(0 if resource == 'first' else 1, len(calls))
            self.assertNotIn('SECRET_AUTH', json.dumps(pending))
            location, headers, form, page = self.approval({'error': {'details': pending}})
            self.assertNotIn(b'SECRET_AUTH', page)
            self.assertEqual(403, self.form(location, dict(form, csrf='invalid'), headers)[0])
            self.assertEqual(403, self.form(location, dict(form, password='wrong'), headers)[0])
            self.assertEqual(0 if resource == 'first' else 1, len(calls))
            self.assertEqual(200, self.form(location, form, headers)[0])
            self.assertEqual(400, self.form(location, form, headers)[0])
        self.assertIsNone(calls[0][0])
        self.assertEqual(['first'], [g['resource'] for g in calls[1][0]['grants']])
        self.assertEqual('SECRET_AUTH', calls[1][0]['client_only'])
        self.assertEqual({'resource': 'second'}, calls[1][1])
        self.assertEqual(600, calls[1][2])
        latest = self.server.function_grants.current(
            self.record.app_id, self.ownership()[0], 'server', 'demo.write')
        self.assertEqual(['first', 'second'], [g['resource'] for g in latest['grants']])
        self.assertEqual('SECRET_AUTH', latest['client_only'])
        status, denied = self.api('/rpc/function/approval_grant', {'args': {}})
        self.assertEqual(409, status, denied)
        self.assertEqual('server_rpc_unsupported', denied['error']['code'])
        self.server.capability_grants.set_password(self.record.app_id, 'rotated-password')
        self.assertIsNone(self.server.function_grants.current(
            self.record.app_id, self.ownership()[0], 'server', 'demo.write'))

    def test_prepare_once_transforms_request_and_failed_grant_never_authorizes(self):
        self.configure()
        calls = []
        def prepare(args):
            calls.append(('prepare', args))
            return {'request': {'canonical': args['input'].upper()}, 'display': 'Client explanation'}
        def grant(old, request, seconds):
            calls.append(('grant', request))
            raise ValueError('Client rejected scope')
        self.server.local_client.functions.register('demo.prepare', execute=lambda args, auth: None,
            approval_prepare=prepare, approval_grant=grant)
        status, pending = self.request_function('demo.prepare', {'input': 'value'})
        self.assertEqual(200, status, pending)
        self.assertEqual([('prepare', {'input': 'value'})], calls)
        location, headers, form, page = self.approval({'error': {'details': pending}})
        self.assertIn(b'Client explanation', page)
        self.assertEqual(400, self.form(location, form, headers)[0])
        self.assertEqual([('prepare', {'input': 'value'}), ('grant', {'canonical': 'VALUE'})], calls)
        self.assertIsNone(self.server.function_grants.current(
            self.record.app_id, self.ownership()[0], 'server', 'demo.prepare'))

    def test_browser_client_rejection_is_html_and_api_errors_remain_json(self):
        from openkapsel.errors import ApiError

        self.configure()
        def reject_prepare(_):
            raise ApiError(400, 'mapping_operation_failed', 'client operation failed',
                           {'errno': 22, 'client_message': 'private path must not leak'})
        self.server.local_client.functions.register(
            'demo.reject_prepare', execute=lambda args, auth: None,
            approval_prepare=reject_prepare,
            approval_grant=lambda old, request, seconds: None)
        status, response = self.request_function('demo.reject_prepare', {'resource': 'secret'})
        self.assertEqual(400, status, response)
        self.assertEqual('mapping_operation_failed', response['error']['code'])
        self.assertEqual(22, response['error']['details']['errno'])

        def reject_grant(old, request, seconds):
            raise ApiError(400, 'mapping_operation_failed', 'client operation failed',
                           {'errno': 22, 'client_message': 'private path must not leak'})
        self.server.local_client.functions.register(
            'demo.reject_grant', execute=lambda args, auth: None,
            approval_grant=reject_grant)
        status, pending = self.request_function('demo.reject_grant', {'resource': 'private'})
        self.assertEqual(200, status, pending)
        location, headers, form, _ = self.approval({'error': {'details': pending}})
        status, response_headers, body = self.form(location, form, headers)
        self.assertEqual(400, status, body)
        self.assertIn('text/html', response_headers['Content-Type'])
        self.assertIn(b'Client declined this approval', body)
        self.assertIn(b'No new access was granted', body)
        self.assertNotIn(b'mapping_operation_failed', body)
        self.assertNotIn(b'private path must not leak', body)
        self.assertNotIn(b'"errno"', body)
        self.assertEqual('no-store', response_headers['Cache-Control'])
        self.assertIsNone(self.server.function_grants.current(
            self.record.app_id, self.ownership()[0], 'server', 'demo.reject_grant'))

        # Legacy approval URLs route to the same safe HTML renderer.
        legacy = location.replace('/capability/', '/admin/capability/')
        status, legacy_headers, legacy_page = self.form(legacy, form, headers)
        self.assertEqual(400, status, legacy_page)
        self.assertIn('text/html', legacy_headers['Content-Type'])
        self.assertIn(b'Client declined this approval', legacy_page)

    def test_browser_offline_client_error_has_safe_recovery_message(self):
        from openkapsel.errors import ApiError

        self.configure()
        def reject_grant(old, request, seconds):
            raise ApiError(503, 'mapping_operation_failed', 'client operation failed',
                           {'errno': 113, 'client_message': 'internal network diagnostic'})
        self.server.local_client.functions.register(
            'demo.offline_grant', execute=lambda args, auth: None,
            approval_grant=reject_grant)
        status, pending = self.request_function('demo.offline_grant', {'resource': 'private'})
        self.assertEqual(200, status, pending)
        location, headers, form, _ = self.approval({'error': {'details': pending}})
        status, response_headers, body = self.form(location, form, headers)
        self.assertEqual(503, status, body)
        self.assertIn('text/html', response_headers['Content-Type'])
        self.assertIn(b'Client could not complete the approval', body)
        self.assertIn(b'Check its connection', body)
        self.assertNotIn(b'internal network diagnostic', body)
        self.assertIsNone(self.server.function_grants.current(
            self.record.app_id, self.ownership()[0], 'server', 'demo.offline_grant'))

    def test_native_files_enter_local_client_and_preserve_binary_transfer(self):
        root = self.server.tokens.scope_root(self.record)
        (root / 'text.txt').write_text('LOCAL FILE')
        with patch.object(self.server.local_client, 'execute_file', wraps=self.server.local_client.execute_file) as local:
            self.assertEqual(200, self.api('/fs/query/list?path=.')[0])
            status, read = self.api('/fs/read/files', {'paths': ['text.txt']})
            self.assertEqual(200, status, read)
            self.assertEqual('LOCAL FILE', read['items'][0]['content'])
            status, _, binary = self.request('GET', self.base + '/fs/content?path=text.txt', headers=self.headers)
            self.assertEqual(200, status, binary)
            self.assertEqual(b'LOCAL FILE', binary)
        self.assertEqual(['_handle_fs_list', '_handle_fs_read_files', '_handle_fs_content'],
            [c.args[1] for c in local.call_args_list])

    def test_real_websocket_file_grants_merge_and_enforce_both_scopes(self):
        from openkapsel.client import ClientRuntime, run_once
        self.configure()
        self.server.config = replace(self.server.config, mappings_enabled=True)
        row, token = self.server.mappings.store.create(self.record.path_prefix, 'real-files', writable=True)
        self.server.mappings.mount_path(row).mkdir()
        # A real Client job_sandbox.path rule must exist before READY because
        # each WebSocket RPC session snapshots the Client's path restrictions.
        external = tempfile.TemporaryDirectory(prefix='kapsel-file-ro-')
        self.addCleanup(external.cleanup)
        base = Path(external.name).resolve()
        directories = [base / 'one', base / 'two']
        for directory in directories:
            directory.mkdir()
            (directory / 'text.txt').write_text(directory.name)
        hidden = directories[0] / 'private'
        hidden.mkdir()
        hard = directories[0] / '.openkapsel'
        hard.mkdir()
        config = {'url': f'ws://127.0.0.1:{self.server.server_port}/kapsel/mapping-connect/{row["id"]}',
                  'token': token, 'root': str(self.export), 'writable': True, 'allow_exec': False,
                  'job_sandbox': {'paths': [
                      {'path': str(directories[0]), 'access': 'ro'},
                      {'path': str(hidden), 'access': 'protect'},
                  ]}}
        with patch.dict(os.environ, {'OPENKAPSEL_JOB_MANAGER_HOME': str(self.manager_home)}):
            runtime = ClientRuntime(config)
        ready, stop = threading.Event(), threading.Event()
        client = threading.Thread(target=run_once, args=(config, stop),
            kwargs={'runtime': runtime, 'on_ready': ready.set}, daemon=True)
        client.start()
        try:
            self.assertTrue(ready.wait(5))
            with tempfile.TemporaryDirectory() as raw:
                unrelated = Path(raw).resolve()
                # The unapproved File API is still bound by Client ro.
                with self.assertRaises(OSError):
                    runtime.files.ensure_mutable_path(directories[0] / 'created')
                with self.assertRaises(OSError):
                    runtime.files.ensure_mutable_path(hidden / 'blocked')
                self.assertTrue(runtime.files.is_protected_path(hidden / 'blocked'))
                self.assertTrue(runtime.files.is_protected_path(hard / 'config'))
                for directory in directories:
                    status, pending = self.request_file_approval('read', row['id'], path=str(directory))
                    self.assertEqual(200, status, pending)
                    self.approve({'error': {'details': pending}})
                auth = self.server.function_grants.current(
                    self.record.app_id, self.ownership()[0], row['id'], 'files.read')
                self.assertEqual([str(p) for p in directories], [g['path'] for g in auth['grants'] if 'path' in g])
                for directory in directories:
                    status, read = self.api('/fs/read/files', {'paths': [str(directory / 'text.txt')],
                        'approved': True, 'target': row['id'], 'writer_nonce': self.ownership()[1]})
                    self.assertEqual(200, status, read)
                    self.assertEqual(directory.name, read['items'][0]['content'])
                    self.assertNotIn('auth', read)
                status, denied = self.api('/fs/write/mkdir', {'path': str(directories[0] / 'blocked'),
                    'approved': True, 'target': row['id'], 'writer_nonce': self.ownership()[1]})
                self.assertEqual(403, status, denied)
                status, pending = self.request_file_approval('write', row['id'], path=str(directories[0]))
                self.assertEqual(200, status, pending)
                self.approve({'error': {'details': pending}})
                status, written = self.api('/fs/write/mkdir', {'path': str(directories[0] / 'created'),
                    'approved': True, 'target': row['id'], 'writer_nonce': self.ownership()[1]})
                self.assertIn(status, (200, 201), written)
                self.assertTrue((directories[0] / 'created').is_dir())
                # The confirmed files.write scope overrides narrower Client
                # deny entries, while the automatically hidden config stays
                # inaccessible even to the same approval.
                status, denied = self.api('/fs/write/mkdir', {
                    'path': str(hidden / 'blocked'),
                    'approved': True, 'target': row['id'],
                    'writer_nonce': self.ownership()[1]})
                self.assertIn(status, (403, 404), denied)
                self.assertFalse((hidden / 'blocked').exists())
                status, pending = self.request_file_approval('write', row['id'], path=str(hidden))
                self.assertEqual(200, status, pending)
                self.approve({'error': {'details': pending}})
                status, allowed = self.api('/fs/write/mkdir', {
                    'path': str(hidden / 'blocked'),
                    'approved': True, 'target': row['id'],
                    'writer_nonce': self.ownership()[1]})
                self.assertEqual(201, status, allowed)
                self.assertTrue((hidden / 'blocked').is_dir())
                status, denied = self.api('/fs/write/mkdir', {
                    'path': str(hard / 'blocked'),
                    'approved': True, 'target': row['id'],
                    'writer_nonce': self.ownership()[1]})
                self.assertIn(status, (403, 404), denied)
                self.assertFalse((hard / 'blocked').exists())
                status, denied = self.api('/fs/write/mkdir', {
                    'path': str(directories[1] / 'unapproved-write-scope'),
                    'approved': True, 'target': row['id'],
                    'writer_nonce': self.ownership()[1]})
                self.assertIn(status, (403, 404), denied)
                self.assertFalse((directories[1] / 'unapproved-write-scope').exists())
                status, denied = self.api('/fs/write/mkdir', {
                    'path': str(unrelated / 'outside-approved-scope'),
                    'approved': True, 'target': row['id'],
                    'writer_nonce': self.ownership()[1]})
                self.assertIn(status, (403, 404), denied)
                self.assertFalse((unrelated / 'outside-approved-scope').exists())
                # Stream more than one RPC chunk through function-owned
                # descriptors, including conditional range reads and no-overwrite.
                from urllib.parse import urlencode
                import hashlib
                content = bytes(range(256)) * 1400
                stream_query = urlencode({'path': str(directories[0] / 'binary.bin'),
                    'approved': 'true', 'target': row['id'], 'writer_nonce': self.ownership()[1],
                    'plan_id': self.plan, 'taskname': 'file-stream', 'message': 'Verify approved binary transfer'})
                stream_url = self.base + '/fs/content?' + stream_query
                headers = dict(self.headers, **{'Content-Type': 'application/octet-stream',
                    'X-Content-SHA256': hashlib.sha256(content).hexdigest(),
                    'OpenKapsel-Plan-Id': str(self.plan), 'OpenKapsel-Taskname': 'file-stream',
                    'OpenKapsel-Message': 'Verify approved binary transfer'})
                status, _, raw_result = self.request('PUT', stream_url, content, headers)
                self.assertEqual(201, status, raw_result)
                self.assertEqual(content, (directories[0] / 'binary.bin').read_bytes())
                self.assertEqual(409, self.request('PUT', stream_url, content, headers)[0])
                # Write and read grants are independent; use the prior read
                # grant for descriptor reads from the same target.
                status, range_headers, part = self.request('GET', stream_url,
                    headers=dict(self.headers, Range='bytes=128000-270000'))
                self.assertEqual(206, status, part[:200])
                self.assertEqual(content[128000:270001], part)
                etag = range_headers['ETag']
                self.assertEqual(304, self.request('GET', stream_url,
                    headers=dict(self.headers, **{'If-None-Match': etag}))[0])
                status, head_headers, head_body = self.request('HEAD', stream_url, headers=self.headers)
                self.assertEqual(200, status, head_body)
                self.assertEqual(str(len(content)), head_headers['Content-Length'])
                self.assertEqual(b'', head_body)
                self.server.capability_grants.revoke_workspace(self.record.app_id)
                self.assertEqual(403, self.api('/fs/read/files', {'paths': [str(directories[0] / 'text.txt')],
                    'approved': True, 'target': row['id'], 'writer_nonce': self.ownership()[1]})[0])
        finally:
            stop.set()
            with self.server.mappings.lock:
                session = self.server.mappings.sessions.get(row['id'])
            if session is not None:
                session.close()
            client.join(5)
            runtime.close()
            self.server.mappings.store.delete(row['id'])


if __name__ == '__main__':
    unittest.main()

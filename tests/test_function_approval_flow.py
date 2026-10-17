"""Generic function request flow: optional prepare and opaque merged grants."""
import types
import unittest

from openkapsel.auth.function_grants import FunctionGrants
from openkapsel.auth.function_handlers import FunctionApprovalHandlersMixin
from openkapsel.execution.function_registry import FunctionRegistry


class Handler(FunctionApprovalHandlersMixin):
    def __init__(self, functions, payload):
        self.payload = payload
        self.server = types.SimpleNamespace(
            config=types.SimpleNamespace(admin_enabled=True),
            local_client=types.SimpleNamespace(functions=functions),
            function_grants=FunctionGrants(),
        )
        self.token_record = types.SimpleNamespace(app_id="token", can_write=True)
        self.output = None

    def _read_json(self):
        return self.payload

    def _require_control_token(self):
        pass

    def _require_password_transport(self):
        pass

    def _require_permission(self, permitted, message):
        if not permitted:
            raise PermissionError(message)

    def _file_approval_conversation(self, body):
        return 7

    def _public_base_url(self):
        return "https://local.example/kapsel"

    def _send_json(self, status, body):
        self.output = (status, body)

    def _function_target(self, target):
        self.assert_target = target
        return None


class FunctionApprovalFlowTests(unittest.TestCase):
    def test_no_prepare_callback_needed(self):
        functions = FunctionRegistry()
        prepared = []
        functions.register(
            "fs.write",
            execute=lambda args, auth: args["path"] in auth["paths"],
            approval_grant=lambda old, request: {
                "paths": sorted(set([*(old or {}).get("paths", []), request["path"]]))
            },
        )
        handler = Handler(functions, {
            "function": "fs.write", "target": "server",
            "args": {"path": "/home/user1"}, "writer_nonce": "@abcd@",
        })
        handler._handle_function_approval_request()
        self.assertEqual(200, handler.output[0])
        ticket = handler.output[1]["approval_url"].rsplit("/", 1)[1]
        self.assertEqual({"path": "/home/user1"},
                         handler.server.function_grants.pending(ticket).request)
        handler.server.function_grants.approve(
            ticket, seconds=600,
            grant=lambda old, request: handler._function_internal("server", {
                "function": "fs.write", "method": "approval.grant",
                "old_auth": old, "request": request,
            }),
        )
        self.assertEqual({"paths": ["/home/user1"]},
                         handler.server.function_grants.current(
                             "token", 7, "server", "fs.write"))

    def test_prepare_callback_may_reject_approval(self):
        calls = []
        functions = FunctionRegistry()
        def prepare(args):
            calls.append(args)
            return {"allowed": False}
        functions.register(
            "fs.write",
            execute=lambda args, auth: True,
            approval_prepare=prepare,
            approval_grant=lambda old, request: request,
        )
        handler = Handler(functions, {
            "function": "fs.write", "target": "server",
            "args": {"path": "/private"}, "writer_nonce": "@abcd@",
        })
        from openkapsel.errors import ApiError
        with self.assertRaises(ApiError):
            handler._handle_function_approval_request()
        self.assertEqual([{"path": "/private"}], calls)
        self.assertEqual({}, handler.server.function_grants.pending_requests)


if __name__ == "__main__":
    unittest.main()

"""Function-owned approval contract tests; no HTTP or Mapping is needed."""
import unittest

from openkapsel.execution.function_registry import FunctionRegistry


class FunctionRegistryTests(unittest.TestCase):
    def test_unapproved_function_exposes_only_execute(self):
        functions = FunctionRegistry()
        functions.register("system.info", execute=lambda args, auth: (args, auth))
        self.assertEqual((), functions.approval_methods("system.info"))
        self.assertEqual(({"detail": True}, None),
                         functions.execute("system.info", {"detail": True}))
        with self.assertRaises(ValueError):
            functions.grant("system.info", old_auth=None, request={})

    def test_approval_without_prepare_merges_opaque_auth(self):
        functions = FunctionRegistry()

        def grant(old_auth, request):
            # The implementation, not the control server, defines merging.
            paths = set((old_auth or {}).get("paths", []))
            paths.add(request["path"])
            return {"paths": sorted(paths)}

        def execute(args, auth):
            return args["path"] in (auth or {}).get("paths", [])

        functions.register("fs.write", execute=execute, approval_grant=grant)
        self.assertEqual(("approval.grant",),
                         functions.approval_methods("fs.write"))
        self.assertIsNone(functions.prepare("fs.write", {"path": "/home/user2"}))
        auth = functions.grant("fs.write",
                               old_auth={"paths": ["/home/user1"]},
                               request={"path": "/home/user2"})
        self.assertEqual({"paths": ["/home/user1", "/home/user2"]}, auth)
        self.assertTrue(functions.execute("fs.write",
                                          {"path": "/home/user2"}, auth=auth))
        self.assertFalse(functions.execute("fs.write",
                                           {"path": "/other"}, auth=auth))

    def test_optional_prepare_and_public_name_collision(self):
        functions = FunctionRegistry()
        functions.register(
            "shell.exec.approval",
            execute=lambda args, auth: auth,
            approval_prepare=lambda args: {"display": args["reason"]},
            approval_grant=lambda old, request: {"permit": request["reason"]},
        )
        self.assertEqual(
            ("approval.prepare", "approval.grant"),
            functions.approval_methods("shell.exec.approval"),
        )
        self.assertEqual({"display": "test"},
                         functions.prepare("shell.exec.approval", {"reason": "test"}))
        with self.assertRaises(ValueError):
            functions.register("invalid", execute=lambda args, auth: None,
                               approval_prepare=lambda args: True)
        with self.assertRaises(ValueError):
            functions.register("shell.exec.approval",
                               execute=lambda args, auth: None)
        with self.assertRaises(TypeError):
            functions.execute("shell.exec.approval", "not an object")

    def test_private_envelope_and_shell_registration(self):
        import errno
        from openkapsel.execution.builtin_functions import register_client_shell

        class Tasks:
            def __init__(self):
                self.calls = []

            def dispatch(self, name, args):
                self.calls.append((name, args))
                return {"ok": True}

        tasks = Tasks()
        registry = FunctionRegistry()
        register_client_shell(registry, tasks)
        self.assertEqual({"shell.exec": {
            "approval": True, "approval_prepare": False}}, registry.describe())
        self.assertEqual(("approval.grant",), registry.approval_methods("shell.exec"))
        new_auth = registry.dispatch_internal({
            "function": "shell.exec", "method": "approval.grant",
            "old_auth": {"custom": "preserved"}, "request": {"reason": "build"},
        })
        self.assertEqual({"custom": "preserved", "unsandboxed": True}, new_auth)
        self.assertTrue(registry.dispatch_internal({
            "function": "shell.exec", "method": "execute",
            "args": {"task_id": "some-id", "command": "echo ok"},
            "internal": {"auth": new_auth},
        })["ok"])
        self.assertEqual("task_start", tasks.calls[-1][0])
        self.assertTrue(tasks.calls[-1][1]["unsandboxed"])
        registry.dispatch_internal({
            "function": "shell.exec", "method": "execute",
            "args": {"task_id": "some-id", "command": "echo ok"},
        })
        self.assertFalse(tasks.calls[-1][1]["unsandboxed"])
        with self.assertRaises(ValueError):
            registry.dispatch_internal({
                "function": "shell.exec", "method": "execute", "args": {},
                "auth": new_auth,
            })
        with self.assertRaises(ValueError):
            registry.dispatch_internal({
                "function": "shell.exec", "method": "approval.prepare",
                "args": {}, "old_auth": {},
            })
        with self.assertRaises(OSError) as rejected:
            registry.dispatch_internal({
                "function": "shell.exec", "method": "execute",
                "args": {"unsandboxed": True},
            })
        self.assertEqual(errno.EINVAL, rejected.exception.errno)

if __name__ == "__main__":
    unittest.main()

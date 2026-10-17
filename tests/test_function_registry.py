"""Function-owned approval contract: time-limited opaque auth, private RPC."""
import errno
import time
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
            functions.grant("system.info", old_auth=None, request={}, seconds=600)

    def test_approval_without_prepare_merges_opaque_auth(self):
        functions = FunctionRegistry()

        def grant(old_auth, request, seconds):
            grants = list((old_auth or {}).get("grants", []))
            return {"grants": [*grants, {"expires_at": time.time() + seconds,
                                        "path": request["path"]}],
                    "custom": (old_auth or {}).get("custom", "preserved")}

        def execute(args, auth):
            return args["path"] in [g["path"] for g in (auth or {}).get("grants", [])]

        functions.register("fs.write", execute=execute, approval_grant=grant)
        self.assertEqual(("approval.grant",), functions.approval_methods("fs.write"))
        self.assertIsNone(functions.prepare("fs.write", {"path": "/b"}))
        previous = {"grants": [{"path": "/a", "expires_at": 12345}], "custom": "preserved"}
        auth = functions.grant("fs.write", old_auth=previous,
                               request={"path": "/b"}, seconds=600)
        self.assertEqual(["/a", "/b"], [g["path"] for g in auth["grants"]])
        self.assertEqual(12345, auth["grants"][0]["expires_at"])
        self.assertEqual("preserved", auth["custom"])
        self.assertTrue(functions.execute("fs.write", {"path": "/b"}, auth=auth))
        self.assertFalse(functions.execute("fs.write", {"path": "/other"}, auth=auth))

    def test_optional_prepare_and_public_name_collision(self):
        functions = FunctionRegistry()
        functions.register(
            "shell.exec.approval",
            execute=lambda args, auth: auth,
            approval_prepare=lambda args: {"display": args["reason"]},
            approval_grant=lambda old, request, seconds: {"grants": [
                {"expires_at": time.time() + seconds, "permit": request["reason"]}]},
        )
        self.assertEqual(("approval.prepare", "approval.grant"),
                         functions.approval_methods("shell.exec.approval"))
        self.assertEqual({"display": "test"}, functions.prepare(
            "shell.exec.approval", {"reason": "test"}))
        with self.assertRaises(ValueError):
            functions.register("invalid", execute=lambda args, auth: None,
                               approval_prepare=lambda args: True)
        with self.assertRaises(ValueError):
            functions.register("shell.exec.approval", execute=lambda args, auth: None)
        with self.assertRaises(TypeError):
            functions.execute("shell.exec.approval", "not an object")

    def test_private_envelope_and_shell_registration(self):
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
            "old_auth": {"grants": [], "custom": "preserved"},
            "request": {"reason": "build"}, "seconds": 600,
        })
        self.assertEqual("preserved", new_auth["custom"])
        self.assertEqual(1, len(new_auth["grants"]))
        self.assertTrue(new_auth["grants"][0]["unsandboxed"])
        self.assertGreater(new_auth["grants"][0]["expires_at"], time.time() + 590)
        self.assertTrue(registry.dispatch_internal({
            "function": "shell.exec", "method": "execute",
            "args": {"task_id": "some-id", "command": "echo ok"},
            "internal": {"auth": new_auth},
        })["ok"])
        self.assertEqual("task_start", tasks.calls[-1][0])
        self.assertTrue(tasks.calls[-1][1]["unsandboxed"])
        # Existing Server grants use a flat Shell auth object. A Client
        # upgraded before its Server must still honour that approved grant.
        registry.dispatch_internal({
            "function": "shell.exec", "method": "execute",
            "args": {"task_id": "old-id", "command": "echo ok"},
            "internal": {"auth": {"unsandboxed": True}},
        })
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
        with self.assertRaises(ValueError):
            registry.dispatch_internal({
                "function": "shell.exec", "method": "approval.grant",
                "old_auth": None, "request": {},
            })
        with self.assertRaises(OSError) as rejected:
            registry.dispatch_internal({
                "function": "shell.exec", "method": "execute",
                "args": {"unsandboxed": True},
            })
        self.assertEqual(errno.EINVAL, rejected.exception.errno)


if __name__ == "__main__":
    unittest.main()

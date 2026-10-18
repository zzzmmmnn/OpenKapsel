"""Security regression: private metadata cannot be reached via mixed-case aliases.

The test uses real directory names. On case-insensitive volumes the alternate
spelling resolves to the same inode as .openkapsel; lexical policy must deny
before any descriptor-based read or mutation.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openkapsel.auth.path_access import (
    effective_path_access, has_private_component, is_private_name,
)
from openkapsel.auth.tokens import TokenStore
from openkapsel.client_runtime.client_files import ClientFiles
from openkapsel.client_runtime.file_approval import FileApproval, absolute_scope
from openkapsel.errors import ApiError
from openkapsel.files.file_handlers import FileExecutionMixin
from openkapsel.files.file_support import FileOperationSupportMixin
from openkapsel.files.filename_index import FilenameIndex
from openkapsel.files.git_operations import git_arguments
from openkapsel.files.share_store import ShareError, ShareStore


class PrivatePathCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openkapsel-private-case-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.internal = self.root / ".openkapsel"
        self.internal.mkdir()
        (self.internal / "secret.txt").write_text("PRIVATE CONTENT")
        self.files = ClientFiles(self.root, writable=True)
        self.addCleanup(self.files.close)

    def test_casefolded_components_deny_real_private_directory(self):
        self.assertTrue(is_private_name(".OPENKAPSEL"))
        self.assertTrue(is_private_name(".OpEnKaPsEl-State"))
        self.assertFalse(is_private_name("not.openkapsel"))
        for name in (".openkapsel", ".OPENKAPSEL", ".OpenKapsel",
                     ".OpEnKaPsEl-client-state", ".OPENKAPSEL-share-123"):
            with self.subTest(name=name):
                target = self.root / name / "secret.txt"
                self.assertTrue(has_private_component(target))
                self.assertEqual("deny", effective_path_access(
                    target, self.root, True, (), resolve_symlinks=False))
                self.assertTrue(self.files.is_protected_path(target))
                with self.assertRaises(OSError):
                    self.files.path(name + "/secret.txt")
                with self.assertRaises(OSError):
                    self.files.ensure_mutable_path(target)
                with self.assertRaises(ApiError):
                    absolute_scope(str(self.root / name))
                with self.assertRaises(ApiError):
                    FileExecutionMixin._external_directory(str(self.root / name))

        alias = self.root / ".OPENKAPSEL"
        if alias.exists():
            # The actual OS volume can identify the alternate case as the
            # same existing private inode. Do not allow it to escape checks.
            self.assertTrue(alias.samefile(self.internal))

    def test_client_file_approval_and_renewal_cannot_escape_private_paths(self):
        approval = FileApproval(self.files)
        auth = {"grants": [{"workspace": True, "expires_at": 10**12}]}
        for name in (".OpenKapsel", ".OPENKAPSEL", ".OPENKAPSEL-State"):
            with self.subTest(name=name):
                alias = self.root / name
                with self.assertRaises(ApiError):
                    approval.prepare({"path": str(alias)})
                with self.assertRaises(ApiError):
                    approval.grant(None, {"path": str(alias)}, 600)
                with self.assertRaises(ApiError):
                    FileApproval.check(str(alias / "secret.txt"),
                                       self.root, auth)

    def test_rpc_resolution_external_scope_and_search_cannot_alias_metadata(self):
        from openkapsel.rpc_plugins.file_search import _candidate

        aliases = (self.root / ".OPENKAPSEL", self.root / ".OpenKapsel")
        for alias in aliases:
            with self.subTest(alias=alias):
                with self.assertRaises(OSError):
                    self.files.dispatch("resolve_path", {
                        "path": str(alias), "directory": True,
                    })
                with self.assertRaises(OSError):
                    self.files.dispatch("api_list", {
                        "external_root": str(alias), "path": ".",
                    })
                # File search post-filter must reject a case alias even when
                # the host filesystem resolves it to real private content.
                self.assertIsNone(_candidate(
                    self.files, self.root, str(alias / "secret.txt"),
                    "secret.txt", case_sensitive=True))
                self.assertEqual("deny", effective_path_access(
                    alias / "secret.txt", self.root, True, ()))

    def test_enumeration_git_share_and_transfer_filters(self):
        self.assertTrue(FilenameIndex._ignored(".OPENKAPSEL"))
        self.assertTrue(FilenameIndex._ignored(".OpenKapsel-state"))
        for name in (".OPENKAPSEL", ".OpEnKaPsEl-TEMP"):
            with self.subTest(name=name):
                with self.assertRaises(ShareError):
                    ShareStore._validate_child_name(name)
                with self.assertRaises(ApiError):
                    git_arguments("blame", {"path": name + "/private.txt"})
                with self.assertRaises(ValueError):
                    TokenStore(self.root, None, None)._prepare_child_workspace(name)
        self.assertTrue(FileOperationSupportMixin._is_internal_transfer_name(
            ".file.OPENKAPSEL-put-ABC"))
        self.assertTrue(FileOperationSupportMixin._is_internal_transfer_name(
            ".OPENKAPSEL-transfer-ABC"))
        self.assertFalse(FilenameIndex._ignored("normal.txt"))


if __name__ == "__main__":
    unittest.main()

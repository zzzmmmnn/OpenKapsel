"""Literal file/directory and prefix-ignored name path rule semantics."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from openkapsel.auth.path_access import (
    _rule_parts, effective_path_access, DEFAULT_ACCESS_RULES,
)


class HiddenPathRuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "d" / "abc"
        self.repo.mkdir(parents=True)

    def mode(self, name, rules=()):
        grants = tuple(SimpleNamespace(path=path, access=access)
                       for path, access in rules)
        return effective_path_access(
            self.root / name, self.root, True, grants,
            resolve_symlinks=False)

    def test_same_anchor_takes_more_restrictive_for_all_descendants(self):
        rules = (("*/abc/", "protect"),
                 (str(self.repo) + "/", "rw"))
        self.assertEqual("protect", self.mode("d/abc", rules))
        self.assertEqual("protect", self.mode("d/abc/e", rules))
        self.assertEqual("protect", self.mode("other/abc/e", rules))
        # Ties must ignore input order.
        self.assertEqual("protect", self.mode("d/abc", rules[::-1]))
        self.assertEqual("protect", self.mode("d/abc/e", rules[::-1]))

    def test_exact_file_not_descendant_and_suffix_file(self):
        exact = str(self.root / "d" / "important")
        rules = ((exact, "deny"), ("*/important", "protect"))
        self.assertEqual("deny", self.mode("d/important", rules))
        self.assertEqual("rw", self.mode("d/important/child", rules))
        self.assertEqual("protect", self.mode("else/important", rules))
        self.assertEqual("rw", self.mode("else/important/e", rules))

    def test_specific_descendant_rule_override_and_default_override(self):
        base = self.root / "d"
        rules = (("*/.git/", "rw"),)
        self.assertEqual("rw", self.mode("d/.git/config", rules))
        self.assertEqual("rw", self.mode("d/.git", rules))
        rules = (("*/.git/", "rw"), (str(base / ".git") + "/", "ro"))
        self.assertEqual("ro", self.mode("d/.git", rules))
        self.assertEqual("ro", self.mode("d/.git/objects/info", rules))
        self.assertEqual("rw", self.mode("else/.git/objects/info", rules))

    def test_system_hidden_default_deny_can_be_explicitly_replaced(self):
        self.assertEqual("deny", self.mode("d/.openkapsel/secrets"))
        self.assertEqual("rw", self.mode(
            "d/.openkapsel/secrets",
            (("*/.openkapsel/", "rw"),)))
        self.assertEqual("rw", self.mode(
            "d/.openkapsel/secrets",
            ((str(self.root / "d" / ".openkapsel") + "/", "rw"),)))
        self.assertEqual("rw", self.mode(
            "d/.git/config", ((str(self.root / "d" / ".git") + "/", "rw"),)))
        self.assertEqual("protect", self.mode("d/.config/settings"))
        self.assertEqual("protect", self.mode("d/.git"))
        self.assertEqual("protect", self.mode("d/.gitattributes"))
        self.assertEqual("rw", self.mode("d/ordinary"))

    def test_system_default_hidden_names_resist_case_aliases(self):
        self.assertEqual("deny", self.mode("d/.OPENKAPSEL/secrets"))
        self.assertEqual("protect", self.mode("d/.GIT/objects/info"))
        self.assertEqual("rw", self.mode(
            "d/.OPENKAPSEL/secrets",
            (("*/.openkapsel/", "rw"),)))
        from openkapsel.auth.path_access import existing_pattern_masks
        (self.root / "d" / ".OPENKAPSEL").mkdir()
        self.assertIn(
            self.root / "d" / ".OPENKAPSEL",
            {Path(rule.path) for rule in existing_pattern_masks(
                self.root, True, ())})

    def test_shell_masks_include_extra_granted_root(self):
        from openkapsel.auth.tokens import PathGrant
        from openkapsel.execution.shell_execution import (
            validated_path_grants, sandbox_hidden_paths,
        )
        outside = self.root / "extra"
        outside.mkdir()
        outside = outside.resolve(strict=True)
        scope = (self.root / "d").resolve(strict=True)
        (outside / ".git").mkdir()
        (outside / ".openkapsel").mkdir()
        fake = SimpleNamespace(
            can_write=True,
            allowed_paths=(PathGrant(str(outside), access="rw"),),
        )
        mounts = validated_path_grants(fake, scope)
        self.assertIn((outside / ".git", "protect"),
                      {(Path(g.path), g.access) for g in mounts})
        hidden = sandbox_hidden_paths(
            scope, grants=fake.allowed_paths)
        self.assertIn(outside / ".openkapsel", hidden)

    def test_shell_default_metadata_mask_honors_explicit_rw_override(self):
        from openkapsel.execution.shell_execution import sandbox_hidden_paths
        scope = self.root / "d"
        internal = scope / ".openkapsel"
        internal.mkdir()
        (internal / "secret").write_text("metadata")
        self.assertIn(internal, sandbox_hidden_paths(scope))
        override = (SimpleNamespace(path="*/.openkapsel/", access="rw"),)
        self.assertNotIn(internal, sandbox_hidden_paths(scope, grants=override))
        self.assertEqual("metadata", (internal / "secret").read_text())

    def test_strict_syntax_and_non_regex(self):
        self.assertEqual((True, True, "abc"), _rule_parts("*/abc/"))
        self.assertEqual((True, False, ".gitconfig"), _rule_parts("*/.gitconfig"))
        for raw in ("foo", "*abc/", "*/a/b/", "*/a*/", "**/abc/", "/x/*",
                    "*/../", "", "./abc/", "*/"):
            with self.subTest(rule=raw):
                with self.assertRaises(ValueError):
                    _rule_parts(raw)

    def test_static_native_sandbox_masks_follow_named_rules(self):
        from openkapsel.auth.path_access import existing_pattern_masks
        from types import SimpleNamespace
        git = self.root / "d" / "source" / ".git"
        git.mkdir(parents=True)
        (git / "config").write_text("test")
        config = self.root / "d" / ".config"
        config.mkdir()
        meta = self.root / "d" / ".openkapsel"
        meta.mkdir()
        masks = {Path(item.path): item.access for item in
                 existing_pattern_masks(self.root, True, ())}
        self.assertEqual("protect", masks[git])
        self.assertEqual("protect", masks[config])
        self.assertEqual("deny", masks[meta])
        custom = (
            SimpleNamespace(path="*/.git/", access="rw"),
            SimpleNamespace(path="*/.openkapsel/", access="rw"),
            SimpleNamespace(path="*/.config/", access="ro"),
        )
        masks = {Path(item.path): item.access for item in
                 existing_pattern_masks(self.root, True, custom)}
        self.assertNotIn(git, masks)
        self.assertNotIn(meta, masks)
        self.assertEqual("ro", masks[config])

    def test_same_named_and_literal_mapped_static_mask_is_strict(self):
        from openkapsel.auth.path_access import existing_pattern_masks
        from types import SimpleNamespace
        self.repo.mkdir(exist_ok=True, parents=True)
        masks = {Path(item.path): item.access for item in existing_pattern_masks(
            self.root, True,
            (SimpleNamespace(path="*/abc/", access="protect"),
             SimpleNamespace(path=str(self.repo) + "/", access="rw")))}
        self.assertEqual("protect", masks[self.repo])

    def test_client_file_api_enforces_defaults_and_explicit_override(self):
        from openkapsel.client_runtime.client_files import ClientFiles
        from types import SimpleNamespace
        from pathlib import Path
        import os
        import tempfile
        # Use a test workspace inside the permitted development workspace:
        # the macOS host sandbox blocks random external tempfile roots.
        with tempfile.TemporaryDirectory(dir=Path.cwd(), prefix="ok-path-rule-") as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("local")
            (root / ".openkapsel").mkdir()
            (root / ".openkapsel" / "secret").write_text("local")
            files = ClientFiles(root, writable=True)
            with self.assertRaises(OSError):
                files.path(".git/config")
            with self.assertRaises(OSError):
                files.path(".openkapsel/secret")
            self.assertNotIn(".git", files.dispatch("list", {"path": "."})["names"])
            files.sandbox_path_rules = (
                SimpleNamespace(path="*/.git/", access="rw"),
                SimpleNamespace(path="*/.openkapsel/", access="rw"),
            )
            self.assertEqual(root / ".git" / "config", files.path(".git/config"))
            self.assertEqual(root / ".openkapsel" / "secret",
                             files.path(".openkapsel/secret"))
            self.assertIn(".git", files.dispatch("list", {"path": "."})["names"])
            files.ensure_mutable_path(root / ".git" / "config")

    def test_token_store_persists_suffix_patterns_and_strict_file(self):
        from openkapsel.auth.tokens import PathGrant, TokenRecord, TokenStore, utc_now
        record = TokenRecord(
            token="x" * 40, preview_token="v" * 16,
            control_token="c" * 40, app_id="i" * 16,
            name="sample", created_at=utc_now(),
            path_prefix="d", shell_mode="restricted",
            allowed_paths=(
                PathGrant("*/.git/", access="rw", legacy_directory=False),
                PathGrant(str(self.root / "d" / "settings") ,
                          access="protect", strict_file=True,
                          legacy_directory=False),
            ),
        )
        token = TokenStore(self.root, None, None)._validate(record)
        data = token.to_dict()
        self.assertEqual("*/.git/", data["allowed_paths"][0]["path"])
        self.assertTrue(data["allowed_paths"][1]["strict_file"])
        from_data = TokenRecord.from_dict(data)
        self.assertTrue(from_data.allowed_paths[1].strict_file)
        self.assertEqual("rw", effective_path_access(
            self.root / "d" / ".git" / "config", self.root / "d", True,
            from_data.allowed_paths, resolve_symlinks=False))

    def test_outside_workspace_remains_forbidden(self):
        self.assertIsNone(self.mode("../outsider/.git/config"))
        outside = self.root.parent / "blocked"
        self.assertEqual("deny", effective_path_access(
            outside, self.root, True,
            (SimpleNamespace(path=str(outside), access="deny"),),
            resolve_symlinks=False))


if __name__ == "__main__":
    unittest.main()

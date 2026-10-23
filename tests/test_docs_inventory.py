"""The README documentation list must match the files in docs/ exactly."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_LINK_RE = re.compile(r"\]\(docs/([^)#\s]+)(?:#[^)]*)?\)")


def listed_docs() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"^## Documentation\n(.*?)(?=^## |\Z)", readme, re.M | re.S)
    if match is None:
        raise AssertionError("README.md has no '## Documentation' section")
    return DOC_LINK_RE.findall(match.group(1))


class DocsInventoryTests(unittest.TestCase):
    def test_docs_directory_matches_readme_list(self):
        listed = listed_docs()
        self.assertEqual(len(listed), len(set(listed)), "README lists a document twice")
        # Hidden OS metadata such as .DS_Store is not documentation.
        actual = sorted(
            path.relative_to(ROOT / "docs").as_posix()
            for path in (ROOT / "docs").rglob("*")
            if path.is_file() and not any(part.startswith(".") for part in
                                          path.relative_to(ROOT / "docs").parts)
        )
        self.assertEqual(
            actual, sorted(listed),
            "docs/ differs from the README '## Documentation' list; "
            "add new documents to the list or remove unlisted files",
        )


class DocsContractTests(unittest.TestCase):
    """Guard retired features and method-specific REST documentation."""

    @staticmethod
    def _documented_rest_row(route: str) -> str:
        overview = (ROOT / "docs/rest-files-and-transfers.md").read_text(encoding="utf-8")
        matches = [
            line for line in overview.splitlines()
            if line.startswith("| ") and f"| `{route}` |" in line
        ]
        if len(matches) != 1:
            raise AssertionError(f"Expected one dedicated REST overview row for {route}: {matches}")
        return matches[0]

    @staticmethod
    def _declared_methods(path: str) -> set[str]:
        from openkapsel.routes import ENDPOINTS
        # Exact static routes own their documented resource; do not count
        # catch-all /memory/<memory_id> methods against /memory/project.
        explicit = [endpoint for endpoint in ENDPOINTS if endpoint.route_template == path]
        endpoints = explicit if explicit else [
            endpoint for endpoint in ENDPOINTS
            if any(endpoint.match(method, path) is not None for method in endpoint.methods)
        ]
        return {method for endpoint in endpoints for method in endpoint.methods}

    def test_removed_share_feature_is_not_still_advertised(self):
        from openkapsel.routes import ENDPOINTS
        self.assertFalse(
            [endpoint.name for endpoint in ENDPOINTS if "share" in endpoint.name],
            "Share endpoints have been removed; review the documentation guard if they return",
        )
        retired_phrases = (
            "temporary sharing", "temporary shares", "capability-addressed shares",
            "share snapshots/imports", "shared snapshots/imports", "share quota",
            "shares remain immutable", "share-inspection", "public share URL",
            "public share inspection", "Mapping share and cross-root transfers",
            "token registry, uploads, shares", "mixed-batch preflight, shares",
            "shares and cross-root transfers",
        )
        files = [
            ROOT / "README.md",
            *(ROOT / "docs").rglob("*.md"),
            *(ROOT / "skills/openkapsel-rest").rglob("*.md"),
        ]
        for path in files:
            text = path.read_text(encoding="utf-8").lower()
            for phrase in retired_phrases:
                with self.subTest(path=path.relative_to(ROOT), phrase=phrase):
                    self.assertNotIn(phrase.lower(), text)

    def test_memory_project_methods_match_rest_documentation(self):
        self.assertEqual({"GET", "POST"}, self._declared_methods("/memory"))
        self.assertEqual({"GET"}, self._declared_methods("/memory/project"))
        self.assertTrue(self._documented_rest_row("/memory").startswith("| `GET/POST` |"))
        self.assertTrue(self._documented_rest_row("/memory/project").startswith("| `GET` |"))

    def test_plan_update_does_not_advertise_mutable_parent(self):
        import inspect
        from openkapsel.context.context_store import ContextStore
        self.assertNotIn("plan_id", inspect.signature(ContextStore.update_plan).parameters)
        self.assertEqual({"PATCH"}, self._declared_methods("/context/plans/123"))
        row = self._documented_rest_row("/context/plans/<id>")
        self.assertTrue(row.startswith("| `PATCH` |"))
        self.assertIn("parentage is immutable", row)


    def test_control_transfer_aliases_match_declared_methods(self):
        text = (ROOT / "skills/openkapsel-rest/references/api-basics.md").read_text(encoding="utf-8")
        section = text.split("## Control-only raw transfer aliases", 1)[1].split("\n## ", 1)[0]
        aliases = re.findall(r"^- `([A-Z|]+) <service-base>/transfer(/[^`?]+)", section, re.M)
        self.assertGreaterEqual(len(aliases), 5, aliases)
        for methods, route in aliases:
            sample = re.sub(r"<[^>]+>", "upload_sample", route)
            with self.subTest(route=route):
                self.assertTrue(sample == "/fs/content" or sample.startswith("/upload/"))
                self.assertEqual(set(methods.split("|")), self._declared_methods(sample))

    def test_retired_file_api_names_are_not_documented(self):
        retired = ("`fs/search`", "`fs/read`", "fs/read_many", "byte_offset", "git_mapping_boundary")
        files = [
            ROOT / "README.md",
            *(ROOT / "docs").rglob("*.md"),
            *(ROOT / "skills/openkapsel-rest").rglob("*.md"),
        ]
        for path in files:
            text = path.read_text(encoding="utf-8")
            for name in retired:
                with self.subTest(path=path.relative_to(ROOT), name=name):
                    self.assertNotIn(name, text)

    def test_mcp_discovery_sections_are_documented(self):
        source = (ROOT / "openkapsel/api/mcp.py").read_text(encoding="utf-8")
        match = re.search(r'"enum": (\["main", [^\]]*\])', source)
        self.assertIsNotNone(match)
        import json
        sections = json.loads(match.group(1))
        doc = (ROOT / "docs/shell-and-mcp.md").read_text(encoding="utf-8")
        line = next(l for l in doc.splitlines() if l.startswith("`discovery` defaults to compact Discovery"))
        self.assertEqual(sections, re.findall(r"`([a-z_]+)`", line.split("accepts", 1)[1].split(".", 1)[0]))

if __name__ == "__main__":
    unittest.main()

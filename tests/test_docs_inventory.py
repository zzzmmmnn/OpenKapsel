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


if __name__ == "__main__":
    unittest.main()

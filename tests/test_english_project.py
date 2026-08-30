from __future__ import annotations

import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[1]
CJK_TEXT = re.compile(r"[\u4e00-\u9fff]")
FULLWIDTH_CHINESE_PUNCTUATION = re.compile(r"[（）。，；：？！]")
CHINESE_LOCALE = re.compile(r"zh(?:-CN|_CN)", re.IGNORECASE)


class EnglishProjectTests(unittest.TestCase):
    def test_user_facing_project_text_is_english(self) -> None:
        paths = [PROJECT_ROOT / "README.md"]
        paths.extend((PROJECT_ROOT / "openkapsel").rglob("*.py"))
        paths.extend(
            path
            for path in (PROJECT_ROOT / "examples").rglob("*")
            if path.is_file() and path.suffix in {".py", ".html", ".js", ".md"}
        )

        violations: list[str] = []
        for path in paths:
            source = path.read_text(encoding="utf-8")
            if (
                CJK_TEXT.search(source)
                or FULLWIDTH_CHINESE_PUNCTUATION.search(source)
                or CHINESE_LOCALE.search(source)
            ):
                violations.append(str(path.relative_to(PROJECT_ROOT)))

        self.assertEqual([], violations)


if __name__ == "__main__":
    unittest.main()

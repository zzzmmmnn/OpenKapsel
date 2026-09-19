import unittest
from unittest.mock import patch

from openkapsel.random_ids import token_urlsafe_alnum


class RandomIdsTests(unittest.TestCase):
    def test_rejects_dash_and_underscore_prefixes(self):
        with patch(
            "openkapsel.random_ids.secrets.token_urlsafe",
            side_effect=["-unsafe", "_unsafe", "A_safe"],
        ) as generate:
            self.assertEqual("A_safe", token_urlsafe_alnum(6))
            self.assertEqual(3, generate.call_count)

    def test_rejects_non_positive_sizes(self):
        for value in (0, -1, True, None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    token_urlsafe_alnum(value)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the display names: the one-liners' copies match their source, and the new
flag spellings are aliases of the old ones. No Docker needed.

Run: python3 -m unittest tests/unit/test_display_names.py
"""

import ast
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "common"))

from quips import QUIPS  # noqa: E402

# Each runs without the rest of the repo, so it carries a copy of the list
COPIES = [
    "src/acquisition/python/gandalf.py",
    "src/acquisition/python/passkey_decrypt.py",
    "src/acquisition/bash/gandalf.sh",
    "src/acquisition/windows/Invoke-Gandalf.ps1",
    "src/web/frontend/src/guide/quotes.js",
]


class QuipsTest(unittest.TestCase):
    def test_every_copy_holds_every_line(self):
        for copy in COPIES:
            text = (REPO / copy).read_text(encoding="utf-8")
            missing = [q for q in QUIPS if q not in text]
            self.assertEqual(missing, [], copy)

    def test_ascii_and_no_repeats(self):
        self.assertTrue(all(q.isascii() for q in QUIPS))
        self.assertEqual(len(set(QUIPS)), len(QUIPS))


class FlagAliasTest(unittest.TestCase):
    def flags(self):
        """Each add_argument in elrond.py as (its option strings, its dest)."""
        tree = ast.parse((REPO / "src" / "analysis" / "elrond.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument":
                names = [a.value for a in node.args if isinstance(a, ast.Constant)]
                dest = next((k.value.value for k in node.keywords if k.arg == "dest"), None)
                yield names, dest

    def test_new_spellings_share_the_old_dest(self):
        found = {tuple(names): dest for names, dest in self.flags()}
        self.assertEqual(found.get(("--Custodian", "--Gandalf")), "Gandalf")
        self.assertEqual(found.get(("--Crucible", "--Mordor")), "Mordor")


if __name__ == "__main__":
    unittest.main()

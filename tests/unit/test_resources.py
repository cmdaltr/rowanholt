"""Unit tests for the system requirements check (src/common/resources.py); no Docker needed.

Run: python3 -m unittest tests/unit/test_resources.py
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "common"))

import resources  # noqa: E402


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ)
        self.env.start()
        os.environ.pop("ROWANHOLT_SKIP_CHECKS", None)

    def tearDown(self):
        self.env.stop()

    def test_the_minimums_pass(self):
        found = resources.check(16, 4, 60, building=True)
        self.assertEqual((found.stops, found.warnings), ([], []))

    def test_under_the_memory_floor_stops(self):
        found = resources.check(4, 8, 200, building=False)
        self.assertEqual(len(found.stops), 1)
        self.assertIn("4 GB of memory", found.stops[0])

    def test_between_floor_and_minimum_warns(self):
        found = resources.check(8, 2, 45, building=False)
        self.assertEqual(found.stops, [])
        self.assertEqual(len(found.warnings), 3)

    def test_disk_floor_only_when_building(self):
        self.assertEqual(len(resources.check(16, 4, 20, building=True).stops), 1)
        found = resources.check(16, 4, 20, building=False)
        self.assertEqual(found.stops, [])
        self.assertIn("20 GB is free", found.warnings[0])

    def test_unknown_figures_are_not_problems(self):
        found = resources.check(None, None, None, building=True)
        self.assertEqual((found.stops, found.warnings), ([], []))

    def test_skip_turns_stops_into_warnings(self):
        os.environ["ROWANHOLT_SKIP_CHECKS"] = "1"
        found = resources.check(4, 4, 10, building=True)
        self.assertEqual(found.stops, [])
        self.assertEqual(len(found.warnings), 2)

    def test_main_exits_1_on_a_stop(self):
        with mock.patch.object(resources, "memory_gb", return_value=4), \
                mock.patch.object(resources, "free_gb", return_value=100), \
                mock.patch("sys.stderr"):
            self.assertEqual(resources.main(["--docker-dir", "/"]), 1)
        with mock.patch.object(resources, "memory_gb", return_value=32), \
                mock.patch.object(resources.os, "cpu_count", return_value=8), \
                mock.patch.object(resources, "free_gb", return_value=100):
            self.assertEqual(resources.main(["--docker-dir", "/"]), 0)


if __name__ == "__main__":
    unittest.main()

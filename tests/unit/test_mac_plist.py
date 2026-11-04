"""Cooked plist records (E31): valid JSON, with the launchd fields analysis uses."""

import json
import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.process.mac import plist_record  # noqa: E402


class PlistRecordTest(unittest.TestCase):
    def test_launch_agent(self) -> None:
        record = plist_record(
            {
                "Label": "com.rivendell-lab.update",
                "ProgramArguments": ["/Users/Shared/.x/update.sh", "--quiet"],
                "RunAtLoad": True,
            }
        )
        self.assertEqual(record["CommandLine"], "/users/shared/.x/update.sh --quiet")
        self.assertEqual(record["Plist"], "com.rivendell-lab.update")
        self.assertEqual(record["RunAtLoad"], "True")
        self.assertNotIn("Process", record)

    def test_awkward_values_serialise(self) -> None:
        record = plist_record(
            {
                "Program": "/usr/libexec/Thing",
                "Data": b"\x00\x01",
                "Nested": [{"quote": "it's \"here\""}, 3],
            }
        )
        self.assertEqual(record["Process"], "/usr/libexec/thing")
        self.assertEqual(record["Data"], "0001")
        self.assertEqual(json.loads(json.dumps([record]))[0]["Nested"][0]["quote"], "it's \"here\"")

    def test_top_level_array(self) -> None:
        self.assertEqual(plist_record(["a", 1]), {"Values": ["a", "1"]})


if __name__ == "__main__":
    unittest.main()

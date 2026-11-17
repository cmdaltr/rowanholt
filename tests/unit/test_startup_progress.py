"""Unit tests for the start-up ETA (src/common/startup_progress.py); no Docker needed.

Run: python3 -m unittest tests/unit/test_startup_progress.py
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "common"))

import startup_progress as sp  # noqa: E402


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class JourneyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp})
        self.env.start()
        self.clock = Clock()
        self.time = mock.patch.object(sp.time, "time", self.clock)
        self.time.start()

    def tearDown(self):
        self.time.stop()
        self.env.stop()

    def history(self, kind, *totals):
        path = Path(self.tmp) / "rowanholt" / "start-history.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            for docker, images, containers, ui in totals:
                f.write(json.dumps({"kind": kind, "phases": {"docker": docker, "images": images,
                                                             "containers": containers, "ui": ui}}) + "\n")

    def test_defaults_without_history(self):
        journey = sp.Journey("warm")
        self.assertTrue(journey.learning)
        self.assertEqual(journey.report()["eta"], sum(sp.DEFAULTS["warm"].values()))

    def test_median_of_same_kind_only(self):
        self.history("warm", (1, 2, 10, 40), (1, 2, 12, 50), (1, 2, 11, 60))
        self.history("cold", (1, 600, 20, 90))
        journey = sp.Journey("warm")
        self.assertFalse(journey.learning)
        self.assertEqual(journey.expected["ui"], 50)
        self.assertEqual(journey.report()["eta"], 1 + 2 + 11 + 50)

    def test_eta_counts_down_through_phases(self):
        self.history("warm", (2, 2, 10, 40))
        journey = sp.Journey("warm")
        self.clock.now += 2
        journey.enter("images")
        self.clock.now += 2
        journey.enter("containers")
        self.clock.now += 5
        self.assertEqual(journey.report()["eta"], 5 + 40)
        self.assertEqual(journey.report()["phase"], "containers")

    def test_build_paces_itself_once_under_way(self):
        journey = sp.Journey("cold")  # default 900s for images
        journey.enter("images")
        self.clock.now += 100
        journey.build_fraction = 0.5  # half built in 100s: ~100s more, not 800
        eta = journey.report()["eta"]
        self.assertEqual(eta, 100 + sp.DEFAULTS["cold"]["containers"] + sp.DEFAULTS["cold"]["ui"])

    def test_overrun_never_shows_zero(self):
        self.history("warm", (1, 1, 5, 10))
        journey = sp.Journey("warm")
        journey.enter("ui")
        self.clock.now += 60  # well past the usual 10s
        report = journey.report()
        self.assertGreaterEqual(report["eta"], 3)
        self.assertLess(report["fraction"], 1.0)

    def test_finish_records_history(self):
        journey = sp.Journey("warm-server")
        for phase in sp.PHASES[1:]:
            self.clock.now += 5
            journey.enter(phase)
        self.clock.now += 5
        journey.finish(ok=True)
        records = sp.load_history("warm-server")
        self.assertEqual(records[-1]["phases"], {"docker": 5, "images": 5, "containers": 5, "ui": 5})
        self.assertEqual(sp.load_history("warm"), [])

    def test_phases_and_time_left_in_plain_words(self):
        self.assertEqual(list(sp.MESSAGES.values()),
                         ["Starting Docker", "Building images", "Starting services", "Opening Rowanholt"])
        self.assertEqual(sp.eta_text(30), "Less than a minute left")
        self.assertEqual(sp.eta_text(60), "About a minute left")
        self.assertEqual(sp.eta_text(300), "About 5 minutes left")

    def test_the_log_names_each_build_step_once_and_every_error(self):
        seen = set()
        lines = ["#14 [celery-worker  7/21] RUN pip install -r requirements.txt",
                 "#14 [celery-worker  7/21] RUN pip install -r requirements.txt",
                 "#14 1.234 Collecting fastapi", "#14 DONE 12.3s",
                 '#22 ERROR: process "/bin/sh -c apt-get update" did not complete']
        self.assertEqual([sp.build_log_line(t, seen) for t in lines],
                         ["celery-worker 7/21: RUN pip install -r requirements.txt", None, None, None,
                          '#22 ERROR: process "/bin/sh -c apt-get update" did not complete'])

    def test_a_failing_step_brings_its_last_output(self):
        seen, tails = set(), {}
        lines = ["#31 [celery-worker 14/21] RUN apt-get update && apt-get install -y python3.12",
                 "#31 2.104 Get:1 http://archive.ubuntu.com/ubuntu jammy InRelease",
                 "#30 2.200 Collecting fastapi",
                 "#31 9.871 E: Failed to fetch https://ppa.launchpadcontent.net/deadsnakes  502  Bad Gateway",
                 '#31 ERROR: process "/bin/sh -c apt-get update" did not complete successfully: exit code: 100']
        out = [sp.build_log_line(t, seen, tails) for t in lines]
        self.assertEqual(out[1:4], [None, None, None])
        self.assertEqual(out[4].split("\n"), [
            "  Get:1 http://archive.ubuntu.com/ubuntu jammy InRelease",
            "  E: Failed to fetch https://ppa.launchpadcontent.net/deadsnakes  502  Bad Gateway",
            lines[4]])
        self.assertIn("#30", tails)
        self.assertNotIn("#31", tails)

    def test_cached_steps_are_no_work(self):
        pace = sp.BuildPace(1)
        for n in range(1, 11):  # an update's rebuild: the first ten of 21 steps are cached
            pace.feed(f"#{n} [celery-worker {n}/21] RUN step {n}")
            pace.feed(f"#{n} CACHED")
        self.assertEqual(pace.fraction(), 0.0)
        pace.feed("#11 [celery-worker 11/21] RUN apt-get install -y python3.12")
        self.assertAlmostEqual(pace.fraction(), 1 / 11)
        pace.feed("#11 2.104 Get:1 http://archive.ubuntu.com/ubuntu jammy InRelease")
        self.assertAlmostEqual(pace.fraction(), 1 / 11)

    def test_a_fully_cached_image_is_done(self):
        pace = sp.BuildPace(2)
        for n in (1, 2):
            pace.feed(f"#{n} [frontend {n}/2] RUN npm ci")
            pace.feed(f"#{n} CACHED")
        pace.feed("#9 [backend 1/4] FROM python:3.10-slim")
        self.assertAlmostEqual(pace.fraction(), (1.0 + 0.25) / 2)

    def test_build_step_lines(self):
        match = sp.STEP.match("#14 [celery-worker  7/21] RUN pip install -r requirements.txt")
        self.assertEqual(match.groups(), ("celery-worker", "7", "21"))
        match = sp.STEP.match("#9 [frontend build 3/6] RUN npm ci")
        self.assertEqual(match.groups(), ("frontend", "3", "6"))


if __name__ == "__main__":
    unittest.main()

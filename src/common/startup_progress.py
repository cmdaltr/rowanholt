#!/usr/bin/env python3
"""
Start the Docker stack with progress and an ETA (`rivendell start --progress`).

The start runs in four phases: waking Docker, getting the images (pulled, or built,
which is most of a first start), starting the containers, and waiting for the web UI.
Each start's phase times are kept in a history file per machine; the ETA for the next
start is the median of earlier starts of the same kind (cold: images to get, warm:
none; local or server). With no history yet, defaults stand in, and a build refines
its own estimate from BuildKit's step counts as it goes.

Output is the compose output, plus a line per second like
    @@progress {"fraction": 0.42, "eta": 95, "phase": "images", "message": "...", "learning": false}
for Rivendell.app's journey across Middle-earth; --zenity prints zenity --progress's
format instead. Stdlib only, Python 3.8+.
"""

import argparse
import json
import os
import re
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

PHASES = ["docker", "images", "containers", "ui"]
# Seconds, until this machine has history of its own
DEFAULTS = {
    "warm": {"docker": 20, "images": 4, "containers": 12, "ui": 45},
    "cold": {"docker": 20, "images": 900, "containers": 25, "ui": 90},
}
MESSAGES = {
    "docker": "Waking Docker",
    "images": "Forging the images",
    "containers": "Raising the halls",
    "ui": "Opening the doors",
}
# Where the traveller is, by fraction of the journey (Rivendell.app draws the same road)
PLACES = [(0.0, "the Shire"), (0.18, "Bree"), (0.38, "Weathertop"), (0.55, "the Last Bridge"),
          (0.7, "the Trollshaws"), (0.86, "the Ford of Bruinen"), (1.0, "Rivendell")]
HISTORY_KEEP = 20
STEP = re.compile(r"^#\d+ \[([\w.-]+)(?:\s+[\w.-]+)?\s+(\d+)/(\d+)\]")


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "rivendell"


def load_history(kind: str) -> List[dict]:
    path = state_dir() / "start-history.jsonl"
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    records = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("kind") == kind:
            records.append(record)
    return records[-HISTORY_KEEP:]


def save_history(record: dict) -> None:
    path = state_dir() / "start-history.jsonl"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = path.read_text().splitlines() if path.exists() else []
        lines = (lines + [json.dumps(record)])[-200:]
        path.write_text("\n".join(lines) + "\n")
    except OSError:
        pass


def place(fraction: float) -> str:
    return [name for at, name in PLACES if fraction >= at][-1]


class Journey:
    """Phase timing and the estimate built on it."""

    def __init__(self, kind: str):
        self.kind = kind
        history = load_history(kind)
        self.learning = len(history) == 0
        base = DEFAULTS["cold" if kind.startswith("cold") else "warm"]
        self.expected = {}
        for phase in PHASES:
            seen = [r["phases"][phase] for r in history if phase in r.get("phases", {})]
            self.expected[phase] = statistics.median(seen) if seen else base[phase]
        self.started = time.time()
        self.phase = PHASES[0]
        self.phase_started = self.started
        self.done: Dict[str, float] = {}
        self.build_fraction: Optional[float] = None
        self.detail = ""

    def enter(self, phase: str) -> None:
        now = time.time()
        self.done[self.phase] = now - self.phase_started
        # Phases skipped on the way count as instant
        for skipped in PHASES[PHASES.index(self.phase) + 1:PHASES.index(phase)]:
            self.done[skipped] = 0.0
        self.phase, self.phase_started, self.detail = phase, now, ""

    def remaining(self) -> float:
        elapsed = time.time() - self.phase_started
        expected = self.expected[self.phase]
        if self.phase == "images" and self.build_fraction and self.build_fraction > 0.05 and elapsed > 20:
            # The build's own pace beats history once it's under way
            expected = elapsed / self.build_fraction
        if elapsed < expected:
            current = expected - elapsed
        else:
            # Overrunning: a small allowance rather than 0, so the bar never sits at "done"
            current = max(3.0, expected * 0.1)
        later = sum(self.expected[p] for p in PHASES[PHASES.index(self.phase) + 1:])
        return current + later

    def report(self) -> dict:
        elapsed = time.time() - self.started
        remaining = self.remaining()
        fraction = min(0.99, elapsed / (elapsed + remaining)) if elapsed + remaining > 0 else 0.0
        message = MESSAGES[self.phase] + (f" ({self.detail})" if self.detail else "")
        return {"fraction": round(fraction, 3), "eta": int(round(remaining)), "phase": self.phase,
                "message": message, "place": place(fraction), "learning": self.learning}

    def finish(self, ok: bool) -> None:
        self.done[self.phase] = time.time() - self.phase_started
        if ok:
            save_history({"kind": self.kind, "at": int(self.started),
                          "phases": {p: round(self.done.get(p, 0.0), 1) for p in PHASES},
                          "total": round(time.time() - self.started, 1)})


class Reporter:
    def __init__(self, journey: Journey, zenity: bool):
        self.journey, self.zenity = journey, zenity
        self.lock = threading.Lock()
        self.stopped = threading.Event()

    def line(self, text: str) -> None:
        with self.lock:
            if self.zenity:
                print(f"# {text[:120]}", flush=True)
            else:
                print(text, flush=True)

    def tick(self) -> None:
        report = self.journey.report()
        with self.lock:
            if self.zenity:
                minutes = report["eta"] // 60
                eta = "less than a minute" if report["eta"] < 60 else f"about {minutes + 1} minutes"
                print(int(report["fraction"] * 100), flush=True)
                print(f"# At {report['place']}: {report['message']}. {eta} to Rivendell", flush=True)
            else:
                print("@@progress " + json.dumps(report), flush=True)

    def run(self) -> None:
        while not self.stopped.wait(1.0):
            self.tick()


def docker_up() -> bool:
    return subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def wake_docker(reporter: Reporter) -> bool:
    if docker_up():
        return True
    reporter.line("Docker is not running.")
    if sys.platform == "darwin":
        for app in ("OrbStack", "Docker"):
            if subprocess.run(["open", "-a", app], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                reporter.line(f"Starting {app}...")
                break
    else:
        reporter.line("Error: Docker is not running. Start it and retry.")
        return False
    deadline = time.time() + 120
    while time.time() < deadline:
        time.sleep(1)
        if docker_up():
            reporter.line("Docker started.")
            return True
    reporter.line("Error: Docker did not start in time. Please start it manually.")
    return False


def missing_images(compose: List[str]) -> List[str]:
    """Images the stack needs that aren't here yet (to pull or build)."""
    try:
        out = subprocess.run(compose + ["config", "--images"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    missing = []
    for image in sorted(set(out.split())):
        found = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL).returncode == 0
        if not found:
            missing.append(image)
    return missing


def compose_up(compose: List[str], build: bool, journey: Journey, reporter: Reporter, builds: int) -> int:
    up = ["up", "-d"] + (["--build"] if build else [])
    if compose[0] == "docker-compose":
        cmd = compose + up
    else:
        # --progress plain: BuildKit's step counts ([service n/m]) to pace a build by
        cmd = compose[:2] + ["--progress", "plain"] + compose[2:] + up
    steps: Dict[str, tuple] = {}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for raw in proc.stdout:
        text = raw.rstrip("\n")
        match = STEP.match(text)
        if match:
            key = match.group(1)
            n, m = int(match.group(2)), int(match.group(3))
            if m:
                steps[key] = (max(n, steps.get(key, (0, m))[0]), m)
                done = sum(n / m for n, m in steps.values())
                journey.build_fraction = min(1.0, done / max(builds, len(steps), 1))
                journey.detail = f"{len(steps)} of {max(builds, len(steps))} images under way"
        if text.startswith("#"):
            continue  # BuildKit's step chatter stays out of the log
        if journey.phase == "images" and re.search(r"\b(Creating|Created|Starting|Started|Recreate|Running)\b", text):
            journey.enter("containers")
        reporter.line(text)
    return proc.wait()


def wait_for_ui(url: str, journey: Journey, timeout: float) -> bool:
    context = None
    if url.startswith("https://"):
        # Our own proxy on this host, possibly with Caddy's internal CA: liveness only
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=3, context=context)
            return True
        except urllib.error.HTTPError:
            return True  # any answer means it's up
        except (urllib.error.URLError, OSError):
            time.sleep(2)
    return False


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", required=True)
    parser.add_argument("--build", action="store_true", help="rebuild the images (after an update)")
    parser.add_argument("--server", action="store_true", help="the server profile")
    parser.add_argument("--url", default="http://localhost:5687", help="the web UI to wait for")
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--zenity", action="store_true", help="print zenity --progress's format")
    parser.add_argument("compose", nargs=argparse.REMAINDER, help="-- then the compose command and its -f files")
    args = parser.parse_args(argv)
    compose = [c for c in args.compose if c != "--"]
    os.chdir(args.root)

    # Kind is known only once Docker answers; start as warm and settle it then
    journey = Journey("warm-server" if args.server else "warm")
    reporter = Reporter(journey, args.zenity)
    ticker = threading.Thread(target=reporter.run, daemon=True)
    ticker.start()
    ok = False
    try:
        if not wake_docker(reporter):
            return 1
        missing = missing_images(compose)
        cold = bool(missing) or args.build
        kind = ("cold" if cold else "warm") + ("-server" if args.server else "")
        if kind != journey.kind:
            fresh = Journey(kind)
            fresh.started, fresh.phase_started = journey.started, journey.phase_started
            journey = reporter.journey = fresh
        builds = len(missing) if missing else 0
        if missing:
            reporter.line(f"{len(missing)} image(s) to fetch or build: the first start takes a while.")
        journey.enter("images")
        status = compose_up(compose, args.build, journey, reporter, builds)
        if status != 0:
            return status
        if journey.phase == "images":
            journey.enter("containers")
        journey.enter("ui")
        if not wait_for_ui(args.url, journey, args.timeout):
            reporter.line(f"The stack started but nothing answered on {args.url}. Try 'rivendell status'.")
            return 1
        ok = True
        return 0
    finally:
        reporter.stopped.set()
        journey.finish(ok)
        if ok:
            with reporter.lock:
                if args.zenity:
                    print("100\n# Rivendell is ready", flush=True)
                else:
                    print("@@progress " + json.dumps({"fraction": 1.0, "eta": 0, "phase": "ui",
                                                      "message": "Rivendell is ready", "place": "Rivendell",
                                                      "learning": journey.learning}), flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

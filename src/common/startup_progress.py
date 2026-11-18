#!/usr/bin/env python3
"""
Start the Docker stack with progress and an ETA (`rowanholt start --progress`).

The start runs in four phases: waking Docker, getting the images (pulled, or built,
which is most of a first start), starting the containers, and waiting for the web UI.
Each start's phase times are kept in a history file per machine; the ETA for the next
start is the median of earlier starts of the same kind (cold: images to get, warm:
none; local or server). With no history yet, defaults stand in, and a build refines
its own estimate from BuildKit's step counts as it goes.

Output is the compose output, plus a line per second like
    @@progress {"fraction": 0.42, "eta": 95, "phase": "images", "message": "...", "learning": false}
for Rowanholt.app's start page; --zenity prints zenity --progress's
format instead. Stdlib only, Python 3.8+.
"""

import argparse
import json
import os
import re
import signal
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resources  # noqa: E402

PHASES = ["docker", "images", "containers", "ui"]
# Seconds, until this machine has history of its own
DEFAULTS = {
    "warm": {"docker": 20, "images": 4, "containers": 12, "ui": 45},
    # A first start's build: 44 and 49 minutes on a 4-core Windows VM; the release notes say 30 to 45
    "cold": {"docker": 20, "images": 2400, "containers": 25, "ui": 90},
    # An update's rebuild: images there already, most of their steps cached
    "rebuild": {"docker": 20, "images": 240, "containers": 25, "ui": 60},
}
MESSAGES = {
    "docker": "Starting Docker",
    "images": "Building images",
    "containers": "Starting services",
    "ui": "Opening Rowanholt",
}
HISTORY_KEEP = 20
# An engine that dies mid-build (seen on Windows, its WSL VM gone) leaves compose waiting on it
# without a word: once compose has been quiet this long, the engine is asked each ENGINE_PROBE
# seconds, and two misses in a row stop compose. A quiet build step doesn't trip it: a live
# engine answers while it builds
ENGINE_QUIET, ENGINE_PROBE = 120, 60
STEP = re.compile(r"^#\d+ \[([\w.-]+)(?:\s+[\w.-]+)?\s+(\d+)/(\d+)\]")


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "rowanholt"


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


def eta_text(seconds: int) -> str:
    """The time left in words, as the Windows launcher puts it."""
    if seconds < 45:
        return "Less than a minute left"
    if seconds < 90:
        return "About a minute left"
    return f"About {int(round(seconds / 60))} minutes left"


class Journey:
    """Phase timing and the estimate built on it."""

    def __init__(self, kind: str):
        self.kind = kind
        history = load_history(kind)
        self.learning = len(history) == 0
        base = DEFAULTS[kind.split("-")[0]]
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
            # Steps aren't equal (the worker's apt and tool installs dwarf the rest), so the step
            # count's pace is trusted only near the end. Earlier it runs ahead (2 minutes for a
            # 15-minute build), and allowed to lengthen the estimate it rose as the long steps
            # came, holding "35 minutes left" for 40 minutes
            if self.build_fraction >= 0.9:
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
                "message": message, "learning": self.learning}

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
                # Progress text is kept short for the bar; an error is kept whole, since the launcher shows it
                print(f"# {text if text.startswith('Error:') else text[:120]}", flush=True)
            else:
                print(text, flush=True)

    def tick(self) -> None:
        report = self.journey.report()
        with self.lock:
            if self.zenity:
                print(int(report["fraction"] * 100), flush=True)
                print(f"# {report['message']}. {eta_text(report['eta'])}", flush=True)
            else:
                print("@@progress " + json.dumps(report), flush=True)

    def run(self) -> None:
        while not self.stopped.wait(1.0):
            self.tick()


def docker_up(timeout: float = 30) -> bool:
    # A wedged engine doesn't fail, it hangs
    try:
        return subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout).returncode == 0
    except subprocess.TimeoutExpired:
        return False


class EngineWatch:
    """Stops proc (compose, and the plugin it runs, in their own session) when Docker's engine has
    stopped answering: see ENGINE_QUIET."""

    def __init__(self, proc, probe=docker_up, quiet: float = ENGINE_QUIET, every: float = ENGINE_PROBE):
        self.proc, self.probe, self.quiet, self.every = proc, probe, quiet, every
        self.last = time.monotonic()
        self.gone = False
        self.done = threading.Event()
        threading.Thread(target=self.run, daemon=True).start()

    def heard(self) -> None:
        self.last = time.monotonic()

    def run(self) -> None:
        misses = 0
        while not self.done.wait(self.every):
            if time.monotonic() - self.last < self.quiet:
                misses = 0
                continue
            misses = 0 if self.probe() else misses + 1
            if misses >= 2:
                self.gone = True
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except (AttributeError, OSError):
                    self.proc.kill()
                return


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


def remove_replaced_images() -> None:
    """The images an update's rebuild replaced, left untagged: each update would otherwise keep
    its predecessor's 8 to 15 GB for good. Only Compose's own for this project."""
    try:
        subprocess.run(["docker", "image", "prune", "-f", "--filter",
                        f"label=com.docker.compose.project={resources.PROJECT}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        pass


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


OUTPUT = re.compile(r"^(#\d+) \d+\.\d+ (.*)$")
TAIL = 12


def build_log_line(text: str, logged: set, tails: Optional[Dict[str, deque]] = None) -> Optional[str]:
    """A BuildKit line as the log shows it: a step the first time it appears, or an error.

    A failing step's last lines of output come with its error: the error itself names only
    the command and its exit code, and the reason (apt's E: line, curl's) is in the output.
    """
    match = STEP.match(text)
    if match:
        key = match.groups()
        if key in logged:
            return None
        logged.add(key)
        rest = text[match.end():].strip()
        return f"{match.group(1)} {match.group(2)}/{match.group(3)}: {rest}"[:160]
    output = OUTPUT.match(text)
    if output and tails is not None:
        tails.setdefault(output.group(1), deque(maxlen=TAIL)).append(output.group(2)[:300])
        return None
    error = re.match(r"^(#\d+) ERROR\b", text)
    if error or " ERROR: " in text:
        tail = list(tails.pop(error.group(1), [])) if error and tails is not None else []
        return "\n".join(["  " + line for line in tail] + [text[:300]])
    return None


class BuildPace:
    """How far the image builds are, from BuildKit's step lines.

    A cached step is no work, so it counts on neither side of the fraction: an update's rebuild,
    its early steps all cached, otherwise read as nearly done while one long uncached step ran
    for half an hour, and the time left crept up instead of down.
    """

    def __init__(self, builds: int):
        self.builds = builds
        self.steps: Dict[str, tuple] = {}  # image -> (furthest step, steps)
        self.cached: Dict[str, set] = {}  # image -> its cached step numbers
        self.ids: Dict[str, tuple] = {}  # BuildKit's "#14" -> (image, step)

    def feed(self, text: str) -> bool:
        """Takes one line of the build's output; True when the fraction may have moved."""
        match = STEP.match(text)
        if match:
            image, n, m = match.group(1), int(match.group(2)), int(match.group(3))
            if not m:
                return False
            self.ids[text.split(" ", 1)[0]] = (image, n)
            self.steps[image] = (max(n, self.steps.get(image, (0, m))[0]), m)
            return True
        cached = re.match(r"^(#\d+) CACHED\b", text)
        if cached and cached.group(1) in self.ids:
            image, n = self.ids[cached.group(1)]
            self.cached.setdefault(image, set()).add(n)
            return True
        return False

    def fraction(self) -> float:
        done = 0.0
        for image, (n, m) in self.steps.items():
            skipped = len(self.cached.get(image, ()))
            done += 1.0 if m <= skipped else max(0, n - skipped) / (m - skipped)
        return min(1.0, done / max(self.builds, len(self.steps), 1))


def compose_up(compose: List[str], build: bool, journey: Journey, reporter: Reporter, builds: int) -> int:
    up = ["up", "-d"] + (["--build"] if build else [])
    if compose[0] == "docker-compose":
        cmd = compose + up
    else:
        # --progress plain: BuildKit's step counts ([service n/m]) to pace a build by
        cmd = compose[:2] + ["--progress", "plain"] + compose[2:] + up
    pace = BuildPace(builds)
    logged: set = set()
    tails: Dict[str, deque] = {}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                            start_new_session=True)
    watch = EngineWatch(proc)
    for raw in proc.stdout:
        watch.heard()
        text = raw.rstrip("\n")
        if pace.feed(text):
            journey.build_fraction = pace.fraction()
            images = max(builds, len(pace.steps))
            journey.detail = f"{len(pace.steps)} of {images} images under way"
        if text.startswith("#"):
            # BuildKit's chatter stays out of the log, but each step is named once as it starts
            # (a long build otherwise looks stuck) and its errors come through as they happen
            line = build_log_line(text, logged, tails)
            for part in (line.split("\n") if line else []):
                reporter.line(part)
            continue
        if journey.phase == "images" and re.search(r"\b(Creating|Created|Starting|Started|Recreate|Running)\b", text):
            journey.enter("containers")
        reporter.line(text)
    watch.done.set()
    status = proc.wait()
    if watch.gone:
        reporter.line("Error: Docker's engine stopped answering part-way through. Restart Docker (OrbStack or "
                      "Docker Desktop), then start Rowanholt again: the build carries on from what it had done.")
        return 1
    return status


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
        # cold: images to fetch or build; rebuild: an update's, over images already here
        cold = bool(missing)
        kind = ("cold" if cold else "rebuild" if args.build else "warm") + ("-server" if args.server else "")
        if kind != journey.kind:
            fresh = Journey(kind)
            fresh.started, fresh.phase_started = journey.started, journey.phase_started
            journey = reporter.journey = fresh
        builds = len(missing) if missing else 0
        found = resources.check_here(cold, rebuilding=args.build)
        for text in found.stops:
            reporter.line(f"Error: {text}")
        for text in found.warnings:
            reporter.line(f"Warning: {text}")
        if found.stops:
            return 1
        if missing:
            reporter.line(f"{len(missing)} image(s) to fetch or build: the first start takes a while.")
        journey.enter("images")
        status = compose_up(compose, args.build, journey, reporter, builds)
        if status != 0:
            return status
        if args.build:
            remove_replaced_images()
        if journey.phase == "images":
            journey.enter("containers")
        journey.enter("ui")
        if not wait_for_ui(args.url, journey, args.timeout):
            reporter.line(f"The stack started but nothing answered on {args.url}. Try 'rowanholt status'.")
            return 1
        ok = True
        return 0
    finally:
        reporter.stopped.set()
        journey.finish(ok)
        if ok:
            with reporter.lock:
                if args.zenity:
                    print("100\n# Rowanholt is ready", flush=True)
                else:
                    print("@@progress " + json.dumps({"fraction": 1.0, "eta": 0, "phase": "ui",
                                                      "message": "Rowanholt is ready",
                                                      "learning": journey.learning}), flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

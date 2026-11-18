#!/usr/bin/env python3
"""
Check this machine against Rowanholt's system requirements (docs/REQUIREMENTS.md).

Below a floor, Rowanholt stops before it starts: under 8 GB of memory, or under 30 GB free
where Docker keeps its data when there are images to build (a first start, or after an
update; the build and its cache took 20 GB on Windows). An update's rebuild counts Rowanholt's
own images as free: the start removes them once the new ones are built. Below a minimum it
warns and carries on: 16 GB of memory, 4 processors, 60 GB free. The Windows launcher
(desktop/windows/Rowanholt.ps1) holds the same numbers. ROWANHOLT_SKIP_CHECKS=1 skips the
floors.

    python3 resources.py [--docker-dir DIR] [--building | --rebuilding]

prints a line per problem and exits 1 when one is a floor. Stdlib only, Python 3.8+.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional

MEMORY_FLOOR_GB = 8
MEMORY_MIN_GB = 16
CORES_MIN = 4
DISK_FLOOR_GB = 30
DISK_MIN_GB = 60
GB = 1024 ** 3
# The Compose project, which Compose labels its images with: docker-compose.yml's name, or the desktop
# app's copy's own (rowanholt-app), which the launcher sets in COMPOSE_PROJECT_NAME
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME") or "rowanholt"
UNITS = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}


class Findings(NamedTuple):
    stops: List[str]
    warnings: List[str]


def memory_gb() -> Optional[int]:
    """Physical memory, rounded: a 16 GB machine that reports 15.6 is still a 16 GB machine."""
    try:
        return round(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / GB)
    except (AttributeError, ValueError, OSError):
        return None


def docker_dir() -> Path:
    """Where Docker's images go: its root directory on Linux; on a Mac, Docker Desktop's and
    OrbStack's disk images live under the home folder."""
    if sys.platform != "darwin":
        try:
            out = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
            if out and Path(out).exists():
                return Path(out)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return Path("/var/lib/docker") if Path("/var/lib/docker").exists() else Path("/")
    return Path.home()


def size_bytes(text: str) -> float:
    """Docker's sizes ("6.001GB", "835.4MB", "0B"), which are decimal."""
    match = re.match(r"^([\d.]+)\s*([kKMGT]?B)$", text.strip())
    return float(match.group(1)) * UNITS[match.group(2)] if match else 0.0


def own_images_gb() -> int:
    """Space Rowanholt's own images hold: an update's rebuild replaces them, and the start then
    removes the old ones. Each image's unique size, so a layer shared with another isn't counted."""
    try:
        out = subprocess.run(["docker", "system", "df", "-v", "--format", "{{json .Images}}"],
                             capture_output=True, text=True, timeout=120).stdout
        images = json.loads(out or "[]")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return 0
    ours = [i for i in images if str(i.get("Repository", "")).startswith(f"{PROJECT}-")]
    return int(sum(size_bytes(i.get("UniqueSize", "0B")) for i in ours) // GB)


def free_gb(path: Path) -> Optional[int]:
    try:
        return int(shutil.disk_usage(str(path)).free // GB)
    except OSError:
        return None


def check(memory: Optional[int], cores: Optional[int], free: Optional[int], building: bool,
          where: str = "Docker's drive", reclaimable: int = 0) -> Findings:
    """Problems with these figures; an unknown figure (None) isn't one. reclaimable: GB an
    update's rebuild gives back (the images it replaces), counted as free for the build."""
    stops: List[str] = []
    warnings: List[str] = []
    if memory is not None:
        if memory < MEMORY_FLOOR_GB:
            stops.append(f"This machine has {memory} GB of memory; Rowanholt needs at least {MEMORY_MIN_GB} GB "
                         f"and won't start on less than {MEMORY_FLOOR_GB} GB.")
        elif memory < MEMORY_MIN_GB:
            warnings.append(f"This machine has {memory} GB of memory; Rowanholt needs {MEMORY_MIN_GB} GB. "
                            "Building the images or analysing a memory image may run out.")
    if cores is not None and cores < CORES_MIN:
        warnings.append(f"This machine has {cores} processors; Rowanholt needs {CORES_MIN}. Expect it to be slow.")
    if free is not None:
        if building and free + reclaimable < DISK_FLOOR_GB:
            mine = f" (and {reclaimable} GB in Rowanholt's images, which the update replaces)" if reclaimable else ""
            stops.append(f"{free} GB is free on {where}{mine}; building Rowanholt's images needs at least "
                         f"{DISK_FLOOR_GB} GB ({DISK_MIN_GB} GB with room for cases). Free some space and retry.")
        elif free < DISK_MIN_GB:
            warnings.append(f"{free} GB is free on {where}; Rowanholt needs {DISK_MIN_GB} GB with room for cases.")
    if os.environ.get("ROWANHOLT_SKIP_CHECKS") == "1" and stops:
        warnings, stops = stops + warnings, []
    return Findings(stops, warnings)


def check_here(building: bool, directory: Optional[Path] = None, rebuilding: bool = False) -> Findings:
    """rebuilding: an update's rebuild, whose old images count as free."""
    directory = directory or docker_dir()
    reclaimable = own_images_gb() if rebuilding else 0
    return check(memory_gb(), os.cpu_count(), free_gb(directory), building or rebuilding, str(directory), reclaimable)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--docker-dir", type=Path, help="where Docker keeps its data (found when left out)")
    parser.add_argument("--building", action="store_true", help="images are to be built")
    parser.add_argument("--rebuilding", action="store_true",
                        help="an update's rebuild: Rowanholt's current images count as free")
    args = parser.parse_args(argv)
    found = check_here(args.building, args.docker_dir, args.rebuilding)
    for line in found.stops:
        print(f"Error: {line}", file=sys.stderr)
    for line in found.warnings:
        print(f"Warning: {line}", file=sys.stderr)
    return 1 if found.stops else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

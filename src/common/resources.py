#!/usr/bin/env python3
"""
Check this machine against Rowanholt's system requirements (docs/REQUIREMENTS.md).

Below a floor, Rowanholt stops before it starts: under 8 GB of memory, or under 30 GB free
where Docker keeps its data when there are images to build (a first start, or after an
update; the build and its cache took 20 GB on Windows). Below a minimum it warns and carries
on: 16 GB of memory, 4 processors, 60 GB free. The Windows launcher
(desktop/windows/Rowanholt.ps1) holds the same numbers. ROWANHOLT_SKIP_CHECKS=1 skips the
floors.

    python3 resources.py [--docker-dir DIR] [--building]

prints a line per problem and exits 1 when one is a floor. Stdlib only, Python 3.8+.
"""

import argparse
import os
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


def free_gb(path: Path) -> Optional[int]:
    try:
        return int(shutil.disk_usage(str(path)).free // GB)
    except OSError:
        return None


def check(memory: Optional[int], cores: Optional[int], free: Optional[int], building: bool,
          where: str = "Docker's drive") -> Findings:
    """Problems with these figures; an unknown figure (None) isn't one."""
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
        if building and free < DISK_FLOOR_GB:
            stops.append(f"{free} GB is free on {where}; building Rowanholt's images needs at least "
                         f"{DISK_FLOOR_GB} GB ({DISK_MIN_GB} GB with room for cases). Free some space and retry.")
        elif free < DISK_MIN_GB:
            warnings.append(f"{free} GB is free on {where}; Rowanholt needs {DISK_MIN_GB} GB with room for cases.")
    if os.environ.get("ROWANHOLT_SKIP_CHECKS") == "1" and stops:
        warnings, stops = stops + warnings, []
    return Findings(stops, warnings)


def check_here(building: bool, directory: Optional[Path] = None) -> Findings:
    directory = directory or docker_dir()
    return check(memory_gb(), os.cpu_count(), free_gb(directory), building, str(directory))


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--docker-dir", type=Path, help="where Docker keeps its data (found when left out)")
    parser.add_argument("--building", action="store_true", help="images are to be built")
    args = parser.parse_args(argv)
    found = check_here(args.building, args.docker_dir)
    for line in found.stops:
        print(f"Error: {line}", file=sys.stderr)
    for line in found.warnings:
        print(f"Warning: {line}", file=sys.stderr)
    return 1 if found.stops else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

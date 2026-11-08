"""Elrond's method, recorded in the case for its report: the command and options it ran with, the
evidence it was given, and the versions of the tools it found (``rowanholt_method.json``)."""

import json
import logging
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

METHOD_FILE = "rowanholt_method.json"
VERSION_TIMEOUT = 20
# (name, executables to look for, arguments that print its version): the tools Elrond runs as
# subprocesses (tools/config.yaml), probed once per run
TOOLS: Sequence[Tuple[str, Sequence[str], Sequence[str]]] = (
    ("Volatility 3", ("vol", "vol3", "vol.py"), ("-h",)),
    ("Plaso (psteal)", ("psteal.py", "psteal"), ("--version",)),
    ("Artemis", ("artemis",), ("--version",)),
    ("RegRipper", ("rip.pl", "regripper"), ("-h",)),
    ("YARA", ("yara",), ("--version",)),
    ("ClamAV", ("clamscan",), ("--version",)),
    ("The Sleuth Kit", ("fls",), ("-V",)),
    ("libewf (ewfmount)", ("ewfmount",), ("-V",)),
    ("QEMU (qemu-nbd)", ("qemu-nbd",), ("--version",)),
    ("apfs-fuse", ("apfs-fuse",), ()),
)
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)*|\b\d{8}\b")


def tool_version(executable: str, arguments: Sequence[str]) -> str:
    """The first line of the tool's output that carries a version number, or ""."""
    if not arguments:
        return ""
    try:
        done = subprocess.run([executable, *arguments], capture_output=True, text=True, timeout=VERSION_TIMEOUT,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug(f"{executable} {' '.join(arguments)}: {exc}")
        return ""
    for line in (done.stdout + "\n" + done.stderr).splitlines():
        if _VERSION.search(line):
            return " ".join(line.split())[:160]
    return ""


def tools(probe: Iterable[Tuple[str, Sequence[str], Sequence[str]]] = TOOLS) -> Tuple[List[Dict[str, str]], List[str]]:
    """(tools found, with path and version; names not found)."""
    found, missing = [], []
    for name, executables, arguments in probe:
        path = next((p for p in (shutil.which(e) for e in executables) if p), None)
        if not path:
            missing.append(name)
            continue
        found.append({"name": name, "path": path, "version": tool_version(path, arguments)})
    return found, missing


def options(args) -> Dict:
    """The options a run was given: every argparse value that isn't its default off or empty."""
    chosen = {}
    for key, value in vars(args).items():
        if key in ("case", "directory") or value in (None, False, [], ""):
            continue
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        chosen[key] = value if isinstance(value, (bool, int, float, list)) else str(value)
    return chosen


def record(case_dir, case: str, args, argv: Sequence[str], sources: Sequence[str],
           started: Optional[str] = None, finished: Optional[str] = None,
           found: Optional[Tuple[List[Dict[str, str]], List[str]]] = None) -> Path:
    """Write (or rewrite, when the run finishes) the case's method file; its path."""
    path = Path(case_dir) / METHOD_FILE
    found_tools, missing = found if found is not None else tools()
    data = {
        "case": case,
        "status": "completed" if finished else "running",
        "started": started or datetime.now().astimezone().isoformat(timespec="seconds"),
        "finished": finished or "",
        "command": [Path(argv[0]).name, *argv[1:]] if argv else [],
        "options": options(args),
        "sources": list(sources),
        "tools": found_tools,
        "tools_missing": missing,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "executable": sys.executable,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.new")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temporary.replace(path)
    return path

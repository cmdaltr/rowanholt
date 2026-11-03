"""
The one place the lab shells out. Everything above it (detection, lifecycle, provisioning)
calls run() with an argv list, never a shell string, so nothing it's given is ever
interpreted by a shell, and tests patch this single function instead of a hypervisor.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence

# A machine or snapshot name we'll put on a command line: letters, digits, dot, dash, underscore
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class LabError(Exception):
    """A lab command failed, or was refused before running. message is shown to the user."""

    def __init__(self, message: str, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.detail = detail


def safe_name(name: str) -> str:
    """A machine/snapshot name, or raise: no spaces, no shell metacharacters, nothing injected."""
    name = (name or "").strip()
    if not NAME.fullmatch(name):
        raise LabError("Invalid name", f"{name!r} must be 1–64 characters of letters, digits, dot, dash or underscore")
    return name


# Set by the lab agent from the lab's config: DOCKER_CONTEXT (the engine Dernvale runs on, so
# machines land on the same Docker as the lab's containers) and TART_HOME (LAB_TART_HOME)
ENV: Dict[str, str] = {}

# utmctl and tart ship inside their apps and aren't always on PATH
KNOWN_PATHS = {"utmctl": "/Applications/UTM.app/Contents/MacOS/utmctl",
               "tart": "/Applications/tart.app/Contents/MacOS/tart"}


def configure(env: Dict[str, str]) -> None:
    ENV.clear()
    ENV.update({k: v for k, v in env.items() if v})


def which(tool: str) -> Optional[str]:
    """The tool's path, or None. Patched in tests to say what's installed."""
    found = shutil.which(tool)
    if found is None and os.path.exists(KNOWN_PATHS.get(tool, "")):
        found = KNOWN_PATHS[tool]
    return found


def _argv(argv: Sequence[str]) -> List[str]:
    argv = list(argv)
    if "/" not in argv[0]:
        argv[0] = which(argv[0]) or argv[0]
    return argv


def _env() -> Dict[str, str]:
    return {**os.environ, **ENV}


def run(argv: Sequence[str], timeout: int = 120, check: bool = True, input_text: Optional[str] = None) -> str:
    """
    Run a command and return its stdout. argv is a list, run with no shell. Raises LabError
    on a non-zero exit (unless check is False) or a timeout. Patched wholesale in tests.
    """
    if not argv or not isinstance(argv, (list, tuple)):
        raise LabError("No command")
    tool = argv[0]
    if which(tool) is None and "/" not in tool:
        raise LabError(f"{tool} isn't installed", f"{tool} was not found on PATH")
    try:
        proc = subprocess.run(_argv(argv), capture_output=True, text=True, timeout=timeout, env=_env(),
                              input=input_text, stdin=None if input_text is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise LabError(f"{tool} timed out", f"{' '.join(argv)} did not finish within {timeout}s")
    except OSError as e:
        raise LabError(f"Could not run {tool}", str(e))
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise LabError(f"{tool} failed", detail[:2000])
    return proc.stdout


def spawn(argv: Sequence[str]):
    """
    Start a long-running command detached and return at once (a VM's `tart run`, which
    blocks for the life of the VM). Its output goes nowhere; the machine's state is read back
    separately. Patched in tests.
    """
    if which(argv[0]) is None and "/" not in argv[0]:
        raise LabError(f"{argv[0]} isn't installed")
    try:
        subprocess.Popen(_argv(argv), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True, env=_env())
    except OSError as e:
        raise LabError(f"Could not start {argv[0]}", str(e))


def run_ok(argv: Sequence[str], timeout: int = 20) -> bool:
    """True when the command exits 0, False on any failure. For probes."""
    try:
        run(argv, timeout=timeout)
        return True
    except LabError:
        return False


def first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0].strip() if (text or "").strip() else ""

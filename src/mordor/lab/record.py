"""
Run Atomic Red Team in a machine and bring the recording into Your lab, from the Mordor page.
It drives the same script ./lab.sh mordor-record uses (lab/windows/Invoke-MordorRecord.ps1, from
Archer's record-atomics.ps1), copied into the machine and run there, then pulls the run folder
into src/mordor/data/telemetry/lab/<run> and rebuilds the lab telemetry. Ported from Archer; the
lab's own Windows VM records through ./lab.sh over SSH instead (the lab agent routes it).

The atomics change the machine, so a run reverts it to a snapshot afterwards when asked — take
a `clean` snapshot first (the page says so). Running them needs the machine provisioned
(logging on, PowerShell 7 and Atomic Red Team installed).

plan() lists exactly what a run would do without doing any of it; record(execute=False) logs
that plan and stops. Nothing here runs an atomic unless record is called with execute=True.
"""

import os
import re
from typing import Callable, Dict, List, Optional

from ..telemetry.lab import LAB_DIR
from .engines import engine_for
from .registry import get as registry_get
from .runner import LabError, safe_name

TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                      "lab", "windows", "Invoke-MordorRecord.ps1")


def clean_techniques(raw) -> List[str]:
    """ATT&CK IDs, upper-cased and de-duplicated; raise on anything that isn't one."""
    items = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw or ""))
    out = []
    for t in (x.strip().upper() for x in items if x.strip()):
        if not TECH.fullmatch(t):
            raise LabError("Not an ATT&CK technique ID", f"{t!r} isn't like T1059 or T1059.001")
        if t not in out:
            out.append(t)
    if not out:
        raise LabError("No techniques", "Give at least one ATT&CK technique ID")
    return out


def _paths(os_name: str, run_name: str):
    """Where the script and the run folder live inside the machine, per OS."""
    if os_name == "windows":
        return r"C:\Windows\Temp\Invoke-MordorRecord.ps1", r"C:\Windows\Temp\mordor-telemetry", f"C:\\Windows\\Temp\\mordor-telemetry\\{run_name}"
    return "/tmp/Invoke-MordorRecord.ps1", "/tmp/mordor-telemetry", f"/tmp/mordor-telemetry/{run_name}"


def _pwsh(os_name: str) -> str:
    return "powershell" if os_name == "windows" else "pwsh"


def plan(engine_key: str, name: str, os_name: str, techniques: List[str], run_name: str,
         settle: int = 20, timeout: int = 120, revert_to: str = "") -> List[str]:
    """A human-readable list of what record() would do, for the dry run and the confirm dialog."""
    script_remote, out_remote, run_remote = _paths(os_name, run_name)
    steps = [
        f"Copy Invoke-MordorRecord.ps1 into {name} at {script_remote}",
        f"In {name}: {_pwsh(os_name)} Invoke-MordorRecord.ps1 -Techniques {','.join(techniques)} "
        f"-Run {run_name} -Out {out_remote} -Settle {settle} -Timeout {timeout}  (runs the atomics)",
        f"Copy {run_remote} out to {os.path.join(LAB_DIR, run_name)}",
    ]
    if revert_to:
        steps.append(f"Revert {name} to the snapshot {revert_to}")
    steps.append("Rebuild Your lab so the recording shows on the Crucible page")
    return steps


def preflight(engine_key: str, name: str, os_name: str) -> List[str]:
    """What's not ready for a run: warnings the page shows before the confirm (not hard stops)."""
    warnings = []
    known = registry_get(engine_key, name)
    done = set((known or {}).get("provisioned", []))
    for step, why in (("logging", "audit logging isn't on"),
                      ("atomics", "Atomic Red Team isn't installed")):
        if step not in done:
            warnings.append(f"{why} (Set up → {step})")
    if os_name not in ("windows", "linux", "macos"):
        warnings.append(f"no recording for {os_name or 'this OS'}")
    return warnings


def record(engine_key: str, name: str, os_name: str, techniques, run_name: str = "",
           settle: int = 20, timeout: int = 120, revert_to: str = "",
           execute: bool = False, say: Callable[[str], None] = print) -> Dict:
    """
    Run the atomics and import the recording. With execute=False it logs the plan and does
    nothing — the path tests and the UI's preview use that; only execute=True detonates.
    """
    name = safe_name(name)
    techniques = clean_techniques(techniques)
    run_name = safe_name(run_name) if run_name else f"{name}-{_stamp()}"
    script_remote, out_remote, run_remote = _paths(os_name, run_name)
    windows = os_name == "windows"

    for line in plan(engine_key, name, os_name, techniques, run_name, settle, timeout, revert_to):
        say(("would: " if not execute else "") + line)
    if not execute:
        say("Dry run: nothing was run. Tick 'I have snapshotted this machine' and run it for real to record.")
        return {"run": run_name, "executed": False, "plan_only": True}

    engine = engine_for(engine_key)
    if not os.path.isfile(SCRIPT):
        raise LabError("Invoke-MordorRecord.ps1 is missing", SCRIPT)
    say(f"Copying the recorder into {name}…")
    _push(engine, name, SCRIPT, script_remote, windows)

    say(f"Running {len(techniques)} technique(s) in {name}. This detonates the atomics; it can take a while.")
    # -Command, not -File: under -File, "T1,T2" reaches the script as one string, not a list
    argv = [_pwsh(os_name), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
            f"& '{script_remote}' -Techniques {','.join(techniques)} -Run {run_name} -Out '{out_remote}' "
            f"-Settle {settle} -Timeout {timeout}"]
    out = engine.exec(name, argv, timeout=max(1800, timeout * len(techniques) * 3))
    for l in (out or "").strip().splitlines()[-15:]:
        say(l)

    say("Collecting the recording…")
    os.makedirs(LAB_DIR, exist_ok=True)
    _pull(engine, name, run_remote, LAB_DIR, windows)
    local = os.path.join(LAB_DIR, run_name)
    if not os.path.isdir(local):
        raise LabError("Nothing came back", f"{run_remote} produced no run folder in the machine")

    if revert_to:
        say(f"Reverting {name} to {revert_to}…")
        from . import machines

        machines.revert(engine_key, name, revert_to)

    say("Rebuilding Your lab…")
    from ..telemetry.__main__ import build

    build(["lab"], log=say)
    say(f"Recorded. {run_name} is now under Your lab on the Crucible page.")
    return {"run": run_name, "executed": True, "path": local}


def _push(engine, name, local, remote, windows):
    if hasattr(engine, "push_file"):
        try:
            engine.push_file(name, local, remote, windows=windows)
        except TypeError:
            engine.push_file(name, local, remote)
    else:
        raise LabError(f"{engine.key} can't copy files in")


def _pull(engine, name, remote_dir, local_parent, windows):
    try:
        engine.pull_dir(name, remote_dir, local_parent, windows=windows)
    except TypeError:
        engine.pull_dir(name, remote_dir, local_parent)


def _stamp() -> str:
    import time

    return time.strftime("%Y%m%d-%H%M")

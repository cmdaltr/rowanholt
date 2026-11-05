"""
The lifecycle of a lab machine, the same verbs for a container or a VM: create (from a
template), start, stop, snapshot, revert (to a snapshot), delete, status and logs. Each verb
dispatches to the engine that runs the machine (engines).

A machine Rowanholt made is tagged in the registry with its template, so the page shows its OS
and what it records, and provisioning knows which script to run. The lab's own machines and any
UTM VM are listed too. Ported from Archer; the lab is admin-only in Rowanholt, so there's no
per-user ownership.
"""

from typing import Dict, List, Optional, Set

from . import registry
from .engines import ENGINES, engine_for
from .runner import LabError, safe_name
from .templates import BY_ID


# The lab's own Windows VM (lab.conf WINDOWS_UTM_VM); set by the lab agent. Its set-up and
# recording go through ./lab.sh over SSH, which it's built for, rather than utmctl exec.
LAB_WINDOWS_VM = "rowan-lab-win11"
# Machines on this host the page never shows (lab.conf LAB_HIDDEN_MACHINES), such as another
# project's UTM VM; set by the lab agent.
HIDDEN: Set[str] = set()


def lab_machine(engine: str, name: str) -> bool:
    """One of the lab's own machines (./lab.sh builds and deletes those, not this page)."""
    if engine == "docker":
        return name.startswith("lab-")
    return name.startswith("rowan-lab-") or (engine == "utm" and name == LAB_WINDOWS_VM)


def is_lab_windows(engine: str, name: str) -> bool:
    return engine == "utm" and name == LAB_WINDOWS_VM


def _lab_os(engine: str, name: str) -> str:
    if engine == "docker":
        return "linux"
    if engine == "utm":
        return "windows"
    return "macos" if "macos" in name else "linux" if "linux" in name else ""


def _decorate(m: Dict) -> Dict:
    """Add what Rowanholt remembers about the machine to the engine's own view.

    A UTM VM counts the moment it exists — Rowanholt didn't make it, but it drives any UTM VM —
    so it shows even before its OS is set. Only a machine Rowanholt created here may be deleted
    here: the lab's own are ./lab.sh's, and another VM in UTM (Archer's, say) is yours."""
    known = registry.get(m["engine"], m["name"])
    template = BY_ID.get((known or {}).get("template", ""))
    lab = lab_machine(m["engine"], m["name"])
    return {**m,
            "known": bool(known) or lab or m["engine"] == "utm",
            "lab": lab,
            "os": (known or {}).get("os") or m.get("os") or (_lab_os(m["engine"], m["name"]) if lab else ""),
            "template": (known or {}).get("template", ""),
            "records": template["records"] if template else "",
            "provisioned": (known or {}).get("provisioned", []),
            "deletable": bool((known or {}).get("created")) and not lab}


def listing(engines: Optional[List[str]] = None) -> List[Dict]:
    """The machines Rowanholt made, the lab's own and every UTM VM, across the engines given
    (default: all that are ready). Anything else built outside Rowanholt is left out."""
    out = []
    for key, engine in ENGINES.items():
        if engines is not None and key not in engines:
            continue
        try:
            out += [d for d in (_decorate(m) for m in engine.list()) if d["known"] and d["name"] not in HIDDEN]
        except LabError:
            continue  # an engine that isn't running doesn't stop the others
    out.sort(key=lambda m: (m["engine"], m["name"]))
    return out


def adopt(engine_key: str, name: str, os_name: str) -> Dict:
    """Tell Rowanholt what OS a VM it didn't create runs, so it can provision and record it."""
    name = safe_name(name)
    if os_name not in ("windows", "linux", "macos"):
        raise LabError("Unknown OS", "Pick windows, linux or macos")
    known = registry.get(engine_key, name) or {}
    registry.record(engine_key, name, known.get("template") or f"{engine_key}-vm", os_name, known.get("image", ""))
    return {"engine": engine_key, "name": name, "os": os_name}


def clone(engine_key: str, name: str, new_name: str) -> Dict:
    """Clone an existing VM into a new machine — the fast Windows path: copy a prepared VM rather
    than install one from an ISO. UTM only (its engine has clone). The clone inherits the source's
    OS when Rowanholt knows it, so Set up and Record work on it straight away."""
    engine, name = _op(engine_key, name)
    engine_clone = getattr(engine, "clone", None)
    if engine_clone is None:
        raise LabError("This engine can't clone a machine", engine_key)
    new_name = safe_name(new_name)
    os_name = (registry.get(engine_key, name) or {}).get("os") or (_lab_os(engine_key, name) if lab_machine(engine_key, name) else "")
    engine_clone(name, new_name)
    registry.record(engine_key, new_name, f"{engine_key}-vm", os_name, "", created=True)
    return {"engine": engine_key, "name": new_name, "os": os_name}


def all_host_names(engines: Optional[List[str]] = None) -> List[str]:
    """Every machine name the engines report, Rowanholt's and not (Tart lists all its VMs; Docker
    lists Rowanholt's containers) — so the create dialog can suggest a name that won't collide."""
    names = []
    for key, engine in ENGINES.items():
        if engines is not None and key not in engines:
            continue
        try:
            names += [m["name"] for m in engine.list()]
        except LabError:
            continue
    if engines is None or "tart" in engines:
        from .engines import parse_tart_list_raw

        try:
            names += parse_tart_list_raw()  # includes VMs and snapshots outside Rowanholt
        except LabError:
            pass
    return names


def create(template_id: str, name: str) -> Dict:
    template = BY_ID.get(template_id)
    if not template:
        raise LabError("Unknown template", template_id)
    name = safe_name(name)
    from . import hosts

    arch = hosts.arch()
    image = (template.get("image") or {}).get(arch)
    if not image:
        raise LabError(f"{template['name']} can't run on this machine",
                       f"no image built for {arch}")
    engine = engine_for(template["engine"])
    engine.create(name, image)
    registry.record(template["engine"], name, template_id, template["os"], image, created=True)
    return {"name": name, "engine": template["engine"], "template": template_id}


def _op(engine_key: str, name: str):
    return engine_for(engine_key), safe_name(name)


def start(engine_key: str, name: str):
    e, name = _op(engine_key, name)
    e.start(name)


def stop(engine_key: str, name: str):
    e, name = _op(engine_key, name)
    e.stop(name)


def snapshot(engine_key: str, name: str, snapshot_name: str) -> Dict:
    e, name = _op(engine_key, name)
    snap = safe_name(snapshot_name)
    e.snapshot(name, snap)
    return {"snapshot": snap}


def revert(engine_key: str, name: str, snapshot_name: str):
    e, name = _op(engine_key, name)
    e.revert(name, safe_name(snapshot_name))


def delete(engine_key: str, name: str):
    e, name = _op(engine_key, name)
    if lab_machine(engine_key, name):
        raise LabError("The lab's own machines are deleted with ./lab.sh", f"{name}: see ./lab.sh help")
    if not (registry.get(engine_key, name) or {}).get("created"):
        raise LabError("Rowanholt didn't create this machine, so it won't delete it",
                       f"{name} was made outside Rowanholt; delete it in {engine_key} yourself if you want it gone")
    e.delete(name)
    registry.forget(engine_key, name)


def status(engine_key: str, name: str) -> Dict:
    e, name = _op(engine_key, name)
    return _decorate(e.status(name))


def logs(engine_key: str, name: str, tail: int = 200) -> str:
    e, name = _op(engine_key, name)
    return e.logs(name, tail)

"""The Mordor page's lab: the agent's /mordor/* endpoints over src.mordor.lab (ported from Archer).

The quick verbs (overview, start, stop, snapshot, logs, delete, set OS, verify ISO) answer
straight away. The slow ones (create, revert, clone, set up, record) run through the agent's
Runner, one job at a time with every other lab command, and the page polls /runs/<id> like any
other run. The lab's own Windows VM is set up and recorded through ./lab.sh (mordor-sensor,
mordor-record), which reach it over SSH; any other machine goes through src.mordor.lab.
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from src.mordor.lab import hosts, iso, machines, provision, record, runner  # noqa: E402
from src.mordor.lab.runner import LabError, safe_name  # noqa: E402
from src.mordor.lab.templates import BY_ID, offered  # noqa: E402

_config: dict = {"at": 0.0}


def _docker_context() -> str:
    """The engine Rowanholt runs on, as lab.sh's pick_docker_context chooses it."""
    try:
        names = subprocess.run(["docker", "context", "ls", "--format", "{{.Name}}"], capture_output=True,
                               text=True, timeout=15).stdout.split()
        for ctx in names:
            ps = subprocess.run(["docker", "--context", ctx, "ps", "--format", "{{.Names}}"], capture_output=True,
                                text=True, timeout=15).stdout.split()
            if "rowanholt-backend" in ps:
                return ctx
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def configure(lab_state: Callable[[], dict]) -> None:
    """Point the engines at the lab's Docker context, Tart home and Windows VM (cached a minute)."""
    if time.time() - _config["at"] < 60:
        return
    cfg = lab_state()
    tart_home = cfg.get("LAB_TART_HOME") or (f"{cfg['LAB_VM_DIR']}/tart" if cfg.get("LAB_VM_DIR") else "")
    runner.configure({"DOCKER_CONTEXT": _docker_context(), "TART_HOME": tart_home})
    machines.LAB_WINDOWS_VM = cfg.get("WINDOWS_UTM_VM") or "rowanholt-lab-win11"
    machines.HIDDEN = {n for n in re.split(r"[,\s]+", cfg.get("LAB_HIDDEN_MACHINES", "")) if n}
    _config["at"] = time.time()


def _error(e: LabError) -> tuple[int, dict]:
    return 400, {"error": e.message, "detail": e.detail}


def overview(busy: dict | None) -> tuple[int, dict]:
    caps = hosts.capabilities()
    current = machines.listing(caps["ready"])
    taken = sorted({m["name"] for m in current} | set(machines.all_host_names(caps["ready"])))
    return 200, {"host": caps, "templates": offered(caps), "machines": current, "taken": taken,
                 "lab_windows_vm": machines.LAB_WINDOWS_VM, "busy": busy}


def handle_get(parts: list[str], query: dict, busy: dict | None) -> tuple[int, dict]:
    q = {k: v[0] for k, v in query.items() if v}
    try:
        if parts == ["overview"]:
            return overview(busy)
        if parts == ["logs"]:
            return 200, {"logs": machines.logs(q.get("engine", ""), q.get("name", ""))}
        if parts == ["provision-steps"]:
            return 200, {"steps": provision.steps_for(q.get("os", ""))}
    except LabError as e:
        return _error(e)
    return 404, {"error": "not found"}


def handle_post(parts: list[str], body: dict, jobs) -> tuple[int, dict]:
    """jobs: the agent's Runner (start for a lab.sh command, start_python for a Python job)."""
    engine, name = str(body.get("engine", "")), str(body.get("name", ""))
    try:
        if parts == ["create"]:
            template_id, name = str(body.get("template", "")), safe_name(name)
            if template_id not in BY_ID:
                raise LabError("Unknown template", template_id)
            return 202, jobs.start_python(f"create {name}", lambda say: (
                say(f"Creating {name} from {BY_ID[template_id]['name']} (pulling the image can take a while)…"),
                machines.create(template_id, name)))

        if parts == ["action"]:
            act, snap = body.get("action", ""), str(body.get("snapshot", ""))
            if act == "start":
                machines.start(engine, name)
            elif act == "stop":
                machines.stop(engine, name)
            elif act == "delete":
                machines.delete(engine, name)
            elif act == "snapshot":
                return 200, {"ok": True, **machines.snapshot(engine, name, snap)}
            elif act == "revert":
                safe_name(snap)
                return 202, jobs.start_python(f"revert {name} to {snap}", lambda say: (
                    say(f"Reverting {name} to {snap}…"), machines.revert(engine, name, snap)))
            else:
                return 400, {"error": f"Unknown action {act}"}
            return 200, {"ok": True}

        if parts == ["adopt"]:
            return 200, {"ok": True, **machines.adopt(engine, name, str(body.get("os", "")))}

        if parts == ["clone"]:
            new_name = safe_name(str(body.get("new_name", "")))
            return 202, jobs.start_python(f"clone {name} to {new_name}", lambda say: (
                say(f"Cloning {name} to {new_name}: copying the disk can take a few minutes…"),
                machines.clone(engine, name, new_name)))

        if parts == ["verify-iso"]:
            path = str(body.get("path", "")).strip()
            if not path:
                return 400, {"error": "Give the path to the .iso file."}
            return 200, iso.inspect(str(Path(path).expanduser())).as_dict()

        if parts == ["provision"]:
            os_name, step = str(body.get("os", "")), str(body.get("step", ""))
            if machines.is_lab_windows(engine, name):
                # Sysmon, audit policy and Atomic Red Team in one go, over SSH
                return 202, jobs.start("mordor-sensor", [])
            label = provision.LABELS.get(step, step)

            def work(say):
                say(f"{label} on {name}. This changes the machine; snapshot it first if you haven't.")
                out = provision.run_step(engine, name, os_name, step)
                for line in (out or "").strip().splitlines()[-12:]:
                    say(line)
            return 202, jobs.start_python(f"{label} on {name}", work)

        if parts == ["record"]:
            os_name = str(body.get("os", ""))
            techs = record.clean_techniques(body.get("techniques", ""))
            run_name = str(body.get("run_name", ""))
            revert_to = str(body.get("revert_to", ""))
            settle, timeout = int(body.get("settle", 20)), int(body.get("timeout", 120))
            lab_windows = machines.is_lab_windows(engine, name)
            if not body.get("execute"):
                plan = (["Copy Invoke-MordorRecord.ps1 into the VM over SSH",
                         f"Run {','.join(techs)}: each test's prerequisites, the test, a {settle}s settle, its cleanup",
                         "Copy the run out to src/mordor/data/telemetry/lab and rebuild Your lab"]
                        if lab_windows else
                        record.plan(engine, name, os_name, techs, run_name or f"{name}-run", settle, timeout, revert_to))
                if lab_windows and revert_to:
                    plan.append(f"Revert {name} to the snapshot {revert_to} (after the run, from this page)")
                return 200, {"preview": True, "plan": plan, "techniques": techs,
                             "warnings": [] if lab_windows else record.preflight(engine, name, os_name)}
            if lab_windows:
                args = ["custom", safe_name(run_name or "ui"), ",".join(techs)]
                return 202, jobs.start("mordor-record", args + ([safe_name(run_name)] if run_name else []))
            return 202, jobs.start_python(f"record {','.join(techs)} on {name}", lambda say: record.record(
                engine, name, os_name, techs, run_name=run_name, settle=settle, timeout=timeout,
                revert_to=revert_to, execute=True, say=say))
    except LabError as e:
        return _error(e)
    except RuntimeError as e:  # the Runner is busy with another job
        return 409, {"error": str(e)}
    except (TypeError, ValueError) as e:
        return 400, {"error": str(e)}
    return 404, {"error": "not found"}

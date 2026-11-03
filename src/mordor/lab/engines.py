"""
The engines Rivendell drives on the machine it runs on, behind one interface
(create/start/stop/snapshot/revert/delete/status/logs/exec):

  docker   Linux containers. A snapshot is a committed image; revert recreates the
           container from it. Works wherever the docker command does.
  tart     macOS and Linux VMs on Apple Silicon. A snapshot is a clone; revert deletes the
           VM and clones the snapshot back. `tart run` holds the VM open, so start spawns it.

The command parsing (parse_docker_ps, parse_tart_list) is pure, so it's tested without either
installed. Names are validated by the caller (machines) before they reach here. Ported from Archer.
"""

import json
import re
import subprocess
import sys
import time
from typing import Dict, List

from .runner import LabError, run, run_ok, spawn

LABEL = "rivendell.mordor=1"  # marks the containers Rivendell made
LAB_PROJECT = "com.docker.compose.project=rivendell-lab"  # the lab's own Gandalf targets (lab-ubuntu…)
SNAP_TAG = "rivendell-snap"    # docker: snapshot images are rivendell-snap/<name>:<snap>
SNAP_SEP = ".snap."          # tart: a snapshot VM is <name>.snap.<snap>


def parse_docker_ps(out: str) -> List[Dict]:
    """`docker ps -a --format {{json .}}`: one JSON object per line."""
    machines = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        name = row.get("Names", "")
        if not name or SNAP_TAG in row.get("Image", ""):
            continue
        state = (row.get("State") or "").lower()
        machines.append({"engine": "docker", "name": name, "kind": "container",
                        "image": row.get("Image", ""), "os": "linux",
                        "state": "running" if state == "running" else "stopped",
                        "detail": row.get("Status", "")})
    return machines


def parse_tart_list(out: str) -> List[Dict]:
    """`tart list --format json`: the local VMs, snapshots (name.snap.*) left out."""
    try:
        rows = json.loads(out or "[]")
    except ValueError:
        return []
    machines = []
    for row in rows if isinstance(rows, list) else []:
        if row.get("Source") != "local":
            continue
        name = row.get("Name", "")
        if not name or SNAP_SEP in name:
            continue
        running = (row.get("State") or row.get("Running") or "").lower()
        machines.append({"engine": "tart", "name": name, "kind": "vm", "image": "", "os": "",
                        "state": "running" if running in ("running", "true") else "stopped",
                        "detail": f"{row.get('Size', '')} on disk"})
    return machines


class Docker:
    key = "docker"

    def list(self) -> List[Dict]:
        # Rivendell's own machines and the lab's Gandalf targets (docker ANDs label filters, so two calls)
        out = run(["docker", "ps", "-a", "--filter", f"label={LABEL}", "--format", "{{json .}}"])
        out += "\n" + run(["docker", "ps", "-a", "--filter", f"label={LAB_PROJECT}", "--format", "{{json .}}"],
                          check=False)
        seen, machines = set(), []
        for m in parse_docker_ps(out):
            if m["name"] not in seen:
                seen.add(m["name"])
                machines.append(m)
        return machines

    def create(self, name: str, image: str):
        run(["docker", "pull", image], timeout=600)
        # sleep infinity keeps the container up so we can exec into it; label marks it ours
        run(["docker", "run", "-d", "--name", name, "--label", LABEL, "--hostname", name,
             image, "sleep", "infinity"], timeout=120)

    def start(self, name: str):
        run(["docker", "start", name])

    def stop(self, name: str):
        run(["docker", "stop", name], timeout=60)

    def snapshot(self, name: str, snap: str):
        run(["docker", "commit", name, f"{SNAP_TAG}/{name}:{snap}"], timeout=120)

    def revert(self, name: str, snap: str):
        image = f"{SNAP_TAG}/{name}:{snap}"
        if not run_ok(["docker", "image", "inspect", image]):
            raise LabError("No such snapshot", f"{name} has no snapshot {snap}")
        run(["docker", "rm", "-f", name], timeout=60)
        run(["docker", "run", "-d", "--name", name, "--label", LABEL, "--hostname", name,
             image, "sleep", "infinity"], timeout=120)

    def delete(self, name: str):
        run(["docker", "rm", "-f", name], timeout=60, check=False)
        # Drop the machine's snapshot images too
        images = run(["docker", "images", f"{SNAP_TAG}/{name}", "--format", "{{.Repository}}:{{.Tag}}"],
                     check=False)
        for image in images.splitlines():
            if image.strip():
                run(["docker", "rmi", "-f", image.strip()], check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def logs(self, name: str, tail: int) -> str:
        return run(["docker", "logs", "--tail", str(tail), name], check=False)

    def exec(self, name: str, argv: List[str], timeout: int) -> str:
        return run(["docker", "exec", name, *argv], timeout=timeout)

    def push_file(self, name: str, local_path: str, remote_path: str):
        run(["docker", "cp", local_path, f"{name}:{remote_path}"], timeout=120)

    def pull_dir(self, name: str, remote_dir: str, local_parent: str):
        run(["docker", "cp", f"{name}:{remote_dir}", local_parent], timeout=600)


class Tart:
    key = "tart"

    def list(self) -> List[Dict]:
        return parse_tart_list(run(["tart", "list", "--format", "json"]))

    def create(self, name: str, image: str):
        run(["tart", "clone", image, name], timeout=1800)  # pulls the image if it's remote

    def start(self, name: str):
        spawn(["tart", "run", name, "--no-graphics"])  # holds the VM open; returns at once

    def stop(self, name: str):
        run(["tart", "stop", name], timeout=90, check=False)

    def snapshot(self, name: str, snap: str):
        run(["tart", "clone", name, f"{name}{SNAP_SEP}{snap}"], timeout=600)

    def revert(self, name: str, snap: str):
        clone = f"{name}{SNAP_SEP}{snap}"
        if not run_ok(["tart", "get", clone]):
            raise LabError("No such snapshot", f"{name} has no snapshot {snap}")
        run(["tart", "stop", name], timeout=90, check=False)
        run(["tart", "delete", name], check=False)
        run(["tart", "clone", clone, name], timeout=600)

    def delete(self, name: str):
        run(["tart", "stop", name], timeout=90, check=False)
        run(["tart", "delete", name], check=False)
        for row in parse_tart_list_raw():
            if row.startswith(f"{name}{SNAP_SEP}"):
                run(["tart", "delete", row], check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def logs(self, name: str, tail: int) -> str:
        ip = run(["tart", "ip", name], check=False).strip()
        return (f"Tart doesn't keep a console log. The VM's address is {ip}.\n" if ip
                else "Tart doesn't keep a console log, and the VM has no address yet "
                     "(it may still be booting).\n")

    def exec(self, name: str, argv: List[str], timeout: int) -> str:
        return run(["tart", "exec", name, *argv], timeout=timeout)

    def push_file(self, name: str, local_path: str, remote_path: str, windows: bool = False):
        # Tart has no cp; stream the file in over the guest agent (the script is text)
        with open(local_path, encoding="utf-8") as fh:
            text = fh.read()
        if windows:
            run(["tart", "exec", name, "powershell", "-NoProfile", "-Command",
                 f"[IO.File]::WriteAllText('{remote_path}', [Console]::In.ReadToEnd())"],
                timeout=120, input_text=text)
        else:
            run(["tart", "exec", name, "bash", "-lc", f"cat > {remote_path}"], timeout=120, input_text=text)

    def pull_dir(self, name: str, remote_dir: str, local_parent: str, windows: bool = False):
        import base64
        import os
        import tarfile

        parent, base = remote_dir.rsplit("/", 1) if "/" in remote_dir else (".", remote_dir)
        if windows:
            parent, base = remote_dir.replace("/", "\\").rsplit("\\", 1)
            b64 = run(["tart", "exec", name, "powershell", "-NoProfile", "-Command",
                       f"$t=[IO.Path]::GetTempFileName(); tar -czf $t -C '{parent}' '{base}'; "
                       "[Convert]::ToBase64String([IO.File]::ReadAllBytes($t))"], timeout=600)
        else:
            b64 = run(["tart", "exec", name, "bash", "-lc",
                       f"tar czf - -C {parent} {base} | base64"], timeout=600)
        data = base64.b64decode("".join(b64.split()))
        tmp = os.path.join(local_parent, f".{base}.tgz")
        os.makedirs(local_parent, exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(data)
        with tarfile.open(tmp) as tf:
            tf.extractall(local_parent, filter="data")
        os.remove(tmp)


_UTM_UUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


def parse_utm_list(out: str) -> List[Dict]:
    """`utmctl list`: a table of UUID, status and name. The header and blank lines are skipped;
    a UTM VM is 'started' when running. The name (space-free, by our convention) is the id we use."""
    machines = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].lower() == "uuid":
            continue
        uuid, status = parts[0], parts[1].lower()
        name = " ".join(parts[2:]) if len(parts) > 2 else uuid
        machines.append({"engine": "utm", "name": name, "uuid": uuid, "kind": "vm", "image": "", "os": "",
                        "state": "running" if status in ("started", "running") else "stopped",
                        "detail": status})
    return machines


def utm_up() -> None:
    """Open UTM in the background and out of the Dock when Rivendell is what launches it
    (lab/lib/common.sh's utm_up). UTM reads HideDockIcon as it starts, so the setting is put
    back once it's running: opening UTM yourself later shows its icon as usual."""
    if sys.platform != "darwin" or subprocess.run(["pgrep", "-xq", "UTM"]).returncode == 0:
        return
    domain = ["defaults", "write", "com.utmapp.UTM", "HideDockIcon", "-bool"]
    previous = subprocess.run(["defaults", "read", "com.utmapp.UTM", "HideDockIcon"],
                              capture_output=True, text=True)
    subprocess.run(domain + ["true"], capture_output=True)
    subprocess.run(["open", "-g", "-j", "-a", "UTM"], capture_output=True)
    for _ in range(30):
        if subprocess.run(["pgrep", "-xq", "UTM"]).returncode == 0:
            break
        time.sleep(1)
    time.sleep(3)  # past its launch, where the setting is read
    if previous.returncode != 0:
        subprocess.run(["defaults", "delete", "com.utmapp.UTM", "HideDockIcon"], capture_output=True)
    else:
        subprocess.run(domain + ["true" if previous.stdout.strip() == "1" else "false"], capture_output=True)


def utmctl(*args: str, timeout: int = 120, check: bool = True) -> str:
    """utmctl with UTM opened hidden first, and its window kept hidden (--hide) by every
    subcommand that takes it; snapshot doesn't."""
    utm_up()
    hide = [] if args[0] == "snapshot" else ["--hide"]
    return run(["utmctl", args[0], *hide, *args[1:]], timeout=timeout, check=check)


class UTM:
    """UTM/QEMU VMs on macOS, driven through utmctl. utmctl can't create a VM from an image (the
    lab's own Windows VM is built by ./lab.sh windows-vm create) — but it starts, snapshots, restores,
    provisions and records whatever UTM holds. Snapshots are QEMU saved states (fast); exec and
    base64 move files, so no dependence on utmctl's undocumented file push/pull."""

    key = "utm"

    def list(self) -> List[Dict]:
        return parse_utm_list(utmctl("list", timeout=30))

    def create(self, name: str, image: str):
        raise LabError("Build this VM in UTM first",
                       "utmctl can't create a VM from an image. Make it in the UTM app "
                       "(New → Virtualize or Emulate), name it without spaces, and it appears "
                       "here for Rivendell to manage.")

    def start(self, name: str):
        utmctl("start", name, timeout=180)

    def stop(self, name: str):
        utmctl("stop", name, timeout=120, check=False)

    def snapshot(self, name: str, snap: str):
        utmctl("snapshot", "create", name, "--name", snap, timeout=600)

    def revert(self, name: str, snap: str):
        utmctl("snapshot", "restore", name, "--snapshot", snap, timeout=600)

    def clone(self, name: str, new_name: str):
        # Copies the disk, so it's slow for a Windows VM — run it as a job. UTM registers the
        # clone itself; it inherits the source's drives, snapshots and guest tools.
        utmctl("clone", name, "--name", new_name, timeout=1800)

    def delete(self, name: str):
        utmctl("delete", name, timeout=60, check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def logs(self, name: str, tail: int) -> str:
        ip = utmctl("ip-address", name, check=False).strip()
        return (f"UTM keeps no console log. The VM's address is {ip}.\n" if ip
                else "UTM keeps no console log, and the VM has no address yet "
                     "(it may be booting, or missing the guest agent / SPICE tools).\n")

    def exec(self, name: str, argv: List[str], timeout: int, input_text=None) -> str:
        utm_up()
        cmd = ["utmctl", "exec", "--hide", name]
        if input_text is not None:
            cmd.append("--input")
        cmd += ["--cmd", *argv]          # --cmd is variadic, so it has to come last
        return run(cmd, timeout=timeout, input_text=input_text)

    def push_file(self, name: str, local_path: str, remote_path: str, windows: bool = False):
        import base64

        with open(local_path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
        if windows:
            ps = ("$b=[Console]::In.ReadToEnd(); "
                  f"[IO.File]::WriteAllBytes('{remote_path}', [Convert]::FromBase64String($b))")
            self.exec(name, ["powershell", "-NoProfile", "-Command", ps], timeout=300, input_text=b64)
        else:
            self.exec(name, ["bash", "-lc", f"base64 -d > '{remote_path}'"], timeout=300, input_text=b64)

    def pull_dir(self, name: str, remote_dir: str, local_parent: str, windows: bool = False):
        import base64
        import os
        import tarfile

        if windows:
            parent, base = remote_dir.replace("/", "\\").rsplit("\\", 1)
            ps = (f"$t=[IO.Path]::GetTempFileName(); tar -czf $t -C '{parent}' '{base}'; "
                  "[Convert]::ToBase64String([IO.File]::ReadAllBytes($t))")
            b64 = self.exec(name, ["powershell", "-NoProfile", "-Command", ps], timeout=600)
        else:
            parent, base = remote_dir.rsplit("/", 1) if "/" in remote_dir else (".", remote_dir)
            b64 = self.exec(name, ["bash", "-lc", f"tar czf - -C {parent} {base} | base64"], timeout=600)
        data = base64.b64decode("".join(b64.split()))
        os.makedirs(local_parent, exist_ok=True)
        tmp = os.path.join(local_parent, f".{base}.tgz")
        with open(tmp, "wb") as fh:
            fh.write(data)
        with tarfile.open(tmp) as tf:
            tf.extractall(local_parent, filter="data")
        os.remove(tmp)


def parse_tart_list_raw() -> List[str]:
    """Every local Tart VM name, snapshots included (delete sweeps a machine's snapshots)."""
    try:
        rows = json.loads(run(["tart", "list", "--format", "json"]))
    except (ValueError, LabError):
        return []
    return [r.get("Name", "") for r in rows if isinstance(r, dict) and r.get("Source") == "local"]


ENGINES = {"docker": Docker(), "tart": Tart(), "utm": UTM()}


def engine_for(key: str):
    engine = ENGINES.get(key)
    if engine is None:
        raise LabError("Unknown engine", key)
    return engine

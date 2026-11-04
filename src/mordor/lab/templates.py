"""
The machines you can create here. Each template names the engine that runs it, the OS it
records, and the image per architecture. offered() keeps only the ones this host can run,
and picks the image for the host's CPU — so on an Apple Silicon Mac the list gives a Linux
container, a Linux VM and a macOS VM. There is no Windows template: Docker and Tart can't run
Windows, and UTM (which does, via QEMU) has no create-from-image. A Windows VM is built in the
UTM app (or by ./lab.sh windows-vm create) and then managed from Your machines (engines.UTM).

A template says what a recording can capture on it, so the page can tie a machine back to the
telemetry it produces.
"""

from typing import Dict, List, Optional

from . import hosts

# image: {arch: reference}. records: the telemetry sources this OS feeds (src.mordor.telemetry).
TEMPLATES = [
    {
        "id": "ubuntu-container", "engine": "docker", "kind": "container", "os": "linux",
        "name": "Ubuntu 24.04 container", "image": {"arm64": "ubuntu:24.04", "amd64": "ubuntu:24.04"},
        "records": "auditd, syslog, journald",
        "about": "A throwaway Linux container. Fast to create and reset; no kernel of its own, "
                 "so auditd records through the host — enough for process and file telemetry.",
    },
    {
        "id": "ubuntu-vm", "engine": "tart", "kind": "vm", "os": "linux",
        "name": "Ubuntu 24.04 VM", "image": {"arm64": "ghcr.io/cirruslabs/ubuntu:latest"},
        "records": "auditd, syslog, journald, Sysmon for Linux",
        "about": "A full Linux VM with its own kernel, so auditd and Sysmon for Linux record "
                 "exactly as on a real host. Heavier than the container.",
    },
    {
        "id": "macos-vm", "engine": "tart", "kind": "vm", "os": "macos",
        "name": "macOS VM", "image": {"arm64": "ghcr.io/cirruslabs/macos-sequoia-base:latest"},
        "records": "Endpoint Security (eslogger), the unified log, launch items",
        "about": "A macOS VM on Apple Silicon. Records the unified log and Endpoint Security, "
                 "which no public dataset has — the main reason to record your own.",
    },
    # No Windows template: Tart can't run Windows (Apple's Virtualization.framework takes only
    # Linux and macOS guests), and UTM — which runs Windows 11 on ARM via QEMU — has no
    # create-from-image. ./lab.sh windows-vm create builds the lab's from Microsoft's ISO, or build
    # one in the UTM app; Rowanholt then manages and records it from Your machines (engines.UTM).
]
BY_ID = {t["id"]: t for t in TEMPLATES}

# One card per OS: the OS-level blurb and the telemetry it feeds. The weight of a machine is the
# platform's (a container is light, a VM heavy) — that lives on the engine cards, not here.
OS_INFO = {
    "linux": {
        "name": "Ubuntu 24.04",
        "about": "A Linux box for recording Linux attack telemetry.",
        "records": "auditd, syslog, journald (Sysmon for Linux on a VM)",
    },
    "macos": {
        "name": "macOS",
        "about": "macOS on Apple Silicon. Records the unified log and Endpoint Security, which "
                 "no public dataset has — the main reason to record your own.",
        "records": "Endpoint Security (eslogger), the unified log, launch items",
    },
    # "windows" intentionally absent — no engine here can create a Windows VM (see TEMPLATES).
}


def _image_for(template: Dict, arch: str) -> Optional[str]:
    return (template.get("image") or {}).get(arch)


def offered(caps: Optional[Dict] = None) -> List[Dict]:
    """
    The templates this host can run: the engine is installed and running, and the image
    exists for the host's CPU. Each carries whether its engine is ready and the reason when not.
    """
    caps = caps or hosts.capabilities()
    ready = set(caps["ready"])
    by_key = {e["key"]: e for e in caps["engines"]}
    out = []
    for t in TEMPLATES:
        image = _image_for(t, caps["arch"])
        if not image:
            continue  # not built for this architecture (a Windows amd64 image on an arm64 host)
        engine = by_key.get(t["engine"], {})
        if not engine.get("supported"):
            continue
        reason = ""
        if not engine.get("installed"):
            reason = f"{engine['name']} isn't installed"
        elif not engine.get("running"):
            reason = f"{engine['name']} isn't running"
        os_info = OS_INFO.get(t["os"], {})
        out.append({**{k: t[k] for k in ("id", "engine", "kind", "os", "name", "records", "about")},
                    "os_name": os_info.get("name", t["name"]), "os_about": os_info.get("about", t["about"]),
                    "os_records": os_info.get("records", t["records"]),
                    "image": image, "ready": t["engine"] in ready, "reason": reason})
    return out

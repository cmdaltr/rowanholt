"""
What this machine is, and which engines it can drive.

OS and CPU architecture decide which templates are offered and which image a template uses
(templates). An engine that isn't installed is reported with the command to
install it — Rowanholt detects and guides, it doesn't install hypervisors itself.
"""

import platform
from typing import Dict, List

from .runner import first_line, run, run_ok, which

# CPU architecture, normalised: Apple Silicon and x86-64 are the two that matter here
ARCH = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64", "x64": "amd64"}


def arch() -> str:
    return ARCH.get(platform.machine().lower(), platform.machine().lower())


def os_name() -> str:
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(platform.system().lower(),
                                                                            platform.system().lower())


# Each engine: how to detect it, what it runs, and how to install it per host OS
ENGINES = {
    "docker": {
        "name": "Docker",
        "runs": "Linux containers",
        "blurb": "A throwaway container. Fast to create and reset; no kernel of its own. "
                 "Enough for process and file telemetry.",
        "probe": ["docker", "version", "--format", "{{.Server.Version}}"],
        "install": {"macos": "brew install --cask orbstack   # or Docker Desktop",
                    "linux": "curl -fsSL https://get.docker.com | sh",
                    "windows": "winget install Docker.DockerDesktop"},
        "note": "OrbStack satisfies this too — it provides the docker command.",
    },
    "tart": {
        "name": "Tart",
        "runs": "macOS and Linux VMs on Apple Silicon",
        "blurb": "A full VM with its own kernel — records exactly as on a real host, Sysmon "
                 "included. Heavier than a container.",
        "probe": ["tart", "--version"],
        "install": {"macos": "brew install cirruslabs/cli/tart"},
        "requires": {"os": "macos", "arch": "arm64"},
    },
    "utm": {
        "name": "UTM",
        "runs": "Windows, Linux and more via QEMU",
        "blurb": "QEMU VMs on macOS, including Windows 11 on ARM. The lab builds its Windows VM "
                 "from Microsoft's ISO (./lab.sh windows-vm create), or you build one in UTM; "
                 "Rowanholt then starts, snapshots, provisions and records it.",
        "probe": ["utmctl", "version"],
        "install": {"macos": "brew install --cask utm"},
        "requires": {"os": "macos"},
        "note": "The first time Rowanholt drives utmctl, macOS asks you to allow Automation access "
                "to UTM — grant it (System Settings → Privacy & Security → Automation), and open "
                "the UTM app once.",
    },
}


_UTM_READY = {"t": 0.0, "ok": False}


def _utm_version() -> str:
    """UTM's version from its bundle — not utmctl, which would try to drive the app and can hang."""
    import plistlib

    try:
        with open("/Applications/UTM.app/Contents/Info.plist", "rb") as fh:
            return plistlib.load(fh).get("CFBundleShortVersionString", "")
    except Exception:
        return ""


def _utm_ready() -> bool:
    """Whether utmctl answers — true only once the UTM app is open and Automation is allowed.
    Cached briefly, and short-timed, because before the grant utmctl blocks on the macOS prompt."""
    import time

    now = time.time()
    if now - _UTM_READY["t"] < 20:
        return _UTM_READY["ok"]
    ok = run_ok(["utmctl", "list", "--hide"], timeout=8)
    _UTM_READY.update(t=now, ok=ok)
    return ok


def _engine_status(key: str, spec: Dict) -> Dict:
    host_os, host_arch = os_name(), arch()
    requires = spec.get("requires") or {}
    supported = (requires.get("os", host_os) == host_os and requires.get("arch", host_arch) == host_arch)
    present = which(spec["probe"][0]) is not None
    version = ""
    if present:
        if key == "utm":
            version = _utm_version()
        else:
            try:
                version = first_line(run(spec["probe"], timeout=15, check=False))
            except Exception:
                version = ""
    # docker: OrbStack reports its own daemon, so "running" means the daemon answers.
    # utm: "running" means utmctl answers (app open + Automation granted), checked with a timeout.
    if key == "docker":
        running = present and run_ok(["docker", "info", "--format", "{{.ServerVersion}}"])
    elif key == "utm":
        running = present and _utm_ready()
    else:
        running = present and run_ok(spec["probe"])
    return {
        "key": key, "name": spec["name"], "runs": spec["runs"], "blurb": spec.get("blurb", ""),
        "supported": supported, "installed": present, "running": running,
        "version": version, "note": spec.get("note", ""),
        "install": spec.get("install", {}).get(host_os, "") if supported and not present else "",
    }


def capabilities() -> Dict:
    """The host and its engines, for the Lab card. Cheap enough to call on each page load."""
    engines = [_engine_status(k, spec) for k, spec in ENGINES.items()]
    return {
        "os": os_name(), "arch": arch(),
        "label": f"{platform.system()} {platform.machine()}",
        "engines": engines,
        "ready": [e["key"] for e in engines if e["running"]],
    }


def engine_ready(key: str) -> bool:
    spec = ENGINES.get(key)
    return bool(spec) and _engine_status(key, spec)["running"]

"""
The lab VMs' screens over VNC, for the Console button on Aragorn › Lab (FR-04).

Every VM serves its screen on the host's loopback:

  tart  `tart run --vnc-experimental` (Virtualization.framework's own VNC server), on a port and
        password Tart picks each run and prints as vnc://:<password>@127.0.0.1:<port> into the
        VM's log, RUN_DIR/<name>.log (engines.Tart.start and lab/macos/tart-vm.sh write it)
  utm   QEMU's `-vnc 127.0.0.1:<display>` among the bundle's QEMU AdditionalArguments
        (config.plist, the bundle found through UTM's registry): port 5900 + display, no password

discover() is the allow-list the lab agent tunnels by: a console is a running VM's own port, on
127.0.0.1, and a port two VMs claim is left out (there's no telling whose screen it is). Nothing
the browser or the backend sends ever names a host or a port.

Standard library only, Python 3.8-compatible: the lab agent runs it on the host.
"""
from __future__ import annotations

import os
import logging
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import unquote, urlsplit

from .runner import LabError, run

log = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"
LOOPBACK_NAMES = {"127.0.0.1", "localhost"}
ENGINES = ("tart", "utm")
VNC_BASE = 5900
# The lab's own Windows VM is display 59 (5959) and its clean siblings 60–68 (utm-vm.sh); a VM
# cloned from the Machines list gets the first free display from here
CLONE_DISPLAYS = range(70, 100)
# lab/lib/common.sh's LAB_CONFIG_DIR/run, where tart-vm.sh logs each VM's `tart run`
RUN_DIR = Path.home() / ".config" / "rowanholt-lab" / "run"
# QEMU -vnc options that need something the relay can't give (a password set over the monitor,
# TLS, SASL) or that point the server elsewhere
_REFUSED_VNC_OPTIONS = ("password", "password-secret", "tls-creds", "tls-authz", "sasl", "reverse")


def enabled() -> bool:
    """Whether the lab's VMs get a VNC console: opt-in with LAB_VM_CONSOLE=1, since a UTM VM's VNC
    has no password and anything on the host's loopback could open it."""
    return os.environ.get("LAB_VM_CONSOLE", "0").strip() == "1"


def tart_log(name: str) -> Path:
    """Where a Tart VM's `tart run` output goes: its VNC address and password are in it."""
    return RUN_DIR / f"{name}.log"


def parse_tart_log(text: str) -> Optional[Dict]:
    """The VNC server from the last vnc:// URL Tart printed ('VNC server is running at …' with
    --no-graphics, 'Opening …...' otherwise), or None. Only a loopback address is accepted."""
    urls = [w for w in (text or "").split() if w.startswith("vnc://")]
    if not urls:
        return None
    url = urlsplit(urls[-1].rstrip("."))
    try:
        port = url.port
    except ValueError:
        return None
    if url.hostname not in LOOPBACK_NAMES or not port:
        return None
    return {"port": port, "password": unquote(url.password or "")}


def _flatten(args: Iterable) -> List[str]:
    """QEMU arguments as UTM keeps them: one per entry, or several in one entry typed by hand."""
    out: List[str] = []
    for arg in args or []:
        if not isinstance(arg, str):
            continue
        try:
            out.extend(shlex.split(arg))
        except ValueError:
            out.append(arg)
    return out


def parse_qemu_vnc(args: Iterable) -> Optional[int]:
    """The TCP port of a `-vnc 127.0.0.1:<display>` among QEMU's arguments, or None: not set, not
    on loopback (a bare `:N` listens on every address), a unix socket, or needing a password."""
    flat = _flatten(args)
    port = None
    for i, arg in enumerate(flat[:-1]):
        if arg not in ("-vnc", "--vnc"):
            continue
        target, _, options = flat[i + 1].partition(",")
        host, sep, display = target.rpartition(":")
        if not sep or host not in LOOPBACK_NAMES or not display.isdigit():
            port = None
            continue
        if any(opt.split("=", 1)[0] in _REFUSED_VNC_OPTIONS for opt in options.split(",") if opt):
            port = None
            continue
        number = int(display)
        port = VNC_BASE + number if VNC_BASE + number <= 65535 else None
    return port


def set_qemu_vnc(args: Iterable, display: Optional[int]) -> List[str]:
    """QEMU's arguments with any -vnc removed and, unless display is None, `-vnc 127.0.0.1:N` added."""
    kept: List[str] = []
    skip = False
    for arg in args or []:
        if skip:
            skip = False
            continue
        if arg in ("-vnc", "--vnc"):
            skip = True
            continue
        if isinstance(arg, str) and arg.lstrip().startswith(("-vnc ", "--vnc ")):
            continue
        kept.append(arg)
    return kept + (["-vnc", f"{LOOPBACK}:{display}"] if display is not None else [])


def parse_utm_registry(data: bytes) -> Dict[str, str]:
    """UTM's preferences (`defaults export com.utmapp.UTM -`): VM UUID -> bundle path."""
    try:
        prefs = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError):
        return {}
    registry = prefs.get("Registry") if isinstance(prefs, dict) else None
    paths: Dict[str, str] = {}
    for uuid, entry in (registry or {}).items():
        package = entry.get("Package") if isinstance(entry, dict) else None
        path = package.get("Path") if isinstance(package, dict) else None
        if isinstance(path, str) and path:
            paths[str(uuid).upper()] = path
    return paths


def read_utm_registry() -> Dict[str, str]:
    """UTM's registry of VMs, read through cfprefsd (UTM is sandboxed, so its preferences live in
    its container); empty when UTM has never run here."""
    try:
        proc = subprocess.run(["defaults", "export", "com.utmapp.UTM", "-"], capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_utm_registry(proc.stdout) if proc.returncode == 0 else {}


def bundle_config(bundle: str) -> Dict:
    """A UTM bundle's config.plist, or {} if it can't be read."""
    try:
        with open(Path(bundle) / "config.plist", "rb") as fh:
            cfg = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def qemu_args(cfg: Dict) -> List:
    qemu = cfg.get("QEMU") if isinstance(cfg.get("QEMU"), dict) else {}
    args = qemu.get("AdditionalArguments")
    return args if isinstance(args, list) else []


def discover(tart_rows: List[Dict], utm_rows: List[Dict], registry: Dict[str, str],
             read_log=None, read_config=None) -> List[Dict]:
    """
    The consoles of the running VMs: [{engine, name, port, password, auth}]. tart_rows and
    utm_rows are the engines' listings (engines.parse_tart_list, engines.parse_utm_list);
    registry is read_utm_registry()'s. A port claimed by two VMs is dropped, with a warning.
    """
    read_log = read_log or (lambda name: tart_log(name).read_text(errors="replace"))
    read_config = read_config or bundle_config
    found: List[Dict] = []
    for row in tart_rows:
        if row.get("state") != "running":
            continue
        try:
            vnc = parse_tart_log(read_log(row["name"]))
        except OSError:
            vnc = None
        if vnc:
            found.append({"engine": "tart", "name": row["name"], "port": vnc["port"], "password": vnc["password"],
                          "auth": "password" if vnc["password"] else "none"})
    for row in utm_rows:
        if row.get("state") != "running":
            continue
        bundle = registry.get(str(row.get("uuid", "")).upper())
        port = parse_qemu_vnc(qemu_args(read_config(bundle))) if bundle else None
        if port:
            found.append({"engine": "utm", "name": row["name"], "port": port, "password": "", "auth": "none"})
    claims: Dict[int, List[str]] = {}
    for c in found:
        claims.setdefault(c["port"], []).append(f"{c['engine']}/{c['name']}")
    for port, owners in claims.items():
        if len(owners) > 1:
            log.warning("VNC port %s is claimed by %s: no console for either", port, ", ".join(owners))
    return [c for c in found if len(claims[c["port"]]) == 1]


def _utm_running() -> bool:
    """Whether UTM is open (no VM can be running otherwise); listing never launches it."""
    return subprocess.run(["pgrep", "-xq", "UTM"], capture_output=True).returncode == 0


def discover_live() -> List[Dict]:
    """discover() over this host's Tart and UTM, as the lab agent sees them now."""
    if sys.platform != "darwin":
        return []
    from . import engines  # engines imports nothing from here; kept local so tests can patch it

    tart_rows: List[Dict] = []
    utm_rows: List[Dict] = []
    try:
        tart_rows = engines.Tart().list()
    except LabError:
        pass
    if _utm_running():
        try:
            utm_rows = engines.UTM().list()
        except LabError:
            pass
    return discover(tart_rows, utm_rows, read_utm_registry() if utm_rows else {})


def find(engine: str, name: str, consoles: Optional[List[Dict]] = None) -> Optional[Dict]:
    """The console of one VM, from discover_live() unless given."""
    for c in discover_live() if consoles is None else consoles:
        if c["engine"] == engine and c["name"] == name:
            return c
    return None


def free_display(used: Iterable[int]) -> Optional[int]:
    taken = set(used)
    return next((d for d in CLONE_DISPLAYS if d not in taken), None)


def renumber_utm_clone(name: str, uuid: str) -> Optional[int]:
    """
    A UTM clone copies its source's config.plist, -vnc display and all, and QEMU won't start a VM
    whose VNC port is taken: give the clone the first free display in CLONE_DISPLAYS (or none,
    if they're all taken) and have UTM reload it. Returns the clone's new port, or None.
    Raises LabError when the clone's bundle can't be found or written.
    """
    registry = read_utm_registry()
    bundle = registry.get(uuid.upper())
    if not bundle:
        raise LabError("Couldn't find the clone in UTM's registry", f"{name} ({uuid})")
    cfg = bundle_config(bundle)
    if parse_qemu_vnc(qemu_args(cfg)) is None:
        return None  # no console to collide
    used = []
    for path in registry.values():
        if path != bundle:
            port = parse_qemu_vnc(qemu_args(bundle_config(path)))
            if port:
                used.append(port - VNC_BASE)
    display = free_display(used)
    cfg.setdefault("QEMU", {})["AdditionalArguments"] = set_qemu_vnc(qemu_args(cfg), display)
    try:
        with open(Path(bundle) / "config.plist", "wb") as fh:
            plistlib.dump(cfg, fh)
    except OSError as exc:
        raise LabError("Couldn't give the clone its own console port", str(exc))
    run(["osascript", "-e", 'tell application "UTM"',
         "-e", f'reload configuration (virtual machine named "{name}")', "-e", "end tell"], timeout=60, check=False)
    return VNC_BASE + display if display is not None else None

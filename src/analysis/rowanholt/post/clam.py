#!/usr/bin/env python3 -tt
"""ClamAV over what a host's malware most likely sits in: the files Elrond collected and the
user-writable folders of the image (or the whole of a Gandalf collection, which is small).
Commodity malware and known tools; YARA, Defender's own detections and stacking cover the rest.

Detections go to the host's analysis table as "ClamAV" rows, where the case browser and Eru's
analysis answer read them. The signature database is the one built into the worker image:
freshclam runs first only when ROWANHOLT_ONLINE_LOOKUPS lists "freshclam"."""
import os
import subprocess
from datetime import datetime
from typing import List, Tuple

from rowanholt.analysis.analysis import analysis_row, write_analysis
from rowanholt.audit import write_audit_log_entry

# Under a mounted image's root: where users, installers and intruders write (Windows, Linux, macOS)
USER_WRITABLE = ("Users", "ProgramData", "Windows/Temp", "$Recycle.Bin", "PerfLogs", "inetpub", "home", "root",
                 "tmp", "var/tmp", "dev/shm", "var/www", "srv", "opt", "private/tmp", "Library/LaunchAgents",
                 "Library/LaunchDaemons", "Library/Application Support")
# What clamscan is asked to skip or cap: the image's symlinks point at the analysis host
CLAMSCAN_OPTIONS = ["-r", "-i", "--no-summary", "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
                    "--max-filesize=100M", "--max-scansize=400M"]


def freshclam_enabled() -> bool:
    """Whether to refresh the signatures before scanning: ROWANHOLT_ONLINE_LOOKUPS includes "freshclam"."""
    return "freshclam" in {n.strip() for n in os.environ.get("ROWANHOLT_ONLINE_LOOKUPS", "").lower().split(",")}


def scan_targets(loc: str, collected: str) -> List[str]:
    """The folders to scan: the collected files, and the user-writable folders under the image's
    root; a root with none of them (a Gandalf collection) is scanned whole."""
    found = [os.path.join(loc, d) for d in USER_WRITABLE if os.path.isdir(os.path.join(loc, d))]
    targets = found or ([loc] if os.path.isdir(loc) else [])
    return targets + ([collected] if os.path.isdir(collected) else [])


def detections(stdout: str) -> List[Tuple[str, str]]:
    """(file, signature) for each "path: Signature FOUND" line clamscan -i prints."""
    found = []
    for line in stdout.splitlines():
        if line.endswith(" FOUND") and ": " in line:
            path, signature = line[: -len(" FOUND")].rsplit(": ", 1)
            found.append((path, signature))
    return found


def run_clamscan(verbosity: str, output_directory: str, loc: str, img: str) -> int:
    """Scan one host with ClamAV; the number of detections, or -1 when clamscan couldn't run."""
    host = img.split("::")[0]
    analysis_dir = os.path.join(output_directory, host, "analysis")
    os.makedirs(analysis_dir, exist_ok=True)
    targets = scan_targets(loc, os.path.join(output_directory, host, "files"))
    if not targets:
        print(f"      Nothing to scan with ClamAV for '{host}'.")
        return 0
    if freshclam_enabled():
        print("      Updating ClamAV's signatures (freshclam)...")
        subprocess.run(["freshclam", "--quiet"], capture_output=True)
    print(f"      Scanning '{host}' with ClamAV ({len(targets)} folders), please stand by...")
    try:
        result = subprocess.run(["clamscan"] + CLAMSCAN_OPTIONS + targets, capture_output=True)
    except OSError as e:
        print(f"      WARNING: ClamAV couldn't run for '{host}': {e}")
        return -1
    # 0: clean, 1: detections, 2: an error (some files unreadable): what it found still counts
    found = detections(result.stdout.decode("utf-8", "replace"))
    if result.returncode == 2 and not found:
        error = result.stderr.decode("utf-8", "replace").strip().splitlines()
        print(f"      WARNING: ClamAV reported errors for '{host}': {error[-1] if error else 'unknown'}")
    rows = []
    for path, signature in found:
        shown = "/" + os.path.relpath(path, loc) if path.startswith(loc.rstrip("/") + "/") else path
        rows.append(analysis_row(host, shown, "ClamAV", signature))
        entry = "{},{},clamAV,'{}' found in '{}'\n".format(datetime.now().isoformat(), host, signature, shown)
        prnt = " -> {} -> ClamAV found '{}' in '{}' for '{}'".format(
            datetime.now().isoformat().replace("T", " "), signature, shown, host)
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
    write_analysis(analysis_dir, host, rows)
    print(f"       ClamAV: {len(found)} detection(s) on '{host}'.")
    return len(found)

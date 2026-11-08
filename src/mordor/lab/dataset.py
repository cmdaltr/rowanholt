"""
Turn a lab recording into a dataset Elrond can analyse.

A recording (src/mordor/data/telemetry/lab/<run>, from Invoke-MordorRecord.ps1) keeps each
Atomic test's logs apart for the Mordor page: <run>/<technique>-<test>/events.xml on Windows,
audit.log and journal.log on Linux, unified/ES/plist ndjson on macOS, with a manifest.json.
Elrond reads acquisitions, so this writes one per run under <dest>/<run>/:

  Windows       acquisitions/<run>.zip     the events as flat OTRF-style JSON lines, which Elrond
                                           ingests as an event dataset (core/event_dataset.py)
  Linux, macOS  acquisitions/<run>.tar.gz  a Gandalf-style archive: host.info and the logs
                                           under artefacts/logs/, which Elrond already reads
  all           expected.json              what ran and when (the ground truth), kept out of the
                                           events so it can't colour the analysis
                network/<test>.pcap[ng]    each test's capture, when one was made, for Elrond's
                                           --Network (a folder apart: beside the acquisition it
                                           would be read as the host's)

Usage: python3 -m src.mordor.lab.dataset --run <run> [--src DIR] --dest DIR
"""

import argparse
import io
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, Iterator, List, Optional

from .runner import LabError, safe_name

logger = logging.getLogger(__name__)

EVENT = re.compile(r"<Event[\s>].*?</Event>", re.S)
# Per-test files on Linux and macOS, and the name each takes under artefacts/logs/
UNIX_LOGS = {"linux": ("audit.log", "journal.log"), "macos": ("unified.ndjson", "es.ndjson", "plists.ndjson")}
PLATFORM_NAME = {"linux": "Linux", "macos": "macOS"}
CAPTURES = ("capture.pcapng", "capture.pcap")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    if el is None:
        return None
    return next((c for c in el if _local(c.tag) == name), None)


def flatten_event(xml: str) -> Optional[Dict]:
    """One <Event> from Get-WinEvent's ToXml() as a flat OTRF-style record, or None."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    system = _child(root, "System")
    if system is None:
        return None
    rec: Dict = {}
    for el in system:
        name = _local(el.tag)
        if name == "Provider":
            rec["SourceName"] = el.get("Name", "")
        elif name == "TimeCreated":
            rec["@timestamp"] = el.get("SystemTime", "")
        elif name == "EventRecordID":
            rec["RecordNumber"] = el.text or ""
        elif name == "Computer":
            rec["Hostname"] = el.text or ""
        elif name == "Execution":
            rec["ProcessID"], rec["ThreadID"] = el.get("ProcessID", ""), el.get("ThreadID", "")
        elif name == "Security":
            if el.get("UserID"):
                rec["UserID"] = el.get("UserID")
        elif el.text and el.text.strip():
            rec[name] = el.text.strip()
    try:
        rec["EventID"] = int(rec.get("EventID", ""))
    except ValueError:
        pass
    unnamed = 0
    event_data = _child(root, "EventData")
    for d in (list(event_data) if event_data is not None else []):
        key = d.get("Name")
        if not key:
            key = "Data" if not unnamed else f"Data{unnamed}"
            unnamed += 1
        rec.setdefault(key, d.text or "")
    # UserData (some providers' payload): its leaf elements by name
    user_data = _child(root, "UserData")
    for el in (user_data.iter() if user_data is not None else []):
        if len(el) == 0 and el.text and el.text.strip():
            rec.setdefault(_local(el.tag), el.text.strip())
    return rec


def windows_events(text: str) -> Iterator[Dict]:
    """Every event in an events.xml (ToXml() strings, one after another)."""
    for match in EVENT.finditer(text):
        rec = flatten_event(match.group(0))
        if rec:
            yield rec


def _manifest(run_dir: str) -> Dict:
    path = os.path.join(run_dir, "manifest.json")
    if not os.path.isfile(path):
        raise LabError("Not a recording", f"{run_dir} has no manifest.json")
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def _tests(manifest: Dict) -> List[Dict]:
    tests = manifest.get("tests") or []
    return [tests] if isinstance(tests, dict) else tests  # ConvertTo-Json unwraps a single test


def expected(manifest: Dict, run: str) -> Dict:
    """The ground truth: which Atomic tests ran, when, on which host."""
    tests = _tests(manifest)
    return {"name": run, "host": manifest.get("host", ""), "platform": manifest.get("platform", ""),
            "start": manifest.get("started", ""), "end": max((t.get("end", "") for t in tests), default=""),
            "techniques": sorted({t.get("technique", "") for t in tests} - {""}),
            "tests": [{k: t.get(k, "") for k in ("technique", "test", "name", "start", "end")} for t in tests]}


def _windows_zip(run_dir: str, tests: List[Dict], dest: str, run: str) -> int:
    count = 0
    buf = io.StringIO()
    for t in tests:
        path = os.path.join(run_dir, t.get("folder", ""), "events.xml")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for rec in windows_events(fh.read()):
                buf.write(json.dumps(rec) + "\n")
                count += 1
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{run}.json", buf.getvalue())
    return count


def _unix_tarball(run_dir: str, tests: List[Dict], dest: str, host: str, platform: str) -> int:
    """host.info and each kind of log, the tests' slices one after another, as gandalf.sh lays
    an acquisition out (artefacts/host.info, artefacts/logs/...)."""
    lines = 0

    def add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
        info = tarfile.TarInfo(f"artefacts/{name}")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    with tarfile.open(dest, "w:gz") as tar:
        add(tar, "host.info", f"{host}::{PLATFORM_NAME[platform]}\n".encode())
        for log in UNIX_LOGS[platform]:
            parts = []
            for t in tests:
                path = os.path.join(run_dir, t.get("folder", ""), log)
                if os.path.isfile(path):
                    with open(path, "rb") as fh:
                        parts.append(fh.read().rstrip(b"\n"))
            data = b"\n".join(p for p in parts if p)
            if data:
                add(tar, f"logs/{log}", data + b"\n")
                lines += data.count(b"\n") + 1
    return lines


def _captures(run_dir: str, tests: List[Dict], dest: str) -> int:
    """Each test's capture as network/<test>.pcap[ng]; how many there were."""
    count = 0
    for t in tests:
        folder = t.get("folder", "")
        for name in CAPTURES:
            path = os.path.join(run_dir, folder, name)
            if os.path.isfile(path) and os.path.getsize(path):
                os.makedirs(dest, exist_ok=True)
                shutil.copyfile(path, os.path.join(dest, f"{safe_name(folder)}{os.path.splitext(name)[1]}"))
                count += 1
                break
    return count


def convert(run_dir: str, dest_root: str) -> Dict:
    """One recording → <dest_root>/<run>/acquisitions/ and expected.json. Returns a summary."""
    run = safe_name(os.path.basename(os.path.normpath(run_dir)))
    manifest = _manifest(run_dir)
    platform = str(manifest.get("platform", "")).lower()
    tests = _tests(manifest)
    host = safe_name(str(manifest.get("host") or run))
    out = os.path.join(dest_root, run)
    acq = os.path.join(out, "acquisitions")
    os.makedirs(acq, exist_ok=True)
    if platform == "windows":
        archive = os.path.join(acq, f"{run}.zip")
        count, unit = _windows_zip(run_dir, tests, archive, run), "events"
    elif platform in UNIX_LOGS:
        archive = os.path.join(acq, f"{run}.tar.gz")
        count, unit = _unix_tarball(run_dir, tests, archive, host, platform), "log lines"
    else:
        raise LabError("Unknown platform in manifest.json", platform or "(none)")
    network = os.path.join(out, "network")
    captures = _captures(run_dir, tests, network)
    with open(os.path.join(out, "expected.json"), "w", encoding="utf-8") as fh:
        json.dump(expected(manifest, run), fh, indent=2)
    result = {"run": run, "platform": platform, "tests": len(tests), unit.replace(" ", "_"): count,
              "acquisitions": acq + os.sep, "archive": archive, "captures": captures}
    if captures:
        result["network"] = network + os.sep
    return result


def main(argv: Optional[List[str]] = None) -> int:
    from ..telemetry.lab import LAB_DIR
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="The recording's run name (a folder under --src)")
    ap.add_argument("--src", default=LAB_DIR, help="Where recordings are (default: Your lab)")
    ap.add_argument("--dest", required=True, help="Where datasets go, e.g. $MORDOR_ROOT/lab")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        result = convert(os.path.join(args.src, safe_name(args.run)), args.dest)
    except LabError as e:
        logger.error("%s: %s", e.message, e.detail)
        return 1
    found = result.get("events", result.get("log_lines", 0))
    if not found:
        logger.warning("%s: nothing was recorded in its %d tests", result["run"], result["tests"])
    logger.info("Dataset for Elrond: %s (%d tests, %s %s)", result["acquisitions"], result["tests"], f"{found:,}",
                "events" if "events" in result else "log lines")
    if result.get("network"):
        logger.info("Captures for --Network: %s (%d)", result["network"], result["captures"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Windows artefacts Gandalf collects into raw/<folder>/ beyond the core set.

Artemis parses the recycle bin, scheduled tasks, BITS, Windows Search and shortcuts;
the rest (Startup folders, Defender, PCA, WER, hosts, Notepad tabs) are parsed here
into cooked/*.csv with a LastWriteTime column where the artefact has a time, so
Splunk, Elastic and the timeline read them like the others.
"""

import csv
import hashlib
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional

from dernvale.audit import write_audit_log_entry
from dernvale.process.extractions import artemis

logger = logging.getLogger(__name__)

# raw/<folder>/ (or raw/vssN/<folder>/) that each processor reads
RAW_FOLDER = re.compile(r"/artefacts/raw(?:/vss\d+)?/([^/]+)/")
FOLDERS = ("recyclebin", "tasks", "startup", "bits", "search", "defender", "pca", "wer", "lnk", "notepad")
# BITS: qmgr.db (Windows 10+, ESE) or qmgr0.dat/qmgr1.dat (older); the rest are its logs
BITS_DATABASES = ("qmgr.db", "qmgr0.dat", "qmgr1.dat")
SEARCH_DATABASES = ("windows.edb", "windows.db")
MPLOG_EVENTS = re.compile(
    r"threat|detection|\bsdn\b|estimatedimpact|quarantin|remediat|exclusion|tamper|processimagename|"
    r"behavior|\basr\b|attack surface|realtime protection", re.I)
THREAT_NAME = re.compile(r"^[A-Za-z]+:[A-Za-z0-9]+/[\w.!@#$%^&()\-]+$")
LOCAL_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost"}

_processed_dirs = set()


def raw_folder(artefact: str) -> Optional[str]:
    """The raw/<folder> an artefact was collected into, if it's one of FOLDERS."""
    match = RAW_FOLDER.search(artefact)
    return match.group(1) if match and match.group(1) in FOLDERS else None


def _cooked(output_directory: str, img: str, vss_path_insert: str) -> str:
    path = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert
    os.makedirs(path, exist_ok=True)
    return path


def _append_rows(path: str, header: List[str], rows: Iterable[Dict]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=header, extrasaction="ignore")
        if new:
            writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _audit(verbosity, output_directory, img, stage, vssimage, what, artefact):
    entry, prnt = "{},{},{},'{}'\n".format(
        datetime.now().isoformat(), img.split("::")[0], stage, os.path.basename(artefact)
    ), " -> {} -> {} {} '{}' for {}".format(
        datetime.now().isoformat().replace("T", " "), stage, what, os.path.basename(artefact), vssimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)


def read_text(path: str) -> str:
    """A text artefact in whichever encoding Windows wrote it (UTF-16 with or without a BOM, or UTF-8)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if len(data) >= 4 and data[1:4:2] == b"\0\0":
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def filetime(value) -> str:
    """A FILETIME (100 ns ticks since 1601) as ISO 8601, or '' if it isn't one."""
    try:
        ticks = int(value)
        if ticks <= 0:
            return ""
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return ""


def utf16_strings(data: bytes, minimum: int = 4) -> List[str]:
    """Printable UTF-16LE runs in binary data."""
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)
    return [m.group(0).decode("utf-16-le") for m in pattern.finditer(data)]


# ---- Artemis-parsed --------------------------------------------------------

def process_artemis_artefact(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact, folder):
    """Recycle bin $I files, task files, BITS and Search databases one by one; the
    shortcuts directory once."""
    name = os.path.basename(artefact)
    common = dict(verbosity=verbosity, vssimage=vssimage, output_directory=output_directory, img=img,
                  vss_path_insert=vss_path_insert, stage=stage)
    if folder == "recyclebin" and "$I" in name:
        artemis.extract_recyclebin(recycle_file=artefact, **common)
    elif folder == "tasks":
        artemis.extract_tasks(task_file=artefact, **common)
    elif folder == "bits" and name.lower() in BITS_DATABASES:
        artemis.extract_bits(bits_file=artefact, **common)
    elif folder == "search" and name.lower() in SEARCH_DATABASES:
        artemis.extract_search(search_file=artefact, **common)
    elif folder == "lnk":
        directory = os.path.dirname(artefact)
        if directory not in _processed_dirs:
            _processed_dirs.add(directory)
            artemis.extract_shortcuts(lnk_dir=directory, **common)


# ---- parsed here -----------------------------------------------------------

def lnk_target(path: str) -> Dict[str, str]:
    """Target and arguments of a .lnk (pylnk, when the worker has it)."""
    try:
        import pylnk
    except ImportError:
        return {}
    try:
        link = pylnk.open(path)
        target = {"Target": link.local_path or link.network_path or link.relative_path or "",
                  "Arguments": link.command_line_arguments or "",
                  "WorkingDirectory": link.working_directory or ""}
        link.close()
        return target
    except Exception as e:  # malformed lnk: keep the row without a target
        logger.debug("lnk %s: %s", path, e)
        return {}


def startup_item(path: str) -> Dict[str, str]:
    """One file from a Startup folder: everything in one runs at logon (T1547.001)."""
    name = os.path.basename(path)
    user, _, item = name.partition("+")
    with open(path, "rb") as fh:
        data = fh.read()
    row = {"User": user, "Item": item or name, "Size": str(len(data)), "SHA256": hashlib.sha256(data).hexdigest(),
           "Technique": "T1547.001"}
    if name.lower().endswith(".lnk"):
        row.update(lnk_target(path))
    return row


def mplog_rows(path: str) -> List[Dict[str, str]]:
    """Defender's MPLog: the lines about detections, remediation, exclusions, tampering
    and the processes behind them (it also names every process it scanned)."""
    rows = []
    for line in read_text(path).splitlines():
        line = line.strip()
        stamp = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(.*)$", line)
        if not stamp:
            continue
        event = MPLOG_EVENTS.search(stamp.group(2))
        if event:
            rows.append({"LastWriteTime": stamp.group(1), "Category": event.group(0).lower(),
                         "Message": stamp.group(2)[:4000], "LogFile": os.path.basename(path)})
    return rows


def detection_history_row(path: str) -> Optional[Dict[str, str]]:
    """A DetectionHistory record: the threat and what it was found in (file, process,
    registry key, URL), from the record's UTF-16 strings."""
    with open(path, "rb") as fh:
        strings = utf16_strings(fh.read())
    threats = [s for s in strings if THREAT_NAME.match(s)]
    resources = [s for s in strings if re.match(r"^(?:[A-Za-z]:\\|\\\\|file:_|process:_|regkey:_|regkeyvalue:_|webfile:_|containerfile:_|amsi:_)", s)]
    if not threats and not resources:
        return None
    users = [s for s in strings if re.match(r"^[^\\/:]+\\[^\\/:]+$", s) and not s.startswith("NT ")]
    return {"ThreatName": "; ".join(dict.fromkeys(threats)), "Resources": "; ".join(dict.fromkeys(resources)),
            "User": users[0] if users else "", "DetectionFile": os.path.basename(path)}


def pca_rows(path: str) -> List[Dict[str, str]]:
    """Program Compatibility Assistant (Windows 11 22H2+): PcaAppLaunchDic.txt is
    path|last launch; PcaGeneralDb0/1.txt is runStatus|time|type|path|product|company|version|programId|exit."""
    rows = []
    name = os.path.basename(path)
    for line in read_text(path).splitlines():
        fields = [f.strip() for f in line.split("|")]
        if name.lower().startswith("pcaapplaunchdic") and len(fields) >= 2:
            rows.append({"LastWriteTime": fields[-1].replace(" ", "T"), "Path": "|".join(fields[:-1]), "Source": name})
        elif len(fields) >= 9:
            rows.append({"LastWriteTime": fields[1].replace(" ", "T"), "RunStatus": fields[0], "ExecutableType": fields[2],
                         "Path": fields[3], "ProductName": fields[4], "CompanyName": fields[5], "ProductVersion": fields[6],
                         "ProgramId": fields[7], "ExitMessage": fields[8], "Source": name})
    return rows


def wer_row(path: str) -> Optional[Dict[str, str]]:
    """A Report.wer: what crashed or hung, when, and the faulting module."""
    values = {}
    for line in read_text(path).splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    if not values:
        return None
    signature = []
    for i in range(16):
        if f"Sig[{i}].Name" in values:
            signature.append(f"{values[f'Sig[{i}].Name']}={values.get(f'Sig[{i}].Value', '')}")
    module = next((values.get(f"Sig[{i}].Value", "") for i in range(16)
                   if values.get(f"Sig[{i}].Name", "").lower() in ("fault module name", "faulting module name")), "")
    return {"LastWriteTime": filetime(values.get("EventTime")), "EventType": values.get("EventType", ""),
            "AppName": values.get("AppName", "") or values.get("NsAppName", ""), "AppPath": values.get("AppPath", ""),
            "FaultModule": module, "Signature": "; ".join(signature), "ReportFile": os.path.basename(path)}


def hosts_rows(path: str) -> List[Dict[str, str]]:
    """hosts entries; anything beyond the loopback names is worth a look (DNS hijack)."""
    rows = []
    for line in read_text(path).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        names = parts[1:]
        rows.append({"Address": parts[0], "Hostnames": " ".join(names),
                     "NonDefault": "yes" if any(n.lower() not in LOCAL_HOSTS for n in names) else ""})
    return rows


def notepad_row(path: str) -> Optional[Dict[str, str]]:
    """Text of a Windows 11 Notepad tab (saved or not) from its TabState .bin."""
    name = os.path.basename(path)
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(b"NP"):
        return None
    text = "\n".join(utf16_strings(data, 2))
    if not text:
        return None
    user, _, tab = name.partition("+")
    return {"User": user, "TabFile": tab or name, "Text": text[:32000]}


HEADERS = {
    "startup_items.csv": ["User", "Item", "Target", "Arguments", "WorkingDirectory", "Size", "SHA256", "Technique"],
    "defender_mplog.csv": ["LastWriteTime", "Category", "Message", "LogFile"],
    "defender_detections.csv": ["ThreatName", "Resources", "User", "DetectionFile"],
    "pca.csv": ["LastWriteTime", "Path", "RunStatus", "ExecutableType", "ProductName", "CompanyName", "ProductVersion",
                "ProgramId", "ExitMessage", "Source"],
    "wer.csv": ["LastWriteTime", "EventType", "AppName", "AppPath", "FaultModule", "Signature", "ReportFile"],
    "hosts.csv": ["Address", "Hostnames", "NonDefault"],
    "notepad_tabs.csv": ["User", "TabFile", "Text"],
}


def process_windows_artefact(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact) -> bool:
    """Route one collected file to its parser. Returns False if it isn't one of these."""
    folder = raw_folder(artefact)
    name = os.path.basename(artefact)
    if folder is None and name != "hosts":
        return False
    try:
        if folder in ("recyclebin", "tasks", "bits", "search", "lnk"):
            process_artemis_artefact(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact, folder)
            return True
        cooked = _cooked(output_directory, img, vss_path_insert)
        if name == "hosts":
            out, rows, what = "hosts.csv", hosts_rows(artefact), "hosts file"
        elif folder == "startup":
            if name.lower().endswith("desktop.ini"):
                return True
            out, rows, what = "startup_items.csv", [startup_item(artefact)], "startup item"
            artemis._record_techniques(os.path.join(output_directory, "mitre_techniques.txt"), ["T1547.001"])
        elif folder == "defender" and "/detectionhistory/" in artefact.lower():
            row = detection_history_row(artefact)
            out, rows, what = "defender_detections.csv", [row] if row else [], "Defender detection"
        elif folder == "defender" and name.lower().startswith(("mplog", "mpdetection")):
            out, rows, what = "defender_mplog.csv", mplog_rows(artefact), "Defender log"
        elif folder == "pca" and name.lower().endswith(".txt"):
            out, rows, what = "pca.csv", pca_rows(artefact), "PCA record"
        elif folder == "wer" and name.lower().endswith("report.wer"):
            row = wer_row(artefact)
            out, rows, what = "wer.csv", [row] if row else [], "error report"
        elif folder == "notepad":
            row = notepad_row(artefact)
            out, rows, what = "notepad_tabs.csv", [row] if row else [], "Notepad tab"
        else:
            return True  # collected for the analyst (logs, caches) with nothing to parse
        if _append_rows(os.path.join(cooked, out), HEADERS[out], rows):
            _audit(verbosity, output_directory, img, stage, vssimage, what, artefact)
    except Exception as e:
        logger.warning("could not process '%s' for %s: %s", name, vssimage, e)
    return True

"""
Artemis wrapper for forensic artifact parsing.

Artemis is a comprehensive Rust-based forensic parser that supports offline analysis
of Windows artifacts via --alt-file and --alt-dir parameters.

Supported artifacts:
- prefetch, eventlogs, mft, shimcache, amcache, registry, userassist,
- shellbags, usnjrnl, bits, srum, search, tasks, services, shortcuts,
- jumplists, recyclebin, outlook, wmipersist

See: https://github.com/puffyCid/artemis
"""

import glob
import json
import os
import re
import subprocess
from datetime import datetime
from typing import Optional, Dict, List

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.records import SUFFIX, iter_json, write_records
from rowanholt.process.extractions.mitre_tagger import presence_technique

ARTEMIS_PATH = "/usr/local/bin/artemis"

# MITRE ATT&CK technique mappings for artefact types
ARTEFACT_MITRE_MAPPING = {
    "prefetch": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider"]
    },
    "eventlogs": {
        "technique_id": "T1070.001",
        "technique_name": "Clear Windows Event Logs",
        "tactics": ["Defense Evasion"],
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group"]
    },
    "mft": {
        "technique_id": "T1070.006",
        "technique_name": "Timestomp",
        "tactics": ["Defense Evasion"],
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group"]
    },
    "shimcache": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "groups": ["APT28", "APT29", "Turla", "Lazarus Group"]
    },
    "amcache": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "groups": ["APT28", "APT29", "Turla", "FIN7"]
    },
    "registry": {
        "technique_id": "T1112",
        "technique_name": "Modify Registry",
        "tactics": ["Defense Evasion"],
        "groups": ["APT28", "APT29", "Turla", "Lazarus Group"]
    },
    "userassist": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "groups": ["APT28", "APT29", "Turla"]
    },
    "shellbags": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactics": ["Discovery"],
        "groups": ["APT28", "APT29", "Turla", "Lazarus Group", "OilRig"]
    },
    "usnjrnl": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactics": ["Defense Evasion"],
        "groups": ["APT28", "APT29", "Turla", "Lazarus Group"]
    },
    "bits": {
        "technique_id": "T1197",
        "technique_name": "BITS Jobs",
        "tactics": ["Defense Evasion", "Persistence"],
        "groups": ["APT41", "Leviathan", "Turla"]
    },
    "srum": {
        "technique_id": "T1049",
        "technique_name": "System Network Connections Discovery",
        "tactics": ["Discovery"],
        "groups": ["APT28", "APT29", "Turla", "Lazarus Group"]
    },
    "search": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactics": ["Discovery"],
        "groups": ["APT28", "APT29", "Turla"]
    },
    "tasks": {
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider"]
    },
    "services": {
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactics": ["Persistence", "Privilege Escalation"],
        "groups": ["APT28", "Turla", "Lazarus Group", "FIN7"]
    },
    "shortcuts": {
        "technique_id": "T1547.009",
        "technique_name": "Shortcut Modification",
        "tactics": ["Persistence", "Privilege Escalation"],
        "groups": ["APT28", "APT29", "Turla"]
    },
    "jumplists": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactics": ["Discovery"],
        "groups": ["APT28", "APT29", "Turla"]
    },
    "recyclebin": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactics": ["Defense Evasion"],
        "groups": ["APT28", "APT29", "Lazarus Group"]
    },
    "outlook": {
        "technique_id": "T1114.001",
        "technique_name": "Local Email Collection",
        "tactics": ["Collection"],
        "groups": ["APT28", "APT29", "Turla", "OilRig", "Kimsuky"]
    },
    "wmipersist": {
        "technique_id": "T1546.003",
        "technique_name": "WMI Event Subscription",
        "tactics": ["Persistence", "Privilege Escalation"],
        "groups": ["APT29", "Turla", "Leviathan"]
    },
}


# Techniques already in each case's mitre_techniques.txt, so every technique is
# written once rather than once per enriched file.
_RECORDED_TECHNIQUES: Dict[str, set] = {}


def _json_mtimes(directory: str) -> Dict[str, int]:
    """mtime of each *.json directly in directory."""
    out = {}
    for path in glob.glob(os.path.join(directory, "*.json")):
        try:
            out[path] = os.stat(path).st_mtime_ns
        except OSError:
            pass
    return out


def _record_techniques(techniques_file_path: str, techniques) -> None:
    """Append techniques not yet listed in the case's mitre_techniques.txt."""
    seen = _RECORDED_TECHNIQUES.get(techniques_file_path)
    if seen is None:
        seen = set()
        if os.path.exists(techniques_file_path):
            with open(techniques_file_path, errors="ignore") as f:
                seen = {line.strip() for line in f if line.strip()}
        _RECORDED_TECHNIQUES[techniques_file_path] = seen
    new = sorted(t for t in techniques if t and t not in seen)
    if new:
        with open(techniques_file_path, "a") as f:
            f.write("".join(f"{t}\n" for t in new))
        seen.update(new)


# Windows event IDs that are evidence of a technique, keyed by channel: the same
# ID means different things in different channels (1102 outside Security isn't
# a log clear).
EVENTLOG_TECHNIQUES = {
    "security": {
        1102: ["T1070.001"],
        4697: ["T1543.003", "T1569.002"],
        4698: ["T1053.005"],
        4702: ["T1053.005"],
        4720: ["T1136.001"],
        4728: ["T1098"],
        4732: ["T1098"],
        4756: ["T1098"],
    },
    "system": {
        104: ["T1070.001"],
        7045: ["T1543.003", "T1569.002"],
    },
    "microsoft-windows-powershell/operational": {4104: ["T1059.001"]},
    "windows powershell": {400: ["T1059.001"], 800: ["T1059.001"]},
    "microsoft-windows-taskscheduler/operational": {106: ["T1053.005"]},
}
# This many failed logons (4625) in one Security log is treated as password guessing
FAILED_LOGON_THRESHOLD = 5
# Substrings of command lines, script blocks and service image paths
EVENTLOG_TEXT_INDICATORS = {
    "T1003.001": ["mimikatz", "sekurlsa", "procdump", "lsass.dmp"],
    "T1059.003": ["cmd.exe /c", "cmd /c"],
    "T1059.005": ["wscript", "cscript"],
    "T1218": ["mshta", "regsvr32", "rundll32", "msiexec"],
    "T1105": ["certutil -urlcache", "bitsadmin", "downloadstring", "downloadfile", "invoke-webrequest"],
    "T1027": ["-encodedcommand", " -enc "],
}
EVENTLOG_TEXT_FIELDS = ("CommandLine", "ScriptBlockText", "ImagePath", "ServiceFileName", "HostApplication")
# Run keys and the Startup folder (T1547.001): written by Sysmon 12-14 (TargetObject), Security
# 4657 (ObjectName), Sysmon 11 (TargetFilename), or named on a command line or in a script block
RUN_KEY = re.compile(
    r"\\microsoft\\windows\\currentversion\\(?:policies\\explorer\\)?run(?:once(?:ex)?|services(?:once)?)?(?![a-z])",
    re.I)
STARTUP_FOLDER = re.compile(r"\\(?:start menu|startmenu)\\programs\\startup(?:\\|$)", re.I)
RUN_KEY_FIELDS = ("TargetObject", "ObjectName", "TargetFilename", "CommandLine", "ScriptBlockText")


def _event_fields(record):
    """(channel, event ID, EventData) from an Artemis event-log record."""
    event = (record.get("data") or {}).get("Event") or {}
    system = event.get("System") or {}
    event_id = system.get("EventID")
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = None
    channel = str(system.get("Channel") or "").lower()
    data = event.get("EventData") or {}
    return channel, event_id, data if isinstance(data, dict) else {}


def eventlog_techniques(records) -> set:
    """Techniques evidenced by Windows event-log records: channel-scoped event
    IDs, repeated failed logons, and suspicious command lines."""
    found, failed_logons = set(), 0
    for record in records:
        if not isinstance(record, dict):
            continue
        channel, event_id, data = _event_fields(record)
        found.update(EVENTLOG_TECHNIQUES.get(channel, {}).get(event_id, []))
        if channel == "security" and event_id == 4625:
            failed_logons += 1
        if channel == "security" and event_id == 4624 and str(data.get("LogonType")) == "10":
            found.add("T1021.001")
        persistence = " ".join(str(data.get(f, "")) for f in RUN_KEY_FIELDS)
        if RUN_KEY.search(persistence) or STARTUP_FOLDER.search(persistence):
            found.add("T1547.001")
        text = " ".join(str(data.get(f, "")) for f in EVENTLOG_TEXT_FIELDS).lower()
        if text.strip():
            for technique, indicators in EVENTLOG_TEXT_INDICATORS.items():
                if any(i in text for i in indicators):
                    found.add(technique)
    if failed_logons >= FAILED_LOGON_THRESHOLD:
        found.update(["T1110", "T1110.001"])
    return found


# Windows' own tasks, services and WMI consumers: every clean host has them, so they don't stand
# for T1053.005, T1543.003 or T1546.003. A task outside Microsoft's folders, a service run from
# outside Windows' (or one that runs an interpreter), and a consumer Windows doesn't create do
OWN_TASK = re.compile(r"(?i)^\\?(?:microsoft\\|softlanding\\|microsoftedgeupdate|onedrive )")
OWN_SERVICE_PATH = re.compile(
    r"(?i)^\s*\"?(?:%systemroot%|%windir%|\\systemroot|\\\?\?\\[a-z]:\\windows|[a-z]:\\windows|system32)\\"
    r"|\\windows defender\\|\\microsoft\\windows defender\\")
INTERPRETER = re.compile(r"(?i)(?:^|[\\/\"\s])(?:cmd|powershell|pwsh|wscript|cscript|mshta)(?:\.exe)?(?=[\s\"]|$)")
OWN_WMI_CONSUMERS = {"scm event log consumer", "bvtconsumer"}


def _records(json_path: str) -> List[dict]:
    """The dicts in a JSON file: a list, one object, or JSON Lines; "tasks" lists opened up."""
    try:
        with open(json_path, errors="ignore") as f:
            text = f.read()
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else [data]
        except ValueError:
            items = [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
    except (OSError, ValueError):
        return []
    out = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("tasks"), list):
            out.extend(i for i in item["tasks"] if isinstance(i, dict))
        elif isinstance(item, dict):
            out.append(item)
    return out


def _not_windows_own(artifact_type: str, record: dict) -> bool:
    if artifact_type == "tasks":
        # Without a URI, the task's file name says where it sits (Gandalf writes \ as +)
        uri = ((record.get("registration_info") or {}).get("uri")
               or str(record.get("path") or record.get("name") or "").replace("\\", "/").split("/")[-1].replace("+", "\\"))
        return bool(uri) and not OWN_TASK.match(uri)
    if artifact_type == "services":
        path = str(record.get("path") or record.get("image_path") or record.get("ImagePath") or "")
        return bool(path) and (not OWN_SERVICE_PATH.search(path) or bool(INTERPRETER.search(path)))
    name = str(record.get("consumer_name") or "")
    return bool(name) and not record.get("note") and name.lower() not in OWN_WMI_CONSUMERS


PERSISTENCE_ARTEFACTS = {"tasks": "T1053.005", "services": "T1543.003", "wmipersist": "T1546.003"}
# A record's time: the first of these it has (Artemis names them per artefact)
TIME_FIELDS = ("timestamp", "last_run_time", "last_run", "last_execution", "last_modified", "modified", "created",
               "deleted", "last_write_time", "update_time")


def _field_values(record, names: frozenset):
    """Every string value, at any depth, of a field ``names`` names (lowercased)."""
    for key, value in record.items():
        if isinstance(value, dict):
            yield from _field_values(value, names)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield from _field_values(item, names)
        elif isinstance(value, str) and str(key).lower() in names:
            yield value


def pattern_techniques(artifact_type: str):
    """A function giving a record the techniques its fields name by the artefact's substring
    patterns (_get_patterns_for_artifact), or None when the artefact has none. Each row carries
    what it matched, so the case report can cite it (FR-07: the scan recorded them for the
    artefact as a whole)."""
    patterns, field_pattern = _get_patterns_for_artifact(artifact_type)
    names = re.search(r"\(\?:([^)]*)\)", field_pattern or "")
    if not patterns or not names:
        return None
    fields = frozenset(n.lower() for n in names.group(1).split("|"))

    def techniques(record) -> List[str]:
        found = set()
        for value in _field_values(record, fields):
            lower = value.lower()
            found.update(t for t, indicators in patterns.items() if any(i in lower for i in indicators))
        return sorted(found)
    return techniques


def failed_logons(json_path: str) -> int:
    """The Security log's failed logons (4625) in one Artemis event-log file, streamed."""
    with open(json_path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for r in iter_json(fh) if isinstance(r, dict) and _event_fields(r)[:2] == ("security", 4625))


def record_techniques(artifact_type: str, guessing: bool = False):
    """Each record's own techniques, where the record shows one: an event log record by its event
    and command line (each failed logon, when ``guessing``: the file's count of them reached
    FAILED_LOGON_THRESHOLD), a task, service or WMI subscription that isn't Windows' own, and what
    the record's fields name by the artefact's patterns."""
    kind = artifact_type.lower()
    if kind == "eventlogs":
        def event(record):
            found = eventlog_techniques([record])
            if guessing and _event_fields(record)[:2] == ("security", 4625):
                found |= {"T1110", "T1110.001"}
            return sorted(found)
        return event
    named = pattern_techniques(kind)
    if kind in PERSISTENCE_ARTEFACTS:
        def persistence(record):
            items = record.get("tasks") if isinstance(record.get("tasks"), list) else [record]
            mine = any(isinstance(i, dict) and _not_windows_own(kind, i) for i in items)
            own = [PERSISTENCE_ARTEFACTS[kind]] if mine else []
            return sorted(set(own) | set(named(record) if named else []))
        return persistence
    return named


def to_json_lines(json_path: str, cooked_root: str, img: str, source: str, artifact_type: str) -> Optional[str]:
    """Rewrite one Artemis output file as a JSON Lines table beside it, streamed (an MFT is several
    GB), with the envelope; the table's path, or None when it held no records. The .json goes."""
    table = json_path[: -len(".json")] + SUFFIX
    building = table + ".new"
    if os.path.exists(building):
        os.remove(building)
    raw = source.find("/artefacts/")
    # Password guessing is a count across the log, known only once it's read
    guessing = artifact_type.lower() == "eventlogs" and failed_logons(json_path) >= FAILED_LOGON_THRESHOLD
    with open(json_path, encoding="utf-8", errors="replace") as fh:
        written = write_records(
            building, (r if isinstance(r, dict) else {"value": r} for r in iter_json(fh)),
            host=img.split("::")[0],
            artefact=os.path.relpath(table, cooked_root)[: -len(SUFFIX)].replace(os.sep, "/"),
            source_path=source[raw + 1:] if raw >= 0 else source, time_field=TIME_FIELDS,
            techniques=record_techniques(artifact_type, guessing))
    os.remove(json_path)
    if not written:
        return None
    os.replace(building, table)
    return table


def enrich_with_mitre(json_path: str, artifact_type: str) -> bool:
    """
    Fast MITRE enrichment for all artifact files.

    Instead of loading the entire JSON and scanning every field, this:
    1. Streams through the file line by line
    2. Only extracts and scans relevant fields based on artifact type
    3. Uses simple string matching for artifact-specific patterns

    This is much faster than full regex scanning.
    """
    import re
    import traceback


    try:
        # Determine techniques file path at CASE level
        # json_path example: /output/case/image.E01/artefacts/cooked/browsers/file.json
        # We need: /output/case/mitre_techniques.txt (alongside rowanholt_audit.log)
        current_dir = os.path.dirname(json_path)
        case_dir = None

        # Walk up looking for known directory markers
        check_dir = current_dir
        for _ in range(8):  # Max 8 levels up
            dir_name = os.path.basename(check_dir)
            parent = os.path.dirname(check_dir)

            if dir_name == "cooked":
                # Found cooked, go up THREE levels: cooked -> artefacts -> image -> case
                case_dir = os.path.dirname(os.path.dirname(os.path.dirname(check_dir)))
                break
            elif dir_name == "artefacts":
                # Found artefacts, go up TWO levels: artefacts -> image -> case
                case_dir = os.path.dirname(os.path.dirname(check_dir))
                break
            elif os.path.exists(os.path.join(check_dir, "rowanholt_audit.log")):
                # Found case level (has audit log)
                case_dir = check_dir
                break

            check_dir = parent

        # Fallback: if we didn't find a marker, use original directory
        if not case_dir:
            case_dir = current_dir

        techniques_file_path = os.path.join(case_dir, "mitre_techniques.txt")
        os.makedirs(case_dir, exist_ok=True)

        # Base technique for artifact type
        if artifact_type.lower() == "eventlogs":
            # Tag what the records show, not the mere presence of a log
            _record_techniques(techniques_file_path, eventlog_techniques(_records(json_path)))
            return True

        base_technique = ARTEFACT_MITRE_MAPPING.get(artifact_type.lower(), {}).get("technique_id")
        if base_technique and not presence_technique(base_technique):
            base_technique = None  # a parsed MFT isn't timestomping, nor a USN journal file deletion
        if artifact_type.lower() in PERSISTENCE_ARTEFACTS:
            kind = artifact_type.lower()
            mine = any(_not_windows_own(kind, r) for r in _records(json_path))
            base_technique = PERSISTENCE_ARTEFACTS[kind] if mine else None

        found_techniques = set()
        if base_technique:
            found_techniques.add(base_technique)

        # Get artifact-appropriate patterns and field extractors
        patterns, field_pattern = _get_patterns_for_artifact(artifact_type)

        if not patterns:
            # No specific patterns for this artifact type, just write base technique
            if base_technique:
                _record_techniques(techniques_file_path, [base_technique])
            return True

        field_regex = re.compile(field_pattern, re.IGNORECASE)
        # A table to_json_lines wrote has each row's techniques in its envelope already
        # (record_techniques): those are recorded, so each one has a row to cite
        tagged = json_path.endswith(SUFFIX)

        lines_processed = 0
        try:
            with open(json_path, 'r', errors='ignore') as f:
                for line in f:
                    lines_processed += 1
                    # Progress every 500k lines
                    if lines_processed % 500000 == 0:
                        print(f"    ...scanned {lines_processed:,} lines, found {len(found_techniques)} techniques", flush=True)

                    if tagged:
                        found_techniques.update(_envelope_techniques(line))
                        continue
                    # Extract relevant fields from this line
                    matches = field_regex.findall(line)
                    for match in matches:
                        match_lower = match.lower()
                        for tech_id, indicators in patterns.items():
                            for indicator in indicators:
                                if indicator in match_lower:
                                    found_techniques.add(tech_id)
                                    break


            _record_techniques(techniques_file_path, found_techniques)

            return True

        except Exception as e:
            print(f"    WARNING: Error during fast scan: {e}", flush=True)
            if base_technique:
                _record_techniques(techniques_file_path, [base_technique])
            return False

    except NameError as e:
        print(f"    *** CRITICAL ERROR: NameError in enrich_with_mitre(): {e}", flush=True)
        print(f"    *** Full traceback:", flush=True)
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"    *** CRITICAL ERROR: Unexpected error in enrich_with_mitre(): {e}", flush=True)
        print(f"    *** Full traceback:", flush=True)
        traceback.print_exc()
        return False


_ENVELOPE_TECHNIQUES = re.compile(r'^\{"host": .*?"techniques": (\[[^\]]*\])')


def _envelope_techniques(line: str) -> List[str]:
    """The techniques in a table line's envelope, without decoding the rest of the line."""
    match = _ENVELOPE_TECHNIQUES.match(line)
    if not match:
        return []
    try:
        return [t for t in json.loads(match.group(1)) if isinstance(t, str)]
    except ValueError:
        return []


def _get_patterns_for_artifact(artifact_type: str):
    """
    Return appropriate MITRE patterns and field extractor based on artifact type.

    Returns:
        tuple: (patterns_dict, field_regex_pattern) or (None, None) if no patterns apply
    """
    artifact_lower = artifact_type.lower()

    # ========================================
    # CROSS-PLATFORM: Event Logs (Windows evtx, macOS/Linux logs)
    # ========================================
    if artifact_lower in ["eventlogs", "evtx", "evt", "logs", "log"]:
        patterns = {
            # Windows event IDs are matched per record in eventlog_techniques();
            # as substrings of free text they matched almost anything
            "T1059.001": ["powershell", ".ps1", "-encodedcommand"],  # PowerShell
            # Cross-platform command/process patterns
            "T1059.003": ["cmd.exe", "cmd /c"],  # Windows cmd
            "T1059.004": ["/bin/sh", "/bin/bash", "/bin/zsh", "sh -c"],  # Unix shell
            "T1059.005": ["wscript", "cscript", ".vbs"],  # VBScript
            "T1059.006": ["python", "/usr/bin/python"],  # Python
            "T1218": ["mshta", "regsvr32", "rundll32", "msiexec", "certutil"],
            "T1003.001": ["mimikatz", "procdump", "lsass"],
            "T1105": ["psexec", "paexec", "bitsadmin", "certutil", "curl", "wget"],
            # macOS/Linux specific
            "T1053.003": ["cron", "crontab"],  # Cron
            "T1543.002": ["systemctl"],  # Systemd
            "T1548.003": ["sudo", "doas"],  # Sudo abuse
        }
        # Extract Event IDs and message content
        field_pattern = r'"(?:event_id|EventID|eventid|message|Message|CommandLine|command_line|msg|log)"\s*:\s*"?([^",}\]]+)"?'
        return patterns, field_pattern

    # ========================================
    # WINDOWS-ONLY: Registry (may contain paths, files, and command lines)
    # ========================================
    if artifact_lower in ["registry", "reg", "shimcache", "amcache", "userassist"]:
        patterns = {
            # Registry-specific
            # Every hive has Run keys, Classes, Policies and Defender's settings: those are
            # recorded from the values in them (registry/system.py, profile.py), not the key names
            "T1562.001": ["disableantispyware", "disablerealtimemonitoring"],  # Disable security
            # Command lines in registry values. Windows' own associations open .vbs with wscript,
            # .hta with mshta and MSIs with msiexec, and its uninstall strings run rundll32
            "T1059.001": ["-encodedcommand", " -enc ", " -nop ", "-w hidden", "-windowstyle hidden"],
            "T1218": ["certutil"],
            # Files referenced in registry
            "T1003": ["mimikatz", "procdump", "pwdump"],
            "T1105": ["psexec", "paexec", "bitsadmin"],
            "T1219": ["anydesk", "teamviewer", "vnc", "logmein"],
        }
        field_pattern = r'"(?:path|key|value|name|full_path|data|command|arguments)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # WINDOWS-ONLY: Prefetch
    # ========================================
    if artifact_lower in ["prefetch", "pf"]:
        patterns = {
            "T1059": ["powershell", "cmd.exe", "wscript", "cscript", "python", "perl"],
            # rundll32, regsvr32 and msiexec run all day on a clean host
            "T1218": ["mshta", "certutil", "cmstp"],
            "T1003": ["mimikatz", "procdump", "pwdump", "gsecdump", "secretsdump"],
            "T1105": ["psexec", "paexec", "bitsadmin"],
            # svchost, csrss, lsass and services are Windows' own: masquerading is a copy elsewhere,
            # which a Prefetch file name can't show
            "T1070.004": ["sdelete"],  # File deletion
            "T1219": ["anydesk", "teamviewer", "vnc", "logmein", "screenconnect"],
        }
        field_pattern = r'"(?:filename|name|path|executable)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # WINDOWS-ONLY: MFT, USNJrnl
    # ========================================
    if artifact_lower in ["mft", "usnjrnl"]:
        # A file table lists what's on the volume, not what ran: Windows ships scripts, mshta,
        # certutil and wevtutil, and every volume has $Recycle.Bin, Startup folders and readme.txt.
        # Only names Windows doesn't ship count. ntds.dit is a domain controller's own
        patterns = {
            "T1003": ["mimikatz", "procdump", "lsass.dmp", "sam.save", "system.save", "pwdump"],
            "T1105": ["psexec", "paexec"],
            "T1070.004": ["sdelete"],
            "T1219": ["anydesk", "teamviewer", "logmein", "ammyy"],
            "T1486": [".encrypted", ".locked"],  # Ransomware
        }
        field_pattern = r'"(?:full_path|filename|name|path)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # CROSS-PLATFORM: Generic file listings
    # ========================================
    if artifact_lower in ["filelisting", "files"]:
        # As for the MFT: what's on disk, so only what an OS doesn't ship ("nc" was in every "sync")
        patterns = {
            "T1003": ["mimikatz", "procdump", "pwdump", "hashdump"],
            "T1105": ["psexec", "paexec", "netcat"],
            "T1219": ["anydesk", "teamviewer", "logmein"],
            "T1486": [".encrypted", ".locked", "ransom"],  # Ransomware
        }
        field_pattern = r'"(?:full_path|filename|name|path)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # MACOS/LINUX: Journal files
    # ========================================
    if artifact_lower in ["journal", "journalctl", "syslog"]:
        patterns = {
            "T1059.004": ["/bin/sh", "/bin/bash", "/bin/zsh", "sh -c"],  # Unix shell
            "T1059.006": ["python", "/usr/bin/python"],  # Python
            "T1053.003": ["cron", "crontab"],  # Cron
            "T1543.002": ["systemctl"],  # Systemd
            "T1070.002": ["shred"],  # Log deletion
            "T1105": ["netcat"],
        }
        field_pattern = r'"(?:message|msg|command|unit|exe)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # MACOS-ONLY: Plists (may contain command lines)
    # ========================================
    if artifact_lower in ["plist", "launchagent", "launchdaemon", "loginitems"]:
        patterns = {
            # Plist-specific persistence
            "T1543.001": ["launchagents"],  # Launch Agent
            "T1543.004": ["launchdaemons"],  # Launch Daemon
            "T1547.015": ["loginitems", "loginwindow"],  # Login Items
            # Command lines in plists
            "T1059.002": ["osascript", "applescript"],  # AppleScript
            "T1059.004": ["/bin/sh", "/bin/bash", "/bin/zsh", "sh -c"],  # Unix shell
            "T1059.006": ["python", "/usr/bin/python", "python3"],  # Python
            "T1059.007": ["node", "javascript"],  # JavaScript
            # Suspicious binaries
            "T1105": ["netcat"],
            "T1553.001": ["xattr -d com.apple.quarantine", "xattr -c"],  # Gatekeeper bypass
        }
        field_pattern = r'"(?:path|program|label|command|arguments|ProgramArguments|Program)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # BROWSER ARTIFACTS (Cross-platform)
    # ========================================
    if artifact_lower in ["browser", "chromium", "firefox", "safari", "history", "downloads"]:
        patterns = {
            # Visiting OneDrive or a login page is a day's browsing, not exfiltration or phishing
            "T1567": ["mega.nz", "wetransfer"],  # Exfil to cloud
            "T1102": ["pastebin", "hastebin", "ghostbin"],  # Web service C2
        }
        field_pattern = r'"(?:url|path|title|filename)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # WINDOWS-ONLY: Shellbags (may contain command lines in target paths)
    # ========================================
    if artifact_lower in ["shellbags"]:
        patterns = {
            # Folders a user opened: Documents and Desktop are every user's
            "T1025": ["removable"],  # Removable media
        }
        field_pattern = r'"(?:path|name|full_path|target)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # CROSS-PLATFORM: Scheduled Tasks / Cron
    # ========================================
    if artifact_lower in ["tasks", "schtasks", "scheduled", "cron", "crontab"]:
        patterns = {
            # Task-specific
            "T1053.005": ["schtasks", "at.exe"],  # Windows scheduled tasks
            "T1053.003": ["cron", "crontab", "* * *"],  # Cron (macOS/Linux)
            # Command lines in tasks
            "T1059.001": ["powershell", ".ps1", "-enc", "-encodedcommand"],
            "T1059.003": ["cmd.exe", "cmd /c"],
            "T1059.004": ["/bin/sh", "/bin/bash", "sh -c"],
            "T1059.005": ["wscript", "cscript", ".vbs"],
            "T1059.006": ["python", "/usr/bin/python"],
            "T1218": ["mshta", "regsvr32", "certutil"],  # Windows' own tasks run rundll32
            "T1105": ["psexec", "bitsadmin"],
        }
        field_pattern = r'"(?:path|command|action|name|arguments|program|schedule)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # WINDOWS-ONLY: Services (contain command lines)
    # ========================================
    if artifact_lower in ["services"]:
        patterns = {
            # Service-specific
            # Every service runs from System32; svchost is how most of them run
            "T1569.002": ["psexec", "paexec"],  # Service Execution
            # Command lines in service configs
            "T1059.001": ["powershell", ".ps1", "-enc"],
            "T1059.003": ["cmd.exe", "cmd /c"],
            "T1218": ["mshta", "regsvr32", "rundll32", "msiexec"],
            "T1105": ["certutil", "bitsadmin"],
            "T1219": ["anydesk", "teamviewer", "vnc"],
        }
        field_pattern = r'"(?:path|binary_path|name|display_name|command|arguments|ImagePath)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # CROSS-PLATFORM: Generic text log files (.log)
    # Could contain commands, paths, errors, etc.
    # ========================================
    if artifact_lower in ["logfile", "textlog", "syslog", "auth", "secure", "messages"]:
        patterns = {
            # Cross-platform commands
            "T1059.001": ["powershell", ".ps1", "-enc", "-encodedcommand"],
            "T1059.003": ["cmd.exe", "cmd /c"],
            "T1059.004": ["/bin/sh", "/bin/bash", "/bin/zsh", "sh -c"],
            "T1059.006": ["python", "/usr/bin/python"],
            # Authentication/credential access
            # A failed or successful logon is a log's daily business: brute force is counted from
            # the records (login_records), and "root" was in every other line
            "T1548.003": ["doas"],
            # Persistence
            "T1053.003": ["cron", "crontab"],
            "T1543.002": ["systemctl"],
            # Lateral movement / tools
            "T1105": ["netcat"],
            "T1003": ["mimikatz", "procdump", "hashdump"],
        }
        field_pattern = r'"(?:message|msg|log|line|content|text|data)"\s*:\s*"([^"]+)"'
        return patterns, field_pattern

    # ========================================
    # DEFAULT: Generic patterns (fallback)
    # ========================================
    patterns = {
        "T1003": ["mimikatz", "procdump"],
        "T1105": ["psexec"],
    }
    field_pattern = r'"(?:path|name|command|value|message|data)"\s*:\s*"([^"]+)"'
    return patterns, field_pattern


def enrich_json_with_mitre(json_path: str, artifact_type: str, techniques_file_path: str = None) -> bool:
    """
    Enrich a JSON file with MITRE ATT&CK metadata.

    Uses the comprehensive MitreEnrichment class for content-based pattern matching.
    Also writes technique IDs to the techniques file for Navigator layer generation.

    Args:
        json_path: Path to JSON file
        artifact_type: Type of artifact (prefetch, eventlogs, etc.)
        techniques_file_path: Optional path to techniques file for Navigator

    Returns:
        True if successful
    """
    try:
        # Use the comprehensive MitreEnrichment class for content-based pattern matching
        from rowanholt.post.mitre.enrichment import MitreEnrichment
        enrichment = MitreEnrichment()

        # Determine techniques file path if not provided
        if not techniques_file_path:
            # Go up from cooked dir to CASE level, write mitre_techniques.txt there
            # json_path example: /output/case/image.E01/artefacts/cooked/browsers/file.json
            # We need: /output/case/mitre_techniques.txt (alongside rowanholt_audit.log)
            current_dir = os.path.dirname(json_path)
            case_dir = None

            # Walk up looking for known directory markers
            check_dir = current_dir
            for _ in range(8):  # Max 8 levels up
                dir_name = os.path.basename(check_dir)
                parent = os.path.dirname(check_dir)

                if dir_name == "cooked":
                    # Found cooked, go up THREE levels: cooked -> artefacts -> image -> case
                    case_dir = os.path.dirname(os.path.dirname(os.path.dirname(check_dir)))
                    break
                elif dir_name == "artefacts":
                    # Found artefacts, go up TWO levels: artefacts -> image -> case
                    case_dir = os.path.dirname(os.path.dirname(check_dir))
                    break
                elif os.path.exists(os.path.join(check_dir, "rowanholt_audit.log")):
                    # Found case level (has audit log)
                    case_dir = check_dir
                    break

                check_dir = parent

            # Fallback: if we didn't find a marker, use original directory
            if not case_dir:
                case_dir = current_dir

            techniques_file_path = os.path.join(case_dir, "mitre_techniques.txt")

        # Ensure directory exists
        os.makedirs(os.path.dirname(techniques_file_path), exist_ok=True)

        # Open techniques file in append mode and enrich the JSON
        with open(techniques_file_path, 'a') as techniques_file:
            return enrichment.enrich_json_file_streaming(json_path, techniques_file, artifact_type)

    except ImportError:
        # Fallback to simple mapping if enrichment module not available
        mitre_data = ARTEFACT_MITRE_MAPPING.get(artifact_type.lower())
        if not mitre_data:
            return False

        try:
            with open(json_path, 'r') as f:
                data = json.load(f)

            # Handle both single records and arrays
            if isinstance(data, list):
                for record in data:
                    if isinstance(record, dict):
                        record["mitre_technique_id"] = mitre_data["technique_id"]
                        record["mitre_technique_name"] = mitre_data["technique_name"]
                        record["mitre_tactics"] = mitre_data["tactics"]
                        record["mitre_groups"] = mitre_data["groups"]
            elif isinstance(data, dict):
                data["mitre_technique_id"] = mitre_data["technique_id"]
                data["mitre_technique_name"] = mitre_data["technique_name"]
                data["mitre_tactics"] = mitre_data["tactics"]
                data["mitre_groups"] = mitre_data["groups"]

            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2)

            # Write technique ID to file if path provided
            if techniques_file_path and mitre_data:
                with open(techniques_file_path, 'a') as f:
                    f.write(f"{mitre_data['technique_id']}\n")

            return True

        except Exception:
            return False
    except Exception:
        return False


def artemis_available() -> bool:
    """Check if Artemis binary is available."""
    return os.path.exists(ARTEMIS_PATH)


def run_artemis(
    artifact: str,
    output_dir: str,
    alt_file: Optional[str] = None,
    alt_dir: Optional[str] = None,
    output_filename: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> tuple[bool, str]:
    """
    Run Artemis to parse a forensic artifact using CLI acquire mode.

    Args:
        artifact: Artifact type (prefetch, eventlogs, mft, shimcache, etc.)
        output_dir: Directory to write output files
        alt_file: Alternative file path for single-file artifacts
        alt_dir: Alternative directory path for multi-file artifacts
        output_filename: Desired output filename (without .json extension).
                        If provided, output will be renamed to this name.
        extra_args: Further artifact options, e.g. ["--alt-mft", path] for usnjrnl

    Returns:
        Tuple of (success: bool, error_message: str)
    """
    if not artemis_available():
        return False, f"Artemis not found at {ARTEMIS_PATH}"

    # Build command using CLI acquire mode
    # NOTE: --format and --output-dir must come BEFORE the artifact subcommand
    cmd = [
        ARTEMIS_PATH,
        "acquire",
        "--format", "JSON",
        "--output-dir", output_dir,
        artifact,
    ]

    # Artifact-specific argument names (artemis has different param names per artifact)
    # Mapping: artifact -> (file_arg, dir_arg)
    artifact_args = {
        "prefetch": (None, "--alt-dir"),           # only supports --alt-dir
        "eventlogs": ("--alt-file", "--alt-dir"),  # supports both
        "mft": ("--alt-file", None),               # only --alt-file
        "shimcache": ("--alt-file", None),         # only --alt-file
        "usnjrnl": ("--alt-path", None),           # uses --alt-path not --alt-file
        "amcache": ("--alt-file", None),           # only --alt-file
        "registry": ("--alt-file", None),          # only --alt-file
        "jumplists": ("--alt-file", None),         # only --alt-file
        "wmipersist": (None, "--alt-dir"),         # only --alt-dir
        "userassist": ("--alt-file", None),        # only --alt-file
        "shellbags": ("--alt-file", None),         # only --alt-file
        "bits": ("--alt-file", None),              # only --alt-file
        "srum": ("--alt-file", None),              # only --alt-file
        "search": ("--alt-file", None),            # only --alt-file
        "tasks": ("--alt-file", None),             # only --alt-file
        "services": ("--alt-file", None),          # only --alt-file
        "shortcuts": (None, "--path"),             # a directory of .lnk files
        "recyclebin": ("--alt-file", None),        # only --alt-file
        "outlook": ("--alt-file", None),           # only --alt-file
    }

    file_arg, dir_arg = artifact_args.get(artifact, ("--alt-file", "--alt-dir"))

    # Add alt_file or alt_dir if specified (these go after the artifact subcommand)
    if alt_file and file_arg:
        cmd.extend([file_arg, alt_file])
    elif alt_dir and dir_arg:
        cmd.extend([dir_arg, alt_dir])
    if extra_args:
        cmd.extend(extra_args)

    try:
        import sys
        import threading
        import time as time_module

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Progress indicator for long-running operations
        stop_progress = threading.Event()
        def show_progress():
            start_time = time_module.time()
            # Use proper display name for artifacts
            display_name = "$MFT" if artifact == "mft" else artifact
            while not stop_progress.is_set():
                elapsed = int(time_module.time() - start_time)
                if elapsed > 0 and elapsed % 30 == 0:  # Every 30 seconds
                    print(f" -> still processing {display_name}... ({elapsed}s elapsed)", flush=True)
                stop_progress.wait(1)

        progress_thread = threading.Thread(target=show_progress, daemon=True)
        progress_thread.start()

        stdout_data, stderr_data = process.communicate()
        stop_progress.set()
        progress_thread.join(timeout=1)

        if process.returncode != 0:
            stderr_text = stderr_data.decode('utf-8', errors='replace') if stderr_data else ''
            stdout_text = stdout_data.decode('utf-8', errors='replace') if stdout_data else ''
            return False, f"{stderr_text} {stdout_text}"[:500]

        # Artemis outputs to a 'local_collector' subdirectory - move files up
        import shutil
        import glob
        local_collector_dir = os.path.join(output_dir, "local_collector")
        if os.path.exists(local_collector_dir):
            json_files = glob.glob(os.path.join(local_collector_dir, "*.json"))

            # For MFT, merge all JSON files into a single file
            if artifact == "mft" and len(json_files) > 1:
                merged_data = []
                for jf in json_files:
                    try:
                        with open(jf, 'r') as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                merged_data.extend(data)
                            else:
                                merged_data.append(data)
                    except:
                        pass
                # Write merged file - always use journal_mft.json for MFT
                merged_path = os.path.join(output_dir, "journal_mft.json")
                with open(merged_path, 'w') as f:
                    json.dump(merged_data, f)
                # Clean up individual files
                for jf in json_files:
                    os.remove(jf)
            elif len(json_files) == 1:
                # Single output file - rename appropriately
                if artifact == "mft":
                    # Always use journal_mft.json for MFT
                    dest = os.path.join(output_dir, "journal_mft.json")
                elif output_filename:
                    # Use provided output filename
                    dest = os.path.join(output_dir, f"{output_filename}.json")
                else:
                    # Keep original name
                    dest = os.path.join(output_dir, os.path.basename(json_files[0]))
                shutil.move(json_files[0], dest)
            elif len(json_files) > 1 and output_filename:
                # Multiple files but we have a desired output name - merge them
                merged_data = []
                for jf in json_files:
                    try:
                        with open(jf, 'r') as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                merged_data.extend(data)
                            else:
                                merged_data.append(data)
                    except:
                        pass
                # Write merged file with desired name
                merged_path = os.path.join(output_dir, f"{output_filename}.json")
                with open(merged_path, 'w') as f:
                    json.dump(merged_data, f)
                # Clean up individual files
                for jf in json_files:
                    os.remove(jf)
            else:
                # Multiple files and no specific output name - move with original names
                for f in glob.glob(os.path.join(local_collector_dir, "*.json")):
                    dest = os.path.join(output_dir, os.path.basename(f))
                    shutil.move(f, dest)

            # Remove local_collector directory
            try:
                shutil.rmtree(local_collector_dir)
            except:
                pass

        return True, ""

    except Exception as e:
        return False, str(e)


def extract_with_artemis(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    artifact_type: str,
    artifact_file: Optional[str] = None,
    artifact_dir: Optional[str] = None,
    output_subdir: str = "",
    fixed_output_name: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> bool:
    """
    Extract artifacts using Artemis with proper logging.

    Args:
        verbosity: Verbosity level
        vssimage: VSS image identifier
        output_directory: Base output directory
        img: Image identifier
        vss_path_insert: VSS path component
        stage: Processing stage name
        artifact_type: Artemis artifact type
        artifact_file: Path to artifact file (for --alt-file)
        artifact_dir: Path to artifact directory (for --alt-dir)
        output_subdir: Subdirectory name for output (e.g., "prefetch", "evt")
        fixed_output_name: Override output filename (without .json extension)

    Returns:
        True if successful, False otherwise
    """
    if not artemis_available():
        entry, prnt = "{},{},{},'{}' (skipped - artemis not found)\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artifact_type,
        ), " -> {} -> skipped '{}' for {} (artemis not found)".format(
            datetime.now().isoformat().replace("T", " "),
            artifact_type,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        return False

    # Determine output path
    cooked_base = (
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
    )

    if output_subdir:
        cooked_dir = cooked_base + output_subdir + "/"
    else:
        cooked_dir = cooked_base

    # Create output directory if needed
    os.makedirs(cooked_dir, exist_ok=True)

    # Log start - only show filename, not full path
    artifact_display = os.path.basename(artifact_file) if artifact_file else (os.path.basename(artifact_dir.rstrip('/')) if artifact_dir else "system")
    entry, prnt = "{},{},{},'{}'\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artifact_type,
    ), " -> {} {} '{}' for {}".format(
        stage,
        artifact_type,
        artifact_display,
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)

    # Derive output filename from the original artefact (without extension)
    if fixed_output_name:
        # Use the fixed output name if provided
        output_name = fixed_output_name
    elif artifact_file:
        # Get filename without path, then remove extension
        base_name = os.path.basename(artifact_file)
        # Remove extension (handle .evtx, .pf, etc.)
        output_name = os.path.splitext(base_name)[0]
    elif artifact_dir:
        # For directories, use the directory name
        output_name = os.path.basename(artifact_dir.rstrip('/'))
    else:
        output_name = None

    # Snapshot cooked_dir so enrichment below only touches what this run writes.
    before = _json_mtimes(cooked_dir)
    success, error = run_artemis(
        artifact=artifact_type,
        output_dir=cooked_dir,
        alt_file=artifact_file,
        alt_dir=artifact_dir,
        output_filename=output_name,
        extra_args=extra_args,
    )

    if not success:
        error_msg = error.replace('\n', ' ').replace(',', ';').replace("'", "")[:200]
        # Always print errors regardless of verbosity
        print(
            " -> {} -> WARNING: artemis {} failed for {}: {}".format(
                datetime.now().isoformat().replace('T', ' '),
                artifact_type,
                vssimage,
                error_msg[:100]
            )
        )
        return False

    # What this run wrote, as JSON Lines, then its MITRE ATT&CK enrichment. Enriching every
    # table in cooked_dir re-read all earlier output after each call, which made
    # event-log processing quadratic per shadow copy.
    source = artifact_file or artifact_dir or ""
    for json_file, mtime in _json_mtimes(cooked_dir).items():
        if before.get(json_file) == mtime:
            continue
        try:
            table = to_json_lines(json_file, cooked_base, img, source, artifact_type)
        except (OSError, ValueError) as e:
            print(f"    WARNING: couldn't convert {os.path.basename(json_file)}: {e}", flush=True)
            continue
        if not table:
            continue
        try:
            enrich_with_mitre(table, artifact_type)
        except Exception as e:
            print(f"    WARNING: MITRE enrichment failed for {os.path.basename(table)}: {e}", flush=True)

    return True


# Convenience functions for specific artifact types

def extract_prefetch(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    prefetch_dir: str,
) -> bool:
    """Extract Windows Prefetch files using Artemis. Its prefetch parser only
    takes a directory (--alt-dir), so the whole directory goes in one run."""
    if not os.path.exists(prefetch_dir):
        return False

    pf_files = [f for f in os.listdir(prefetch_dir) if f.lower().endswith('.pf')]

    if not pf_files:
        return False

    print("     processing {} prefetch files".format(len(pf_files)))
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="prefetch",
        artifact_dir=prefetch_dir,
        output_subdir="prefetch",
    )


def extract_eventlogs(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    evtx_file: Optional[str] = None,
    evtx_dir: Optional[str] = None,
) -> bool:
    """Extract Windows Event Logs using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="eventlogs",
        artifact_file=evtx_file,
        artifact_dir=evtx_dir,
        output_subdir="evt",
    )


def extract_mft(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    mft_file: str,
) -> bool:
    """Extract MFT using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="mft",
        artifact_file=mft_file,
        output_subdir="",
    )


def extract_shimcache(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    system_hive: str,
) -> bool:
    """Extract Shimcache from SYSTEM registry hive using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="shimcache",
        artifact_file=system_hive,
        output_subdir="",  # Output directly to cooked/ as shimcache.json
        fixed_output_name="shimcache",  # Force output name to shimcache.json
    )


def extract_amcache(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    amcache_file: str,
) -> bool:
    """Extract Amcache using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="amcache",
        artifact_file=amcache_file,
        output_subdir="amcache",
    )


def extract_userassist(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    ntuser_file: str,
) -> bool:
    """Extract UserAssist from NTUSER.DAT using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="userassist",
        artifact_file=ntuser_file,
        output_subdir="userassist",
    )


def extract_shellbags(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    registry_file: str,
) -> bool:
    """Extract Shellbags from NTUSER.DAT or UsrClass.dat using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="shellbags",
        artifact_file=registry_file,
        output_subdir="shellbags",
    )


def extract_usnjrnl(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    usnjrnl_file: str,
    mft_file: Optional[str] = None,
) -> bool:
    """Extract USN Journal using Artemis; with the $MFT, entries get their full paths."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="usnjrnl",
        artifact_file=usnjrnl_file,
        output_subdir="",  # Output directly to cooked/ as journal_usn.json
        fixed_output_name="journal_usn",  # Force output name to journal_usn.json
        extra_args=["--alt-mft", mft_file] if mft_file else None,
    )


def extract_srum(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    srum_file: str,
) -> bool:
    """Extract SRUM database using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="srum",
        artifact_file=srum_file,
        output_subdir="srum",
    )


def extract_bits(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    bits_file: str,
) -> bool:
    """Extract BITS database using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="bits",
        artifact_file=bits_file,
        output_subdir="bits",
    )


def extract_tasks(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    task_file: str,
) -> bool:
    """Extract Scheduled Task using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="tasks",
        artifact_file=task_file,
        output_subdir="tasks",
        # Task names hold dots (".NET Framework NGEN v4.0.30319 64"): splitext would
        # collapse several onto one output
        fixed_output_name=os.path.basename(task_file),
    )


def extract_services(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    system_hive: str,
) -> bool:
    """Extract Windows Services from SYSTEM hive using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="services",
        artifact_file=system_hive,
        output_subdir="services",
    )


def extract_shortcuts(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    lnk_dir: str,
) -> bool:
    """Every .lnk in a directory using Artemis (it takes the directory, not a file)."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="shortcuts",
        artifact_dir=lnk_dir,
        output_subdir="shortcuts",
    )


def extract_jumplists(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    jumplist_file: str,
) -> bool:
    """Extract Jumplist file using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="jumplists",
        artifact_file=jumplist_file,
        output_subdir="jumplists",
    )


def extract_recyclebin(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    recycle_file: str,
) -> bool:
    """Extract Recycle Bin entry using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="recyclebin",
        artifact_file=recycle_file,
        output_subdir="recyclebin",
    )


def extract_outlook(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    ost_file: str,
) -> bool:
    """Extract Outlook OST file using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="outlook",
        artifact_file=ost_file,
        output_subdir="outlook",
    )


def extract_wmipersist(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    wmi_dir: str,
) -> bool:
    """Extract WMI persistence from repository directory using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="wmipersist",
        artifact_dir=wmi_dir,
        output_subdir="",  # Output directly to cooked/ as wbem.json
        fixed_output_name="wbem",  # Force output name to wbem.json
    )


def extract_search(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    search_file: str,
) -> bool:
    """Extract Windows Search database using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="search",
        artifact_file=search_file,
        output_subdir="search",
    )


def extract_registry(
    verbosity: str,
    vssimage: str,
    output_directory: str,
    img: str,
    vss_path_insert: str,
    stage: str,
    registry_file: str,
) -> bool:
    """Extract Windows Registry hive using Artemis."""
    return extract_with_artemis(
        verbosity=verbosity,
        vssimage=vssimage,
        output_directory=output_directory,
        img=img,
        vss_path_insert=vss_path_insert,
        stage=stage,
        artifact_type="registry",
        artifact_file=registry_file,
        output_subdir="registry",
    )

"""Event datasets: archives of Windows events as JSON, with no host.info.

OTRF Security-Datasets (Mordor), the lab's mordor-capture and its converted recordings all ship
events as flat JSON records (one per line, or one array), not as a Gandalf acquisition. Each
host the events name becomes an Elrond host whose events sit in artefacts/cooked/evt/ in the
shape Artemis gives a disk image's .evtx, so ATT&CK tagging, Splunk and Elastic read them the
same way.
"""

import json
import logging
import os
import re
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

PLATFORM = "Windows"
EVT_DIR = os.path.join("artefacts", "cooked", "evt")
# Elrond's IOC extraction skips files of 10 MB or more (analysis.py), so a host's events are
# written in parts below that.
PART_BYTES = 9_000_000
# Flat OTRF fields that belong in the event's System block; the rest is EventData, apart from
# what Winlogbeat/NXLog added in transit, which isn't part of the event.
SYSTEM_FIELDS = {
    "EventID": "EventID", "Channel": "Channel", "Hostname": "Computer", "Computer": "Computer",
    "RecordNumber": "EventRecordID", "EventRecordID": "EventRecordID", "Level": "Level",
    "Task": "Task", "Opcode": "Opcode", "Keywords": "Keywords", "Version": "Version",
}
PROVIDER_FIELDS = ("ProviderName", "SourceName")
TIME_FIELDS = ("@timestamp", "TimeCreated", "EventTime", "timestamp")
TRANSPORT_FIELDS = {
    "@version", "beat_hostname", "host", "tags", "port", "EventReceivedTime", "SourceModuleName",
    "SourceModuleType", "Severity", "SeverityValue", "EventType", "log_name", "source_name",
    "event_data", "user", "agent", "ecs", "log", "input", "fields", "winlog", "event",
}


def _host_name(value: object, fallback: str) -> str:
    """A directory-safe host name: the event's own, else the dataset's."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "").strip()).strip("._")
    return name or fallback


def is_event_record(record: object) -> bool:
    """A Windows event: something with an EventID and a channel or provider."""
    return isinstance(record, dict) and "EventID" in record and any(
        record.get(f) for f in ("Channel", *PROVIDER_FIELDS))


def to_artemis(record: Dict) -> Dict:
    """One flat OTRF record in Artemis's event-log shape (data.Event.System / EventData)."""
    system: Dict = {}
    data: Dict = {}
    timestamp = next((record[f] for f in TIME_FIELDS if record.get(f)), "")
    for key, value in record.items():
        if key in SYSTEM_FIELDS:
            system[SYSTEM_FIELDS[key]] = value
        elif key in PROVIDER_FIELDS:
            system["Provider"] = {"#attributes": {"Name": value}}
        elif key in TIME_FIELDS or key in TRANSPORT_FIELDS:
            continue
        else:
            data[key] = value
    try:
        system["EventID"] = int(system.get("EventID"))
    except (TypeError, ValueError):
        pass
    if timestamp:
        system["TimeCreated"] = {"#attributes": {"SystemTime": timestamp}}
    return {"@timestamp": timestamp, "timestamp": timestamp,
            "data": {"Event": {"System": system, "EventData": data}}}


def read_records(path: str) -> Iterator[Dict]:
    """The records in one JSON file: JSON lines, or a single JSON array."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(1)
        while head and head.isspace():
            head = fh.read(1)
        fh.seek(0)
        if head == "[":
            try:
                records = json.load(fh)
            except ValueError as e:
                logger.warning("%s isn't valid JSON (%s); skipping it", path, e)
                return
            yield from (r for r in records if isinstance(r, dict))
            return
        for number, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                logger.debug("%s:%d isn't JSON; skipped", path, number)
                continue
            if isinstance(record, dict):
                yield record


def json_files(directory: str) -> List[str]:
    """Every JSON file under an extracted archive, macOS metadata aside."""
    found = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d != "__MACOSX"]
        found += [os.path.join(root, f) for f in sorted(files)
                  if f.lower().endswith((".json", ".jsonl", ".ndjson")) and not f.startswith("._")]
    return found


def looks_like_event_dataset(directory: str) -> bool:
    """Whether an extracted archive holds Windows events: its first JSON record is one."""
    for path in json_files(directory):
        for record in read_records(path):
            return is_event_record(record)
    return False


def split_by_host(paths: Iterable[str], fallback: str, out_dir: str) -> Dict[str, Tuple[str, int]]:
    """Convert every event in the files to Artemis's shape, one JSON-lines file per host in
    out_dir (streamed, so a large dataset isn't held in memory). Returns {host: (file, count)}."""
    handles: Dict[str, object] = {}
    counts: Dict[str, int] = {}
    os.makedirs(out_dir, exist_ok=True)
    try:
        for path in paths:
            for record in read_records(path):
                if not is_event_record(record):
                    continue
                host = _host_name(record.get("Hostname") or record.get("Computer"), fallback)
                if host not in handles:
                    handles[host] = open(os.path.join(out_dir, f"{host}.jsonl"), "w", encoding="utf-8")
                    counts[host] = 0
                handles[host].write(json.dumps(to_artemis(record)) + "\n")
                counts[host] += 1
    finally:
        for fh in handles.values():
            fh.close()
    return {h: (os.path.join(out_dir, f"{h}.jsonl"), counts[h]) for h in handles}


def write_json_arrays(lines_path: str, dest_dir: str, stem: str, part_bytes: int = PART_BYTES) -> List[str]:
    """Rewrite a JSON-lines file as JSON arrays like Artemis's, streamed: <stem>.json, or
    <stem>-0001.json, <stem>-0002.json ... when the events don't fit in one part."""
    os.makedirs(dest_dir, exist_ok=True)
    parts: List[str] = []
    out = None
    size = 0
    try:
        with open(lines_path, encoding="utf-8") as src:
            for line in src:
                line = line.rstrip("\n")
                if out is None or size + len(line) + 1 > part_bytes:
                    if out is not None:
                        out.write("]")
                        out.close()
                    parts.append(os.path.join(dest_dir, f"{stem}-{len(parts) + 1:04d}.json"))
                    out = open(parts[-1], "w", encoding="utf-8")
                    out.write("[" + line)
                    size = len(line) + 2
                else:
                    out.write("," + line)
                    size += len(line) + 1
    finally:
        if out is not None:
            out.write("]")
            out.close()
    if len(parts) == 1:
        single = os.path.join(dest_dir, f"{stem}.json")
        os.replace(parts[0], single)
        parts = [single]
    return parts


def ingest(staging: str, stem: str, output_directory: str) -> List[Tuple[str, int, List[str]]]:
    """Lay one extracted event dataset out as Elrond hosts.

    Writes <output>/<host>/artefacts/cooked/evt/<stem>.json for every host its events name and
    creates <host>/artefacts/raw/ (empty: there's no disk behind it), so the host is registered
    like any other. Returns [(host, events, [evt files])]."""
    split_dir = os.path.join(staging, ".by-host")
    hosts = split_by_host(json_files(staging), _host_name(stem, "dataset"), split_dir)
    placed = []
    for host, (lines_path, count) in sorted(hosts.items()):
        host_dir = os.path.join(output_directory, host)
        os.makedirs(os.path.join(host_dir, "artefacts", "raw"), exist_ok=True)
        files = write_json_arrays(lines_path, os.path.join(host_dir, EVT_DIR), stem)
        placed.append((host, count, files))
    return placed


def platform_entry(host: str) -> str:
    """The allimgs value for an event-dataset host: '<host>::Windows'."""
    return f"{host}::{PLATFORM}"


def summary(placed: List[Tuple[str, int, List[str]]]) -> Optional[str]:
    """'3 hosts, 196,071 events' for the audit log."""
    if not placed:
        return None
    events = sum(c for _, c, _ in placed)
    return f"{len(placed)} host{'s' if len(placed) != 1 else ''}, {events:,} events"

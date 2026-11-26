"""
Recorded attack telemetry (#22, stage 1): which logs record each technique, from datasets
recorded while attacks were emulated in labs. No infrastructure and no AI.

Sources (each its own module, same output):

- Splunk attack_data (Apache-2.0, maintained): Atomic Red Team and tool runs in Splunk's
  Attack Range, Windows, Linux and cloud. src.mordor.telemetry.splunk_attack_data
- Security-Datasets (OTRF, formerly Mordor; MIT; last updated March 2024): Empire, Covenant
  and tool runs in OTRF's lab, with network captures. src.mordor.telemetry.security_datasets

    python -m src.mordor.telemetry --build                  # all (first run ~1.2 GB, then what changed)
    python -m src.mordor.telemetry --build --source otrf    # one

Output:

- src/mordor/data/telemetry_datasets.json (committed): each dataset's techniques and the event
  types it recorded ("Microsoft-Windows-Sysmon/Operational 1", "Security 4688",
  "CloudTrail iam.amazonaws.com CreateUser"), with counts.
- src/mordor/data/telemetry_values.json.gz (committed, ~2 MB): the distinct values of the fields
  detections match on, per dataset and event type, so a detection's indicators can be
  checked against real recorded events: which event types contain them.

A recording shows that a technique can be recorded and by which log, for that tool in that
lab; not every way the technique can be done. Each also carries the lab's background
activity, so an event type in most datasets is marked as background.
"""

import gzip
import html
import io
import json
import os
import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.dirname(__file__))
SUMMARY_PATH = os.path.join(HERE, "data", "telemetry_datasets.json")
VALUES_PATH = os.path.join(HERE, "data", "telemetry_values.json.gz")
# Sources whose licence keeps them out of git (INFO["local"]): built on this machine only
LOCAL_SUMMARY_PATH = os.path.join(HERE, "data", "cache", "telemetry_local.json")
LOCAL_VALUES_PATH = os.path.join(HERE, "data", "cache", "telemetry_local_values.json.gz")
STATE_PATH = os.path.join(HERE, "data", "cache", "telemetry_state.json")
MAP_FILES = (os.path.join(HERE, "mappings", "telemetry_map.json"),
             os.path.join("bespoke", "mappings", "telemetry_map.json"))
PARSER_VERSION = 3  # part of each recording's build key: a parser change fetches everything again
BACKGROUND_SHARE = 0.4  # an event type recorded in this share of datasets is the lab's background
MAX_VALUES = 150  # distinct values per field per event type per dataset
MAX_LEN = 500

# The fields kept, by what a detection's indicators are (Shikari's indicator kinds)
FIELDS = {
    "cmd": ["CommandLine", "ParentCommandLine", "ScriptBlockText", "Payload", "ContextInfo"],
    "file": ["Image", "ParentImage", "TargetFilename", "ImageLoaded", "NewProcessName", "ParentProcessName",
             "ServiceFileName", "ImagePath", "TargetImage", "SourceImage", "Application", "ObjectName",
             "RelativeTargetName", "OriginalFileName", "exe"],
    "reg": ["TargetObject", "ObjectName", "Details", "NewName"],
    "network": ["QueryName", "DestinationHostname", "DestinationIp", "DestinationPort", "ShareName", "PipeName"],
    "other": ["ServiceName", "TargetUserName", "TicketEncryptionType", "Properties", "AccessMask", "GrantedAccess",
              "CallTrace", "AttributeLDAPDisplayName", "TaskName", "TaskContent", "Operation", "Parameters",
              "UserAgent"],
}
KEEP = {f for fs in FIELDS.values() for f in fs}
# Indicator kinds (YAML 'indicators:' keys) to the field groups they're looked for in
KIND_FIELDS = {"cmd": ("cmd",), "sw": ("file", "cmd"), "path": ("file", "cmd"), "file": ("file", "cmd"),
               "reg": ("reg", "cmd"), "evt": ("other",), "api": ("other", "cmd"), "operation": ("other",),
               "op": ("other",), "network": ("network", "cmd"), "domain": ("network", "cmd"), "ip": ("network",),
               "port": ("network",), "service": ("other", "cmd"), "acct": ("other",)}

# How each kind of log is collected: native OS logging is everywhere, Sysmon and agents only
# where someone deployed them
COLLECTIONS = {"native": "Native OS logs", "sysmon": "Sysmon", "edr": "EDR", "osquery": "osquery", "cloud": "Cloud and SaaS"}
_CLOUD = ("CloudTrail ", "Office 365 ", "Azure ", "Entra ID ", "GCP ", "Google Workspace ", "Okta ")


def collection(etype: str) -> str:
    if etype.startswith(("Microsoft-Windows-Sysmon/", "Linux-Sysmon/")):
        return "sysmon"
    # macOS Endpoint Security is what an EDR on a Mac sees; eslogger shows the same events
    if etype.startswith(("CrowdStrike ", "Elastic Endpoint ", "MDE ", "ESF ")):
        return "edr"
    if etype.startswith("osquery "):
        return "osquery"
    if etype.startswith(_CLOUD):
        return "cloud"
    return "native"


PLATFORMS = {"windows": "Windows", "linux": "Linux", "macos": "macOS", "esxi": "ESXi", "cloud": "Cloud and SaaS"}
_MAC_TYPES = ("osquery es_process_events", "osquery launchd", "osquery es_")


def _given(d: Dict) -> set:
    out = {str(p).lower() for p in d.get("platform") or []}
    return {"macos" if p in ("macos", "osx", "mac") else p for p in out} & set(PLATFORMS)


def event_platform(etype: str, d: Dict) -> Optional[str]:
    """The platform an event type in a recording comes from; None when only the recording says."""
    if etype.startswith("syslog ") and "esxi" in d["id"].lower():
        return "esxi"
    if etype.startswith(("auditd ", "syslog ", "Linux-Sysmon/")):
        return "linux"
    if etype.startswith(_MAC_TYPES + ("ESF ", "Unified log ", "plist ")) or ("macos" in d["id"].lower() and etype.startswith("osquery ")):
        return "macos"
    if etype.startswith(_CLOUD):
        return "cloud"
    if etype.startswith(("osquery ", "Elastic Endpoint ", "CrowdStrike ", "MDE ")):
        return None
    return "windows"


def platforms(d: Dict) -> List[str]:
    """The platforms a recording's logs come from (its own "platform" where the source gives one)."""
    out = _given(d)
    out.update(p for p in (event_platform(e, d) for e in d["events"]) if p)
    return sorted(out)


# Channel names as recorded, in whichever case a lab wrote them
_CHANNELS = {c.lower(): c for c in (
    "Security", "System", "Application", "Windows PowerShell", "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Linux-Sysmon/Operational", "Microsoft-Windows-SMBClient/Security", "Microsoft-Windows-CodeIntegrity/Operational")}

# Windows' rendered event text ("Process Command Line:\t…") to the XML field names
_TEXT_FIELDS = {
    "Process Command Line": "CommandLine", "New Process Name": "NewProcessName", "Creator Process Name": "ParentProcessName",
    "Service File Name": "ServiceFileName", "Service Name": "ServiceName", "Object Name": "ObjectName",
    "Task Name": "TaskName", "Task Content": "TaskContent", "Ticket Encryption Type": "TicketEncryptionType",
    "Properties": "Properties", "Accesses": "AccessMask", "Access Mask": "AccessMask", "Share Name": "ShareName",
    "Relative Target Name": "RelativeTargetName", "Application Name": "Application", "Image Path": "ImagePath",
    "LDAP Display Name": "AttributeLDAPDisplayName", "Host Application": "ContextInfo",
}
_TEXT_BLOCK = re.compile(r"(?m)^(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M\s*$)")
_XML_EVENT = re.compile(r"<Event[ >].*?</Event>", re.S)
_XML_DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]\s*>(.*?)</Data>", re.S)


def channel(name: str) -> str:
    name = (name or "").strip()
    return _CHANNELS.get(name.lower(), name)


def _keep(event: Dict, fields: Dict[str, str]) -> Dict[str, str]:
    for k, v in fields.items():
        if k in KEEP and v not in (None, "", "-", "null", "None"):
            event[k] = str(v)[:MAX_LEN]
    return event


def _xml_events(text: str, default_channel: str = "") -> Iterable[Tuple[str, Dict]]:
    for raw in _XML_EVENT.findall(text):
        eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", raw)
        ch = re.search(r"<Channel>(.*?)</Channel>", raw)
        if not eid:
            continue
        fields = {k: html.unescape(v) for k, v in _XML_DATA.findall(raw)}
        yield f"{channel(ch.group(1) if ch else default_channel)} {eid.group(1)}", _keep({}, fields)


def _evtx_events(blob: bytes, default_channel: str = "") -> Iterable[Tuple[str, Dict]]:
    """A binary .evtx file's records, through their XML (the evtx package)."""
    import io

    import evtx

    for record in evtx.PyEvtxParser(io.BytesIO(blob)).records():
        yield from _xml_events(record["data"], default_channel)


def _text_events(text: str, default_channel: str = "") -> Iterable[Tuple[str, Dict]]:
    for block in _TEXT_BLOCK.split(text):
        code = re.search(r"(?m)^EventCode=(\d+)", block)
        if not code:
            continue
        log = re.search(r"(?m)^LogName=(.+)$", block)
        fields = {}
        for name, value in re.findall(r"(?m)^[ \t]*([A-Z][A-Za-z ]{2,40}):[ \t]*\t[ \t]*(\S.*)$", block):
            if name.strip() in _TEXT_FIELDS:
                fields[_TEXT_FIELDS[name.strip()]] = value.strip()
        script = re.search(r"Creating Scriptblock text \(\d+ of \d+\):\s*(.*?)\s*ScriptBlock ID:", block, re.S)
        if script:
            fields["ScriptBlockText"] = script.group(1)
        yield f"{channel(log.group(1) if log else default_channel)} {code.group(1)}", _keep({}, fields)


def _cloud_type(e: Dict) -> Optional[Tuple[str, str]]:
    """(event type, operation) for a cloud audit record."""
    if isinstance(e.get("eventSource"), str) and isinstance(e.get("eventName"), str):
        return f"CloudTrail {e['eventSource']} {e['eventName']}", e["eventName"]
    if e.get("kind") == "admin#reports#activity" and isinstance(e.get("event"), dict):
        app = (e.get("id") or {}).get("applicationName", "")
        return f"Google Workspace {app} {e['event'].get('name', '')}".strip(), str(e["event"].get("name", ""))
    if isinstance(e.get("eventType"), str) and isinstance(e.get("actor"), dict):
        return f"Okta {e['eventType']}", e["eventType"]
    if e.get("Workload") and e.get("Operation"):
        return f"Office 365 {e['Workload']} {e['Operation']}", e["Operation"]
    op = e.get("operationName")
    if isinstance(op, dict):
        op = op.get("value") or op.get("localizedValue")
    if op:
        category = str(e.get("category", "")).lower()
        prefix = "Entra ID" if "signin" in category or category == "auditlogs" else "Azure"
        return f"{prefix} {op}", str(op)
    method = (e.get("protoPayload") or {}).get("methodName") if isinstance(e.get("protoPayload"), dict) else None
    if method:
        return f"GCP {method}", method
    return None


def _json_events(text: str, default_channel: str = "") -> Iterable[Tuple[str, Dict]]:
    def records():
        stripped = text.strip()
        if stripped.startswith("["):
            try:
                yield from json.loads(stripped)
                return
            except ValueError:
                pass
        lines = [line.strip() for line in text.splitlines() if line.strip().startswith("{")]
        parsed = 0
        for line in lines:
            try:
                yield json.loads(line)
                parsed += 1
            except ValueError:
                continue
        if not parsed and stripped.startswith("{"):
            yield from _pretty_records(stripped)

    for e in records():
        if not isinstance(e, dict):
            continue
        if isinstance(e.get("Records"), list):  # a CloudTrail file
            for r in e["Records"]:
                cloud = _cloud_type(r) if isinstance(r, dict) else None
                if cloud:
                    yield cloud[0], _keep({}, {"Operation": cloud[1], "UserAgent": r.get("userAgent"),
                                               "Parameters": json.dumps(r.get("requestParameters"))[:MAX_LEN]})
            continue
        win = e.get("Event") if isinstance(e.get("Event"), dict) else e
        eid = win.get("EventID") if win.get("EventID") is not None else (win.get("System") or {}).get("EventID")
        ch = win.get("Channel") or (win.get("System") or {}).get("Channel") or default_channel
        if eid is not None and ch:
            data = win.get("EventData") if isinstance(win.get("EventData"), dict) else win
            yield f"{channel(ch)} {eid}", _keep({}, data)
            continue
        cloud = _cloud_type(e)
        if cloud:
            yield cloud[0], _keep({}, {"Operation": cloud[1], "UserAgent": e.get("userAgent"),
                                       "Parameters": json.dumps(e.get("requestParameters") or e.get("Parameters")
                                                                or e.get("properties"))[:MAX_LEN]})
        elif str(e.get("Table") or "").startswith(("Device", "Identity", "Email", "Cloud", "Alert")):
            yield _mde(e)
        elif isinstance(e.get("event"), dict) and "event_type" in e and isinstance(e.get("process"), dict):
            yield _eslogger(e)
        elif "eventMessage" in e and ("subsystem" in e or "processImagePath" in e):
            yield _unified_log(e)
        elif e.get("plist") in ("added", "changed", "removed"):
            yield f"plist {e['plist']}", _keep({}, {"TargetFilename": e.get("path"), "TaskName": e.get("Label"),
                                                   "CommandLine": e.get("ProgramArguments") or e.get("Program")})
        elif isinstance(e.get("columns"), dict) and e.get("name"):
            yield _osquery(e)
        elif isinstance(e.get("_source"), dict) or "endpoint.events" in json.dumps(e.get("data_stream") or e.get("event") or {}):
            elastic = _elastic_endpoint(e.get("_source") if isinstance(e.get("_source"), dict) else e)
            if elastic:
                yield elastic
        elif e.get("event_simpleName"):
            yield f"CrowdStrike {e['event_simpleName']}", _keep({}, {
                "CommandLine": e.get("CommandLine"), "Image": e.get("ImageFileName"), "TargetFilename": e.get("TargetFileName")})


def _pretty_records(text: str) -> Iterable[Dict]:
    """Pretty-printed objects one after another, as Kibana's Dev Tools copies them ("\"\"\"…\"\"\"" strings too)."""
    text = re.sub(r'"""(.*?)"""', lambda m: json.dumps(m.group(1)), text, flags=re.S)
    decoder, i = json.JSONDecoder(), 0
    while i < len(text):
        while i < len(text) and text[i] in " \r\n\t,[]":
            i += 1
        if i >= len(text):
            break
        try:
            obj, i = decoder.raw_decode(text, i)
        except ValueError:
            return
        yield obj


def _mde(e: Dict) -> Tuple[str, Dict]:
    """An Advanced Hunting row, as Shikari's mde.py exports them: "MDE DeviceProcessEvents ProcessCreated"."""
    table = e["Table"]
    path = e.get("FolderPath")
    return f"MDE {table} {e.get('ActionType') or ''}".strip(), _keep({}, {
        "CommandLine": e.get("ProcessCommandLine"), "ParentCommandLine": e.get("InitiatingProcessCommandLine"),
        "Image": path if table == "DeviceProcessEvents" else None,
        "TargetFilename": path if table in ("DeviceFileEvents", "DeviceEvents") else None,
        "ImageLoaded": path if table == "DeviceImageLoadEvents" else None,
        "ParentImage": e.get("InitiatingProcessFolderPath"), "TargetObject": e.get("RegistryKey"),
        "Details": e.get("RegistryValueData"), "DestinationHostname": e.get("RemoteUrl"),
        "DestinationIp": e.get("RemoteIP"), "DestinationPort": e.get("RemotePort"),
        "TargetUserName": e.get("AccountName"),
        "Parameters": e.get("AdditionalFields") if isinstance(e.get("AdditionalFields"), str) else
        (json.dumps(e["AdditionalFields"])[:MAX_LEN] if e.get("AdditionalFields") else None)})


def _eslogger(e: Dict) -> Tuple[str, Dict]:
    """A macOS Endpoint Security event from eslogger: "ESF exec", "ESF btm_launch_item_add"."""
    name, body = next(iter(e["event"].items()), ("unknown", {}))
    body = body if isinstance(body, dict) else {}
    path = lambda f: (f or {}).get("path") if isinstance(f, dict) else None
    target = body.get("target") or {}
    dest = body.get("destination") or {}
    item = body.get("item") or {}
    args = body.get("args")
    return f"ESF {name}", _keep({}, {
        "CommandLine": " ".join(map(str, args)) if isinstance(args, list) else None,
        "Image": body.get("executable_path") or path((target.get("executable") if isinstance(target, dict) else None))
        or path(e["process"].get("executable")),
        "ParentImage": path(e["process"].get("executable")) if name == "exec" else None,
        "TargetFilename": path(target) or path(dest.get("existing_file")) or path(body.get("source"))
        or path(dest.get("new_path", {}).get("dir") if isinstance(dest.get("new_path"), dict) else None)
        or item.get("item_url") or path(body.get("file")),
        "TaskName": item.get("app_url") or body.get("type"),
        "TargetUserName": body.get("username") or body.get("to_username")})


def _unified_log(e: Dict) -> Tuple[str, Dict]:
    """A unified log entry (log stream/show --style ndjson): "Unified log com.apple.xprotect"."""
    source = e.get("subsystem") or os.path.basename(str(e.get("processImagePath") or "")) or "unknown"
    return f"Unified log {source}", _keep({}, {"Payload": e.get("eventMessage"), "Image": e.get("processImagePath")})


def _osquery(e: Dict) -> Tuple[str, Dict]:
    """An osquery result: "osquery es_process_events" (macOS Endpoint Security), "osquery launchd" (plists)."""
    name = re.sub(r"^pack_[^_]+(?:-[^_]+)*_", "", str(e["name"]))
    c = e["columns"]
    args = c.get("program_arguments") or c.get("program")
    return f"osquery {name}", _keep({}, {
        "CommandLine": c.get("cmdline") or args, "Image": c.get("path") if "cmdline" in c else None,
        "ParentImage": c.get("parent_path"), "TargetFilename": c.get("path") if "cmdline" not in c else c.get("target_path"),
        "TaskName": c.get("label"), "DestinationIp": c.get("remote_address"), "DestinationPort": c.get("remote_port")})


def _elastic_endpoint(s: Dict) -> Optional[Tuple[str, Dict]]:
    """An Elastic Endpoint (Elastic Defend) event: "Elastic Endpoint process exec"."""
    ds = str((s.get("data_stream") or {}).get("dataset") or (s.get("event") or {}).get("dataset") or "")
    if not ds.startswith("endpoint.events."):
        return None
    action = (s.get("event") or {}).get("action")
    action = action[0] if isinstance(action, list) and action else action
    proc, parent = s.get("process") or {}, (s.get("process") or {}).get("parent") or {}
    line = lambda p: p.get("command_line") or (" ".join(map(str, p["args"])) if isinstance(p.get("args"), list) else None)
    dns = ((s.get("dns") or {}).get("question") or {}).get("name")
    return f"Elastic Endpoint {ds.rsplit('.', 1)[1]} {action or ''}".strip(), _keep({}, {
        "CommandLine": line(proc), "Image": proc.get("executable"), "ParentCommandLine": line(parent),
        "ParentImage": parent.get("executable"), "TargetFilename": (s.get("file") or {}).get("path"),
        "DestinationIp": (s.get("destination") or {}).get("ip"), "DestinationPort": (s.get("destination") or {}).get("port"),
        "QueryName": dns})


def _auditd_events(text: str) -> Iterable[Tuple[str, Dict]]:
    for line in text.splitlines():
        m = re.match(r"\s*type=(\w+) msg=audit\(", line)
        if not m:
            continue
        fields = {}
        exe = re.search(r'\bexe="([^"]+)"', line)
        if exe:
            fields["exe"] = exe.group(1)
        if m.group(1) == "EXECVE":
            fields["CommandLine"] = " ".join(v.strip('"') for v in re.findall(r"\ba\d+=(\"[^\"]*\"|\S+)", line))
        title = re.search(r"\bproctitle=([0-9A-Fa-f]+)\b", line)
        if title:
            try:
                fields["CommandLine"] = bytes.fromhex(title.group(1)).replace(b"\x00", b" ").decode("utf-8", "replace")
            except ValueError:
                pass
        name = re.search(r'\bname="([^"]+)"', line)
        if name:
            fields["TargetFilename"] = name.group(1)
        yield f"auditd {m.group(1)}", _keep({}, fields)


_SYSLOG = re.compile(r"^\w{3}\s+\d+ \d\d:\d\d:\d\d \S+ (?:\S+ \S+ )?([A-Za-z][\w.-]*)(?:\[\d+\])?: (.*)$")


def _syslog_events(text: str) -> Iterable[Tuple[str, Dict]]:
    for line in text.splitlines():
        m = _SYSLOG.match(line)
        if m:
            message = re.sub(r"^\[[^\]]*\]:\s*", "", m.group(2))  # ESXi shell: "[root]: esxcli …"
            yield f"syslog {m.group(1)}", _keep({}, {"CommandLine": message})


def parse(blob: bytes, default_channel: str = "") -> Iterable[Tuple[str, Dict]]:
    """(event type, kept fields) for every event a log file holds, whatever its format."""
    if blob[:8] == b"ElfFile\x00":
        yield from _evtx_events(blob, default_channel)
        return
    text = blob.decode("utf-8", "replace")
    head = text[:4000]
    if "<Event" in head:
        yield from _xml_events(text, default_channel)
    elif re.search(r"(?m)^EventCode=\d+", head) or "LogName=" in head:
        yield from _text_events(text, default_channel)
    elif re.search(r"(?m)^\s*[\[{]", head):
        yield from _json_events(text, default_channel)
    elif "msg=audit(" in head:
        yield from _auditd_events(text)
    elif _SYSLOG.match(head.split("\n", 1)[0]):
        yield from _syslog_events(text)


def unpack(blob: bytes) -> Iterable[bytes]:
    """The files in a zip or tar.gz, or the blob itself."""
    import io
    import tarfile
    import zipfile

    if blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for name in z.namelist():
                if not name.endswith("/"):
                    yield z.read(name)
    elif blob[:2] == b"\x1f\x8b":
        try:
            with tarfile.open(fileobj=io.BytesIO(blob)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        yield t.extractfile(m).read()
        except tarfile.ReadError:
            yield gzip.decompress(blob)
    else:
        yield blob


def summarise(events: Iterable[Tuple[str, Dict]]) -> Tuple[Dict[str, int], Dict[str, Dict[str, List[str]]]]:
    """({event type: count}, {event type: {field: [distinct values]}})."""
    counts: Counter = Counter()
    values: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for etype, fields in events:
        counts[etype] += 1
        for k, v in fields.items():
            bucket = values[etype][k]
            if len(bucket) < MAX_VALUES:
                bucket.add(v)
    return dict(counts.most_common()), {t: {k: sorted(v) for k, v in fs.items()} for t, fs in values.items()}


def mark_background(datasets: List[Dict], share: float = BACKGROUND_SHARE) -> None:
    """Event types recorded in `share` of a source's datasets are its lab's background (in place)."""
    by_source = defaultdict(list)
    for d in datasets:
        by_source[d["source"]].append(d)
    for group in by_source.values():
        seen: Counter = Counter()
        for d in group:
            seen.update(d["events"].keys())
        common = {t for t, n in seen.items() if n >= share * len(group) and len(group) >= 10}
        for d in group:
            d["background"] = sorted(t for t in d["events"] if t in common)


# ---------------------------------------------------------------- saving and reading

def save(datasets: List[Dict], values: Dict[str, Dict], sources: Dict[str, Dict]) -> None:
    """The shipped files, and beside them (gitignored) the sources whose licence keeps them local."""
    mark_background(datasets)
    local = {k for k, v in sources.items() if v.get("local")}
    for keep, summary_path, values_path in ((lambda s: s not in local, SUMMARY_PATH, VALUES_PATH),
                                            (lambda s: s in local, LOCAL_SUMMARY_PATH, LOCAL_VALUES_PATH)):
        part = [d for d in datasets if keep(d["source"])]
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump({"sources": {k: v for k, v in sources.items() if keep(k)},
                       "datasets": sorted(part, key=lambda d: (d["source"], d["id"]))}, fh, indent=1)
        # mtime=0: the same values give the same bytes, so a build of only the local "lab"
        # source leaves the committed file unchanged in git
        with open(values_path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
                io.TextIOWrapper(gz, encoding="utf-8") as fh:
            json.dump({d["id"]: values[d["id"]] for d in part if d["id"] in values}, fh, separators=(",", ":"))
    _cache.clear()


_cache: Dict[str, object] = {}


def load() -> Dict:
    if "summary" not in _cache:
        summary = {"sources": {}, "datasets": []}
        for path in (SUMMARY_PATH, LOCAL_SUMMARY_PATH):
            try:
                with open(path, encoding="utf-8") as fh:
                    part = json.load(fh)
            except (OSError, ValueError):
                continue
            summary["sources"].update(part.get("sources") or {})
            summary["datasets"].extend(part.get("datasets") or [])
        _cache["summary"] = summary
    return _cache["summary"]


def values() -> Optional[Dict]:
    """{dataset id: {event type: {field: [values]}}}, or None until a build has run here."""
    if "values" not in _cache:
        try:
            with gzip.open(VALUES_PATH, "rt", encoding="utf-8") as fh:
                _cache["values"] = json.load(fh)
        except (OSError, ValueError, EOFError):
            _cache["values"] = None
        try:
            with gzip.open(LOCAL_VALUES_PATH, "rt", encoding="utf-8") as fh:
                local = json.load(fh)
            if _cache["values"] is not None:
                _cache["values"].update(local)
        except (OSError, ValueError, EOFError):
            pass
    return _cache["values"]


def event_map() -> Dict:
    if "map" not in _cache:
        events, prefixes = {}, {}
        for path in MAP_FILES:
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            events.update(data.get("events") or {})
            prefixes.update({k: v for k, v in (data.get("prefixes") or {}).items() if not k.startswith("_")})
        _cache["map"] = (events, prefixes)
    return _cache["map"]


def describe(etype: str) -> Dict:
    """{label, mde, udm} for an event type; unknown ones keep their own name."""
    events, prefixes = event_map()
    if etype in events:
        return events[etype]
    for prefix, info in prefixes.items():
        if etype.startswith(prefix):
            return {**info, "label": f"{info['label']}: {etype[len(prefix):]}".rstrip(": ")}
    return {"label": etype, "mde": "", "udm": ""}


def for_technique(tid: str) -> List[Dict]:
    """Datasets for a technique: exact; else its sub-techniques' (for a parent) or its parent's."""
    tid = (tid or "").upper().strip()
    family = tid.split(".")[0]
    data = load()["datasets"]
    exact = [d for d in data if tid in d["techniques"]]
    if exact:
        return exact
    return [d for d in data if any(t == family or t.startswith(family + ".") for t in d["techniques"])]


def covered() -> Dict[str, int]:
    """{technique: number of datasets}."""
    out: Counter = Counter()
    for d in load()["datasets"]:
        out.update(t for t in d["techniques"] if t != "T0000")  # Security-Datasets' "no technique"
    return dict(out)

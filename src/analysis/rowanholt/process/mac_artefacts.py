"""macOS artefacts collected into raw/macos/ beyond the core set.

Files in raw/macos/ are named after their path on the host with '/' as '+'
(private+var+db+SystemPolicyConfiguration+ExecPolicy), as Gandalf (gandalf.sh,
gandalf.py) and Elrond's image collection both write them; SQLite write-ahead
logs sit beside their database as <name>-wal. Gandalf's live unified-log export
is gandalf+unifiedlog.ndjson; the unified-log store itself (tracev3, with uuidtext/
and timesync/) is under raw/unified_log_store/, its layout kept. Each parser writes a
cooked/*.jsonl. Plists with no parser here go on to Elrond's generic plist processing.
"""

import csv
import logging
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Tuple

from rowanholt.process.extractions import spotlight, tracev3
from rowanholt.process.linux_artefacts import SUSPICIOUS_COMMAND, _append_rows, _audit, _cooked, _techniques, epoch

logger = logging.getLogger(__name__)

MACOS_RAW = re.compile(r"/artefacts/raw/(?:macos|unified_log_store|spotlight)/")
LOG_STORE = re.compile(r"^(.*/artefacts/raw/unified_log_store)/")
# Gandalf flattens each Spotlight store's path: spotlight/Store-V2+<UUID>+store.db beside its dbStr maps
SPOTLIGHT = re.compile(r"^(.*/artefacts/raw/spotlight)/(.*)\+([^+]+)$")
# What's kept from the store: the processes and subsystems of Gandalf's live export
# (MACOS_UNIFIED_LOG_PREDICATE in gandalf.py's collector and gandalf.sh); keep them in step
UNIFIED_LOG_PROCESSES = frozenset({"sudo", "su", "sshd", "sshd-session", "loginwindow", "screensharingd", "syspolicyd",
                                   "XprotectService", "backgroundtaskmanagementd", "authd", "osascript"})
UNIFIED_LOG_SUBSYSTEMS = frozenset({"com.apple.TCC", "com.apple.xprotect", "com.apple.syspolicy.exec",
                                    "com.apple.backgroundtaskmanagement"})
# logd's own plain-text log in the store (diagnostics/logd.0.log): `log erase` leaves "All logs erased" in it
LOGD_LOG = re.compile(r"/diagnostics/logd(?:_helper)?\.\d+\.log$")
LOGD_LINE = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)([+-]\d{4}) ([^\[:]+)\[(\d+)\]: (.*)$")
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
UNIFIED_LOG_FIELDS = ("timestamp", "processImagePath", "processID", "subsystem", "category", "messageType", "eventMessage")
APPLE_TEAMS = {"", "apple", "Apple", "APPLECOMPUTER"}
SQLITE_SIDECARS = ("-wal", "-shm", "-journal")

HEADERS = {
    "btm_items": ["Source", "Name", "Identifier", "Type", "Disposition", "Enabled", "URL", "ExecutablePath",
                      "TeamIdentifier", "DeveloperName", "Flag"],
    "shared_file_lists": ["Source", "List", "Name", "Path"],
    "notifications": ["Source", "App", "Title", "Subtitle", "Body", "LastWriteTime"],
    "emond_rules": ["Source", "Name", "Enabled", "EventTypes", "Actions", "Flag"],
    "periodic": ["Source", "LineNumber", "Line", "Flag"],
    "unified_log": ["LastWriteTime", "Process", "PID", "Subsystem", "Category", "Type", "Message", "Technique"],
    "unified_log_store": ["LastWriteTime", "Process", "PID", "Subsystem", "Category", "Type", "Message", "Technique"],
    "spotlight": spotlight.COLUMNS,
    "logd_log": ["LastWriteTime", "Process", "PID", "Message", "Flag"],
}


def host_path(name: str) -> str:
    """The path on the host, with /private/etc and /private/var read as /etc and /var."""
    path = "/" + name.replace("+", "/")
    return re.sub(r"^/private/(etc|var|tmp)/", r"/\1/", path)


def mac_time(value) -> str:
    """Seconds since 2001-01-01 (Cocoa/Mac absolute time) as ISO 8601."""
    try:
        seconds = float(value)
        if seconds <= 0:
            return ""
        return (MAC_EPOCH + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return ""


# ---- NSKeyedArchiver and bookmarks ----------------------------------------

def unarchive(data: bytes):
    """A keyed archive (bplist with $objects/$top) as plain Python values; any other plist as loaded."""
    top = plistlib.loads(data)
    if not isinstance(top, dict) or "$objects" not in top:
        return top
    objects = top["$objects"]

    def resolve(value, depth=0):
        if depth > 64:
            return None
        if isinstance(value, plistlib.UID):
            value = objects[value.data]
        if isinstance(value, str) and value == "$null":
            return None
        if isinstance(value, list):
            return [resolve(v, depth + 1) for v in value]
        if not isinstance(value, dict):
            return value
        if "NS.keys" in value and "NS.objects" in value:
            return {str(resolve(k, depth + 1)): resolve(v, depth + 1) for k, v in zip(value["NS.keys"], value["NS.objects"])}
        if "NS.objects" in value:
            return [resolve(v, depth + 1) for v in value["NS.objects"]]
        if "NS.string" in value:
            return str(value["NS.string"])
        if "NS.bytes" in value:
            return value["NS.bytes"]
        if "NS.data" in value:
            return resolve(value["NS.data"], depth + 1)
        if "NS.relative" in value:
            base = resolve(value.get("NS.base"), depth + 1)
            relative = resolve(value["NS.relative"], depth + 1)
            return (base or "") + (relative or "") if isinstance(relative, str) else relative
        if "NS.time" in value:
            return mac_time(value["NS.time"])
        return {k: resolve(v, depth + 1) for k, v in value.items() if k != "$class"}

    return {k: resolve(v) for k, v in top["$top"].items()}


def bookmark_path(data: bytes) -> str:
    """The file path held in a macOS bookmark ('book' blob): its 0x1004 path components."""
    if not isinstance(data, (bytes, bytearray)) or data[:4] != b"book" or len(data) < 0x34:
        return ""
    try:
        header = struct.unpack_from("<I", data, 12)[0]
        toc = header + struct.unpack_from("<I", data, header)[0]

        def item(offset):
            length, kind = struct.unpack_from("<II", data, header + offset)
            return kind, data[header + offset + 8: header + offset + 8 + length]

        for _ in range(8):
            _, magic, _, next_toc, count = struct.unpack_from("<IIIII", data, toc)
            if magic != 0xFFFFFFFE:
                break
            for i in range(count):
                key, offset, _ = struct.unpack_from("<III", data, toc + 20 + i * 12)
                if key == 0x1004:
                    kind, payload = item(offset)
                    if kind == 0x0601:
                        parts = []
                        for (ref,) in struct.iter_unpack("<I", payload):
                            part_kind, part = item(ref)
                            if part_kind == 0x0101:
                                parts.append(part.decode("utf-8", errors="replace"))
                        return "/" + "/".join(parts)
            if not next_toc:
                break
            toc = header + next_toc
    except struct.error:
        pass
    return ""


def _walk(value, test):
    """Every dict under value for which test(dict) holds."""
    if isinstance(value, dict):
        if test(value):
            yield value
        for v in value.values():
            yield from _walk(v, test)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, test)


# ---- parsers -----------------------------------------------------------------

def btm_rows(path: str) -> List[Dict[str, str]]:
    """Background Task Management items (login items, launch agents and daemons) from a .btm store."""
    with open(path, "rb") as fh:
        archive = unarchive(fh.read())
    source = host_path(os.path.basename(path))
    rows, seen = [], set()
    for item in _walk(archive, lambda d: "disposition" in d and "type" in d):
        key = (item.get("identifier"), item.get("url"), item.get("executablePath"))
        if key in seen:
            continue
        seen.add(key)
        disposition = item.get("disposition") if isinstance(item.get("disposition"), int) else 0
        identifier = str(item.get("identifier") or "")
        team = str(item.get("teamIdentifier") or "")
        url = str(item.get("url") or "")
        flags = []
        if not identifier.startswith("com.apple.") and team not in APPLE_TEAMS:
            flags.append("third party")
        if SUSPICIOUS_COMMAND.search(url + " " + str(item.get("executablePath") or "")):
            flags.append("suspicious path")
        rows.append({
            "Source": source, "Name": str(item.get("name") or ""), "Identifier": identifier,
            "Type": hex(item["type"]) if isinstance(item.get("type"), int) else str(item.get("type")),
            "Disposition": hex(disposition), "Enabled": "yes" if disposition & 0x1 else "no", "URL": url,
            "ExecutablePath": str(item.get("executablePath") or ""), "TeamIdentifier": team,
            "DeveloperName": str(item.get("developerName") or ""), "Flag": "; ".join(flags),
        })
    return rows


def sfl_rows(path: str) -> List[Dict[str, str]]:
    """Shared file lists (.sfl2/.sfl3: recent documents, applications, servers, favourites)."""
    with open(path, "rb") as fh:
        archive = unarchive(fh.read())
    source = host_path(os.path.basename(path))
    name = os.path.basename(path).split("+")[-1]
    rows = []
    for entry in _walk(archive, lambda d: "Bookmark" in d or "bookmark" in d):
        bookmark = entry.get("Bookmark") or entry.get("bookmark")
        rows.append({"Source": source, "List": name, "Name": str(entry.get("Name") or entry.get("name") or ""),
                     "Path": bookmark_path(bookmark) if isinstance(bookmark, (bytes, bytearray)) else str(bookmark or "")})
    return rows


def _connect(path: str, work: str) -> sqlite3.Connection:
    """A read-only view of a SQLite database including its write-ahead log, from a copy."""
    if not os.path.exists(path + "-wal"):
        return sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    copy = os.path.join(work, "db")
    shutil.copy2(path, copy)
    shutil.copy2(path + "-wal", copy + "-wal")
    return sqlite3.connect(copy)


def sqlite_tables(path: str, tables: Optional[Iterable[str]] = None) -> Dict[str, List[Dict]]:
    """Rows of the named tables (all tables if None) as dicts."""
    out = {}
    with tempfile.TemporaryDirectory(prefix="elrond-sqlite-") as work:
        connection = _connect(path, work)
        connection.row_factory = sqlite3.Row
        try:
            names = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in names:
                if tables is not None and table not in tables:
                    continue
                rows = connection.execute(f'SELECT * FROM "{table}"').fetchall()
                out[table] = [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(r).items()} for r in rows]
        finally:
            connection.close()
    return out


def notification_rows(path: str) -> List[Dict[str, str]]:
    """Notification Center's db2/db: what each app showed the user, and when."""
    source = host_path(os.path.basename(path))
    rows = []
    with tempfile.TemporaryDirectory(prefix="elrond-sqlite-") as work:
        connection = _connect(path, work)
        try:
            query = ("SELECT app.identifier, record.data, record.delivered_date FROM record "
                     "LEFT JOIN app ON app.app_id = record.app_id")
            for identifier, data, delivered in connection.execute(query):
                request = {}
                try:
                    request = (plistlib.loads(data) or {}).get("req", {}) if data else {}
                except Exception:
                    pass
                rows.append({"Source": source, "App": identifier or "", "Title": request.get("titl", ""),
                             "Subtitle": request.get("subt", ""), "Body": request.get("body", ""),
                             "LastWriteTime": mac_time(delivered)})
        finally:
            connection.close()
    return rows


def emond_row(path: str) -> List[Dict[str, str]]:
    """emond rules: event types matched and the actions (commands) they run."""
    with open(path, "rb") as fh:
        rules = plistlib.load(fh)
    rules = rules if isinstance(rules, list) else [rules]
    source = host_path(os.path.basename(path))
    rows = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        actions = []
        for action in rule.get("actions", []) or []:
            if isinstance(action, dict):
                command = " ".join([str(action.get("command", ""))] + [str(a) for a in action.get("arguments", []) or []])
                actions.append(f"{action.get('type', '')}: {command.strip()}")
        events = [str(c.get("eventType", "")) for c in rule.get("criterion", []) or [] if isinstance(c, dict)]
        enabled = bool(rule.get("enabled"))
        sample = os.path.basename(path).endswith("SampleRules.plist")
        rows.append({"Source": source, "Name": str(rule.get("name", "")), "Enabled": "yes" if enabled else "no",
                     "EventTypes": ", ".join(events), "Actions": " | ".join(actions),
                     "Flag": "" if sample and not enabled else "runs on an event"})
    return rows


def periodic_rows(path: str) -> List[Dict[str, str]]:
    """periodic(8) scripts and local overrides: suspicious lines, and anything in a *.local or launchd.conf."""
    source = host_path(os.path.basename(path))
    local = source.endswith((".local", "/launchd.conf"))
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if SUSPICIOUS_COMMAND.search(line):
                rows.append({"Source": source, "LineNumber": number, "Line": line, "Flag": "suspicious command"})
            elif local:
                rows.append({"Source": source, "LineNumber": number, "Line": line, "Flag": "runs on a schedule or at boot"})
    return rows


def unified_log_technique(process: str, message: str) -> str:
    """The technique a unified-log message evidences: an AppleScript run, from osascript's own messages
    or, where those are gone (a log erase spares some processes' messages), loginwindow's check-in of it."""
    name = process.rsplit("/", 1)[-1]
    if name == "osascript" or (name == "loginwindow" and "Checked in app : osascript" in message):
        return "T1059.002"
    return ""


def unified_log_rows(path: str) -> List[Dict[str, str]]:
    """Gandalf's filtered unified-log export (log show --style ndjson)."""
    import json

    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict) or "eventMessage" not in event:
                continue
            rows.append({"LastWriteTime": event.get("timestamp", ""), "Process": event.get("processImagePath", ""),
                         "PID": event.get("processID", ""), "Subsystem": event.get("subsystem", ""),
                         "Category": event.get("category", ""), "Type": event.get("messageType", ""),
                         "Message": event.get("eventMessage", ""),
                         "Technique": unified_log_technique(event.get("processImagePath", ""), event.get("eventMessage", ""))})
    return rows


def logd_rows(path: str) -> List[Dict[str, str]]:
    """logd's own log: one row per line, flagged where the store was erased (`log erase`)."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            match = LOGD_LINE.match(line.rstrip("\n"))
            if not match:
                continue
            day, clock, offset, process, pid, message = match.groups()
            when = datetime.strptime(f"{day} {clock}{offset}", "%Y-%m-%d %H:%M:%S%z").astimezone(timezone.utc)
            rows.append({"LastWriteTime": when.isoformat().replace("+00:00", "Z"), "Process": process, "PID": pid,
                         "Message": message, "Flag": "log store erased" if "logs erased" in message.lower() else ""})
    return rows


@lru_cache(maxsize=1)
def _log_store(root: str) -> tracev3.Store:
    """One store's format strings and timesync, read once for all its tracev3 files."""
    return tracev3.Store(root)


def _kept(process: str, subsystem: str) -> bool:
    return process in UNIFIED_LOG_PROCESSES or subsystem in UNIFIED_LOG_SUBSYSTEMS


def unified_log_store_rows(path: str) -> List[Dict[str, str]]:
    """The log messages in one tracev3 file of the store that the live export's predicate would keep."""
    match = LOG_STORE.match(path)
    if not match:
        return []
    rows = list(tracev3.Reader(_log_store(match.group(1)), path).messages(_kept))
    for row in rows:
        row["Technique"] = unified_log_technique(row["Process"], row["Message"])
    return rows


def spotlight_rows(path: str) -> List[Dict[str, str]]:
    """One collected Spotlight store's items, read from its store.db and the dbStr maps beside it."""
    match = SPOTLIGHT.match(path)
    if not match:
        return []
    folder, store, _ = match.groups()
    prefix = f"{store}+"
    files = {name[len(prefix):]: os.path.join(folder, name) for name in os.listdir(folder) if name.startswith(prefix)}
    try:
        return spotlight.rows(spotlight.Store(files), store.replace("+", "/"))
    except (spotlight.SpotlightError, OSError) as exc:
        logger.warning(f"Spotlight store {store}: {exc}")
        return []


def _append_table(path: str, rows: List[Dict], img: str, artefact: str) -> int:
    """Append rows whose fields come from the database table itself."""
    if not rows:
        return 0
    return _append_rows(path, list(rows[0]), rows, img, artefact)


# ---- routing -------------------------------------------------------------------

def _route(artefact: str):
    """(csv name or None, rows or {csv: rows}, description, techniques); csv None: not ours."""
    name = os.path.basename(artefact)
    if LOG_STORE.match(artefact):
        if name.endswith(".tracev3"):
            return "unified_log_store", unified_log_store_rows(artefact), "unified log store", []
        if LOGD_LOG.search(artefact):
            rows = logd_rows(artefact)
            return "logd_log", rows, "logd log", ["T1685.006"] if any(r["Flag"] for r in rows) else []
        return "", [], "", []  # uuidtext and timesync: read with the tracev3 files
    if SPOTLIGHT.match(artefact):
        if name.endswith("+store.db"):
            return "spotlight", spotlight_rows(artefact), "Spotlight index", []
        return "", [], "", []  # .store.db, the dbStr maps, VolumeConfiguration.plist: read with store.db
    path = host_path(name)
    lower = path.lower()
    if name.endswith(SQLITE_SIDECARS):
        return "", [], "", []
    if lower.endswith(".btm"):
        rows = btm_rows(artefact)
        techniques = []
        for row in rows:
            if row["Flag"] and row["Enabled"] == "yes":
                techniques.append("T1543.001" if "/Launch" in row["URL"] + row["ExecutablePath"] else "T1547.015")
        return "btm_items", rows, "background task items", sorted(set(techniques))
    if lower.endswith((".sfl2", ".sfl3")):
        return "shared_file_lists", sfl_rows(artefact), "shared file list", []
    if path.endswith("/db2/db") and ("usernoted" in path or "notificationcenter" in path):
        return "notifications", notification_rows(artefact), "notification database", []
    if path == "/var/db/SystemPolicyConfiguration/ExecPolicy":
        tables = sqlite_tables(artefact, ("executable_measurements_v2", "policy_scan_cache", "provenance_tracking"))
        return {f"execpolicy_{t}": r for t, r in tables.items()}, None, "ExecPolicy database", []
    if path == "/var/db/SystemPolicyConfiguration/KextPolicy":
        tables = sqlite_tables(artefact)
        third_party = [r for r in tables.get("kext_load_history_v3", []) if not str(r.get("path", "")).startswith("/System/")]
        return {f"kextpolicy_{t}": r for t, r in tables.items()}, None, "KextPolicy database", \
            ["T1547.006"] if third_party else []
    if path == "/var/protected/xprotect/XPdb":
        return {f"xprotect_{t}": r for t, r in sqlite_tables(artefact).items()}, None, "XProtect database", []
    if path.startswith("/etc/emond.d/rules/") and lower.endswith(".plist"):
        rows = emond_row(artefact)
        return "emond_rules", rows, "emond rule", ["T1546.014"] if any(r["Flag"] for r in rows) else []
    if path.startswith("/etc/periodic/") or path in ("/etc/periodic.conf", "/etc/daily.local", "/etc/weekly.local",
                                                       "/etc/monthly.local", "/etc/launchd.conf", "/etc/rc.common"):
        return "periodic", periodic_rows(artefact), "periodic script", []
    if name == "gandalf+unifiedlog.ndjson":
        return "unified_log", unified_log_rows(artefact), "unified log export", []
    if lower.endswith(".plist"):
        return None, [], "", []  # Elrond's generic plist processing reads it
    return "", [], "", []  # collected for the analyst (Biome, PowerLog, emondClients) with nothing to parse


def is_mac_artefact(artefact: str) -> bool:
    return bool(MACOS_RAW.search(artefact))


def process_mac_artefact(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact) -> bool:
    """Route one raw/macos/ file to its parser. Returns False if Elrond's other processors should read it."""
    if not is_mac_artefact(artefact):
        return False
    try:
        out, rows, what, techniques = _route(artefact)
        if out is None:
            return False
        if not out:
            return True
        cooked = _cooked(output_directory, img, vss_path_insert)
        if isinstance(out, dict):
            written = sum(_append_table(os.path.join(cooked, name), table, img, artefact) for name, table in out.items())
        else:
            written = _append_rows(os.path.join(cooked, out), HEADERS[out], rows, img, artefact, techniques)
        if written:
            _audit(verbosity, output_directory, img, stage, vssimage, what, artefact)
            _techniques(output_directory, techniques)
    except Exception as e:
        logger.warning("could not process '%s' for %s: %s", os.path.basename(artefact), vssimage, e)
    return True

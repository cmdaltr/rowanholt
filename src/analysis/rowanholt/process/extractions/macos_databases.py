"""macOS privacy and activity databases: TCC, KnowledgeC and Quarantine Events.

  TCC.db                 which apps the user (or an installer, or an MDM profile)
                         let reach the camera, microphone, screen, files and
                         Accessibility, and when. Full Disk Access and Accessibility
                         grants are how macOS malware gets its reach. Every sensitive
                         grant is flagged; a technique is tagged only when the client
                         runs from a temp, shared or hidden path.
  knowledgeC.db          CoreDuet's event store: app use, display state, Safari
                         history, and more, as streams with start and end times
                         (macOS 12 and earlier; still present, mostly quiet, later).
  QuarantineEventsV2     every file a quarantine-aware app downloaded, with the
                         app, the URL and the page it came from (T1105, T1204).

Each parser takes the table rows (from mac_artefacts.sqlite_tables) so it never
opens a database itself.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List

COCOA = datetime(2001, 1, 1, tzinfo=timezone.utc)
AUTH = {0: "denied", 1: "unknown", 2: "allowed", 3: "limited", 4: "add only"}
REASONS = {1: "error", 2: "user consent", 3: "user set", 4: "system set", 5: "service policy", 6: "MDM policy",
           7: "override policy", 8: "missing usage string", 9: "prompt timeout", 10: "preflight unknown",
           11: "entitled", 12: "app type policy"}
CLIENT_TYPES = {0: "bundle ID", 1: "path"}
# services whose grant gives an app (or attacker) real reach
SENSITIVE = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceAccessibility": "Accessibility (control the computer)",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceAppleEvents": "Apple Events (control another app)",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Synthetic input",
    "kTCCServiceDeveloperTool": "Developer Tools",
    "kTCCServiceEndpointSecurityClient": "Endpoint Security client",
    "kTCCServiceSystemPolicySysAdminFiles": "Administer files",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
}
STAGING = re.compile(r"^(/tmp/|/private/tmp/|/var/tmp/|/private/var/folders/|/Users/Shared/|/Users/[^/]+/(Downloads|Library/"
                     r"Application Support)/)|/\.[^/]+/")
SERVICE_TECHNIQUES = {
    "kTCCServiceAccessibility": "T1056", "kTCCServicePostEvent": "T1056", "kTCCServiceListenEvent": "T1056.001",
    "kTCCServiceScreenCapture": "T1113", "kTCCServiceAppleEvents": "T1059.002", "kTCCServiceMicrophone": "T1123",
    "kTCCServiceCamera": "T1125", "kTCCServiceSystemPolicyAllFiles": "T1005",
}
APPLE_CLIENTS = ("com.apple.", "/System/", "/usr/libexec/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")
TCC_HEADER = ["Database", "Service", "Client", "ClientType", "Access", "Reason", "TargetApp", "LastModified", "Flag",
              "Techniques"]
KNOWLEDGE_HEADER = ["Stream", "Value", "Start", "End", "DurationSeconds", "Created", "Bundle", "Device"]
QUARANTINE_HEADER = ["User", "Time", "Agent", "AgentBundle", "DataURL", "OriginURL", "OriginTitle", "Sender", "Type",
                     "EventID", "Flag"]
QUARANTINE_TYPES = {0: "web download", 1: "other download", 2: "e-mail attachment", 3: "instant message", 4: "calendar",
                    5: "other"}
SCRIPTING_AGENTS = re.compile(r"\b(curl|wget|python|ruby|perl|osascript|bash|zsh|sh|Terminal|iTerm)\b", re.I)


def cocoa(seconds) -> str:
    if seconds in (None, ""):
        return ""
    try:
        return (COCOA + timedelta(seconds=float(seconds))).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError, TypeError):
        return ""


def unix(seconds) -> str:
    if not seconds:
        return ""
    try:
        return datetime.fromtimestamp(int(seconds), timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError, TypeError):
        return ""


def tcc_rows(tables: Dict[str, List[Dict]], database: str) -> List[Dict[str, str]]:
    """One row per TCC grant or denial, flagging sensitive grants and odd clients."""
    rows = []
    for entry in tables.get("access", []):
        service = entry.get("service") or ""
        client = entry.get("client") or ""
        auth = entry.get("auth_value")
        if auth is None:  # macOS 10.15 and earlier: allowed is 0/1
            auth = 2 if entry.get("allowed") else 0
        access = AUTH.get(auth, str(auth))
        reason = REASONS.get(entry.get("auth_reason"), str(entry.get("auth_reason") or ""))
        flags, techniques = [], []
        staged = entry.get("client_type") == 1 and bool(STAGING.search(client))
        if access == "allowed" and service in SENSITIVE:
            flags.append(SENSITIVE[service] + " granted")
            # listed for every client; tagged only for one running from a staging path
            if staged and not client.startswith(APPLE_CLIENTS) and service in SERVICE_TECHNIQUES:
                techniques.append(SERVICE_TECHNIQUES[service])
        if staged:
            flags.append("client runs from a temp, shared or hidden directory")
        if access == "allowed" and service in SENSITIVE and reason in ("user set", "system set") and database.startswith("system"):
            flags.append("set outside a user prompt")
        rows.append({
            "Database": database, "Service": service.replace("kTCCService", ""), "Client": client,
            "ClientType": CLIENT_TYPES.get(entry.get("client_type"), str(entry.get("client_type") or "")),
            "Access": access, "Reason": reason, "TargetApp": entry.get("indirect_object_identifier") or "",
            "LastModified": unix(entry.get("last_modified")), "Flag": "; ".join(flags),
            "Techniques": ", ".join(sorted(set(techniques))),
        })
    return rows


def knowledgec_rows(tables: Dict[str, List[Dict]]) -> List[Dict[str, str]]:
    """Every KnowledgeC event, with its stream, value, times and source app."""
    sources = {s.get("Z_PK"): s for s in tables.get("ZSOURCE", [])}
    rows = []
    for event in tables.get("ZOBJECT", []):
        start, end = event.get("ZSTARTDATE"), event.get("ZENDDATE")
        value = event.get("ZVALUESTRING")
        if value in (None, ""):
            value = event.get("ZVALUEINTEGER") if event.get("ZVALUEINTEGER") is not None else event.get("ZVALUEDOUBLE")
        source = sources.get(event.get("ZSOURCE"), {})
        try:
            duration = round(float(end) - float(start), 3) if start is not None and end is not None else ""
        except (TypeError, ValueError):
            duration = ""
        rows.append({
            "Stream": event.get("ZSTREAMNAME") or "", "Value": "" if value is None else value,
            "Start": cocoa(start), "End": cocoa(end), "DurationSeconds": duration,
            "Created": cocoa(event.get("ZCREATIONDATE")), "Bundle": source.get("ZBUNDLEID") or "",
            "Device": source.get("ZDEVICEID") or "",
        })
    return sorted(rows, key=lambda r: r["Start"])


def quarantine_rows(tables: Dict[str, List[Dict]], user: str) -> List[Dict[str, str]]:
    """Every download macOS quarantined for this user, flagging ones from scripting tools."""
    rows = []
    for event in tables.get("LSQuarantineEvent", []):
        agent = event.get("LSQuarantineAgentName") or ""
        bundle = event.get("LSQuarantineAgentBundleIdentifier") or ""
        flags = []
        if SCRIPTING_AGENTS.search(agent) or SCRIPTING_AGENTS.search(bundle):
            flags.append("downloaded by a scripting tool")
        url = event.get("LSQuarantineDataURLString") or ""
        if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", url):
            flags.append("URL is a bare IP address")
        kind = event.get("LSQuarantineTypeNumber")
        rows.append({
            "User": user, "Time": cocoa(event.get("LSQuarantineTimeStamp")), "Agent": agent, "AgentBundle": bundle,
            "DataURL": url, "OriginURL": event.get("LSQuarantineOriginURLString") or "",
            "OriginTitle": event.get("LSQuarantineOriginTitle") or "",
            "Sender": " ".join(x for x in (event.get("LSQuarantineSenderName"), event.get("LSQuarantineSenderAddress")) if x),
            "Type": QUARANTINE_TYPES.get(kind, str(kind if kind is not None else "")),
            "EventID": event.get("LSQuarantineEventIdentifier") or "", "Flag": "; ".join(flags),
        })
    return sorted(rows, key=lambda r: r["Time"])


def techniques(rows: Iterable[Dict[str, str]]) -> List[str]:
    found = set()
    for row in rows:
        found.update(t.strip() for t in str(row.get("Techniques", "")).split(",") if t.strip())
    return sorted(found)

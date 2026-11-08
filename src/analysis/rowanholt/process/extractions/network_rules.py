"""ATT&CK techniques from network logs, each rule naming what it saw in the row's Flag.

The rules are deliberately narrow: a technique goes on a row only when the protocol logs show the
behaviour itself, not when traffic merely could be it.

  T1071.004, T1572  DNS tunnelling's shape: many distinct long names under one domain, one client
  T1071(.00x)       regular connections: ten or more to one address and port at a steady interval
  T1571             a protocol Zeek identified on a port that isn't its own (T1572 too for SSH on 80/443)
  T1048             one connection or flow sending 20 MiB or more, at least ten times what came back
  T1105             an executable received over HTTP or FTP (files.log)
  T1570             an executable written to an SMB share (files.log)

Each rule takes (key, row) pairs and returns {key: [(flag, techniques)]} for the rows it flags, so
a caller can read a log once to judge it and again to write it. Stdlib only.
"""

import ipaddress
import statistics
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Hashable, Iterable, List, Optional, Tuple

Finding = Tuple[str, List[str]]
Findings = Dict[Hashable, List[Finding]]

TUNNEL_MIN_NAMES = 20  # distinct long names under one domain from one client
TUNNEL_MIN_SUBDOMAIN = 30  # characters before the domain
BEACON_MIN_CONNECTIONS = 10
BEACON_MIN_INTERVAL = 10.0  # seconds: faster than this is a session, not a check-in
BEACON_MAX_JITTER = 0.10  # standard deviation over mean of the intervals
LARGE_UPLOAD_BYTES = 20 * 1024 * 1024
UPLOAD_RATIO = 10
# Infrastructure that is regular by design: DNS to a resolver, NTP, DHCP, NetBIOS, mDNS, SSDP, LLMNR
REGULAR_BY_DESIGN = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
FILE_SHARING_PORTS = {139, 445, 2049, 111}  # bulk copies to file servers are uploads by design
STANDARD_PORTS: Dict[str, set] = {
    "http": {80, 81, 591, 3128, 8000, 8008, 8080, 8081, 8888},
    "ssl": {443, 465, 563, 587, 636, 853, 989, 990, 992, 993, 994, 995, 3269, 5061, 5986, 6697, 8443, 8883, 9443,
            25, 110, 143, 21},  # STARTTLS on mail and FTP shows as ssl too
    "ssh": {22},
    "dns": {53, 5353, 5355},
    "ftp": {21},
    "smtp": {25, 465, 587, 2525},
    "rdp": {3389},
    "smb": {139, 445},
}
WEB_PORTS = {80, 443}
SERVICE_TECHNIQUE = {"http": "T1071.001", "ssl": "T1071.001", "dns": "T1071.004", "smtp": "T1071.003",
                     "pop3": "T1071.003", "imap": "T1071.003", "ftp": "T1071.002"}
EXECUTABLE_MIME = {"application/x-dosexec", "application/x-executable", "application/x-elf",
                   "application/x-mach-o-executable", "application/x-sharedlib", "application/x-msdownload"}
TWO_LEVEL_SUFFIXES = {"co", "com", "net", "org", "gov", "ac", "edu", "ltd", "plc", "sch", "nhs", "police", "mod"}


def seconds(value: Any) -> Optional[float]:
    """An ISO 8601 time or epoch seconds as epoch seconds."""
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _number(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _services(value: Any) -> List[str]:
    if isinstance(value, list):
        items = value
    else:
        items = str(value or "").split(",")
    return [s.strip().lower() for s in items if s and str(s).strip() not in ("", "-")]


def _not_unicast(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_multicast or ip.is_unspecified or address.endswith(".255")


def parent_domain(name: str) -> str:
    """The registered domain a name is under, roughly: the last two labels, or three under a
    two-level suffix (example.co.uk)."""
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def dns_tunnelling(rows: Iterable[Tuple[Hashable, Dict[str, Any]]]) -> Findings:
    """dns.log: a client asking for many distinct long names under one domain."""
    names: Dict[Tuple[str, str], set] = defaultdict(set)
    keys: Dict[Tuple[str, str], List[Hashable]] = defaultdict(list)
    for key, row in rows:
        query = str(row.get("query") or "").lower().rstrip(".")
        if not query or query.endswith((".arpa", ".local")):
            continue
        parent = parent_domain(query)
        if len(query) - len(parent) - 1 < TUNNEL_MIN_SUBDOMAIN:
            continue
        group = (str(row.get("id_orig_h") or ""), parent)
        names[group].add(query)
        keys[group].append(key)
    found: Findings = {}
    for group, distinct in names.items():
        if len(distinct) >= TUNNEL_MIN_NAMES:
            flag = f"DNS tunnelling shape: {len(distinct)} distinct long names under {group[1]} from {group[0]}"
            for key in keys[group]:
                found.setdefault(key, []).append((flag, ["T1071.004", "T1572"]))
    return found


def flow_view(row: Dict[str, Any]) -> Dict[str, Any]:
    """A conn.log row or a NetFlow row as the same fields: ts, orig, resp, port, service, sent, received."""
    if "id_orig_h" in row:
        return {"ts": seconds(row.get("ts")), "orig": str(row.get("id_orig_h") or ""),
                "resp": str(row.get("id_resp_h") or ""), "port": _number(row.get("id_resp_p")),
                "service": _services(row.get("service")), "sent": _number(row.get("orig_bytes")),
                "received": _number(row.get("resp_bytes")), "proto": str(row.get("proto") or "").lower()}
    return {"ts": seconds(row.get("Start")), "orig": str(row.get("SrcAddr") or ""), "resp": str(row.get("DstAddr") or ""),
            "port": _number(row.get("DstPort")), "service": [], "sent": _number(row.get("Bytes")),
            "received": _number(row.get("OutBytes")), "proto": str(row.get("Proto") or "").lower()}


def beaconing(rows: Iterable[Tuple[Hashable, Dict[str, Any]]]) -> Findings:
    """Connections from one address to one address and port at a steady interval."""
    starts: Dict[Tuple[str, str, int], List[Tuple[float, Hashable]]] = defaultdict(list)
    services: Dict[Tuple[str, str, int], set] = defaultdict(set)
    for key, row in rows:
        flow = flow_view(row)
        if flow["ts"] is None or flow["port"] is None or flow["port"] in REGULAR_BY_DESIGN or _not_unicast(flow["resp"]):
            continue
        group = (flow["orig"], flow["resp"], flow["port"])
        starts[group].append((flow["ts"], key))
        services[group].update(flow["service"])
    found: Findings = {}
    for group, seen in starts.items():
        if len(seen) < BEACON_MIN_CONNECTIONS:
            continue
        seen.sort(key=lambda item: item[0])
        intervals = [b[0] - a[0] for a, b in zip(seen, seen[1:])]
        mean = statistics.mean(intervals)
        if mean < BEACON_MIN_INTERVAL:
            continue
        jitter = statistics.pstdev(intervals) / mean
        if jitter > BEACON_MAX_JITTER:
            continue
        known = sorted(services[group])
        technique = next((SERVICE_TECHNIQUE[s] for s in known if s in SERVICE_TECHNIQUE), "T1071")
        protocol = "/".join(known) if known else "protocol not identified"
        flag = (f"regular connections: {len(seen)} to {group[1]}:{group[2]} ({protocol}) every {mean:.0f}s "
                f"(jitter {jitter:.0%})")
        for _, key in seen:
            found.setdefault(key, []).append((flag, [technique]))
    return found


def non_standard_port(rows: Iterable[Tuple[Hashable, Dict[str, Any]]]) -> Findings:
    """conn.log: a protocol Zeek identified on a port that none of its services use."""
    found: Findings = {}
    for key, row in rows:
        flow = flow_view(row)
        port, known = flow["port"], [s for s in flow["service"] if s in STANDARD_PORTS]
        if port is None or not known or any(port in STANDARD_PORTS[s] for s in known):
            continue
        techniques = ["T1571"]
        flag = f"{'/'.join(known)} on port {port}"
        if "ssh" in known and port in WEB_PORTS:
            techniques.append("T1572")
            flag = f"ssh on port {port}: tunnelled through a web port"
        found.setdefault(key, []).append((flag, techniques))
    return found


def large_upload(rows: Iterable[Tuple[Hashable, Dict[str, Any]]]) -> Findings:
    """One connection (or flow) sending LARGE_UPLOAD_BYTES or more, and at least UPLOAD_RATIO times
    what it received when that's known."""
    found: Findings = {}
    for key, row in rows:
        flow = flow_view(row)
        sent, received = flow["sent"], flow["received"]
        if sent is None or sent < LARGE_UPLOAD_BYTES or flow["port"] in FILE_SHARING_PORTS or _not_unicast(flow["resp"]):
            continue
        if received is not None and received * UPLOAD_RATIO > sent:
            continue
        what = "/".join(flow["service"]) or (flow["proto"] or "unidentified")
        back = f", {received:,} bytes back" if received is not None else ""
        flag = f"large outbound transfer: {sent:,} bytes to {flow['resp']}:{flow['port']} ({what}){back}"
        found.setdefault(key, []).append((flag, ["T1048"]))
    return found


def _file_hosts(row: Dict[str, Any]) -> Tuple[str, str]:
    """(sender, receiver) of a files.log row: Zeek 6+'s connection fields, or the older tx/rx hosts."""
    if row.get("id_orig_h"):
        client, server = str(row["id_orig_h"]), str(row.get("id_resp_h") or "")
        return (client, server) if row.get("is_orig") in (True, "T") else (server, client)
    first = lambda value: (value[0] if isinstance(value, list) and value else str(value or ""))  # noqa: E731
    return first(row.get("tx_hosts")), first(row.get("rx_hosts"))


def executable_transfers(rows: Iterable[Tuple[Hashable, Dict[str, Any]]]) -> Findings:
    """files.log: executables downloaded over HTTP or FTP (T1105), or written to an SMB share (T1570)."""
    found: Findings = {}
    for key, row in rows:
        mime = str(row.get("mime_type") or "").lower()
        if mime not in EXECUTABLE_MIME:
            continue
        source = str(row.get("source") or "").upper()
        sender, receiver = _file_hosts(row)
        name = f" '{row['filename']}'" if row.get("filename") else ""
        uploaded = row.get("is_orig") in (True, "T")
        if source in ("HTTP", "FTP", "FTP_DATA") and not uploaded:
            flag = f"executable{name} ({mime}) received over {source} from {sender} by {receiver}"
            found.setdefault(key, []).append((flag, ["T1105"]))
        elif source.startswith("SMB") and uploaded:
            flag = f"executable{name} ({mime}) written over SMB to {receiver} by {sender}"
            found.setdefault(key, []).append((flag, ["T1570"]))
    return found


RULES = {
    "conn": (beaconing, non_standard_port, large_upload),
    "dns": (dns_tunnelling,),
    "files": (executable_transfers,),
    "netflow": (beaconing, large_upload),
}


def merge(findings: Iterable[Findings]) -> Findings:
    """Several rules' findings as one."""
    merged: Findings = {}
    for found in findings:
        for key, items in found.items():
            merged.setdefault(key, []).extend(items)
    return merged


def apply(row: Dict[str, Any], items: List[Finding]) -> Dict[str, Any]:
    """The row with its Flag and Techniques fields filled from its findings."""
    flags = [flag for flag, _ in items]
    techniques: List[str] = []
    for _, tids in items:
        techniques.extend(t for t in tids if t not in techniques)
    row["Flag"] = "; ".join(dict.fromkeys(flags))
    row["Techniques"] = ", ".join(techniques)
    return row

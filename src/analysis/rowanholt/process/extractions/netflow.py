"""NetFlow/IPFIX exports as text: nfdump's CSV (``nfdump -r <file> -o csv``, 1.6 and 1.7 headers),
SiLK's rwcut (pipe-delimited) and any CSV whose header names the usual flow fields. Each flow
becomes one row with the same field names whatever exported it. Binary nfcapd, NetFlow v9 and
IPFIX files aren't read here: export them as text first. Stdlib only.
"""

import csv
import io
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from rowanholt.core.records import iso_timestamp

HEADER = ["Start", "End", "Duration", "SrcAddr", "SrcPort", "DstAddr", "DstPort", "Proto", "TcpFlags", "Packets",
          "Bytes", "OutPackets", "OutBytes", "Flag", "Techniques"]

# Each normalised field, and the column names exporters give it (lower-cased)
ALIASES: Dict[str, tuple] = {
    "Start": ("ts", "stime", "firstseen", "first", "start", "start_time", "flowstart", "timestamp"),
    "End": ("te", "etime", "lastseen", "last", "end", "end_time", "flowend"),
    "Duration": ("td", "duration", "dur"),
    "SrcAddr": ("sa", "sip", "srcaddr", "src_addr", "srcip", "src_ip", "source", "sourceipv4address"),
    "SrcPort": ("sp", "sport", "srcport", "src_port", "sourcetransportport"),
    "DstAddr": ("da", "dip", "dstaddr", "dst_addr", "dstip", "dst_ip", "destination", "destinationipv4address"),
    "DstPort": ("dp", "dport", "dstport", "dst_port", "destinationtransportport"),
    "Proto": ("pr", "pro", "protocol", "proto", "protocolidentifier"),
    "TcpFlags": ("flg", "flags", "tcpflags", "tcp_flags", "tcpcontrolbits"),
    "Packets": ("ipkt", "packets", "pkts", "inpackets", "in_pkts", "packetdeltacount"),
    "Bytes": ("ibyt", "bytes", "inbytes", "in_bytes", "octetdeltacount"),
    "OutPackets": ("opkt", "outpackets", "out_pkts"),
    "OutBytes": ("obyt", "outbytes", "out_bytes"),
}
PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMP6", "132": "SCTP"}
REQUIRED = ("SrcAddr", "DstAddr", "Bytes")


def _columns(header: List[str]) -> Dict[str, int]:
    """Normalised field -> column index, for the fields this header has."""
    lowered = [re.sub(r"[^a-z0-9_]", "", h.strip().lower()) for h in header]
    found: Dict[str, int] = {}
    for field, names in ALIASES.items():
        for index, name in enumerate(lowered):
            if name in names:
                found[field] = index
                break
    return found


def _delimiter(line: str) -> str:
    return "|" if line.count("|") > line.count(",") else ","


def is_flow_export(path: Path) -> bool:
    """Whether the file's first line is a flow export's header (source, destination, bytes)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            first = fh.readline(65536)
    except OSError:
        return False
    if not first.strip() or "\0" in first:
        return False
    header = next(csv.reader(io.StringIO(first), delimiter=_delimiter(first)), [])
    return all(field in _columns(header) for field in REQUIRED)


def _time(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if re.match(r"^\d{4}/\d{2}/\d{2}T", value):  # SiLK: 2026/11/01T08:00:01.123
        value = value.replace("/", "-", 2)
    return iso_timestamp(value) or value


def _int(value: str) -> Optional[int]:
    value = value.strip()
    multiplier = 1
    # nfdump's text output scales large counts: "1.2 M", "3.4 G"
    match = re.match(r"^([\d.]+)\s*([KMG])$", value)
    if match:
        value, multiplier = match.group(1), {"K": 1_000, "M": 1_000_000, "G": 1_000_000_000}[match.group(2)]
    try:
        return int(float(value) * multiplier)
    except ValueError:
        return None


def flow_rows(path: Path) -> Iterator[Dict[str, object]]:
    """The flows in a text export, one normalised row each; nfdump's trailing summary is left out."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        first = fh.readline()
        delimiter = _delimiter(first)
        header = next(csv.reader(io.StringIO(first), delimiter=delimiter), [])
        columns = _columns(header)
        if not all(field in columns for field in REQUIRED):
            return
        for values in csv.reader(fh, delimiter=delimiter):
            if not values or not "".join(values).strip():
                continue
            if values[0].strip().lower() in ("summary", "no matched flows") or values[0].startswith("Sys:"):
                break  # nfdump's footer
            cell = {field: values[index].strip() if index < len(values) else "" for field, index in columns.items()}
            if not cell.get("SrcAddr") or not cell.get("DstAddr"):
                continue
            proto = cell.get("Proto", "")
            row: Dict[str, object] = {
                "Start": _time(cell.get("Start", "")),
                "End": _time(cell.get("End", "")),
                "Duration": cell.get("Duration", ""),
                "SrcAddr": cell["SrcAddr"],
                "SrcPort": _int(cell.get("SrcPort", "")),
                "DstAddr": cell["DstAddr"],
                "DstPort": _int(cell.get("DstPort", "")),
                "Proto": PROTOCOLS.get(proto, proto.upper()),
                "TcpFlags": cell.get("TcpFlags", ""),
                "Packets": _int(cell.get("Packets", "")),
                "Bytes": _int(cell.get("Bytes", "")),
                "OutPackets": _int(cell.get("OutPackets", "")),
                "OutBytes": _int(cell.get("OutBytes", "")),
            }
            yield row

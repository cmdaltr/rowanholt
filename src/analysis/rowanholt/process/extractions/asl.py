"""Apple System Log (ASL) store files: /var/log/asl/*.asl and DiagnosticMessages.

ASL is the pre-unified-log system log, still written on current macOS by aslmanager
and a few daemons (and by everything on 10.11 and earlier). A store file is a
big-endian "ASL DB" with a 128-byte header, then a chain of objects: strings
(type 1) and messages (type 2). Each message holds a fixed block (time, level,
process and user IDs, and references to host, sender, facility and message
strings) and any number of key/value string pairs. A string reference with its
top bit set holds up to seven bytes inline; otherwise it is the file offset of a
string object.
"""

import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional

COOKIE = b"ASL DB"
MESSAGE, STRING = 0, 1
FIXED = 114  # type, length and the fixed message fields, up to the first key/value
LEVELS = ("Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug")
HEADER = ["Time", "Level", "Host", "Sender", "Facility", "PID", "UID", "GID", "Message", "Extra", "SourceFile"]
MAX_RECORDS = 500000


def _string(data: bytes, reference: int) -> str:
    if not reference:
        return ""
    if reference >> 63:
        length = (reference >> 56) & 0x7F
        return reference.to_bytes(8, "big")[1:1 + length].decode("utf-8", errors="replace")
    if reference + 6 > len(data):
        return ""
    kind, length = struct.unpack_from(">HI", data, reference)
    if kind != STRING:
        return ""
    return data[reference + 6:reference + 6 + length].rstrip(b"\x00").decode("utf-8", errors="replace")


def _message(data: bytes, offset: int) -> Optional[Dict[str, object]]:
    if offset + FIXED > len(data):
        return None
    kind, length, following, _id, seconds, nanoseconds, level, _flags = struct.unpack_from(">HIQQQIHH", data, offset)
    if kind != MESSAGE or offset + 6 + length > len(data):
        return None
    pid, uid, gid, _ruid, _rgid, _refpid, pairs = struct.unpack_from(">IIIIIII", data, offset + 38)
    host, sender, facility, message, _refproc, _session = struct.unpack_from(">QQQQQQ", data, offset + 66)
    extra = []
    for i in range(min(pairs, (length + 6 - FIXED) // 8) // 2):
        key, value = struct.unpack_from(">QQ", data, offset + FIXED + 16 * i)
        extra.append(f"{_string(data, key)}={_string(data, value)}")
    try:
        when = datetime.fromtimestamp(seconds + nanoseconds / 1e9, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        when = ""
    return {"next": following, "Time": when, "Level": LEVELS[level] if level < len(LEVELS) else str(level),
            "Host": _string(data, host), "Sender": _string(data, sender), "Facility": _string(data, facility),
            "PID": pid, "UID": uid, "GID": gid, "Message": _string(data, message), "Extra": "; ".join(extra)}


def asl_rows(path: str, source: str) -> List[Dict[str, object]]:
    """Every message in an ASL store file, in the order written."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(COOKIE) or len(data) < 0x80:
        return []
    offset = struct.unpack_from(">Q", data, 16)[0]
    rows, seen = [], set()
    while offset and offset not in seen and len(rows) < MAX_RECORDS:
        seen.add(offset)
        record = _message(data, offset)
        if record is None:
            break
        offset = record.pop("next")
        record["Message"] = str(record["Message"])[:4000]
        record["SourceFile"] = source
        rows.append(record)
    return rows

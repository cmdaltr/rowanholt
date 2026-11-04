"""macOS Biome streams (SEGB files under biome/streams): what the user did and when.

Biome replaced KnowledgeC for most behavioural telemetry on macOS 13 and later: app
in focus, notifications, Screen Time usage, device and power state, and more, one
stream per directory. Each file is a SEGB container of protobuf records:

  v1 (macOS 13)        56-byte header with "SEGB" at 0x34; records from 0x38, each
                       with a 32-byte header (length, state, two times, CRC)
  v2 (macOS 14 and up) "SEGB" at 0; records from 0x20, each with an 8-byte header
                       (CRC, flags); a 16-byte index entry per record at the end of
                       the file (end offset, state, time), growing backwards

Record schemas differ per stream and aren't published, so each payload is walked as
protobuf and reported as its strings and the times it holds. State 3 means deleted;
deleted records are usually zeroed, but any that survive are reported.
"""

import re
import struct
import zlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Tuple

COCOA = datetime(2001, 1, 1, tzinfo=timezone.utc)
STATES = {1: "written", 3: "deleted", 4: "unknown"}
# Cocoa seconds for 2005-01-01 .. 2040-01-01: plausible event times
TIME_RANGE = (126230400.0, 1230768000.0)
PRINTABLE = re.compile(r"^[\x20-\x7e -￿]{2,}$")
MAX_DEPTH = 6
HEADER = ["Stream", "Record", "State", "RecordTime", "Times", "Strings", "SourceFile"]


def cocoa(seconds: float) -> str:
    try:
        return (COCOA + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return ""


def _varint(data: bytes, pos: int) -> Tuple[int, int]:
    value = shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("bad varint")


def walk_protobuf(data: bytes, strings: List[str], times: List[float], depth: int = 0) -> bool:
    """Collect strings and plausible Cocoa times from a protobuf message; False if it isn't one."""
    pos = 0
    try:
        while pos < len(data):
            key, pos = _varint(data, pos)
            field, wire = key >> 3, key & 7
            if field == 0:
                return False
            if wire == 0:
                _, pos = _varint(data, pos)
            elif wire == 1:
                if pos + 8 > len(data):
                    return False
                value = struct.unpack_from("<d", data, pos)[0]
                if TIME_RANGE[0] <= value <= TIME_RANGE[1]:
                    times.append(value)
                pos += 8
            elif wire == 2:
                length, pos = _varint(data, pos)
                if pos + length > len(data):
                    return False
                chunk = data[pos:pos + length]
                pos += length
                nested_strings, nested_times = [], []
                if depth < MAX_DEPTH and chunk and walk_protobuf(chunk, nested_strings, nested_times, depth + 1):
                    strings.extend(nested_strings)
                    times.extend(nested_times)
                    continue
                try:
                    text = chunk.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if PRINTABLE.match(text):
                    strings.append(text)
            elif wire == 5:
                if pos + 4 > len(data):
                    return False
                pos += 4
            else:
                return False
    except ValueError:
        return False
    return True


def segb_records(data: bytes) -> Iterator[Tuple[int, str, float, bytes]]:
    """(index, state, record time in Cocoa seconds, payload) for every record in a SEGB file."""
    if data[:4] == b"SEGB":
        yield from _segb_v2(data)
    elif len(data) >= 0x38 and data[0x34:0x38] == b"SEGB":
        yield from _segb_v1(data)


def _segb_v2(data: bytes) -> Iterator[Tuple[int, str, float, bytes]]:
    count = struct.unpack_from("<I", data, 4)[0]
    count = min(count, (len(data) - 0x20) // 16)
    start = 0
    for index in range(count):
        end, state, when = struct.unpack_from("<IId", data, len(data) - 16 * (index + 1))
        if end < start or 0x20 + end > len(data) - 16 * count:
            break
        record = data[0x20 + start:0x20 + end]
        start = (end + 3) & ~3
        if len(record) < 8:
            continue
        crc = struct.unpack_from("<I", record, 0)[0]
        payload = record[8:]
        if not any(payload):
            continue  # deleted and zeroed
        if crc and zlib.crc32(payload) != crc:
            payload = record[4:] if zlib.crc32(record[4:]) == crc else payload
        yield index, STATES.get(state, str(state)), when, payload


def _segb_v1(data: bytes) -> Iterator[Tuple[int, str, float, bytes]]:
    end_of_data = struct.unpack_from("<I", data, 0)[0] or len(data)
    pos, index = 0x38, 0
    while pos + 32 <= min(end_of_data, len(data)):
        length, state, first, _second, _crc, _ = struct.unpack_from("<IIddII", data, pos)
        if length == 0 or pos + 32 + length > len(data):
            break
        payload = data[pos + 32:pos + 32 + length]
        if any(payload):
            yield index, STATES.get(state, str(state)), first, payload
        index += 1
        pos = (pos + 32 + length + 7) & ~7


def stream_name(source: str) -> str:
    """biome+streams+restricted+App.InFocus+local+<file> -> App.InFocus (tombstone streams keep the suffix)."""
    match = re.search(r"streams[+/](?:restricted|public)[+/]([^+/]+)[+/]local([+/]tombstone)?", source)
    if not match:
        return ""
    return match.group(1) + (" (tombstone)" if match.group(2) else "")


def biome_rows(path: str, source: str) -> List[Dict[str, str]]:
    with open(path, "rb") as fh:
        data = fh.read()
    stream = stream_name(source)
    rows = []
    for index, state, when, payload in segb_records(data):
        strings, times = [], []
        walk_protobuf(payload, strings, times)
        rows.append({
            "Stream": stream, "Record": index, "State": state, "RecordTime": cocoa(when) if when else "",
            "Times": " | ".join(dict.fromkeys(cocoa(t) for t in times)),
            "Strings": " | ".join(dict.fromkeys(strings))[:4000], "SourceFile": source,
        })
    return rows

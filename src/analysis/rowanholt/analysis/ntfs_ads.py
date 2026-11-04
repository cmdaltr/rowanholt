"""Alternate data streams from a raw NTFS $MFT.

Artemis's MFT output has no stream names, but every ADS is a named $DATA
attribute in its file's MFT record, so Gandalf's raw $MFT copy is enough.
"""

import struct
from pathlib import Path
from typing import BinaryIO, Dict, Iterator, List, Optional, Tuple

ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF
REF_MASK = 0xFFFFFFFFFFFF
ROOT_RECORD = 5
FIRST_USER_RECORD = 24  # records 0-23 are NTFS metadata files and reserved

# Streams Windows and common software write themselves: reported, but marked as safe to ignore
KNOWN_STREAMS = {
    "zone.identifier": "Mark of the Web (where the file was downloaded from)",
    "smartscreen": "SmartScreen verdict",
    "wofcompresseddata": "Windows Overlay Filter compression",
    "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}": "Windows document summary properties",
    "encryptable": "Windows thumbnail cache flag",
    "ms-properties": "Windows property store",
    "com.dropbox.attributes": "Dropbox",
    "com.dropbox.attrs": "Dropbox",
    "afp_afpinfo": "macOS file info over SMB",
    "afp_resource": "macOS resource fork over SMB",
    "kernel.purge.cipcache": "Windows code integrity cache",
}


def known_stream_note(stream: str) -> Optional[str]:
    """Why a stream name is benign, or None if it isn't a known one."""
    reason = KNOWN_STREAMS.get(stream.lower())
    return f"likely benign: {reason}" if reason else None


def _apply_fixups(record: bytearray, sector: int = 512) -> bool:
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_offset + usa_count * 2 > len(record):
        return False
    usn = record[usa_offset:usa_offset + 2]
    for i in range(1, usa_count):
        end = i * sector - 2
        if end + 2 > len(record) or record[end:end + 2] != usn:
            return False
        record[end:end + 2] = record[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return True


def _parse_record(record: bytearray) -> Tuple[Optional[Tuple[int, str]], List[Tuple[str, int]]]:
    """(parent ref, long name) and [(stream name, size)] for one fixed-up record."""
    name: Optional[Tuple[int, str]] = None
    name_namespace = None
    streams: List[Tuple[str, int]] = []
    offset = struct.unpack_from("<H", record, 0x14)[0]
    while offset + 16 <= len(record):
        attr_type, length = struct.unpack_from("<II", record, offset)
        if attr_type == ATTR_END or length == 0 or offset + length > len(record):
            break
        non_resident, name_length, name_offset = struct.unpack_from("<BBH", record, offset + 8)
        if attr_type == ATTR_FILE_NAME and not non_resident:
            content = offset + struct.unpack_from("<H", record, offset + 0x14)[0]
            parent = struct.unpack_from("<Q", record, content)[0] & REF_MASK
            fn_length, namespace = record[content + 0x40], record[content + 0x41]
            # Prefer the Win32/POSIX name over the 8.3 DOS one (namespace 2)
            if name is None or (name_namespace == 2 and namespace != 2):
                raw = bytes(record[content + 0x42:content + 0x42 + fn_length * 2])
                name, name_namespace = (parent, raw.decode("utf-16-le", "replace")), namespace
        elif attr_type == ATTR_DATA and name_length:
            raw = bytes(record[offset + name_offset:offset + name_offset + name_length * 2])
            if non_resident:
                size = struct.unpack_from("<Q", record, offset + 0x30)[0]
            else:
                size = struct.unpack_from("<I", record, offset + 0x10)[0]
            streams.append((raw.decode("utf-16-le", "replace"), size))
        offset += length
    return name, streams


def _records(f: BinaryIO) -> Iterator[Tuple[int, bytearray]]:
    first = f.read(1024)
    if first[:4] != b"FILE":
        raise ValueError("not an NTFS $MFT (record 0 has no FILE signature)")
    record_size = struct.unpack_from("<I", first, 0x1C)[0] or 1024
    f.seek(0)
    number = 0
    while True:
        chunk = f.read(record_size * 1024)
        if not chunk:
            return
        for start in range(0, len(chunk) - record_size + 1, record_size):
            yield number, bytearray(chunk[start:start + record_size])
            number += 1


def mft_alternate_data_streams(mft_path: Path) -> Iterator[Tuple[str, str, int]]:
    """(file path, stream name, size) for every named $DATA stream on an in-use
    file, paths resolved from $FILE_NAME parent references."""
    names: Dict[int, Tuple[int, str]] = {}
    found: List[Tuple[int, str, int]] = []
    with open(mft_path, "rb") as f:
        for number, record in _records(f):
            if record[:4] != b"FILE" or not struct.unpack_from("<H", record, 0x16)[0] & 1:
                continue
            if not _apply_fixups(record):
                continue
            base = struct.unpack_from("<Q", record, 0x20)[0] & REF_MASK
            owner = base or number
            name, streams = _parse_record(record)
            if name and not base:
                names[number] = name
            if owner >= FIRST_USER_RECORD:
                found.extend((owner, stream, size) for stream, size in streams)

    def path_of(number: int) -> str:
        parts, seen = [], set()
        while number != ROOT_RECORD and number in names and number not in seen:
            seen.add(number)
            parent, name = names[number]
            parts.append(name)
            number = parent
        return ".\\" + "\\".join(reversed(parts)) if parts else f"<record {number}>"

    for owner, stream, size in found:
        path = path_of(owner)
        if not path.lower().startswith(".\\$extend\\"):  # NTFS's own journal and repair streams
            yield path, stream, size

"""Alternate data streams from a raw $MFT (synthetic records)."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from dernvale.analysis.ntfs_ads import known_stream_note, mft_alternate_data_streams  # noqa: E402


def resident(attr_type: int, content: bytes, name: str = "") -> bytes:
    encoded = name.encode("utf-16-le")
    content_offset = (0x18 + len(encoded) + 7) & ~7
    length = (content_offset + len(content) + 7) & ~7
    a = bytearray(length)
    struct.pack_into("<IIBBH", a, 0, attr_type, length, 0, len(name), 0x18)
    struct.pack_into("<IH", a, 0x10, len(content), content_offset)
    a[0x18:0x18 + len(encoded)] = encoded
    a[content_offset:content_offset + len(content)] = content
    return bytes(a)


def file_name(parent: int, name: str, namespace: int = 1) -> bytes:
    content = bytearray(0x42)
    struct.pack_into("<Q", content, 0, parent | (1 << 48))
    content[0x40], content[0x41] = len(name), namespace
    return resident(0x30, bytes(content) + name.encode("utf-16-le"))


def record(attrs: list, in_use: bool = True, base: int = 0) -> bytes:
    r = bytearray(1024)
    r[0:4] = b"FILE"
    struct.pack_into("<HH", r, 4, 0x30, 3)
    struct.pack_into("<HH", r, 0x14, 0x38, 1 if in_use else 0)
    struct.pack_into("<I", r, 0x1C, 1024)
    struct.pack_into("<Q", r, 0x20, base)
    offset = 0x38
    for a in attrs:
        r[offset:offset + len(a)] = a
        offset += len(a)
    struct.pack_into("<I", r, offset, 0xFFFFFFFF)
    struct.pack_into("<H", r, 0x30, 7)  # update sequence number
    for i in (1, 2):
        end = i * 512 - 2
        r[0x30 + 2 * i:0x32 + 2 * i] = r[end:end + 2]
        r[end:end + 2] = struct.pack("<H", 7)
    return bytes(r)


def write_mft(tmp_path: Path) -> Path:
    records = [record([]) for _ in range(40)]
    records[5] = record([file_name(5, ".")])
    records[30] = record([file_name(5, "Users")])
    records[31] = record([
        file_name(30, "NOTES~1.TXT", namespace=2), file_name(30, "notes.txt"),
        resident(0x80, b"text"), resident(0x80, b"Write-Output x", "hidden.ps1"),
    ])
    records[32] = record([file_name(30, "setup.exe"), resident(0x80, b"[ZoneTransfer]", "Zone.Identifier")])
    records[33] = record([file_name(30, "gone.txt"), resident(0x80, b"x", "deleted")], in_use=False)
    records[34] = record([resident(0x80, b"extension", "more")], base=31)
    path = tmp_path / "$MFT"
    path.write_bytes(b"".join(records))
    return path


def test_streams_are_found_with_resolved_paths(tmp_path: Path) -> None:
    streams = sorted(mft_alternate_data_streams(write_mft(tmp_path)))
    assert streams == [
        (".\\Users\\notes.txt", "hidden.ps1", 14),
        (".\\Users\\notes.txt", "more", 9),
        (".\\Users\\setup.exe", "Zone.Identifier", 14),
    ]


def test_known_streams_are_marked_benign() -> None:
    assert known_stream_note("Zone.Identifier").startswith("likely benign")
    assert known_stream_note("hidden.ps1") is None

"""macOS FSEvents (/.fseventsd, /System/Volumes/Data/.fseventsd): the volume's change journal.

fseventsd writes a gzip file per batch of file-system changes, named by the last
event ID in it. Each holds pages of records:

  page    "1SLD" (10.12 and earlier), "2SLD" (10.13+, adds the file's inode) or
          "3SLD" (macOS 11+, adds four more bytes); a u32 we don't use, then the page
          length including this 12-byte header
  record  NUL-terminated path, u64 event ID, u32 flags, [u64 inode], [u32 extra]

Records have no times of their own; the gzip file's modification time bounds when
its batch was written. Paths are relative to the volume root.
"""

import gzip
import os
import struct
import zlib
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Tuple

VERSIONS = {b"1SLD": 1, b"2SLD": 2, b"3SLD": 3}
FLAGS = (
    (0x00000001, "FolderEvent"), (0x00000002, "Mount"), (0x00000004, "Unmount"),
    (0x00000020, "EndOfTransaction"), (0x00000800, "LastHardLinkRemoved"), (0x00001000, "HardLink"),
    (0x00004000, "SymbolicLink"), (0x00008000, "FileEvent"), (0x00010000, "PermissionChange"),
    (0x00020000, "ExtendedAttrModified"), (0x00040000, "ExtendedAttrRemoved"), (0x00100000, "DocumentRevision"),
    (0x00400000, "ItemCloned"), (0x01000000, "Created"), (0x02000000, "Removed"), (0x04000000, "InodeMetaMod"),
    (0x08000000, "Renamed"), (0x10000000, "Modified"), (0x20000000, "Exchange"), (0x40000000, "FinderInfoMod"),
    (0x80000000, "FolderCreated"),
)
MAX_DECOMPRESSED = 256 << 20
HEADER = ["Path", "EventID", "Flags", "Inode", "PageFile", "PageModified"]


def flag_names(flags: int) -> str:
    return "; ".join(name for bit, name in FLAGS if flags & bit)


def fsevents_records(data: bytes) -> Iterator[Tuple[str, int, int, int]]:
    """(path, event ID, flags, inode) for every record in a decompressed FSEvents file."""
    page = 0
    while page + 12 <= len(data):
        version = VERSIONS.get(data[page:page + 4])
        if not version:
            return
        length = struct.unpack_from("<I", data, page + 8)[0]
        end = min(page + length, len(data)) if length >= 12 else len(data)
        pos = page + 12
        tail = 12 + (8 if version >= 2 else 0) + (4 if version >= 3 else 0)
        while pos < end:
            nul = data.find(b"\x00", pos, end)
            if nul < 0 or nul + 1 + tail > end:
                break
            path = data[pos:nul].decode("utf-8", errors="replace")
            event_id, flags = struct.unpack_from("<QI", data, nul + 1)
            inode = struct.unpack_from("<Q", data, nul + 13)[0] if version >= 2 else 0
            yield path, event_id, flags, inode
            pos = nul + 1 + tail
        page = end


def fsevents_rows(path: str) -> List[Dict[str, object]]:
    """Every record in one .fseventsd page file."""
    try:
        with gzip.open(path, "rb") as fh:
            data = fh.read(MAX_DECOMPRESSED)
    except (OSError, EOFError, zlib.error):
        return []  # fseventsd-uuid, or a file still being written
    try:
        modified = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        modified = ""
    source = os.path.basename(path)
    return [{"Path": "/" + record_path.lstrip("/"), "EventID": event_id, "Flags": flag_names(flags), "Inode": inode or "",
             "PageFile": source, "PageModified": modified}
            for record_path, event_id, flags, inode in fsevents_records(data)]

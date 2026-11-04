"""Windows thumbnail and icon caches (thumbcache_*.db, iconcache_*.db).

Explorer keeps a thumbnail of every picture, video and document it has shown, in
"CMMM" databases under %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer. A thumbnail
outlives the file it came from, so the cache shows what was on (or seen from) a
machine after the file is gone. Each entry's hash is the file's
System.ThumbnailCacheId in Windows Search, which ties a thumbnail back to a path.

Layouts by format version (header field at offset 4):
  20 Vista   entry header 56 bytes, an 8-byte extension, no dimensions
  21 7       entry header 48 bytes
  30+ 8/10/11 entry header 56 bytes, with width and height
"""

import hashlib
import os
import struct
from typing import Dict, Iterator, List, Optional

SIGNATURE = b"CMMM"
IMAGE_TYPES = ((b"BM", "bmp"), (b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"))
MAX_DATABASE = 2 << 30
HEADER = ["Database", "Offset", "EntryHash", "Identifier", "Width", "Height", "DataSize", "ImageType", "SHA256", "ExtractedTo"]


def image_type(data: bytes) -> str:
    for magic, kind in IMAGE_TYPES:
        if data.startswith(magic):
            return kind
    return "bin" if data else ""


def _layout(version: int):
    """(first-entry offset field, entry header size, has dimensions, has extension)."""
    if version >= 30:
        return 16, 56, True, False
    if version == 20:
        return 12, 56, False, True
    return 12, 48, False, False


def entries(data: bytes) -> Iterator[Dict[str, object]]:
    """Every entry in a CMMM database, in file order, with its image bytes."""
    if len(data) < 24 or not data.startswith(SIGNATURE):
        return
    version = struct.unpack_from("<I", data, 4)[0]
    first_field, header_size, dimensions, extension = _layout(version)
    offset = struct.unpack_from("<I", data, first_field)[0] or 24
    while offset + header_size <= len(data):
        if data[offset:offset + 4] != SIGNATURE:
            # Free space or a torn entry: resume at the next entry signature
            offset = data.find(SIGNATURE, offset + 1)
            if offset < 0:
                return
            continue
        size = struct.unpack_from("<I", data, offset + 4)[0]
        if size < header_size or offset + size > len(data):
            offset = data.find(SIGNATURE, offset + 4)
            if offset < 0:
                return
            continue
        entry_hash = struct.unpack_from("<Q", data, offset + 8)[0]
        cursor = offset + 16 + (8 if extension else 0)
        id_size, pad_size, data_size = struct.unpack_from("<III", data, cursor)
        width = height = 0
        if dimensions:
            width, height = struct.unpack_from("<II", data, cursor + 12)
        start = offset + header_size
        identifier = data[start:start + id_size].decode("utf-16-le", errors="replace").rstrip("\x00")
        image_start = start + id_size + pad_size
        image = data[image_start:image_start + data_size] if image_start + data_size <= offset + size else b""
        yield {"version": version, "offset": offset, "hash": entry_hash, "identifier": identifier,
               "width": width, "height": height, "data": image}
        offset += size


def thumbcache_rows(path: str, extract_to: Optional[str] = None) -> List[Dict[str, str]]:
    """One row per cached thumbnail or icon; images are written to extract_to when given."""
    if os.path.getsize(path) > MAX_DATABASE:
        return []
    with open(path, "rb") as fh:
        data = fh.read()
    database = os.path.basename(path)
    rows = []
    for entry in entries(data):
        image = entry["data"]
        kind = image_type(image)
        digest = hashlib.sha256(image).hexdigest() if image else ""
        saved = ""
        if image and extract_to:
            os.makedirs(extract_to, exist_ok=True)
            saved = os.path.join(extract_to, "{:016x}.{}".format(entry["hash"], kind))
            if not os.path.exists(saved):
                with open(saved, "wb") as out:
                    out.write(image)
        rows.append({
            "Database": database,
            "Offset": entry["offset"],
            "EntryHash": "{:016x}".format(entry["hash"]),
            "Identifier": entry["identifier"],
            "Width": entry["width"] or "",
            "Height": entry["height"] or "",
            "DataSize": len(image),
            "ImageType": kind,
            "SHA256": digest,
            "ExtractedTo": saved,
        })
    return rows

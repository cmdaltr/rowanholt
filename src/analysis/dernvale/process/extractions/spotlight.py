"""
Spotlight's index store (store.db), read with the stdlib.

A volume's index is `.Spotlight-V100/Store-V2/<UUID>/`: store.db (and .store.db, its shadow) holds
one record per indexed item, and the dbStr-N.map.* files beside it hold what the records refer to:
dbStr-1 the property table (each property's name and value type), dbStr-2 the category strings
(content types, bundle ids), dbStr-4 lists of categories. Without the dbStr files a store.db can't
be read, so a copy has to take them too.

store.db: a header block (magic 8tsd), a page map (1mbd), then 16 KB pages (2pbd), each holding LZ4
blocks (bv41, bv4-, as in the unified log's chunksets; tracev3.chunkset reads them). A page is a run
of records:

    u32 size | oid varint | flags u8 | sequence varint | parent oid varint | updated varint (us, 1970)

The oid is the file's id (its inode on APFS; the volume's root folder is 2) and the parent is its
folder's oid, so paths are rebuilt from the records themselves.
    then (property index delta varint, value)...

Varints carry their length in the first byte's leading ones (0xxxxxxx: one byte, 10xxxxxx: two, ...
11111111: nine). Values by the property's type: 0-7 integers, 8 a byte, 9 float, 0xA double,
0xB string(s) (length, NUL-separated; localised ones carry \\x16\\x02<language>), 0xC dates
(seconds since 2001), 0xE bytes, 0xF a category (or, multi-valued, a dbStr-4 list of them); the
property's flag 0x02 marks a list, which is length-prefixed.

Checked on 3 November 2026: on a volume indexed for the purpose (files, folders, PDFs, images, a
download with kMDItemWhereFroms), every record read whole, and the paths and 131 values compared
matched `mdls`. The per-user CoreSpotlight stores (~/Library/Metadata/CoreSpotlight, app donations
from Messages, Mail, Photos) use the same format, but only 46-71% of their records read to the end
(counts only, on a macOS 27 host): some value encodings there aren't understood yet. A record that
can't be read to its end keeps what came before, marked Complete "no".
"""

import json
import logging
import mmap
import os
import plistlib
import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Optional, Tuple

from dernvale.process.extractions import tracev3

logger = logging.getLogger(__name__)

MAGIC = b"8tsd"
PAGE = b"2pbd"
BLOCK = 0x1000
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
APFS_ROOT = 2  # the volume's root folder's oid: paths are built up to it
MULTI = 0x02
LOCALISED = b"\x16\x02"
NO_CATEGORY = 0xFEFFFFFF  # -16777217: a category value with nothing in it
TABLES = ("dbStr-1", "dbStr-2", "dbStr-4")  # properties, categories, category lists
BLOB_SHOWN = 64

COLUMNS = ["Store", "ItemID", "ParentID", "Path", "Name", "ContentType", "Kind", "Created", "Modified",
           "LastUsed", "UseCount", "DateAdded", "Downloaded", "WhereFroms", "Size", "OwnerUID",
           "IndexUpdated", "Complete", "Other"]
# Columns of their own; everything else that isn't internal (_kMDItem…) or derived goes to Other
NAMED = {
    "kMDItemContentType": "ContentType", "kMDItemKind": "Kind", "kMDItemContentCreationDate": "Created",
    "kMDItemContentModificationDate": "Modified", "kMDItemLastUsedDate": "LastUsed",
    "kMDItemUseCount": "UseCount", "kMDItemDateAdded": "DateAdded", "kMDItemDownloadedDate": "Downloaded",
    "kMDItemWhereFroms": "WhereFroms", "kMDItemLogicalSize": "Size", "_kMDItemOwnerUserID": "OwnerUID",
}
NAMES = ("_kMDItemFileName", "kMDItemFSName", "kMDItemDisplayName", "kMDItemTitle")
SKIPPED = ("kMDItemContentTypeTree", "kMDStore", "kMDItemDisplayName")


class SpotlightError(ValueError):
    """Not a Spotlight store, or one without the dbStr files it needs."""


def varint(data, at: int) -> Tuple[int, int]:
    """(value, next offset): the first byte's leading ones say how many bytes follow."""
    first = data[at]
    if first < 0x80:
        return first, at + 1
    extra = 0
    while extra < 8 and first & (0x80 >> extra):
        extra += 1
    value = first & (0xFF >> (extra + 1)) if extra < 8 else 0
    for k in range(extra):
        value = (value << 8) | data[at + 1 + k]
    return value, at + 1 + extra


class StrTable:
    """One dbStr-N map: entry k is offsets[k] into data, a length-prefixed body."""

    def __init__(self, header: bytes, offsets: bytes, data: bytes):
        if len(header) < 0x20 or header[1:6] != b"PataD":
            raise SpotlightError("not a dbStr map header")
        count = struct.unpack_from("<I", header, 0x1C)[0]
        self.offsets = struct.unpack_from(f"<{min(count, len(offsets) // 4)}I", offsets)
        self.data = data

    @classmethod
    def load(cls, files: Dict[str, str], name: str) -> "StrTable":
        parts = []
        for suffix in ("header", "offsets", "data"):
            path = files.get(f"{name}.map.{suffix}")
            if not path:
                raise SpotlightError(f"{name}.map.{suffix} is missing: the store can't be read without it")
            with open(path, "rb") as fh:
                parts.append(fh.read())
        return cls(*parts)

    def __len__(self) -> int:
        return len(self.offsets)

    def body(self, k: int) -> bytes:
        size, at = varint(self.data, self.offsets[k])
        return self.data[at:at + size]


class Store:
    """One index store: store.db and its dbStr tables, by file name (as collected, or in its folder)."""

    def __init__(self, files: Dict[str, str], db: str = "store.db"):
        if db not in files:
            raise SpotlightError(f"no {db}")
        self.path = files[db]
        self.properties: Dict[int, Tuple[int, int, str]] = {}
        table = StrTable.load(files, "dbStr-1")
        for k in range(1, len(table)):
            body = table.body(k)
            if len(body) >= 3:
                self.properties[k] = (body[0], body[1], body[2:].split(b"\0", 1)[0].decode("utf-8", "replace"))
        categories = StrTable.load(files, "dbStr-2")
        self.categories = [categories.body(k).split(b"\0", 1)[0].decode("utf-8", "replace")
                           for k in range(len(categories))]
        try:
            self.lists: Optional[StrTable] = StrTable.load(files, "dbStr-4")
        except SpotlightError:
            self.lists = None  # only multi-valued categories need it

    @classmethod
    def from_dir(cls, directory: str, db: str = "store.db") -> "Store":
        return cls({name: os.path.join(directory, name) for name in os.listdir(directory)}, db)

    def pages(self) -> Iterator[bytes]:
        """Each page's records, decompressed; a page that can't be is skipped with a warning."""
        with open(self.path, "rb") as fh:
            if os.fstat(fh.fileno()).st_size < BLOCK:
                raise SpotlightError(f"{self.path}: too small for a Spotlight store")
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
                if data[:4] != MAGIC:
                    raise SpotlightError(f"{self.path}: not a Spotlight store (magic {bytes(data[:4])!r})")
                at = BLOCK
                while at + 0x14 <= len(data):
                    if data[at:at + 4] != PAGE:
                        at += BLOCK
                        continue
                    size, used = struct.unpack_from("<II", data, at + 4)
                    try:
                        yield tracev3.chunkset(bytes(data[at + 0x14:at + min(used, size)]))
                    except (tracev3.TraceError, struct.error, IndexError, ValueError) as exc:
                        logger.warning(f"{self.path}: skipped the page at {at:#x}: {exc}")
                    at += max(size, BLOCK)

    def records(self) -> Iterator[Dict]:
        for page in self.pages():
            at = 0
            while at + 4 <= len(page):
                size = struct.unpack_from("<I", page, at)[0]
                if size == 0:
                    break
                end = min(at + 4 + size, len(page))
                record = self._record(page, at + 4, end)
                if record:
                    yield record
                at = end

    def _record(self, page: bytes, at: int, end: int) -> Optional[Dict]:
        try:
            oid, at = varint(page, at)
            flags = page[at]
            _, at = varint(page, at + 1)  # a sequence number, not the file's id
            parent, at = varint(page, at)
            updated, at = varint(page, at)
        except IndexError:
            return None
        record = {"oid": oid, "flags": flags, "parent": parent, "updated": updated,
                  "properties": {}, "complete": True}
        index = 0
        try:
            while at < end:
                delta, at = varint(page, at)
                index += delta
                vtype, ptype, name = self.properties[index]
                value, at = self._value(page, at, vtype, ptype)
                record["properties"][name] = value
            record["complete"] = at == end
        except (KeyError, IndexError, struct.error, ValueError, UnicodeError):
            record["complete"] = False
        return record

    def _value(self, data: bytes, at: int, vtype: int, ptype: int):
        multi = ptype & MULTI
        if vtype <= 7 or vtype == 8:
            if multi:
                size, at = varint(data, at)
                end = at + size
                if vtype == 8:
                    return data[at:end].hex(), end
                values = []
                while at < end:
                    value, at = varint(data, at)
                    values.append(value)
                if at != end:
                    raise ValueError("integer list overran")
                return values, end
            if vtype == 8:
                return data[at], at + 1
            return varint(data, at)
        if vtype in (9, 0xA, 0xC):
            width, form = (4, "<f") if vtype == 9 else (8, "<d")
            if multi:
                size, at = varint(data, at)
                values = [struct.unpack_from(form, data, at + k)[0] for k in range(0, size - size % width, width)]
                end = at + size
            else:
                values, end = [struct.unpack_from(form, data, at)[0]], at + width
            if end > len(data):
                raise ValueError("value overran")
            if vtype == 0xC:
                values = [mac_date(v) for v in values]
            return (values if multi else values[0]), end
        if vtype in (0xB, 0xE):
            size, at = varint(data, at)
            end = at + size
            if end > len(data):
                raise ValueError("value overran")
            raw = data[at:end]
            return (strings(raw, multi) if vtype == 0xB else blob(raw)), end
        if vtype == 0xF:
            value, at = varint(data, at)
            if value == NO_CATEGORY:
                return "", at
            if multi and self.lists is not None and value < len(self.lists):
                body = self.lists.body(value)
                size, k = varint(body, 0)
                ids = struct.unpack_from(f"<{size // 4}I", body, k) if k + size <= len(body) else ()
                return [self._category(i) for i in ids], at
            return self._category(value), at
        raise ValueError(f"value type {vtype:#x}")

    def _category(self, k: int) -> str:
        return self.categories[k] if 0 < k < len(self.categories) else f"#{k}"


def mac_date(seconds: float) -> str:
    try:
        return (MAC_EPOCH + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, ValueError):
        return ""


def strings(raw: bytes, multi: bool):
    """One string, or a list; a localised one (text\\x16\\x02<language>, one per language) is its
    English text, else the unlabelled one, else the first."""
    parts = [p for p in raw.split(b"\0") if p]
    if any(LOCALISED in p for p in parts):
        by_language = {}
        for part in parts:
            text, _, language = part.partition(LOCALISED)
            by_language.setdefault(language.decode("ascii", "replace"), text)
        chosen = next((by_language[k] for k in ("en", "en_GB", "Base", "") if by_language.get(k)), parts[0])
        parts = [chosen.split(LOCALISED, 1)[0]]
    texts = [p.decode("utf-8", "replace") for p in parts]
    return texts if multi else (texts[0] if texts else "")


def blob(raw: bytes) -> str:
    """A property list as its contents, anything else as hex (the first BLOB_SHOWN bytes)."""
    if raw[:6] == b"bplist" or raw[:5] == b"<?xml":
        try:
            return json.dumps(plistlib.loads(raw), default=str, ensure_ascii=False)
        except (plistlib.InvalidFileException, ValueError, TypeError):
            pass
    return raw[:BLOB_SHOWN].hex() + ("…" if len(raw) > BLOB_SHOWN else "")


def _cell(value) -> str:
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    return "" if value is None else str(value)


def rows(store: Store, label: str = "") -> List[Dict[str, str]]:
    """One row per indexed item (its newest record), each with the path rebuilt from its parents."""
    latest: Dict[int, Dict] = {}
    for record in store.records():
        if record["flags"] & 0x01:
            continue  # the store's own record (its properties and sizes), not an item
        seen = latest.get(record["oid"])
        if seen is None or record["updated"] >= seen["updated"]:
            latest[record["oid"]] = record
    names: Dict[int, Tuple[str, int]] = {}
    for record in latest.values():
        name = next((record["properties"][k] for k in NAMES if record["properties"].get(k)), "")
        names[record["oid"]] = (_cell(name), record["parent"])

    def path(item: int) -> str:
        parts, seen = [], set()
        while item in names and item != APFS_ROOT and item not in seen:
            seen.add(item)
            name, item = names[item]
            parts.append(name)
        return "/" + "/".join(reversed(parts)) if item == APFS_ROOT else ""

    out = []
    for record in sorted(latest.values(), key=lambda r: r["oid"]):
        props = record["properties"]
        row = {column: "" for column in COLUMNS}
        row.update(Store=label, ItemID=str(record["oid"]), ParentID=str(record["parent"]),
                   Name=names[record["oid"]][0], Path=path(record["oid"]),
                   IndexUpdated=(UNIX_EPOCH + timedelta(microseconds=record["updated"])).strftime(
                       "%Y-%m-%dT%H:%M:%S.%fZ") if record["updated"] else "",
                   Complete="yes" if record["complete"] else "no")
        other = {}
        for name, value in props.items():
            if name in NAMED:
                row[NAMED[name]] = _cell(value)
            elif not name.startswith("_") and not name.endswith("_Ranking") and not name.startswith(SKIPPED) \
                    and value not in ("", [], None):
                other[name] = value
        row["Other"] = json.dumps(other, ensure_ascii=False, default=str) if other else ""
        out.append(row)
    return out

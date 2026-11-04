"""NTFS $LogFile: the file-system transaction journal.

$LogFile holds the redo and undo records NTFS writes before every metadata change,
so for the last few minutes to hours of activity (it is circular, 64 MB by default)
it shows files created, deleted and renamed even when $MFT has since been reused
and $UsnJrnl has been cleared. This reads the record pages ("RCRD") and decodes the
operations that carry a $FILE_NAME:

  AddIndexEntryRoot/Allocation       a name added to a directory (created, renamed to, hard link)
  DeleteIndexEntryRoot/Allocation    a name removed from a directory (deleted, renamed from)
  InitializeFileRecordSegment        an MFT record written fresh (a new file)
  DeallocateFileRecordSegment        an MFT record freed (a deleted file)

A delete and an add of the same file in one transaction is reported as a rename.
Records carry no time of their own; the times are the $FILE_NAME's.
"""

import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Optional, Tuple

PAGE_SIGNATURES = (b"RCRD",)
RESTART_SIGNATURES = (b"RSTR", b"CHKD")
LFS_HEADER = 0x30
SECTOR = 512
MAX_CLIENT_DATA = 0x10000

OPERATIONS = {
    0x00: "Noop", 0x01: "CompensationLogRecord", 0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment", 0x04: "WriteEndOfFileRecordSegment", 0x05: "CreateAttribute",
    0x06: "DeleteAttribute", 0x07: "UpdateResidentValue", 0x08: "UpdateNonresidentValue",
    0x09: "UpdateMappingPairs", 0x0A: "DeleteDirtyClusters", 0x0B: "SetNewAttributeSizes",
    0x0C: "AddIndexEntryRoot", 0x0D: "DeleteIndexEntryRoot", 0x0E: "AddIndexEntryAllocation",
    0x0F: "DeleteIndexEntryAllocation", 0x10: "WriteEndOfIndexBuffer", 0x11: "SetIndexEntryVcnRoot",
    0x12: "SetIndexEntryVcnAllocation", 0x13: "UpdateFileNameRoot", 0x14: "UpdateFileNameAllocation",
    0x15: "SetBitsInNonresidentBitMap", 0x16: "ClearBitsInNonresidentBitMap", 0x17: "HotFix",
    0x18: "EndTopLevelAction", 0x19: "PrepareTransaction", 0x1A: "CommitTransaction",
    0x1B: "ForgetTransaction", 0x1C: "OpenNonresidentAttribute", 0x1D: "OpenAttributeTableDump",
    0x1E: "AttributeNamesDump", 0x1F: "DirtyPageTableDump", 0x20: "TransactionTableDump",
    0x21: "UpdateRecordDataRoot", 0x22: "UpdateRecordDataAllocation", 0x25: "UpdateRelativeDataInIndex",
    0x26: "UpdateRelativeDataInIndex2", 0x27: "ZeroEndOfFileRecord",
}
ADD_INDEX = (0x0C, 0x0E)
DELETE_INDEX = (0x0D, 0x0F)
INITIALISE, DEALLOCATE = 0x02, 0x03
DOS_NAMESPACE = 2
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

HEADER = ["LSN", "PreviousLSN", "TransactionID", "Operation", "UndoOperation", "Event", "MFTRecord", "Sequence",
          "ParentRecord", "FileName", "OldName", "Created", "Modified", "MFTModified", "Accessed", "LastWriteTime"]


def filetime(value: int) -> str:
    if not value or value > 0x7FFFFFFFFFFFFFFF:
        return ""
    try:
        return (EPOCH + timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return ""


def apply_fixups(page: bytearray) -> bool:
    """Put back the last two bytes of each sector from the update sequence array."""
    usa_offset, usa_count = struct.unpack_from("<HH", page, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(page):
        return False
    check = page[usa_offset:usa_offset + 2]
    for i in range(1, usa_count):
        end = i * SECTOR
        if end > len(page):
            break
        if page[end - 2:end] != check:
            return False
        page[end - 2:end] = page[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return True


def page_size(data: bytes) -> int:
    """The log page size from the first restart page (4096 when it can't be read)."""
    if data[:4] in RESTART_SIGNATURES:
        size = struct.unpack_from("<I", data, 0x14)[0]
        if size in (0x1000, 0x2000, 0x10000):
            return size
    return 0x1000


def _data_start(page: bytes) -> int:
    usa_offset, usa_count = struct.unpack_from("<HH", page, 4)
    return (usa_offset + usa_count * 2 + 7) & ~7


def lfs_records(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """(LSN, LFS record) for every record in the record pages, joining those split across pages."""
    size = page_size(data)
    carry, need = b"", 0
    seen = set()
    for offset in range(2 * size, len(data) - size + 1, size):
        page = bytearray(data[offset:offset + size])
        if page[:4] not in PAGE_SIGNATURES or not apply_fixups(page):
            carry, need = b"", 0
            continue
        start = _data_start(page)
        body = bytes(page[start:])
        pos = 0
        if need:
            take = min(need, len(body))
            carry += body[:take]
            need -= take
            pos = (take + 7) & ~7
            if need:
                continue
            record = _check(carry)
            if record and record[0] not in seen:
                seen.add(record[0])
                yield record
            carry = b""
        while pos + LFS_HEADER <= len(body):
            head = body[pos:pos + LFS_HEADER]
            lsn, _, _, length, _, kind = struct.unpack_from("<QQQIII", head)
            if not lsn or kind not in (1, 2) or length > MAX_CLIENT_DATA:
                break
            total = LFS_HEADER + length
            if pos + total > len(body):
                carry, need = body[pos:], total - (len(body) - pos)
                break
            record = _check(body[pos:pos + total])
            if record and record[0] not in seen:
                seen.add(record[0])
                yield record
            pos += (total + 7) & ~7


def _check(record: bytes) -> Optional[Tuple[int, bytes]]:
    if len(record) < LFS_HEADER:
        return None
    lsn, _, _, length = struct.unpack_from("<QQQI", record)
    return (lsn, record) if len(record) >= LFS_HEADER + length else None


def file_name(attribute: bytes) -> Optional[Dict[str, object]]:
    """A $FILE_NAME attribute's value: parent, four times and the name."""
    if len(attribute) < 0x42:
        return None
    parent = struct.unpack_from("<Q", attribute, 0)[0]
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", attribute, 8)
    length = attribute[0x40]
    name = attribute[0x42:0x42 + length * 2]
    if len(name) < length * 2 or not length:
        return None
    return {"parent": parent & 0xFFFFFFFFFFFF, "name": name.decode("utf-16-le", errors="replace"), "namespace": attribute[0x41],
            "created": created, "modified": modified, "mft_modified": mft_modified, "accessed": accessed}


def index_entry(data: bytes) -> Optional[Dict[str, object]]:
    """An $I30 index entry: the file it points to and its $FILE_NAME key."""
    if len(data) < 0x10 + 0x42:
        return None
    reference, _, key_length = struct.unpack_from("<QHH", data, 0)
    if key_length < 0x42:
        return None
    entry = file_name(data[0x10:0x10 + key_length])
    if entry:
        entry["record"], entry["sequence"] = reference & 0xFFFFFFFFFFFF, reference >> 48
    return entry


def file_record(data: bytes) -> Optional[Dict[str, object]]:
    """The record number and first $FILE_NAME (preferring a Win32 name) of an MFT FILE record."""
    if len(data) < 0x38 or data[:4] != b"FILE":
        return None
    sequence = struct.unpack_from("<H", data, 0x10)[0]
    attribute = struct.unpack_from("<H", data, 0x14)[0]
    number = struct.unpack_from("<I", data, 0x2C)[0]
    best = None
    while attribute + 0x18 <= len(data):
        kind, length = struct.unpack_from("<II", data, attribute)
        if kind == 0xFFFFFFFF or length < 0x18 or attribute + length > len(data):
            break
        if kind == 0x30 and data[attribute + 8] == 0:  # resident $FILE_NAME
            value_length, value_offset = struct.unpack_from("<IH", data, attribute + 0x10)
            entry = file_name(data[attribute + value_offset:attribute + value_offset + value_length])
            if entry and (best is None or best["namespace"] == DOS_NAMESPACE):
                best = entry
        attribute += length
    if best is None:
        return None
    best["record"], best["sequence"] = number, sequence
    return best


def logfile_events(data: bytes) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """(rows, operation counts) for the name-bearing operations in a $LogFile."""
    rows, counts = [], {}
    for lsn, record in lfs_records(data):
        previous, _, length, _, kind, transaction = struct.unpack_from("<QQIIII", record, 8)
        client = record[LFS_HEADER:LFS_HEADER + length]
        if kind != 1 or len(client) < 0x20:
            continue
        redo, undo, redo_offset, redo_length, undo_offset, undo_length = struct.unpack_from("<HHHHHH", client)
        name = OPERATIONS.get(redo, "0x{:02X}".format(redo))
        counts[name] = counts.get(name, 0) + 1
        redo_data = client[redo_offset:redo_offset + redo_length]
        undo_data = client[undo_offset:undo_offset + undo_length]
        if redo in ADD_INDEX:
            entry, event = index_entry(redo_data), "name added to directory"
        elif redo in DELETE_INDEX:
            entry, event = index_entry(undo_data), "name removed from directory"
        elif redo == INITIALISE:
            entry, event = file_record(redo_data), "MFT record initialised"
        elif redo == DEALLOCATE:
            entry, event = file_record(undo_data), "MFT record deallocated"
        else:
            continue
        if not entry or entry["namespace"] == DOS_NAMESPACE:  # the 8.3 twin of a long name
            continue
        rows.append({
            "LSN": lsn, "PreviousLSN": previous, "TransactionID": transaction, "Operation": name,
            "UndoOperation": OPERATIONS.get(undo, "0x{:02X}".format(undo)), "Event": event,
            "MFTRecord": entry["record"], "Sequence": entry["sequence"], "ParentRecord": entry["parent"],
            "FileName": entry["name"], "OldName": "", "Created": filetime(entry["created"]),
            "Modified": filetime(entry["modified"]), "MFTModified": filetime(entry["mft_modified"]),
            "Accessed": filetime(entry["accessed"]), "LastWriteTime": filetime(entry["mft_modified"]),
        })
    return _renames(rows), counts


def _renames(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Mark a name removed and the next name added for the same file (record and
    sequence number) in the same transaction as a rename. Transaction IDs are
    reused slots and records are reused after a delete, so a pair only counts with
    no fresh MFT record in between.
    """
    rows = sorted(rows, key=lambda r: r["LSN"])
    pending = {}
    for row in rows:
        key = (row["TransactionID"], row["MFTRecord"], row["Sequence"])
        if row["Event"] == "MFT record initialised":
            for k in [k for k in pending if k[1] == row["MFTRecord"]]:
                del pending[k]
        elif row["Event"] == "name removed from directory":
            pending[key] = row
        elif row["Event"] == "name added to directory":
            old = pending.pop(key, None)
            if old and old["FileName"] != row["FileName"]:
                row["Event"], row["OldName"] = "renamed", old["FileName"]
                old["Event"] = "renamed (old name)"
    return rows


def logfile_rows(path: str) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    with open(path, "rb") as fh:
        return logfile_events(fh.read())

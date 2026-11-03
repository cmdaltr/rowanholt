"""Spotlight's index store reader (process/extractions/spotlight.py) over a store built here: store.db
with its pages stored (bv4-) or LZ4 (bv41), and the dbStr maps it needs. Checked by hand against `mdls`
on a volume indexed for the purpose; nothing from a real host is kept."""
import json
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from dernvale.process import mac_artefacts as ma  # noqa: E402
from dernvale.process.extractions import spotlight as sp  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PROPERTIES = [  # (value type, property flags, name): index 1 onwards
    (0x0B, 0x4C, "_kMDItemFileName"), (0x0F, 0x48, "kMDItemContentType"), (0x0B, 0x83, "kMDItemKind"),
    (0x0C, 0x40, "kMDItemContentCreationDate"), (0x0B, 0x62, "kMDItemWhereFroms"), (0x07, 0x40, "kMDItemLogicalSize"),
    (0x07, 0x40, "kMDItemUseCount"), (0x0F, 0x4A, "kMDItemSupportFileType"), (0x0B, 0x42, "kMDItemAuthors"),
    (0x07, 0x4C, "_kMDItemOwnerUserID"), (0x0E, 0x0C, "kMDStoreProperties"), (0x0C, 0x42, "kMDItemUsedDates"),
]
P = {name: k + 1 for k, (_, _, name) in enumerate(PROPERTIES)}
CATEGORIES = ["", "com.microsoft.windows-executable", "public.data", "public.item"]
CREATED = 815_000_000.0  # seconds since 2001: 2026-10-29T20:53:20Z
UPDATED = 1_793_700_000_000_000  # microseconds since 1970


def varint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    for extra in range(1, 9):
        if extra == 8 or value < 1 << (8 * extra + 7 - extra):
            break
    prefix = (0xFF << (8 - extra)) & 0xFF
    body = value.to_bytes(extra + 1, "big") if extra < 8 else b"\0" + value.to_bytes(8, "big")
    return bytes([prefix | body[0]]) + body[1:]


def map_files(entries, name, folder: Path, prefix=""):
    data, offsets = bytearray(b"\0"), [0]
    for body in entries:
        offsets.append(len(data))
        data += varint(len(body)) + body
    header = b"\x00PataD\x00\x00" + struct.pack("<IIIIII", 13, 0, 1, len(data), 0x1000, len(offsets)) + b"\0" * 24
    for suffix, content in (("header", header), ("offsets", struct.pack(f"<{len(offsets)}I", *offsets)), ("data", data)):
        (folder / f"{prefix}{name}.map.{suffix}").write_bytes(bytes(content))


def string(*parts: str) -> bytes:
    raw = b"".join(p.encode() + b"\0" for p in parts)
    return varint(len(raw)) + raw


def record(oid: int, parent: int, props, flags: int = 0, updated: int = UPDATED) -> bytes:
    body = varint(oid) + bytes([flags]) + varint(oid & 0xFF) + varint(parent) + varint(updated)
    last = 0
    for index, value in props:
        body += varint(index - last) + value
        last = index
    return struct.pack("<I", len(body)) + body


def lz4_literals(data: bytes) -> bytes:
    n = len(data)
    if n < 15:
        return bytes([n << 4]) + data
    rest, out = n - 15, bytearray([0xF0])
    while rest >= 255:
        out.append(255)
        rest -= 255
    return bytes(out) + bytes([rest]) + data


def store_db(records: bytes, lz4: bool = False) -> bytes:
    if lz4:
        payload = b"bv41" + struct.pack("<II", len(records), len(lz4_literals(records))) + lz4_literals(records)
    else:
        payload = b"bv4-" + struct.pack("<I", len(records)) + records
    payload += b"bv4$"
    page = b"2pbd" + struct.pack("<IIII", 0x4000, 0x14 + len(payload), 0x1009, 0x14 + len(records)) + payload
    header = b"8tsd" + b"\0" * (0x1000 - 4)
    pagemap = b"1mbd" + b"\0" * (0x1000 - 4)
    return header + pagemap + page + b"\0" * (0x4000 - len(page))


def item_records() -> bytes:
    file_props = [
        (P["_kMDItemFileName"], string("setup.exe")),
        (P["kMDItemContentType"], varint(1)),
        (P["kMDItemKind"], string("Windows EXE File\x16\x02en", "Fichier EXE Windows\x16\x02fr")),
        (P["kMDItemContentCreationDate"], struct.pack("<d", CREATED)),
        (P["kMDItemWhereFroms"], string("https://downloads.example.org/setup.exe", "https://example.org/page")),
        (P["kMDItemLogicalSize"], varint(73_728)),
        (P["kMDItemUseCount"], varint(3)),
        (P["kMDItemSupportFileType"], varint(1)),
        (P["kMDItemAuthors"], string("Example Ltd")),
        (P["_kMDItemOwnerUserID"], varint(501)),
        (P["kMDItemUsedDates"], varint(16) + struct.pack("<dd", CREATED, CREATED + 86400)),
    ]
    return b"".join([
        record(1, 0, [(P["kMDStoreProperties"], varint(4) + b"\x01\x02\x03\x04")], flags=1),
        record(2, 0xFFFFFFFFFFFFFFFF, [(P["_kMDItemFileName"], string("Macintosh HD"))]),
        record(100, 2, [(P["_kMDItemFileName"], string("Users"))]),
        record(200, 100, [(P["_kMDItemFileName"], string("Downloads"))]),
        record(300, 200, [(P["_kMDItemFileName"], string("old.exe"))], updated=UPDATED - 1),  # superseded
        record(300, 200, file_props),
        # A record that can't be read to its end (an index past the table) keeps what came before
        record(400, 200, [(P["_kMDItemFileName"], string("broken.bin")), (99, varint(1))]),
    ])


def make_store(folder: Path, prefix: str = "", lz4: bool = False, maps=("dbStr-1", "dbStr-2", "dbStr-4")) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    tables = {
        "dbStr-1": [bytes([t, f]) + n.encode() + b"\0" for t, f, n in PROPERTIES],
        "dbStr-2": [c.encode() + b"\0" for c in CATEGORIES[1:]],
        "dbStr-4": [varint(8) + struct.pack("<II", 2, 3)],
    }
    for name in maps:
        map_files(tables[name], name, folder, prefix)
    (folder / f"{prefix}store.db").write_bytes(store_db(item_records(), lz4))
    return folder / f"{prefix}store.db"


@pytest.mark.parametrize("lz4", [False, True])
def test_rows(tmp_path, lz4):
    make_store(tmp_path, lz4=lz4)
    rows = {r["Name"]: r for r in sp.rows(sp.Store.from_dir(str(tmp_path)), "Store-V2/ABC")}
    assert set(rows) == {"Macintosh HD", "Users", "Downloads", "setup.exe", "broken.bin"}  # not the store's own
    item = rows["setup.exe"]
    assert item["Path"] == "/Users/Downloads/setup.exe" and rows["Macintosh HD"]["Path"] == "/"
    assert (item["ItemID"], item["ParentID"], item["Store"]) == ("300", "200", "Store-V2/ABC")
    assert item["ContentType"] == "com.microsoft.windows-executable"
    assert item["Kind"] == "Windows EXE File"
    assert item["WhereFroms"] == "https://downloads.example.org/setup.exe; https://example.org/page"
    assert (item["Size"], item["UseCount"], item["OwnerUID"]) == ("73728", "3", "501")
    assert item["Created"] == "2026-10-29T20:53:20.000000Z"
    assert item["IndexUpdated"] == "2026-11-03T10:00:00.000000Z"
    assert item["Complete"] == "yes"
    other = json.loads(item["Other"])
    assert other["kMDItemAuthors"] == ["Example Ltd"]
    assert other["kMDItemSupportFileType"] == ["public.data", "public.item"]
    assert other["kMDItemUsedDates"] == ["2026-10-29T20:53:20.000000Z", "2026-10-30T20:53:20.000000Z"]


def test_a_record_that_cant_be_read_keeps_what_came_before(tmp_path):
    make_store(tmp_path)
    broken = next(r for r in sp.rows(sp.Store.from_dir(str(tmp_path))) if r["ItemID"] == "400")
    assert (broken["Name"], broken["Path"], broken["Complete"]) == ("broken.bin", "/Users/Downloads/broken.bin", "no")


def test_the_maps_are_needed(tmp_path):
    make_store(tmp_path, maps=("dbStr-2",))
    with pytest.raises(sp.SpotlightError, match="dbStr-1"):
        sp.Store.from_dir(str(tmp_path))
    # dbStr-4 is only for multi-valued categories: without it the rest still reads
    make_store(tmp_path / "no4", maps=("dbStr-1", "dbStr-2"))
    rows = {r["Name"]: r for r in sp.rows(sp.Store.from_dir(str(tmp_path / "no4")))}
    assert rows["setup.exe"]["Kind"] == "Windows EXE File"


def test_refuses_what_is_not_a_store(tmp_path):
    make_store(tmp_path)
    (tmp_path / "store.db").write_bytes(b"SQLite format 3\0" + b"\0" * 0x2000)
    with pytest.raises(sp.SpotlightError, match="not a Spotlight store"):
        list(sp.Store.from_dir(str(tmp_path)).records())


def test_varints():
    for value in (0, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0xFFFF_FFFF, 0xFEFF_FFFF, 1 << 55, (1 << 64) - 1):
        encoded = varint(value)
        assert sp.varint(encoded + b"\xAA", 0) == (value, len(encoded)), hex(value)


def test_strings():
    assert sp.strings(b"Plain Text\x16\x02\x00Texte brut\x16\x02fr\x00Plain Text Document\x16\x02en\x00", False) \
        == "Plain Text Document"
    assert sp.strings(b"Volume\x16\x02\x00Volum\x16\x02ca\x00", False) == "Volume"  # no English: the unlabelled one
    assert sp.strings(b"a\x00b\x00", True) == ["a", "b"]
    assert sp.strings(b"", False) == ""


def test_router_reads_a_collected_store(tmp_path):
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw" / "spotlight"
    prefix = "Store-V2+6A1B2C3D-0000-4000-8000-000000000000+"
    db = make_store(raw, prefix=prefix)
    (raw / f"{prefix}.store.db").write_bytes(db.read_bytes())
    out = str(tmp_path / "out") + "/"
    assert ma.process_mac_artefact("", "'HOST'", out, "HOST::macOS", "/", "processing", str(db)) is True
    # the shadow copy and the maps are read with store.db, not on their own
    for other in (raw / f"{prefix}.store.db", raw / f"{prefix}dbStr-1.map.data"):
        assert ma.process_mac_artefact("", "'HOST'", out, "HOST::macOS", "/", "processing", str(other)) is True
    with open(tmp_path / "out" / "HOST" / "artefacts" / "cooked" / "spotlight.csv") as fh:
        lines = fh.read().splitlines()
    assert lines[0] == ",".join(ma.HEADERS["spotlight.csv"]) and len(lines) == 6
    assert any("/Users/Downloads/setup.exe" in line and "Store-V2/6A1B2C3D" in line for line in lines)


def test_router_warns_when_the_maps_werent_collected(tmp_path, caplog):
    raw = tmp_path / "HOST" / "artefacts" / "raw" / "spotlight"
    db = make_store(raw, prefix="Store-V2+X+", maps=())
    assert ma.spotlight_rows(str(db)) == []
    assert "dbStr-1" in caplog.text


def test_collectors_take_the_maps(tmp_path):
    from dernvale.collect import mac as collect_mac

    bash = (REPO / "src" / "acquisition" / "bash" / "gandalf.sh").read_text()
    assert "-name 'dbStr-*.map.*'" in bash
    python = (REPO / "src" / "acquisition" / "python" / "collect_artefacts-py").read_text()
    assert "MACOS_SPOTLIGHT_MAPS.match(name)" in python
    mnt = tmp_path / "mnt"
    store = mnt / "System" / "Volumes" / "Data" / ".Spotlight-V100" / "Store-V2" / "UUID"
    store.mkdir(parents=True)
    for name in ("store.db", ".store.db", "dbStr-1.map.data", "dbStr-2.map.header", "0.indexHead", "journalAttr.1"):
        (store / name).write_bytes(b"x")
    (store.parent.parent / "VolumeConfiguration.plist").write_bytes(b"x")
    dest = tmp_path / "raw"
    assert collect_mac.collect_macos_spotlight(str(mnt), str(dest)) == 5
    assert sorted(p.name for p in (dest / "spotlight").iterdir()) == [
        "Store-V2+UUID+.store.db", "Store-V2+UUID+dbStr-1.map.data", "Store-V2+UUID+dbStr-2.map.header",
        "Store-V2+UUID+store.db", "VolumeConfiguration.plist"]

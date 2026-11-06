"""The unified-log store reader (process/extractions/tracev3.py) over a store built here: a uuidtext
file, a timesync file and a tracev3 file whose chunkset is LZ4 (macOS up to 26) or LZBITMAP (27).
Checked by hand against `log show` on a macOS 27 store as well; nothing from a real host is kept."""
import re
import struct
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "analysis"))

from rowanholt.process import mac_artefacts as ma  # noqa: E402
from rowanholt.process.extractions import tracev3 as t  # noqa: E402

MAIN = uuid.UUID("0123456789ABCDEF0123456789ABCDEF")
BOOT = uuid.UUID("00112233445566778899AABBCCDDEEFF")
WALL = 1_793_700_000 * 1_000_000_000  # 2026-11-02T...Z, in ns
FORMAT = "%{public}s : TTY=%{private}s ; USER=%{public}s ; COMMAND=%{public}s ; uid=%d ok=%{bool}d"


def lz4_literals(data: bytes) -> bytes:
    """An LZ4 block that is all literals: what the stdlib decoder must read at its simplest."""
    n = len(data)
    if n < 15:
        return bytes([n << 4]) + data
    rest, out = n - 15, bytearray([0xF0])
    while rest >= 255:
        out.append(255)
        rest -= 255
    return bytes(out) + bytes([rest]) + data


def chunk(tag: int, body: bytes) -> bytes:
    return struct.pack("<IIQ", tag, 0x11, len(body)) + body + b"\0" * (-len(body) % 8)


def uuidtext() -> bytes:
    strings = FORMAT.encode() + b"\0" + b"ignored\0"
    # two ranges, stored out of order as real files have them
    return (struct.pack("<IIII", t.UUIDTEXT_MAGIC, 2, 1, 2) + struct.pack("<II", 0x900, 8) +
            struct.pack("<II", 0x100, len(FORMAT) + 1) + b"ignored\0" + FORMAT.encode() + b"\0" + b"/usr/bin/sudo\0")


def timesync() -> bytes:
    return (t.BOOT.pack(t.TIMESYNC_BOOT, 48, 0, BOOT.bytes, 1, 1, WALL, 0, 0) +
            t.SYNC.pack(t.TIMESYNC_RECORD, 0, 1_000, WALL + 1_000, 0, 0))


def entry(kind: int, log_type: int, flags: int, body: bytes, delta: int) -> bytes:
    out = t.ENTRY.pack(kind, log_type, flags, 0x100, 7, delta, 0, len(body)) + body
    return out + b"\0" * (-len(out) % 8)


def log_body(subsystem: int, args) -> bytes:
    """pc, subsystem, then the items and the strings they point at."""
    items, backing = bytearray([0x02, len(args)]), bytearray()
    for kind, value in args:
        if kind in (0x22, 0x21):
            items += bytes([kind, 4]) + struct.pack("<HH", len(backing), len(value) + 1 if value else 0)
            backing += value + b"\0" if value else b""
        else:
            items += bytes([kind, 4]) + struct.pack("<i", value)
    return struct.pack("<IH", 0xABCD, subsystem) + bytes(items) + bytes(backing)


def firehose() -> bytes:
    sudo = log_body(7, [(0x22, b"bob"), (0x21, b""), (0x22, b"root"), (0x22, b"/bin/sh"), (0x02, 501), (0x02, 1)])
    public = (entry(t.LOG_ENTRY, 0x00, t.MAIN_EXE | t.HAS_SUBSYSTEM, sudo, 500) +
              entry(0x2, 0x01, t.MAIN_EXE, b"\0" * 12, 600) +  # an activity: left out
              entry(t.LOG_ENTRY, 0x11, t.MAIN_EXE | t.HAS_SUBSYSTEM, sudo, 700))
    head = t.FIREHOSE_HEAD.pack(1, 2, 0, 0, b"\0\0", 16 + len(public), 0x1000, 0, 0, 0, 2_000)
    return chunk(t.FIREHOSE, head + public)


def catalog() -> bytes:
    subsystems = b"com.apple.TCC\0access\0"
    processes_at = 16 + len(subsystems)
    process = t.PROCESS.pack(0, 0, 0, 0xFFFF, 1, 2, 42, 0, 0, 0, 0) + struct.pack("<II", 1, 0) + \
        struct.pack("<HHH", 7, 0, 14) + b"\0\0"
    head = t.CATALOG_HEAD.pack(16, processes_at, 1, processes_at + len(process), 0, b"\0" * 6, 0)
    return chunk(t.CATALOG, head + MAIN.bytes + subsystems + process)


def header() -> bytes:
    fixed = struct.pack("<IIQQIIII", 1, 1, 0, 0, 0, 0, 0, 0)
    boot = struct.pack("<II", t.HEADER_BOOT, 24) + BOOT.bytes + struct.pack("<II", 1, 0)
    return chunk(t.HEADER, fixed + struct.pack("<IIQ", 0x6100, 8, 0) + boot)


def lz4_chunkset(data: bytes) -> bytes:
    block = lz4_literals(data)
    return b"bv41" + struct.pack("<II", len(data), len(block)) + block + b"bv4$"


def zbm_chunkset(data: bytes) -> bytes:
    """LZBITMAP version 12 with the data as stored chunks of at most 0x8000 bytes."""
    out = bytearray(b"ZBM\x0c")
    for i in range(0, len(data), t.ZBM_MAX_CHUNK):
        part = data[i:i + t.ZBM_MAX_CHUNK]
        out += struct.pack("<I", len(part) + 6)[:3] + struct.pack("<I", len(part))[:3] + part
    return bytes(out + b"\x06\0\0\0\0\0")


def make_store(root: Path, compress=lz4_chunkset) -> Path:
    (root / "uuidtext" / MAIN.hex.upper()[:2]).mkdir(parents=True)
    (root / "uuidtext" / MAIN.hex.upper()[:2] / MAIN.hex.upper()[2:]).write_bytes(uuidtext())
    (root / "diagnostics" / "timesync").mkdir(parents=True)
    (root / "diagnostics" / "timesync" / "0000000000000001.timesync").write_bytes(timesync())
    (root / "diagnostics" / "Persist").mkdir()
    path = root / "diagnostics" / "Persist" / "0000000000000001.tracev3"
    path.write_bytes(header() + catalog() + chunk(t.CHUNKSET, compress(firehose())))
    return path


@pytest.mark.parametrize("compress", [lz4_chunkset, zbm_chunkset])
def test_messages(tmp_path, compress):
    path = make_store(tmp_path / "store", compress)
    found = list(t.Reader(t.Store(str(tmp_path / "store")), str(path)).messages())
    assert [m["Type"] for m in found] == ["Default", "Fault"]  # the activity between them isn't a message
    first = found[0]
    assert first["Message"] == "bob : TTY=<private> ; USER=root ; COMMAND=/bin/sh ; uid=501 ok=true"
    assert (first["Process"], first["PID"], first["Subsystem"], first["Category"]) == \
        ("/usr/bin/sudo", "42", "com.apple.TCC", "access")
    # 2,000 ticks of base time plus 500 of the entry's, 1,000 past the sync record (timebase 1/1: ns)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", first["LastWriteTime"])
    assert first["LastWriteTime"].endswith(".000002Z")
    assert found[1]["LastWriteTime"].endswith(".000002Z")


def test_keep_is_asked_before_decoding(tmp_path):
    path = make_store(tmp_path / "store")
    asked = []
    found = list(t.Reader(t.Store(str(tmp_path / "store")), str(path)).messages(lambda *a: asked.append(a) or False))
    assert found == [] and asked == [("sudo", "com.apple.TCC")] * 2


def test_router_keeps_what_the_live_export_would(tmp_path):
    raw = tmp_path / "out" / "HOST" / "artefacts" / "raw"
    path = make_store(raw / "unified_log_store")
    out = str(tmp_path / "out") + "/"
    ma._log_store.cache_clear()
    assert ma.process_mac_artefact("", "'HOST'", out, "HOST::macOS", "/", "processing", str(path)) is True
    # format strings and timesync are read with the tracev3 files, not on their own
    timesync_file = raw / "unified_log_store" / "diagnostics" / "timesync" / "0000000000000001.timesync"
    assert ma.process_mac_artefact("", "'HOST'", out, "HOST::macOS", "/", "processing", str(timesync_file)) is True
    with open(tmp_path / "out" / "HOST" / "artefacts" / "cooked" / "unified_log_store.csv") as fh:
        lines = fh.read().splitlines()
    assert lines[0] == ",".join(ma.HEADERS["unified_log_store.csv"]) and len(lines) == 3
    assert "COMMAND=/bin/sh" in lines[1]


def test_kept_processes_match_gandalfs_predicate():
    source = (Path(__file__).resolve().parents[2] / "src" / "acquisition" / "python" / "collect_artefacts-py").read_text()
    predicate = re.search(r"MACOS_UNIFIED_LOG_PREDICATE = \((.*?)\n\)", source, re.S).group(1)
    processes, subsystems = re.findall(r"IN \{([^}]*)\}", predicate.replace("'\n    '", "").replace("'", ""))
    assert set(re.findall(r'"([^"]+)"', processes)) == ma.UNIFIED_LOG_PROCESSES
    assert set(re.findall(r'"([^"]+)"', subsystems)) == ma.UNIFIED_LOG_SUBSYSTEMS


def test_lz4_matches_and_overlaps():
    # "abc" then a match of 9 at offset 3 (overlapping: abcabcabc), then literals "xyz"
    block = bytes([0x35]) + b"abc" + struct.pack("<H", 3) + bytes([0x30]) + b"xyz"
    saved, t._lz4_block = t._lz4_block, None
    try:
        assert t.lz4_block(block, 64) == b"abcabcabcabcxyz"
        with pytest.raises(t.TraceError):
            t.lz4_block(bytes([0x10]) + b"a" + struct.pack("<H", 5), 64)  # a match before the start
    finally:
        t._lz4_block = saved


def test_lz4_blocks_match_into_the_previous_one():
    # Seen in lab-macos's Spotlight store: a bv41 block's match reaches back into the block before
    first = bytes([0x50]) + b"hello"
    second = bytes([0x11]) + b"!" + struct.pack("<H", 6)  # "!" then "hello", 6 back: in the first block
    data = b"bv41" + struct.pack("<II", 5, len(first)) + first + \
        b"bv41" + struct.pack("<II", 6, len(second)) + second + b"bv4$"
    saved, t._lz4_block = t._lz4_block, None
    try:
        assert t.chunkset(data) == b"hello!hello"
    finally:
        t._lz4_block = saved


def zbm_compressed(version: int) -> bytes:
    """16 bytes, "ab" then 14 copies at period 2: an explicit bitmap (2 literals, 6 copies) and an all-copy bitmap."""
    body = bytearray(b"ab")
    m1 = 15 + len(body)
    body.append(2)  # the period
    m2 = 15 + len(body)
    body.append(0b0000_0011)  # explicit bitmap: two literals, six copies
    m3 = 15 + len(body)
    # version 9: nibble 1 (explicit, one period byte), then 3 (bitmap 0); version 12: 1, then 15 (bitmap 12)
    body.append(0x31 if version == 0x09 else 0xF1)
    body += b"\0" * t.ZBM_TAIL  # every bitmap 0: all copies, no new period
    length = 15 + len(body)
    head = struct.pack("<I", length)[:3] + struct.pack("<I", 16)[:3]
    offsets = b"".join(struct.pack("<I", m)[:3] for m in (m1, m2, m3))
    return b"ZBM" + bytes([version]) + head + offsets + bytes(body) + b"\x06\0\0\0\0\0"


@pytest.mark.parametrize("version", [0x09, 0x0C])
def test_lzbitmap(version):
    assert t.lzbitmap(zbm_compressed(version), 64) == b"ab" * 8
    with pytest.raises(t.TraceError):
        t.lzbitmap(zbm_compressed(version), 8)  # larger than allowed


def test_lzbitmap_refuses_what_it_cannot_read():
    good = zbm_compressed(0x0C)
    with pytest.raises(t.TraceError):
        t.lzbitmap(b"ZBM\x0b" + good[4:], 64)  # an unknown version
    for cut in range(len(good)):
        try:
            t.lzbitmap(good[:cut], 64)
        except t.TraceError:
            pass


def test_render():
    number = lambda v, size=4: ("number", v.to_bytes(size, "little", signed=True))  # noqa: E731
    assert t.render("%d%% of %u, %#x %#x", [number(5), number(-1), number(255), number(0)]) == "5% of 4294967295, 0xff 0"
    assert t.render("%{public, uuid_t}.16P", [("precision", 16), ("string", MAIN.bytes)]) == str(MAIN).upper()
    assert t.render("%{errno}d %{time_t}d", [number(2), number(0)]) == \
        "[2: No such file or directory] 1970-01-01 00:00:00+0000"
    assert t.render("%.*s|%s|%s", [("precision", 3), ("string", "abcdef"), ("string", t.NULL), ("number", t.PRIVATE)]) == \
        "abc|(null)|<private>"
    assert t.render("%s and %s", [("string", "one")]) == f"one and {t.MISSING}"
    # %m is the strerror of the errno logged with the message, by macOS's numbers (35 is EAGAIN there,
    # EDEADLK on Linux), and it takes its argument, so the next one isn't shifted
    assert t.render("send failed: %m (%d)", [number(22), number(7)]) == "send failed: Invalid argument (7)"
    assert t.render("%{errno}d", [number(35)]) == "[35: Resource temporarily unavailable]"


def test_refuses_what_is_not_a_tracev3_file(tmp_path):
    path = tmp_path / "x.tracev3"
    path.write_bytes(b"\0" * 64)
    with pytest.raises(t.TraceError):
        list(t.Reader(t.Store(str(tmp_path)), str(path)).messages())
    path.write_bytes(chunk(t.CHUNKSET, b"nope"))
    with pytest.raises(t.TraceError):
        list(t.Reader(t.Store(str(tmp_path)), str(path)).messages())


def test_image_collection_takes_the_store(tmp_path, monkeypatch):
    from rowanholt.collect import mac as collect_mac

    mnt = tmp_path / "mnt"
    files = {"private/var/db/uuidtext/AB/CDEF": b"u" * 10, "private/var/db/uuidtext/dsc/0011": b"d" * 10,
             "private/var/db/diagnostics/Persist/0001.tracev3": b"t" * 10,
             "private/var/db/diagnostics/timesync/0001.timesync": b"s" * 10}
    for rel, data in files.items():
        (mnt / rel).parent.mkdir(parents=True, exist_ok=True)
        (mnt / rel).write_bytes(data)
    dest = tmp_path / "raw"
    monkeypatch.setattr(collect_mac, "MACOS_LOG_STORE_MAX", 35)  # uuidtext first, then what still fits
    assert collect_mac.collect_macos_log_store(str(mnt), str(dest)) == 3
    taken = sorted(str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file())
    assert {"unified_log_store/uuidtext/AB/CDEF", "unified_log_store/uuidtext/dsc/0011"} < set(taken)
    assert len([p for p in taken if p.startswith("unified_log_store/diagnostics/")]) == 1


def test_a_chunk_with_private_data_may_or_may_not_be_padded():
    def private_chunk() -> bytes:  # a firehose chunk with private data, 33 bytes long
        body = t.FIREHOSE_HEAD.pack(1, 2, 0, 0, b"\0\0", 16, 0x0FFF, 0, 0, 0, 0) + b"p"
        return struct.pack("<IIQ", t.FIREHOSE, 0, len(body)) + body
    after = chunk(t.OVERSIZE, b"x" * 8)
    unpadded = private_chunk() + after
    padded = private_chunk() + b"\0" * 7 + after
    for data in (unpadded, padded):
        assert [tag for tag, _ in t.chunks(data)] == [t.FIREHOSE, t.OVERSIZE]

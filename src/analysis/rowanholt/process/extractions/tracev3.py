"""A read-only reader for macOS's unified-log store (tracev3), stdlib only.

The store is diagnostics/ (Persist, Special, Signpost, HighVolume: *.tracev3; timesync/*.timesync)
and uuidtext/ (format strings: uuidtext/<2 hex>/<30 hex> for each binary, uuidtext/dsc/<uuid> for the
shared cache). A tracev3 file is a run of chunks: a header (the boot's UUID), catalogs (the processes,
the UUIDs of their binaries and their subsystems) and LZ4-compressed chunksets holding firehose chunks,
whose entries are the log messages: a format string's offset in a binary, and the arguments. Wall-clock
time comes from the boot's timesync records.

Only log messages (Default, Info, Debug, Error, Fault) are read; activities, signposts, traces, state
and simple dumps are left out. An argument logged as private reads <private>, as `log show` prints it.

The layout follows libyal's dtformats ("Apple Unified Logging and Activity Tracing formats") and
Mandiant's macos-UnifiedLogs.
"""

import base64
import bisect
import logging
import mmap
import os
import re
import struct
from datetime import datetime, timezone
from typing import Callable, Dict, Iterator, List, Optional, Tuple

try:  # the worker has it (Plaso's dependencies); the stdlib decoder below is the fallback
    import lz4.block as _lz4_block
except ImportError:  # pragma: no cover
    _lz4_block = None

logger = logging.getLogger(__name__)

CHUNK = struct.Struct("<IIQ")  # tag, subtag, data size
HEADER, FIREHOSE, OVERSIZE, CATALOG, CHUNKSET = 0x1000, 0x6001, 0x6002, 0x600B, 0x600D
STATEDUMP, SIMPLEDUMP = 0x6003, 0x6004
KNOWN_CHUNKS = {0, HEADER, FIREHOSE, OVERSIZE, STATEDUMP, SIMPLEDUMP, CATALOG, CHUNKSET}
HEADER_BOOT = 0x6102
HEADER_FIXED = 40  # timebase, continuous and wall time, bias, daylight saving, flags; then sub-chunks
CATALOG_HEAD = struct.Struct("<HHHHH6sQ")
PROCESS = struct.Struct("<HHHHQIIIIII")  # index, ?, main uuid, dsc uuid, first proc id, second proc id, pid, euid, ?, uuids, ?
FIREHOSE_HEAD = struct.Struct("<QIBB2sHHHBBQ")
ENTRY = struct.Struct("<BBHIQIHH")  # activity type, log type, flags, format offset, thread, time delta (lo, hi), size
OVERSIZE_HEAD = struct.Struct("<QIB3sQIHH")
UUIDTEXT_MAGIC, DSC_MAGIC = 0x66778899, 0x64736368
TIMESYNC_BOOT, TIMESYNC_RECORD = 0xBBB0, 0x207354
BOOT = struct.Struct("<HHI16sIIqii")
SYNC = struct.Struct("<IIQqii")

LOG_ENTRY = 0x4
LOG_TYPES = {0x00: "Default", 0x01: "Info", 0x02: "Debug", 0x10: "Error", 0x11: "Fault"}
HAS_CURRENT_AID, HAS_LARGE_OFFSET, HAS_PRIVATE_RANGE = 0x0001, 0x0020, 0x0100
HAS_EXTRA = 0x0040  # four more bytes before the caller's address (seen on macOS 27; meaning unknown)
HAS_SUBSYSTEM, HAS_RULES, HAS_OVERSIZE = 0x0200, 0x0400, 0x0800
MAIN_EXE, SHARED_CACHE, ABSOLUTE, UUID_RELATIVE, LARGE_SHARED_CACHE = 0x2, 0x4, 0x8, 0xA, 0xC
DYNAMIC = 0x80000000  # the format offset's top bit: the message is its one string argument
MAX_FILE_BYTES = 512 << 20
MAX_CHUNKSET = 16 << 20
PRIVATE = "<private>"
NULL = "(null)"
MISSING = "<decode: missing data>"
UNKNOWN_FORMAT = "<decode: unknown format string>"


class TraceError(ValueError):
    """Not a tracev3 file, or one whose chunks don't hold together."""


# Not the uuid module: it imports platform, which Elrond's own platform package
# shadows in the worker.
def _dashed(raw: bytes) -> str:
    """A UUID in its usual dashed, upper-case form."""
    h = raw.hex().upper()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


# ---- LZ4 -----------------------------------------------------------------------


def lz4_block(src: bytes, size: int, history: bytes = b"") -> bytes:
    """One raw LZ4 block, decompressed to at most size bytes.

    history is what the stream's earlier blocks decompressed to: Apple's bv41 blocks match back
    into it (up to 64 KiB), so a block decoded on its own fails ("match before the start").
    """
    history = history[-65536:]
    if _lz4_block is not None:
        try:
            return _lz4_block.decompress(src, uncompressed_size=size, dict=history) if history \
                else _lz4_block.decompress(src, uncompressed_size=size)
        except Exception as e:  # lz4.block.LZ4BlockError
            raise TraceError(f"LZ4 block: {e}") from e
    size += len(history)
    out = bytearray(history)
    i, n = 0, len(src)
    try:
        while i < n:
            token = src[i]
            i += 1
            literals = token >> 4
            if literals == 15:
                while True:
                    extra = src[i]
                    i += 1
                    literals += extra
                    if extra != 255:
                        break
            out += src[i:i + literals]
            i += literals
            if i >= n:
                break
            offset = src[i] | src[i + 1] << 8
            i += 2
            if not 0 < offset <= len(out):
                raise TraceError("LZ4 match before the start of the block")
            length = token & 15
            if length == 15:
                while True:
                    extra = src[i]
                    i += 1
                    length += extra
                    if extra != 255:
                        break
            length += 4
            start = len(out) - offset
            if length <= offset:
                out += out[start:start + length]
            else:  # the match overlaps what it writes: the last offset bytes, repeated
                run = out[start:]
                whole, part = divmod(length, offset)
                out += run * whole + run[:part]
            if len(out) > size:
                raise TraceError("LZ4 block larger than its header says")
    except IndexError as e:
        raise TraceError("LZ4 block cut short") from e
    return bytes(out[len(history):])


# LZBITMAP (macOS 27's chunksets): after zbm_decompress in libzbitmap (MIT, Corellium LLC, Ernesto A.
# Fernández), by way of the zbitmap crate. Chunks of up to 0x8000 bytes, each stored or compressed; a
# compressed one has three metadata areas (periods, explicit bitmaps, a nibble stream choosing bitmaps)
# and 10-bit bitmaps in its last 17 bytes. Each bitmap is eight bytes of output, LSB first: a set bit a
# literal, a clear bit the byte one period back. Version 9 (APFS) has twelve bitmaps and nibble 15 starts
# a repeat count; version 12 (the unified log's) has thirteen, nibble 15 the thirteenth, and no repeats,
# which Rowanholt found by checking against libcompression.
ZBM_MAX_CHUNK = 0x8000
ZBM_TAIL = 17
ZBM_VERSIONS = {0x09: (12, True), 0x0C: (13, False)}  # version: bitmaps, repeat counts
# Each bitmap value as runs of (literal?, length), so a run is one slice rather than byte by byte
ZBM_RUNS = []
for _value in range(256):
    _runs: List[Tuple[bool, int]] = []
    for _bit in range(8):
        _literal = bool(_value >> _bit & 1)
        if _runs and _runs[-1][0] == _literal:
            _runs[-1] = (_literal, _runs[-1][1] + 1)
        else:
            _runs.append((_literal, 1))
    ZBM_RUNS.append(tuple(_runs))


def _u24(data: bytes, at: int) -> int:
    return data[at] | data[at + 1] << 8 | data[at + 2] << 16


def lzbitmap(src: bytes, limit: int) -> bytes:
    """An LZBITMAP buffer (ZBM<version>), decompressed to at most limit bytes."""
    if src[:3] != b"ZBM":
        raise TraceError("not LZBITMAP")
    out = bytearray()
    pos = 4
    try:
        while True:
            length, size = _u24(src, pos), _u24(src, pos + 3)
            if length < 6 or pos + length > len(src) or size > ZBM_MAX_CHUNK:
                raise TraceError("LZBITMAP chunk header")
            if len(out) + size > limit:
                raise TraceError("LZBITMAP data larger than its chunk")
            if length == size + 6:
                out += src[pos + 6:pos + length]
            elif size:
                _zbm_chunk(src[pos:pos + length], size, out, src[3])
            pos += length
            if size == 0:
                return bytes(out)
    except IndexError as e:
        raise TraceError("LZBITMAP data cut short") from e


def _zbm_chunk(c: bytes, size: int, out: bytearray, version: int) -> None:
    if version not in ZBM_VERSIONS:
        raise TraceError(f"LZBITMAP version {version}")
    count_bitmaps, repeats = ZBM_VERSIONS[version]
    n = len(c)
    if n < 15 + ZBM_TAIL:
        raise TraceError("LZBITMAP chunk too short")
    periods, explicit, nibbles = _u24(c, 6), _u24(c, 9), _u24(c, 12)
    if max(periods, explicit, nibbles) >= n:
        raise TraceError("LZBITMAP metadata outside its chunk")
    bits = int.from_bytes(c[n - ZBM_TAIL:], "little")
    bitmaps = []
    for k in range(count_bitmaps):
        value = bits >> (10 * k)
        if value >> 8 & 3 > 2:
            raise TraceError("LZBITMAP period of more than two bytes")
        bitmaps.append((value & 0xFF, value >> 8 & 3))
    data, period, end = 15, 8, len(out) + size
    nib = nibbles * 2  # nibble index, low nibble first

    def nibble(i: int) -> int:
        byte = c[i >> 1]
        return byte >> 4 if i & 1 else byte & 0xF

    while len(out) < end:
        number = nibble(nib)
        nib += 1
        repeat = 1
        if repeats and end - len(out) > 8 and nibble(nib) == 0xF:  # a run of the same bitmap: 4 + the nibbles after
            nib += 1
            repeat = 4
            while True:
                more = nibble(nib)
                nib += 1
                repeat += more
                if more != 0xF:
                    break
        for _ in range(repeat):
            if number - 3 >= count_bitmaps:
                raise TraceError("LZBITMAP bitmap number 15")
            if number > 2:
                bitmap, count = bitmaps[number - 3]
            else:
                bitmap, count = c[explicit], number
                explicit += 1
            if count:
                period = int.from_bytes(c[periods:periods + count], "little")
                periods += count
            if period == 0:
                raise TraceError("LZBITMAP zero period")
            left = end - len(out)
            if left >= 8:
                for literal, run in ZBM_RUNS[bitmap]:
                    if literal:
                        if data + run > n:
                            raise TraceError("LZBITMAP literals past the chunk")
                        out += c[data:data + run]
                        data += run
                    else:
                        at = len(out) - period
                        if at < 0:
                            raise TraceError("LZBITMAP match before the start")
                        if period >= run:
                            out += out[at:at + run]
                        else:
                            for _ in range(run):
                                out.append(out[-period])
            else:
                for i in range(left):
                    if bitmap >> i & 1:
                        out.append(c[data])
                        data += 1
                    else:
                        if len(out) < period:
                            raise TraceError("LZBITMAP match before the start")
                        out.append(out[-period])
            if len(out) >= end:
                break


def chunkset(data: bytes) -> bytes:
    """A chunkset decompressed: LZBITMAP (macOS 27), or LZ4 blocks (bv41 compressed, bv4- stored) up to bv4$."""
    if data[:3] == b"ZBM":
        return lzbitmap(data, MAX_CHUNKSET)
    out = bytearray()
    i = 0
    while i + 4 <= len(data):
        magic = data[i:i + 4]
        if magic == b"bv4$":
            break
        if magic == b"bv41":
            size, compressed = struct.unpack_from("<II", data, i + 4)
            out += lz4_block(data[i + 12:i + 12 + compressed], size, bytes(out[-65536:]))
            i += 12 + compressed
        elif magic == b"bv4-":
            (size,) = struct.unpack_from("<I", data, i + 4)
            out += data[i + 8:i + 8 + size]
            i += 8 + size
        else:
            raise TraceError(f"chunkset block {magic!r}")
    return bytes(out)


def chunks(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """(tag, data) for each chunk; chunks are padded to 8 bytes, except that a firehose chunk holding
    private data usually (not always) has the next chunk straight after it: whichever starts a known chunk."""
    i = 0
    while i + CHUNK.size <= len(data):
        tag, _, size = CHUNK.unpack_from(data, i)
        if tag == 0:
            return  # zero padding to the end of a chunkset
        start = i + CHUNK.size
        if start + size > len(data):
            raise TraceError(f"chunk {tag:#x} at {i} runs past the end")
        yield tag, data[start:start + size]
        end, padded = start + size, (start + size + 7) & ~7
        private = tag == FIREHOSE and size >= FIREHOSE_HEAD.size and \
            struct.unpack_from("<H", data, start + 18)[0] < 0x1000
        i = end if private and end != padded and _known_chunk(data, end) else padded


def _known_chunk(data: bytes, at: int) -> bool:
    """A chunk starts at, or the data ends there (zeros could be padding, so they don't count)."""
    return at + 4 > len(data) or struct.unpack_from("<I", data, at)[0] in KNOWN_CHUNKS - {0}


def _cstring(data, start: int, end: Optional[int] = None) -> str:
    stop = data.find(b"\0", start, len(data) if end is None else end)
    return bytes(data[start:stop if stop >= 0 else end]).decode("utf-8", "replace")


# ---- format strings: uuidtext/ and the shared cache's dsc/ -----------------------------

class UUIDText:
    """One binary's format strings (uuidtext/XX/YYYY…) and its path."""

    def __init__(self, data: bytes):
        magic, _, _, count = struct.unpack_from("<IIII", data)
        if magic != UUIDTEXT_MAGIC:
            raise TraceError("not a uuidtext file")
        self.data = data
        self.ranges: List[Tuple[int, int, int]] = []  # offset, size, where in the file
        at = 16 + 8 * count
        for start, size in struct.iter_unpack("<II", data[16:16 + 8 * count]):
            self.ranges.append((start, size, at))
            at += size
        self.path = _cstring(data, at) if at < len(data) else ""
        self.ranges.sort()  # the file doesn't keep them in order
        self.starts = [r[0] for r in self.ranges]

    def string(self, offset: int) -> Optional[str]:
        i = bisect.bisect_right(self.starts, offset) - 1
        if i >= 0:
            start, size, at = self.ranges[i]
            if offset < start + size:
                return _cstring(self.data, at + offset - start, at + size)
        return None


class SharedCacheStrings:
    """The shared cache's format strings (uuidtext/dsc/<uuid>)."""

    def __init__(self, path: str):
        with open(path, "rb") as fh:
            self.data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        magic, major, _, ranges, _ = struct.unpack_from("<IHHII", self.data)
        if magic != DSC_MAGIC:
            raise TraceError("not a shared-cache strings file")
        at = 16
        self.ranges: List[Tuple[int, int, int, int]] = []  # offset, size, where in the file, library index
        if major >= 2:
            for offset, data_at, size, library in struct.iter_unpack("<QIIQ", self.data[at:at + 24 * ranges]):
                self.ranges.append((offset, size, data_at, library))
        else:
            for library, offset, data_at, size in struct.iter_unpack("<IIII", self.data[at:at + 16 * ranges]):
                self.ranges.append((offset, size, data_at, library))
        self.ranges.sort()
        self.starts = [r[0] for r in self.ranges]

    def string(self, offset: int) -> Optional[str]:
        i = bisect.bisect_right(self.starts, offset) - 1
        if i >= 0:
            start, size, at, _ = self.ranges[i]
            if offset < start + size:
                return _cstring(self.data, at + offset - start, at + size)
        return None


class Store:
    """One unified-log store: <root>/diagnostics and <root>/uuidtext, as Gandalf copies it."""

    def __init__(self, root: str):
        self.root = root
        self.uuidtext_dir = os.path.join(root, "uuidtext")
        self._uuidtext: Dict[str, Optional[UUIDText]] = {}
        self._dsc: Dict[str, Optional[SharedCacheStrings]] = {}
        self._boots: Optional[Dict[str, Tuple[int, int, List[int], List[int]]]] = None

    def uuidtext(self, value: str) -> Optional[UUIDText]:
        if value not in self._uuidtext:
            path = os.path.join(self.uuidtext_dir, value[:2], value[2:])
            try:
                with open(path, "rb") as fh:
                    self._uuidtext[value] = UUIDText(fh.read(64 << 20))
            except (OSError, TraceError, struct.error):
                self._uuidtext[value] = None
        return self._uuidtext[value]

    def shared_cache(self, value: str) -> Optional[SharedCacheStrings]:
        if value not in self._dsc:
            try:
                self._dsc[value] = SharedCacheStrings(os.path.join(self.uuidtext_dir, "dsc", value))
            except (OSError, ValueError, struct.error):
                self._dsc[value] = None
        return self._dsc[value]

    def boots(self) -> Dict[str, Tuple[int, int, List[int], List[int]]]:
        """Boot UUID: (numerator, denominator, kernel times, wall times in ns) from timesync/."""
        if self._boots is None:
            self._boots = {}
            folder = os.path.join(self.root, "diagnostics", "timesync")
            for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
                try:
                    with open(os.path.join(folder, name), "rb") as fh:
                        self._read_timesync(fh.read(64 << 20))
                except (OSError, struct.error):
                    continue
            for numer, denom, kernel, wall in self._boots.values():
                pairs = sorted(zip(kernel, wall))
                kernel[:], wall[:] = [k for k, _ in pairs], [w for _, w in pairs]
        return self._boots

    def _read_timesync(self, data: bytes) -> None:
        i, current = 0, None
        while i + 4 <= len(data):
            if struct.unpack_from("<H", data, i)[0] == TIMESYNC_BOOT and i + BOOT.size <= len(data):
                _, size, _, boot, numer, denom, boot_ns, _, _ = BOOT.unpack_from(data, i)
                current = self._boots.setdefault(bytes(boot).hex().upper(), (numer, denom or 1, [], []))
                current[2].append(0)
                current[3].append(boot_ns)
                i += size or BOOT.size
            elif struct.unpack_from("<I", data, i)[0] == TIMESYNC_RECORD and i + SYNC.size <= len(data):
                _, _, kernel, wall, _, _ = SYNC.unpack_from(data, i)
                if current is not None:
                    current[2].append(kernel)
                    current[3].append(wall)
                i += SYNC.size
            else:
                break

    def wall_time(self, boot: str, continuous: int) -> str:
        """ISO 8601 UTC for a continuous (mach) time since the boot; empty when timesync/ hasn't the boot."""
        found = self.boots().get(boot)
        if not found:
            return ""
        numer, denom, kernel, wall = found
        i = max(bisect.bisect_right(kernel, continuous) - 1, 0)
        ns = wall[i] + (continuous - kernel[i]) * numer // denom
        seconds, rest = divmod(ns, 1_000_000_000)
        try:
            when = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return ""
        return when.strftime("%Y-%m-%dT%H:%M:%S") + f".{rest // 1000:06d}Z"


# ---- the catalog ------------------------------------------------------------------

class Process:
    """A catalog's process: its PID, main and shared-cache UUIDs, and subsystems."""

    def __init__(self, pid: int, main: str, dsc: str, subsystems: Dict[int, Tuple[str, str]],
                 images: List[Tuple[int, int, str]]):
        self.pid, self.main, self.dsc, self.subsystems = pid, main, dsc, subsystems
        self.images = images  # (load address, size, UUID) of the other binaries it loaded

    def image_at(self, address: int) -> str:
        """The UUID of the loaded binary whose range holds address."""
        return next((value for start, size, value in self.images if start <= address <= start + size), "")


def catalog(data: bytes) -> Dict[Tuple[int, int], Process]:
    """(first proc id, second proc id): Process for one catalog chunk."""
    strings_at, processes_at, count, _, _, _, _ = CATALOG_HEAD.unpack_from(data)
    base = CATALOG_HEAD.size
    uuids = [bytes(data[base + i:base + i + 16]).hex().upper() for i in range(0, strings_at - strings_at % 16, 16)]
    strings = data[base + strings_at:base + processes_at]
    at = base + processes_at
    out: Dict[Tuple[int, int], Process] = {}
    for _ in range(count):
        _, _, main, dsc, first, second, pid, _, _, n_uuids, _ = PROCESS.unpack_from(data, at)
        at += PROCESS.size
        images = []
        for size, _, index, load in struct.iter_unpack("<IIH6s", data[at:at + 16 * n_uuids]):
            if index < len(uuids):
                images.append((int.from_bytes(load, "little"), size, uuids[index]))
        at += 16 * n_uuids
        (n_subsystems,) = struct.unpack_from("<I", data, at)
        at += 8
        subsystems = {}
        for ident, subsystem, category in struct.iter_unpack("<HHH", data[at:at + 6 * n_subsystems]):
            subsystems[ident] = (_cstring(strings, subsystem), _cstring(strings, category))
        at += (6 * n_subsystems + 7) & ~7
        out[(first, second)] = Process(pid, uuids[main] if main < len(uuids) else "",
                                       uuids[dsc] if dsc < len(uuids) else "", subsystems, images)
    return out


# ---- messages ------------------------------------------------------------------

def _items(blob: bytes, start: int, private: bytes, private_at: int) -> List[Tuple[str, object]]:
    """The arguments after an entry's fixed fields: ('number', bytes), ('precision', int) or ('string', value)."""
    if start + 2 > len(blob):
        return []
    count = blob[start + 1]
    at = start + 2
    described = []
    for _ in range(count):
        if at + 2 > len(blob):
            break
        kind, size = blob[at], blob[at + 1]
        at += 2
        described.append((kind, size, blob[at:at + size]))
        at += size
    backing = blob[at:]
    out: List[Tuple[str, object]] = []
    for kind, size, value in described:
        family, privacy = kind >> 4, kind & 0xF
        if family == 0x0:
            out.append(("number", PRIVATE if privacy == 0x1 else value))
        elif family == 0x1:
            out.append(("precision", int.from_bytes(value, "little")))
        elif len(value) == 4:
            offset, length = struct.unpack("<HH", value)
            if privacy in (0x1, 0x5):  # private or sensitive: in the chunk's private data when it was kept
                where = private_at + offset
                data = private[where:where + length] if private and length and private_at >= 0 else b""
                out.append(("string", data if data else PRIVATE))
            elif not length:
                out.append(("string", NULL))
            else:
                data = backing[offset:offset + length]
                if family == 0x3:
                    out.append(("string", data))
                elif family == 0xF:
                    out.append(("string", base64.b64encode(data).decode()))
                else:
                    out.append(("string", _cstring(data, 0)))
        else:
            out.append(("string", MISSING))
    return out


SPEC = re.compile(r"%(?:\{([^}]*)\})?([-+ #0']*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|qd|q|j|z|t|L)?"
                  r"([%diouxXDOUeEfFgGaAcCsSp@nPm])")


DARWIN_ERRNO = (  # strerror(1…106) on macOS: Elrond runs on Linux, whose numbers and strings differ
    "Operation not permitted", "No such file or directory", "No such process", "Interrupted system call",
    "Input/output error", "Device not configured", "Argument list too long", "Exec format error",
    "Bad file descriptor", "No child processes", "Resource deadlock avoided", "Cannot allocate memory",
    "Permission denied", "Bad address", "Block device required", "Resource busy", "File exists",
    "Cross-device link", "Operation not supported by device", "Not a directory", "Is a directory",
    "Invalid argument", "Too many open files in system", "Too many open files", "Inappropriate ioctl for device",
    "Text file busy", "File too large", "No space left on device", "Illegal seek", "Read-only file system",
    "Too many links", "Broken pipe", "Numerical argument out of domain", "Result too large",
    "Resource temporarily unavailable", "Operation now in progress", "Operation already in progress",
    "Socket operation on non-socket", "Destination address required", "Message too long",
    "Protocol wrong type for socket", "Protocol not available", "Protocol not supported",
    "Socket type not supported", "Operation not supported", "Protocol family not supported",
    "Address family not supported by protocol family", "Address already in use", "Can't assign requested address",
    "Network is down", "Network is unreachable", "Network dropped connection on reset",
    "Software caused connection abort", "Connection reset by peer", "No buffer space available",
    "Socket is already connected", "Socket is not connected", "Can't send after socket shutdown",
    "Too many references: can't splice", "Operation timed out", "Connection refused",
    "Too many levels of symbolic links", "File name too long", "Host is down", "No route to host",
    "Directory not empty", "Too many processes", "Too many users", "Disc quota exceeded", "Stale NFS file handle",
    "Too many levels of remote in path", "RPC struct is bad", "RPC version wrong", "RPC prog. not avail",
    "Program version wrong", "Bad procedure for program", "No locks available", "Function not implemented",
    "Inappropriate file type or format", "Authentication error", "Need authenticator", "Device power is off",
    "Device error", "Value too large to be stored in data type", "Bad executable (or shared library)",
    "Bad CPU type in executable", "Shared library version mismatch", "Malformed Mach-o file", "Operation canceled",
    "Identifier removed", "No message of desired type", "Illegal byte sequence", "Attribute not found",
    "Bad message", "EMULTIHOP (Reserved)", "No message available on STREAM", "ENOLINK (Reserved)",
    "No STREAM resources", "Not a STREAM", "Protocol error", "STREAM ioctl timeout",
    "Operation not supported on socket", "Policy not found", "State not recoverable", "Previous owner died",
    "Interface output queue is full",
)


def darwin_strerror(number: int) -> str:
    return DARWIN_ERRNO[number - 1] if 0 < number <= len(DARWIN_ERRNO) else f"Unknown error: {number}"


def _signed(value: bytes) -> int:
    return int.from_bytes(value, "little", signed=True) if value else 0


def render(fmt: str, args: List[Tuple[str, object]]) -> str:
    """printf with the unified log's annotations ({public}, {bool}, {time_t}, {uuid_t}, {errno}…)."""
    queue = list(args)

    def take(want: str):
        """The next argument of the kind wanted; a precision nobody asked for (%.16P carries one) is skipped."""
        while queue:
            kind, value = queue.pop(0)
            if kind == want or (want == "value" and kind != "precision"):
                return value
        return None

    def one(match: re.Match) -> str:
        annotation, flags, width, precision, _, conv = match.groups()
        if conv == "%":
            return "%"
        if conv == "m":  # strerror of the errno logged with the message
            value = take("value")
            if value in (None, PRIVATE):
                return MISSING if value is None else PRIVATE
            return darwin_strerror(_signed(value)) if isinstance(value, (bytes, bytearray)) else str(value)
        if width == "*":
            width = str(take("precision") or "")
        if precision == "*":
            precision = take("precision")
            precision = "" if precision is None else str(precision)
        value = take("value")
        if value is None:
            return MISSING
        if value == PRIVATE:
            return PRIVATE
        notes = {n.strip() for n in (annotation or "").split(",")}
        flags = (flags or "").replace("'", "")
        spec = f"%{flags}{width or ''}"
        try:
            if conv in "sS@":
                text = value if isinstance(value, str) else _cstring(bytes(value), 0)
                return (spec + (f".{precision}" if precision else "") + "s") % text
            if conv == "P" or isinstance(value, str):
                raw = value if isinstance(value, (bytes, bytearray)) else str(value).encode()
                if "uuid_t" in notes and len(raw) >= 16:
                    return _dashed(bytes(raw[:16]))
                return raw.hex() if conv == "P" else raw.decode("utf-8", "replace")
            if conv in "eEfFgGaA":
                number = struct.unpack("<d", value[:8].ljust(8, b"\0"))[0] if len(value) >= 8 else \
                    struct.unpack("<f", value[:4].ljust(4, b"\0"))[0]
                return (spec + (f".{precision}" if precision else "") + conv.replace("a", "e").replace("A", "E")) % number
            number = _signed(value)
            if "BOOL" in notes:
                return "YES" if number else "NO"
            if "bool" in notes:
                return "true" if number else "false"
            if "time_t" in notes:
                return datetime.fromtimestamp(number, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S+0000")
            if "errno" in notes:
                return f"[{number}: {darwin_strerror(number)}]"
            if conv == "c":
                return chr(number & 0xFF)
            if conv == "p":
                return f"0x{number & (1 << 8 * len(value)) - 1:x}"
            if conv in "ouxXOU":
                number &= (1 << 8 * len(value)) - 1
            if number == 0:
                spec = spec.replace("#", "")  # C prints a zero without its 0x
            letter = {"D": "d", "U": "u", "O": "o", "i": "d"}.get(conv, conv)
            return (spec + (f".{precision}" if precision else "") + letter) % number
        except (TypeError, ValueError, OverflowError, struct.error):
            return MISSING

    return SPEC.sub(one, fmt)


class Reader:
    """The log messages in one tracev3 file of a store."""

    def __init__(self, store: Store, path: str):
        self.store, self.path = store, path

    def _format(self, process: Process, flags: int, offset: int, extra: Dict[str, object]) -> str:
        """An entry's format string."""
        kind = flags & 0xE
        dynamic = bool(offset & DYNAMIC)
        if kind in (SHARED_CACHE, LARGE_SHARED_CACHE):
            if kind == LARGE_SHARED_CACHE:
                offset |= extra.get("large_cache", 0) << 31  # type: ignore[operator]
            elif extra.get("large_offset"):
                offset |= extra["large_offset"] << 31  # type: ignore[operator]
            if dynamic and kind == SHARED_CACHE and not extra.get("large_offset"):
                return "%s"
            cache = self.store.shared_cache(process.dsc) if process.dsc else None
            found = cache.string(offset) if cache else None
            return found if found is not None else UNKNOWN_FORMAT
        if kind in (MAIN_EXE, UUID_RELATIVE):
            if dynamic and not extra.get("large_offset"):  # with a large offset, bit 31 is the offset's own
                return "%s"
            if extra.get("large_offset"):
                offset |= extra["large_offset"] << 31  # type: ignore[operator]
            image = extra.get("uuid") if kind == UUID_RELATIVE else process.main
            text = self.store.uuidtext(image) if image else None  # type: ignore[arg-type]
            found = text.string(offset) if text else None
            return found if found is not None else UNKNOWN_FORMAT
        if kind == ABSOLUTE:
            if dynamic:
                return "%s"
            image = process.image_at(extra.get("alt_index", 0) << 32 | extra.get("pc", 0))  # type: ignore[operator]
            text = self.store.uuidtext(image) if image else None
            found = text.string(offset) if text else None
            return found if found is not None else UNKNOWN_FORMAT
        return UNKNOWN_FORMAT

    def messages(self, keep: Optional[Callable[[str, str], bool]] = None) -> Iterator[Dict[str, str]]:
        """Each log message: time, process path, pid, subsystem, category, type, message.

        keep(process name, subsystem), when given, is asked before a message is decoded.
        """
        if os.path.getsize(self.path) > MAX_FILE_BYTES:
            raise TraceError(f"{self.path}: over {MAX_FILE_BYTES >> 20} MB")
        with open(self.path, "rb") as fh:
            data = fh.read()
        boot = ""
        processes: Dict[Tuple[int, int], Process] = {}
        sets: List[Tuple[Dict[Tuple[int, int], Process], List[Tuple[int, bytes]]]] = []
        for tag, body in chunks(data):
            if tag == HEADER:
                boot = self._boot(body)
            elif tag == CATALOG:
                processes = catalog(body)
            elif tag == CHUNKSET:
                try:
                    sets.append((processes, list(chunks(chunkset(body)))))
                except TraceError as e:  # one bad chunkset shouldn't cost the rest of the file
                    logger.warning("%s: skipped a chunkset: %s", self.path, e)
        if not sets and not boot:
            raise TraceError(f"{self.path}: not a tracev3 file")
        oversize: Dict[Tuple[int, int, int], Tuple[bytes, bytes]] = {}
        for _, inner in sets:
            for tag, chunk in inner:
                if tag == OVERSIZE and len(chunk) >= OVERSIZE_HEAD.size:
                    first, second, _, _, _, ref, public, private = OVERSIZE_HEAD.unpack_from(chunk)
                    start = OVERSIZE_HEAD.size
                    oversize[(first, second, ref)] = (chunk[start:start + public],
                                                      chunk[start + public:start + public + private])
        names: Dict[str, str] = {}
        for catalog_processes, inner in sets:
            for tag, chunk in inner:
                if tag == FIREHOSE:
                    yield from self._firehose(chunk, catalog_processes, boot, oversize, names, keep)

    @staticmethod
    def _boot(body: bytes) -> str:
        at = HEADER_FIXED
        while at + 8 <= len(body):
            tag, size = struct.unpack_from("<II", body, at)
            if tag == HEADER_BOOT and size >= 16:
                return bytes(body[at + 8:at + 24]).hex().upper()
            at += 8 + size
        return ""

    def _image(self, process: Process, names: Dict[str, str]) -> str:
        if process.main not in names:
            text = self.store.uuidtext(process.main) if process.main else None
            names[process.main] = text.path if text else ""
        return names[process.main]

    def _firehose(self, chunk: bytes, processes: Dict[Tuple[int, int], Process], boot: str,
                  oversize: Dict[Tuple[int, int, int], Tuple[bytes, bytes]], names: Dict[str, str],
                  keep: Optional[Callable[[str, str], bool]]) -> Iterator[Dict[str, str]]:
        first, second, _, _, _, public_size, private_virtual, _, _, _, base = FIREHOSE_HEAD.unpack_from(chunk)
        public = chunk[FIREHOSE_HEAD.size:16 + public_size]
        private = chunk[len(chunk) - (0x1000 - private_virtual):] if private_virtual < 0x1000 else b""
        process = processes.get((first, second))
        if process is None:
            return
        image = self._image(process, names)
        name = image.rsplit("/", 1)[-1]
        at = 0
        while at + ENTRY.size <= len(public):
            kind, log_type, flags, offset, _, low, high, size = ENTRY.unpack_from(public, at)
            if kind == 0:
                break  # the rest of the chunk is unused
            body = public[at + ENTRY.size:at + ENTRY.size + size]
            at = (at + ENTRY.size + size + 7) & ~7
            if kind != LOG_ENTRY or log_type not in LOG_TYPES:
                continue
            fields = self._log_fields(body, flags)
            if fields is None:
                continue
            subsystem, category = process.subsystems.get(fields["subsystem"], ("", "")) if \
                fields.get("subsystem") is not None else ("", "")
            if keep is not None and not keep(name, subsystem):
                continue
            items_at = fields["items_at"]
            if fields.get("data_ref") is not None and items_at >= len(body):
                public_blob, private_blob = oversize.get((first, second, fields["data_ref"]), (b"", b""))
                args = _items(public_blob, 0, private_blob, 0) if public_blob else []
            else:
                private_at = fields["private_offset"] - private_virtual if fields.get("private_offset") else -1
                args = _items(body, items_at, private, private_at)
            fmt = self._format(process, flags, offset, fields)
            yield {
                "LastWriteTime": self.store.wall_time(boot, base + (low | high << 32)),
                "Process": image,
                "PID": str(process.pid),
                "Subsystem": subsystem,
                "Category": category,
                "Type": LOG_TYPES[log_type],
                "Message": render(fmt, args).rstrip(),  # log show drops trailing whitespace
            }

    @staticmethod
    def _log_fields(body: bytes, flags: int) -> Optional[Dict[str, object]]:
        """A log entry's fields before its arguments; None when they're past the end."""
        try:
            at = 0
            fields: Dict[str, object] = {}
            if flags & HAS_CURRENT_AID:
                at += 8
            if flags & HAS_PRIVATE_RANGE:
                fields["private_offset"], _ = struct.unpack_from("<HH", body, at)
                at += 4
            if flags & HAS_EXTRA:
                at += 4
            (fields["pc"],) = struct.unpack_from("<I", body, at)
            at += 4
            kind = flags & 0xE
            if kind in (MAIN_EXE, SHARED_CACHE):
                if flags & HAS_LARGE_OFFSET:
                    (fields["large_offset"],) = struct.unpack_from("<H", body, at)
                    at += 2
            elif kind == ABSOLUTE:
                (fields["alt_index"],) = struct.unpack_from("<H", body, at)
                at += 2
            elif kind == UUID_RELATIVE:
                fields["uuid"] = bytes(body[at:at + 16]).hex().upper()
                at += 16
            elif kind == LARGE_SHARED_CACHE:
                if flags & HAS_LARGE_OFFSET:
                    (fields["large_offset"],) = struct.unpack_from("<H", body, at)
                    at += 2
                (fields["large_cache"],) = struct.unpack_from("<H", body, at)
                at += 2
            else:
                return None
            if flags & HAS_SUBSYSTEM:
                (fields["subsystem"],) = struct.unpack_from("<H", body, at)
                at += 2
            if flags & HAS_RULES:
                at += 1
            if flags & HAS_OVERSIZE:
                (fields["data_ref"],) = struct.unpack_from("<H", body, at)
                at += 2
            fields["items_at"] = at
            return fields
        except (struct.error, ValueError):
            return None

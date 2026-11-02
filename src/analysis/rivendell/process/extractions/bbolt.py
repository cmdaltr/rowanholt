"""A read-only bbolt (BoltDB) reader, stdlib only: containerd's meta.db is one.

bbolt is a B+tree of fixed-size pages. Pages 0 and 1 are meta pages; the one with the valid
checksum and the higher transaction id holds the root bucket. A bucket is a tree of branch and
leaf pages, or, when small, an "inline" page carried inside its parent's value. Leaf elements
are keys with either a value or (bucket flag) a child bucket's header. Free pages and the
freelist aren't read: only what the last committed transaction can reach.

https://github.com/etcd-io/bbolt (page.go, node.go, bucket.go) is the reference for the layout.
"""

import struct
from typing import Dict, Iterator, Optional, Tuple

MAGIC = 0xED0CDAED
VERSION = 2
BRANCH_PAGE, LEAF_PAGE, META_PAGE = 0x01, 0x02, 0x04
BUCKET_LEAF = 0x01
PAGE_HEADER = struct.Struct("<QHHI")  # id, flags, count, overflow
META = struct.Struct("<IIIIQQQQQQ")  # magic, version, page size, flags, root, sequence, freelist, pgid, txid, checksum
LEAF_ELEMENT = struct.Struct("<IIII")  # flags, pos, ksize, vsize
BRANCH_ELEMENT = struct.Struct("<IIQ")  # pos, ksize, pgid
BUCKET_HEADER = struct.Struct("<QQ")  # root pgid (0: inline), sequence
MAX_BYTES = 1 << 30
MAX_DEPTH = 64


class BoltError(ValueError):
    """Not a bbolt file, or one whose pages don't hold together."""


def _fnv64a(data: bytes) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


class Bucket:
    """One bucket: its values and its child buckets, by key."""

    def __init__(self, db: "Bolt", root: int, inline: Optional[bytes] = None):
        self.db, self.root, self.inline = db, root, inline

    def _elements(self) -> Iterator[Tuple[bytes, bytes, bool]]:
        if self.root == 0:
            yield from self.db.leaf_elements(self.inline or b"", 0)
        else:
            yield from self.db.page_elements(self.root, depth=0)

    def items(self) -> Iterator[Tuple[bytes, bytes]]:
        """(key, value) for each plain value."""
        for key, value, is_bucket in self._elements():
            if not is_bucket:
                yield key, value

    def buckets(self) -> Iterator[Tuple[bytes, "Bucket"]]:
        """(key, child bucket) for each nested bucket."""
        for key, value, is_bucket in self._elements():
            if is_bucket:
                yield key, self.db.bucket_from(value)

    def get(self, key: bytes) -> Optional[bytes]:
        return next((v for k, v in self.items() if k == key), None)

    def bucket(self, key: bytes) -> Optional["Bucket"]:
        return next((b for k, b in self.buckets() if k == key), None)

    def values(self) -> Dict[bytes, bytes]:
        return dict(self.items())


class Bolt:
    """A bbolt file, read whole into memory (meta.db is kilobytes to a few megabytes)."""

    def __init__(self, path: str):
        with open(path, "rb") as fh:
            self.data = fh.read(MAX_BYTES + 1)
        if len(self.data) > MAX_BYTES:
            raise BoltError(f"{path}: over {MAX_BYTES >> 20} MB")
        meta = self._meta()
        self.page_size = meta[2]
        self.root_page = meta[4]

    def _meta(self) -> tuple:
        first = self._read_meta(0)
        # Page 1 is one page in; with page 0 torn, its own page size field, or the usual sizes, find it
        sizes = [first[2]] if first else [self._claimed_page_size(), 4096, 8192, 16384, 65536]
        second = next((m for m in (self._read_meta(size) for size in sizes if size) if m), None)
        candidates = [m for m in (first, second) if m]
        if not candidates:
            raise BoltError("not a bbolt file: no valid meta page")
        return max(candidates, key=lambda m: m[8])  # the later transaction

    def _claimed_page_size(self) -> int:
        raw = self.data[PAGE_HEADER.size:PAGE_HEADER.size + META.size]
        if len(raw) < META.size:
            return 0
        magic, version, size = META.unpack(raw)[:3]
        return size if magic == MAGIC and version == VERSION and size >= 512 and not size & (size - 1) else 0

    def _read_meta(self, offset: int) -> Optional[tuple]:
        start = offset + PAGE_HEADER.size
        raw = self.data[start:start + META.size]
        if len(raw) < META.size:
            return None
        meta = META.unpack(raw)
        if meta[0] != MAGIC or meta[1] != VERSION or meta[2] < 512 or meta[2] & (meta[2] - 1):
            return None
        if _fnv64a(raw[:META.size - 8]) != meta[9]:
            return None  # torn write: the other meta page is the good one
        return meta

    def root(self) -> Bucket:
        return Bucket(self, self.root_page)

    def bucket_from(self, value: bytes) -> Bucket:
        if len(value) < BUCKET_HEADER.size:
            raise BoltError("bucket value shorter than its header")
        root, _ = BUCKET_HEADER.unpack_from(value)
        return Bucket(self, root, value[BUCKET_HEADER.size:] if root == 0 else None)

    def _page(self, pgid: int) -> bytes:
        start = pgid * self.page_size
        if pgid < 2 or start + PAGE_HEADER.size > len(self.data):
            raise BoltError(f"page {pgid} outside the file")
        _, _, _, overflow = PAGE_HEADER.unpack_from(self.data, start)
        end = start + (overflow + 1) * self.page_size
        if end > len(self.data):
            raise BoltError(f"page {pgid} runs past the end of the file")
        return self.data[start:end]

    def page_elements(self, pgid: int, depth: int) -> Iterator[Tuple[bytes, bytes, bool]]:
        if depth > MAX_DEPTH:
            raise BoltError("tree deeper than any real one: a loop")
        page = self._page(pgid)
        _, flags, count, _ = PAGE_HEADER.unpack_from(page)
        if flags & LEAF_PAGE:
            yield from self.leaf_elements(page, 0)
        elif flags & BRANCH_PAGE:
            for i in range(count):
                offset = PAGE_HEADER.size + i * BRANCH_ELEMENT.size
                if offset + BRANCH_ELEMENT.size > len(page):
                    raise BoltError(f"page {pgid}: element {i} past the page")
                _, _, child = BRANCH_ELEMENT.unpack_from(page, offset)
                yield from self.page_elements(child, depth + 1)
        else:
            raise BoltError(f"page {pgid}: neither branch nor leaf (flags {flags:#x})")

    @staticmethod
    def leaf_elements(page: bytes, start: int) -> Iterator[Tuple[bytes, bytes, bool]]:
        """(key, value, is a bucket) for each element of the leaf page at page[start:]."""
        if len(page) < start + PAGE_HEADER.size:
            raise BoltError("leaf page shorter than its header")
        _, flags, count, _ = PAGE_HEADER.unpack_from(page, start)
        if not flags & LEAF_PAGE:
            raise BoltError(f"expected a leaf page (flags {flags:#x})")
        for i in range(count):
            offset = start + PAGE_HEADER.size + i * LEAF_ELEMENT.size
            if offset + LEAF_ELEMENT.size > len(page):
                raise BoltError(f"leaf element {i} past the page")
            element_flags, pos, ksize, vsize = LEAF_ELEMENT.unpack_from(page, offset)
            key_at = offset + pos  # pos is relative to the element itself
            if key_at + ksize + vsize > len(page):
                raise BoltError(f"leaf element {i}'s key or value past the page")
            yield (page[key_at:key_at + ksize], page[key_at + ksize:key_at + ksize + vsize],
                   bool(element_flags & BUCKET_LEAF))

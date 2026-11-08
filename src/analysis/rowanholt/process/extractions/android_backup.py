"""Android ADB backups (`adb backup`, .ab): the header, the payload, and the files as a file system.

An .ab file is a short text header and then a tar stream, zlib-compressed when the header says so
and AES-256-CBC encrypted when the analyst set a password at backup time:

    ANDROID BACKUP
    <version>            1 to 5
    <compressed>         1 or 0
    <encryption>         none, or AES-256 followed by five more lines:
    <user salt hex> <checksum salt hex> <PBKDF2 rounds> <user key IV hex> <master key blob hex>

The password opens the master key blob (PBKDF2-HMAC-SHA1 of it, with the user salt), and the
master key decrypts the stream. The tar's members are apps/<package>/<token>/<path>, Android's own
backup layout, not a file system: ALEAPP looks for data/data/<package>/databases/... and finds
nothing in it. extract_to_filesystem lays the members out where they were on the phone.

Stdlib, apart from AES for an encrypted backup (`cryptography`, which Elrond already uses for
Gandalf's encrypted archives). The password is never logged or written anywhere.
"""

import hashlib
import io
import logging
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Dict, Optional

logger = logging.getLogger(__name__)

MAGIC = b"ANDROID BACKUP\n"
CHUNK = 1 << 20
# Android's FullBackup tokens: where each kind of an app's data lived on the phone
APP_DOMAINS: Dict[str, str] = {
    "a": "data/app/{pkg}",
    "obb": "data/media/0/Android/obb/{pkg}",
    "r": "data/data/{pkg}",
    "f": "data/data/{pkg}/files",
    "db": "data/data/{pkg}/databases",
    "sp": "data/data/{pkg}/shared_prefs",
    "c": "data/data/{pkg}/cache",
    "nb": "data/data/{pkg}/no_backup",
    "ef": "data/media/0/Android/data/{pkg}/files",
    "d_r": "data/user_de/0/{pkg}",
    "d_f": "data/user_de/0/{pkg}/files",
    "d_db": "data/user_de/0/{pkg}/databases",
    "d_sp": "data/user_de/0/{pkg}/shared_prefs",
    "d_c": "data/user_de/0/{pkg}/cache",
    "d_nb": "data/user_de/0/{pkg}/no_backup",
}


class AndroidBackupError(ValueError):
    """An .ab file that isn't one, or can't be opened (no password, or the wrong one)."""


class PasswordRequired(AndroidBackupError):
    """The backup is encrypted and no password was given."""


class WrongPassword(AndroidBackupError):
    """The password didn't open the backup's master key."""


@dataclass
class Header:
    """An .ab file's header, and where its payload starts."""

    version: int
    compressed: bool
    encryption: str
    payload_offset: int
    user_salt: bytes = b""
    checksum_salt: bytes = b""
    rounds: int = 0
    user_iv: bytes = b""
    master_blob: bytes = b""

    @property
    def encrypted(self) -> bool:
        """Whether the payload is encrypted (anything but 'none')."""
        return self.encryption.lower() != "none"


def is_android_backup(path: Path) -> bool:
    """Whether a file starts with the ADB backup magic."""
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _line(fh: BinaryIO) -> str:
    line = fh.readline(4096)
    if not line.endswith(b"\n"):
        raise AndroidBackupError("truncated header")
    return line[:-1].decode("ascii", errors="replace")


def read_header(path: Path) -> Header:
    """The header of an .ab file; AndroidBackupError when it isn't one."""
    with open(path, "rb") as fh:
        if fh.read(len(MAGIC)) != MAGIC:
            raise AndroidBackupError("not an Android backup (no ANDROID BACKUP header)")
        try:
            version = int(_line(fh))
            compressed = _line(fh).strip() == "1"
        except ValueError as e:
            raise AndroidBackupError(f"unreadable header ({e})") from None
        encryption = _line(fh).strip()
        header = Header(version, compressed, encryption, 0)
        if header.encrypted:
            if encryption != "AES-256":
                raise AndroidBackupError(f"unknown encryption '{encryption}'")
            try:
                header.user_salt = bytes.fromhex(_line(fh))
                header.checksum_salt = bytes.fromhex(_line(fh))
                header.rounds = int(_line(fh))
                header.user_iv = bytes.fromhex(_line(fh))
                header.master_blob = bytes.fromhex(_line(fh))
            except ValueError as e:
                raise AndroidBackupError(f"unreadable encryption header ({e})") from None
        header.payload_offset = fh.tell()
    return header


def _java_password_bytes(key: bytes, version: int) -> bytes:
    """The master key as Android hashes it for the checksum: version 1 as raw bytes; later ones
    as Java chars made from signed bytes (so 0x80 and up become 0xFF80...), UTF-8 encoded."""
    if version == 1:
        return key
    return "".join(chr(b) if b < 0x80 else chr(0xFF00 | b) for b in key).encode("utf-8", "surrogatepass")


def _aes_cbc_decryptor(key: bytes, iv: bytes):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()


def _unpad(data: bytes) -> bytes:
    if not data or data[-1] < 1 or data[-1] > 16 or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise WrongPassword("the password didn't open the backup")
    return data[:-data[-1]]


def master_key(header: Header, password: str) -> tuple:
    """(key, iv) for the payload, from the password; WrongPassword when it doesn't fit."""
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), header.user_salt, header.rounds, 32)
    decryptor = _aes_cbc_decryptor(user_key, header.user_iv)
    blob = _unpad(decryptor.update(header.master_blob) + decryptor.finalize())
    try:
        at = 0
        parts = []
        for _ in range(3):
            length = blob[at]
            parts.append(blob[at + 1:at + 1 + length])
            at += 1 + length
        iv, key, checksum = parts
    except IndexError:
        raise WrongPassword("the password didn't open the backup") from None
    if len(key) != 32 or len(iv) != 16:
        raise WrongPassword("the password didn't open the backup")
    expected = {hashlib.pbkdf2_hmac("sha1", _java_password_bytes(key, v), header.checksum_salt, header.rounds, 32)
                for v in (1, header.version)}
    if checksum not in expected:
        raise WrongPassword("the password didn't open the backup")
    return key, iv


class PayloadReader(io.RawIOBase):
    """The backup's tar stream, read from the .ab file: decrypted and decompressed as it's read."""

    def __init__(self, path: Path, header: Header, password: Optional[str] = None) -> None:
        super().__init__()
        self._fh = open(path, "rb")
        self._fh.seek(header.payload_offset)
        self._decryptor = None
        self._held = b""  # the last cipher block, kept back until the end for its padding
        if header.encrypted:
            if not password:
                self._fh.close()
                raise PasswordRequired("the backup is encrypted: it needs the password it was made with")
            key, iv = master_key(header, password)
            self._decryptor = _aes_cbc_decryptor(key, iv)
        self._inflate = zlib.decompressobj() if header.compressed else None
        self._buffer = b""
        self._done = False

    def readable(self) -> bool:
        """Always: it's a stream to read."""
        return True

    def _plain(self, data: bytes, last: bool) -> bytes:
        if self._decryptor is None:
            return data
        out = self._held + self._decryptor.update(data)
        if last:
            return _unpad(out + self._decryptor.finalize())
        keep = len(out) % 16 or 16
        self._held = out[-keep:]
        return out[:-keep]

    def _fill(self, size: int) -> None:
        while not self._done and len(self._buffer) < size:
            data = self._fh.read(CHUNK)
            last = not data
            plain = self._plain(data, last)
            if self._inflate is not None:
                try:
                    self._buffer += self._inflate.decompress(plain)
                    if last:
                        self._buffer += self._inflate.flush()
                except zlib.error as e:
                    raise AndroidBackupError(f"the payload doesn't decompress ({e})") from None
            else:
                self._buffer += plain
            self._done = last

    def readinto(self, b) -> int:
        """Fill b from the stream; 0 at its end."""
        self._fill(len(b))
        n = min(len(b), len(self._buffer))
        b[:n] = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return n

    def close(self) -> None:
        """Close the .ab file."""
        self._fh.close()
        super().close()


def phone_path(member: str) -> Optional[str]:
    """Where a backup member lived on the phone (apps/com.x/db/a.db -> data/data/com.x/databases/a.db),
    or None for the backup's own files (_manifest) and anything that could leave the folder."""
    parts = PurePosixPath(member.lstrip("/")).parts
    if not parts or any(p in ("..", "") for p in parts):
        return None
    if parts[0] == "apps" and len(parts) >= 3:
        pkg, token, rest = parts[1], parts[2], parts[3:]
        if token not in APP_DOMAINS or not rest:  # apps/<pkg>/_manifest is the backup's own
            return None
        return str(PurePosixPath(APP_DOMAINS[token].format(pkg=pkg), *rest))
    if parts[0] == "shared" and len(parts) >= 3:  # shared/0/DCIM/... : the user's shared storage
        return str(PurePosixPath("data/media", *parts[1:]))
    return None


def extract_to_filesystem(path: Path, destination: Path, password: Optional[str] = None) -> Dict[str, int]:
    """Lay an .ab file's members out under destination as they were on the phone; counts of
    files written and members left out. Links and devices are left out: only regular files."""
    header = read_header(path)
    destination = Path(destination)
    root = destination.resolve()
    counts = {"files": 0, "skipped": 0}
    reader = PayloadReader(path, header, password)
    try:
        with tarfile.open(fileobj=io.BufferedReader(reader, CHUNK), mode="r|") as tar:
            for member in tar:
                target_rel = phone_path(member.name) if member.isfile() else None
                if target_rel is None:
                    counts["skipped"] += 1
                    continue
                target = destination / target_rel
                if not str(target.resolve()).startswith(str(root) + "/"):
                    counts["skipped"] += 1
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                with open(target, "wb") as out:
                    while True:
                        block = source.read(CHUNK)
                        if not block:
                            break
                        out.write(block)
                counts["files"] += 1
    except tarfile.ReadError as e:
        raise AndroidBackupError(f"the payload isn't a tar stream ({e})") from None
    finally:
        reader.close()
    return counts

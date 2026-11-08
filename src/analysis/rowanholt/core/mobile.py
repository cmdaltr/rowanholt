"""Mobile evidence (--Mobile): the source node for phones, in place of mount + collect.

Rowanholt doesn't extract from devices. It takes what the analyst already has:

  itunes_backup        an iTunes/Finder backup folder (Manifest.db, Info.plist), encrypted or not
  adb_backup           an Android `adb backup` file (.ab), encrypted or not
  bugreport            an Android bug report (`adb bugreport`, a .zip)
  ios_filesystem       a full file system extraction of an iPhone, as a commercial tool's output
  android_filesystem   folder or archive (.zip, .tar, .tar.gz), likewise for an Android phone

Each item becomes an Elrond host, <case>/<host>/, registered in allimgs as "<host>::iOS" or
"<host>::Android" with an empty artefacts/raw/: the evidence stays where it is (a phone's backup
is tens of gigabytes, and it isn't Elrond's to copy), and <host>/mobile_evidence.json records
where it is and what it is. process/mobile.py runs iLEAPP or ALEAPP over it.

The password of an encrypted backup comes from the analyst at run time (elrond.py's
--backupPasswordStdin), is held in memory here only, and never reaches a command line, the
audit log or the case.
"""

import getpass
import json
import logging
import os
import plistlib
import re
import sqlite3
import sys
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, TextIO

from rowanholt.audit import write_audit_log_entry
from rowanholt.core.identify import print_identification
from rowanholt.process.extractions.android_backup import AndroidBackupError, is_android_backup, read_header

logger = logging.getLogger(__name__)

IOS, ANDROID = "iOS", "Android"
PLATFORMS = (IOS, ANDROID)
EVIDENCE_FILE = "mobile_evidence.json"
ARCHIVES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz")
# Paths only a phone's file system has, as an extraction tool lays it out (any prefix before them)
IOS_MARKERS = ("private/var/mobile/", "private/var/containers/", "var/mobile/Library/",
               "System/Library/CoreServices/SystemVersion.plist")
ANDROID_MARKERS = ("data/data/", "data/system/packages.xml", "data/system_ce/", "system/build.prop",
                   "data/user_de/")
# How far into an archive to look for the markers before giving up on it
MEMBER_LIMIT = 200_000
DIR_DEPTH = 4


class _Secret:
    """A value that never prints: repr() and str() of it say nothing about it."""

    def __init__(self) -> None:
        self._value: Optional[str] = None

    def set(self, value: Optional[str]) -> None:
        """Hold the value (None or '' clears it)."""
        self._value = value or None

    def get(self) -> Optional[str]:
        """The value, or None."""
        return self._value

    def __repr__(self) -> str:
        return "<backup password: {}>".format("given" if self._value else "none")

    __str__ = __repr__


_BACKUP_PASSWORD = _Secret()


def set_backup_password(password: Optional[str]) -> None:
    """The password for this run's encrypted backups (iTunes/Finder or ADB), held in memory only."""
    _BACKUP_PASSWORD.set(password)


def backup_password() -> Optional[str]:
    """The password given for this run's encrypted backups, or None."""
    return _BACKUP_PASSWORD.get()


def read_backup_password(stream: Optional[TextIO] = None) -> Optional[str]:
    """The backup password from standard input (--backupPasswordStdin): asked for without echo
    at a terminal, else its first line, as the web worker writes it. None when it's empty."""
    stream = stream or sys.stdin
    if stream.isatty():
        password = getpass.getpass("  Backup password (not shown): ")
    else:
        password = stream.readline().rstrip("\r\n")
    return password or None


@dataclass
class MobileEvidence:
    """One item of mobile evidence, as classify() found it."""

    kind: str
    platform: str
    path: str
    name: str
    input_type: str  # what the LEAPP tool's -t takes for it: itunes, fs, zip, tar, gz
    encrypted: bool = False
    details: Dict[str, str] = field(default_factory=dict)

    @property
    def tool(self) -> str:
        """iLEAPP for iOS, ALEAPP for Android."""
        return "ileapp" if self.platform == IOS else "aleapp"


def host_name(value: str, fallback: str = "mobile") -> str:
    """A directory-safe host name."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "").strip()).strip("._")
    return name or fallback


def _stem(path: Path) -> str:
    name = path.name
    for suffix in ARCHIVES + (".ab",):
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return name


def _read_plist(path: Path) -> Dict:
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def _itunes_backup(path: Path) -> Optional[MobileEvidence]:
    if not path.is_dir() or not ((path / "Manifest.db").is_file() or (path / "Manifest.plist").is_file()):
        return None
    info = _read_plist(path / "Info.plist")
    manifest = _read_plist(path / "Manifest.plist")
    details = {k: str(info[k]) for k in ("Device Name", "Product Type", "Product Version", "Serial Number",
                                         "Unique Identifier", "Last Backup Date", "IMEI", "Phone Number")
               if info.get(k) not in (None, "")}
    return MobileEvidence("itunes_backup", IOS, str(path), host_name(info.get("Device Name") or path.name),
                          "itunes", bool(manifest.get("IsEncrypted")), details)


def _adb_backup(path: Path) -> Optional[MobileEvidence]:
    if not path.is_file() or not is_android_backup(path):
        return None
    try:
        header = read_header(path)
    except AndroidBackupError as e:
        logger.warning("%s looks like an ADB backup but its header isn't readable: %s", path, e)
        return None
    return MobileEvidence("adb_backup", ANDROID, str(path), host_name(_stem(path)), "fs", header.encrypted,
                          {"Backup Version": str(header.version), "Compressed": "yes" if header.compressed else "no",
                           "Encryption": header.encryption})


def _archive_type(path: Path) -> str:
    lower = path.name.lower()
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith((".tar.gz", ".tgz")):
        return "gz"
    return "tar"


def _member_names(path: Path) -> Iterable[str]:
    """The names in an archive, up to MEMBER_LIMIT of them."""
    if path.name.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zipped:
            for number, name in enumerate(zipped.namelist()):
                if number >= MEMBER_LIMIT:
                    return
                yield name
        return
    with tarfile.open(path, "r|*") as tar:
        for number, member in enumerate(tar):
            if number >= MEMBER_LIMIT:
                return
            yield member.name


def platform_of(names: Iterable[str]) -> Optional[str]:
    """iOS or Android from the paths in an extraction: the first marker either has."""
    for name in names:
        candidate = "/" + name.replace("\\", "/").lstrip("./")
        if any("/" + marker in candidate for marker in IOS_MARKERS):
            return IOS
        if any("/" + marker in candidate for marker in ANDROID_MARKERS):
            return ANDROID
    return None


def _is_bugreport(names: List[str]) -> bool:
    return any(re.match(r"^(?:[^/]+/)?(bugreport-.+\.txt|main_entry\.txt|dumpstate_board\.txt)$", n) for n in names)


def _archive(path: Path) -> Optional[MobileEvidence]:
    if not path.is_file() or not path.name.lower().endswith(ARCHIVES):
        return None
    try:
        names = list(_member_names(path))
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as e:
        logger.warning("%s isn't a readable archive: %s", path, e)
        return None
    if path.name.lower().endswith(".zip") and _is_bugreport(names):
        return MobileEvidence("bugreport", ANDROID, str(path), host_name(_stem(path)), "zip")
    platform = platform_of(names)
    if not platform:
        return None
    kind = "ios_filesystem" if platform == IOS else "android_filesystem"
    return MobileEvidence(kind, platform, str(path), host_name(_stem(path)), _archive_type(path))


def _directory_names(root: Path, depth: int = DIR_DEPTH) -> Iterable[str]:
    """Relative paths in a folder, a few levels down: enough to find the markers."""
    base = len(root.parts)
    for current, dirs, files in os.walk(root):
        level = len(Path(current).parts) - base
        if level >= depth:
            dirs[:] = []
        dirs.sort()
        rel = Path(current).relative_to(root).as_posix()
        prefix = "" if rel == "." else rel + "/"
        for name in dirs:
            yield prefix + name + "/"
        for name in files:
            yield prefix + name


def _filesystem_folder(path: Path) -> Optional[MobileEvidence]:
    if not path.is_dir():
        return None
    platform = platform_of(_directory_names(path))
    if not platform:
        return None
    kind = "ios_filesystem" if platform == IOS else "android_filesystem"
    return MobileEvidence(kind, platform, str(path), host_name(path.name), "fs")


def classify(path: Path) -> Optional[MobileEvidence]:
    """What a file or folder is as mobile evidence, or None when it isn't any."""
    path = Path(path)
    for test in (_itunes_backup, _adb_backup, _archive, _filesystem_folder):
        evidence = test(path)
        if evidence:
            return evidence
    return None


def find_evidence(source: Path) -> List[MobileEvidence]:
    """The mobile evidence in a source: the source itself, or each item directly inside it."""
    source = Path(source)
    evidence = classify(source)
    if evidence:
        return [evidence]
    found = []
    if source.is_dir():
        for child in sorted(source.iterdir()):
            if child.name.startswith((".", "._")):
                continue
            item = classify(child)
            if item:
                found.append(item)
            else:
                print("   '{}' isn't mobile evidence Elrond reads; skipping it".format(child.name))
    return found


def _unique(name: str, taken: set) -> str:
    candidate, number = name, 2
    while candidate in taken:
        candidate, number = f"{name}-{number}", number + 1
    taken.add(candidate)
    return candidate


def ingest_mobile(output_directory: str, verbosity: str, source: str, allimgs: Dict[str, str]) -> List[str]:
    """
    Register each item of mobile evidence in source as a host: <output>/<host>/ with host.info,
    mobile_evidence.json and an empty artefacts/raw/, in allimgs as {raw dir: "<host>::<platform>"}
    (updated in place). Returns the hosts.
    """
    evidence = find_evidence(Path(source))
    if not evidence:
        print("   No mobile evidence in '{}': Elrond reads iTunes/Finder backups, ADB backups (.ab), bug reports "
              "and full file system extractions (folders or .zip/.tar archives)\n".format(source))
        return []
    write_audit_log_entry(verbosity, output_directory, "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
                          " -> {} -> created audit log file for '{}'".format(
                              datetime.now().isoformat().replace("T", " "), os.path.basename(source.rstrip("/"))))
    hosts, taken = [], set()
    for item in evidence:
        item.name = _unique(item.name, taken)
        host_dir = Path(output_directory) / item.name
        raw = host_dir / "artefacts" / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (host_dir / "artefacts" / "host.info").write_text(
            f"{item.name}::{item.platform}\n" + "".join(f"{k}: {v}\n" for k, v in item.details.items()),
            encoding="utf-8")
        record = asdict(item)
        record["registered"] = datetime.now().isoformat()
        (host_dir / EVIDENCE_FILE).write_text(json.dumps(record, indent=2), encoding="utf-8")
        print_identification(verbosity, output_directory, item.name, item.platform)
        write_audit_log_entry(
            verbosity, output_directory,
            "{},{},mobile evidence,{} at {}{}\n".format(
                datetime.now().isoformat(), item.name, item.kind, item.path.replace(",", ";"),
                " (encrypted)" if item.encrypted else ""),
            "   '{}' is {} ({}){}".format(item.name, item.kind.replace("_", " "), item.path,
                                         ", encrypted" if item.encrypted else ""))
        if item.encrypted and not backup_password():
            print("   '{}' is encrypted and no password was given (--backupPasswordStdin): "
                  "it will be skipped when processed".format(item.name))
        allimgs[str(raw)] = f"{item.name}::{item.platform}"
        hosts.append(item.name)
    print()
    return hosts


def load_evidence(output_directory: str, host: str) -> Optional[MobileEvidence]:
    """The evidence ingest_mobile recorded for a host, or None."""
    path = Path(output_directory) / host / EVIDENCE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    data.pop("registered", None)
    try:
        return MobileEvidence(**data)
    except TypeError:
        return None


def is_mobile_image(img: str) -> bool:
    """Whether an allimgs value ("<host>::<platform>") is a phone's."""
    parts = img.split("::")
    return len(parts) == 2 and parts[1] in PLATFORMS


def manifest_files(backup: Path, path_like: str) -> List[tuple]:
    """(domain/relativePath, file on disk) for the files in an unencrypted iTunes/Finder backup
    whose relativePath is LIKE path_like: Manifest.db lists them, each stored as
    <fileID[:2]>/<fileID>. An encrypted backup's Manifest.db can't be read: []."""
    db = Path(backup) / "Manifest.db"
    if not db.is_file():
        return []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT fileID, domain || '/' || relativePath FROM Files WHERE relativePath LIKE ? AND flags = 1",
                (path_like,)).fetchall()
        finally:
            con.close()
    except sqlite3.Error as e:
        logger.warning("Manifest.db in %s isn't readable: %s", backup, e)
        return []
    found = []
    for file_id, relative in rows:
        on_disk = Path(backup) / file_id[:2] / file_id
        if on_disk.is_file():
            found.append((relative, on_disk))
    return found

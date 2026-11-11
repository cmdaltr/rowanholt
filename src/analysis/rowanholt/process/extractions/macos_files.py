"""The macOS file listing Elrond takes from a mounted image (raw/macos/gandalf+file_listing.csv):
every entry in the temp folders, /Users/Shared and the top of each home, with its type, owner,
change time, symlink target, what it holds (from its first bytes) and its Finder invisible flag.

Every row is kept, so an analyst can filter the listing; these are flagged as leads:

  keychain copy         a keychain database outside a Keychains folder (T1555.001)
  exported credentials  PEM certificates or private keys in a temp or shared folder (T1555.001)
  hidden                a dot-named entry in a temp or shared folder, or one the Finder flags
                        hide anywhere listed (T1564.001)
  history to /dev/null  a shell history linked to /dev/null, so nothing is kept (T1070.003)
  staged executable     a Mach-O binary or script in a temp or shared folder (a lead, no technique:
                        installers stage there too)
"""

import csv
import re
from datetime import datetime, timezone
from typing import Dict, List

COLUMNS = ["Path", "Type", "Size", "Mode", "UID", "LastWriteTime", "Target", "Kind", "FinderHidden", "Flag",
           "Technique"]
STAGING = re.compile(r"^/(?:private/)?(?:var/)?tmp/|^/Users/Shared/")
# What macOS and common apps leave dot-named in those folders themselves
EVERYDAY_DOT_NAMES = frozenset({".DS_Store", ".localized", ".betamigrated", ".X11-unix", ".ICE-unix", ".font-unix",
                                ".Trashes", ".fseventsd", ".com.apple.timemachine.supported"})
# macOS sets the Finder's invisible flag on every home's Library itself
APPLE_HIDDEN = re.compile(r"^/Users/[^/]+/Library$")
HISTORY = re.compile(r"/\.(?:bash|zsh|sh|python|mysql|psql|node_repl|lesshst)_?history$|/\.lesshst$")


def _epoch(seconds) -> str:
    try:
        seconds = int(float(seconds))
        if seconds <= 0:
            return ""
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _dot_hidden(path: str) -> bool:
    """A dot-named component below a staging folder, not one macOS or an everyday app puts there."""
    match = STAGING.match(path)
    if not match:
        return False
    return any(part.startswith(".") and part not in EVERYDAY_DOT_NAMES and not part.startswith(".com.apple.")
               for part in path[match.end():].split("/"))


def flag(row: Dict[str, str]) -> tuple:
    """(flag, technique) for one listed entry; ("", "") when it's nothing to look at."""
    path, kind = row.get("Path", ""), row.get("Kind", "")
    staged = bool(STAGING.match(path))
    if kind == "keychain" and "/Library/Keychains/" not in path:
        return "keychain copy outside a Keychains folder", "T1555.001"
    if kind in ("pem-certificate", "pem-key") and staged:
        return "certificates or keys exported to a temp or shared folder", "T1555.001"
    if row.get("Type") == "symlink" and row.get("Target") == "/dev/null" and HISTORY.search(path):
        return "shell history linked to /dev/null", "T1070.003"
    if row.get("FinderHidden") == "yes" and not APPLE_HIDDEN.match(path):
        return "hidden from the Finder", "T1564.001"
    if _dot_hidden(path):
        return "hidden (dot-named) in a temp or shared folder", "T1564.001"
    if kind in ("macho", "script") and staged:
        return "executable staged in a temp or shared folder", ""
    return "", ""


def listing_rows(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row["LastWriteTime"] = _epoch(row.pop("MTime", ""))
        row["Flag"], row["Technique"] = flag(row)
    return rows

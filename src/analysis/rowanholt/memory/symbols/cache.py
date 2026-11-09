"""The symbol tables Rowanholt has fetched or built, in Volatility 3's own symbols folders
(symbols/linux and symbols/mac in the repository, mounted into the worker), with an index of
which banner each one serves, where it came from and its SHA-256.

The index is rowanholt.index, not .json: Volatility reads every .json in those folders as a
symbol table.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

INDEX = "rowanholt.index"
LOG = "rowanholt-symbols.log"
SYMBOL_DIRS = (
    "/usr/local/lib/python3.10/dist-packages/volatility3/symbols",
    "/usr/local/lib/python3.12/dist-packages/volatility3/symbols",
)


def symbols_root() -> Path:
    """Volatility 3's symbols folder: ROWANHOLT_SYMBOLS_DIR, the worker's, or the repository's
    symbols/ (the same folders, which the worker mounts)."""
    if os.environ.get("ROWANHOLT_SYMBOLS_DIR"):
        return Path(os.environ["ROWANHOLT_SYMBOLS_DIR"])
    for candidate in SYMBOL_DIRS:
        if Path(candidate).is_dir():
            return Path(candidate)
    return Path(__file__).resolve().parents[5] / "symbols"


def sha256(path: Path) -> str:
    """The file's SHA-256."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _index_path(os_name: str, root: Optional[Path] = None) -> Path:
    return (root or symbols_root()) / os_name / INDEX


def entries(os_name: str, root: Optional[Path] = None) -> List[Dict]:
    """The index's entries for linux or mac, newest first; those whose table has gone are left out."""
    path = _index_path(os_name, root)
    try:
        listed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    folder = path.parent
    present = [e for e in listed if (folder / e.get("file", "")).is_file()]
    return sorted(present, key=lambda e: e.get("added", ""), reverse=True)


def find(os_name: str, banner: str, root: Optional[Path] = None) -> Optional[Dict]:
    """The indexed table for exactly this banner, if there is one."""
    banner = banner.strip()
    return next((e for e in entries(os_name, root) if e.get("banner", "").strip() == banner), None)


def add(os_name: str, banner: str, table: Path, source: str, url: str = "", root: Optional[Path] = None) -> Dict:
    """Index a table already written into the OS's folder."""
    entry = {
        "banner": banner.strip(),
        "file": table.name,
        "sha256": sha256(table),
        "source": source,
        "url": url,
        "added": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path = _index_path(os_name, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    kept = [e for e in entries(os_name, root) if e.get("banner") != entry["banner"]]
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps([entry] + kept, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return entry


def log(os_name: str, line: str, root: Optional[Path] = None) -> None:
    """Append to the OS folder's own audit log, rowanholt-symbols.log: every download and
    build, from a job or the CLI (the folders are the ones mounted from the repository)."""
    path = _index_path(os_name, root).with_name(LOG)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {line}\n")
    except OSError:
        pass

"""A memory image's Linux or macOS symbol table, found or made before Volatility needs it.

In order: a table already indexed for the banner; a table in the symbols folders that serves it
(indexed then, once); the prebuilt collection; the distribution's debug package, built with
dwarf2json. Downloads are on unless ROWANHOLT_SYMBOL_DOWNLOADS is off (team servers write off),
and then the job says the command that fetches the table. Windows needs none of this:
Volatility fetches its PDBs itself, and vol.py runs --offline when downloads are off.
"""

import base64
import codecs
import json
import logging
import lzma
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from . import build, cache, sources
from .banner import Kernel, parse

logger = logging.getLogger(__name__)

OFF = ("off", "0", "false", "no")
# Called with one line for the case's audit log for every download and build
Audit = Callable[[str], None]


@dataclass
class Result:
    """What resolving a banner came to."""
    status: str             # cached, local, fetched, built, offline, unavailable, failed
    message: str
    kernel: Optional[Kernel] = None
    table: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return self.status in ("cached", "local", "fetched", "built")


def downloads_enabled() -> bool:
    """Whether fetching symbols is allowed (ROWANHOLT_SYMBOL_DOWNLOADS, on unless set off)."""
    return os.environ.get("ROWANHOLT_SYMBOL_DOWNLOADS", "on").strip().lower() not in OFF


def fetch_command(banner: str) -> str:
    """The command that fetches the table for a banner, for messages."""
    return "rowanholt symbols fetch --banner '" + banner.replace("'", "'\\''") + "'"


def banners_from(output: str) -> List[str]:
    """The kernel banners in banners.Banners output, which memory.py has as the repr of its
    bytes (literal \\n and \\t); Linux and Darwin ones, first seen first, no repeats."""
    if "\\n" in output and "\n" not in output:
        output = codecs.decode(output, "unicode_escape", errors="replace")
    found: List[str] = []
    for line in output.splitlines():
        text = line.split("\t", 1)[-1].strip()
        if (text.startswith("Linux version") or text.startswith("Darwin Kernel Version")) and text not in found:
            found.append(text)
    return found


def table_banner(table: Path) -> str:
    """The banner a Linux or macOS ISF serves, from its linux_banner or version constant."""
    try:
        opener = lzma.open if table.suffix == ".xz" else open
        with opener(table, "rb") as fh:
            isf = json.load(fh)
    except (OSError, ValueError, lzma.LZMAError):
        return ""
    for name in ("linux_banner", "version"):
        data = isf.get("symbols", {}).get(name, {}).get("constant_data")
        if data:
            return sources.normalise_banner(base64.b64decode(data).decode("utf-8", errors="replace"))
    return ""


def _local(kernel: Kernel, root: Path) -> Optional[Path]:
    """A table in the OS's folder, not yet indexed, serving exactly this banner."""
    folder = root / kernel.os
    indexed = {e["file"] for e in cache.entries(kernel.os, root)}
    wanted = sources.normalise_banner(kernel.banner)
    for table in sorted(folder.glob("*.json*")):
        if table.name not in indexed and table_banner(table) == wanted:
            return table
    return None


def resolve(banner: str, audit: Audit = lambda line: None, root: Optional[Path] = None,
            allow_downloads: Optional[bool] = None, get: sources.Fetch = sources.fetch) -> Result:
    """Make sure Volatility has a symbol table for this banner."""
    kernel = parse(banner)
    if kernel is None:
        return Result("unavailable", "not a Linux or macOS kernel banner")
    root = root or cache.symbols_root()
    case_audit = audit

    def audit(line: str) -> None:
        cache.log(kernel.os, line, root)
        case_audit(line)

    entry = cache.find(kernel.os, kernel.banner, root)
    if entry:
        return Result("cached", f"symbols for {kernel.release} ({entry['source']})", kernel, root / kernel.os / entry["file"])
    local = _local(kernel, root)
    if local:
        cache.add(kernel.os, kernel.banner, local, "local", root=root)
        return Result("local", f"symbols for {kernel.release} ({local.name})", kernel, local)

    if allow_downloads is None:
        allow_downloads = downloads_enabled()
    if not allow_downloads:
        return Result("offline", f"no symbols for {kernel.release} here, and symbol downloads are off "
                      f"(ROWANHOLT_SYMBOL_DOWNLOADS). To fetch them: {fetch_command(kernel.banner)}", kernel)

    table = root / kernel.os / f"{kernel.name}.json.xz"
    reasons = []
    for label, find in (("prebuilt", sources.prebuilt), ("debug package", sources.debug_package)):
        try:
            item = find(kernel, get)
        except (sources.SourceError, OSError) as exc:
            reasons.append(f"{label}: {exc}")
            continue
        if item.kind != "isf" and not shutil.which(build.DWARF2JSON):
            reasons.append(f"{label}: dwarf2json isn't installed to build from {item.name}")
            continue
        audit(f"symbols download {item.url} ({item.algorithm} {item.digest}) for {kernel.release}")
        try:
            build.table_from(item, kernel.release, table)
        except (build.BuildError, sources.SourceError, OSError) as exc:
            audit(f"symbols failed for {kernel.release}: {exc}")
            reasons.append(f"{label}: {exc}")
            continue
        entry = cache.add(kernel.os, kernel.banner, table, item.source, item.url, root)
        status = "fetched" if item.kind == "isf" else "built"
        audit(f"symbols {status} {table.name} (sha256 {entry['sha256']}) from {item.source}")
        return Result(status, f"symbols for {kernel.release} {status} from {item.source}", kernel, table)

    if kernel.os == "mac":
        reasons.append(f"build one from the Kernel Debug Kit for xnu-{kernel.package_version} "
                       "(developer.apple.com/download/all) with rowanholt symbols add --kdk")
    else:
        reasons.append("build one from the kernel's vmlinux with rowanholt symbols add --vmlinux")
    return Result("unavailable", f"no symbols found for {kernel.release}: " + "; ".join(reasons), kernel)

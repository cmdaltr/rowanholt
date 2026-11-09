"""rowanholt symbols: Volatility 3 symbol tables, run in the worker (the launcher execs it there).

    rowanholt symbols fetch <image>          the table for an image's kernel (Windows: its PDB)
    rowanholt symbols fetch --banner '<b>'   the table for a banner a job reported
    rowanholt symbols add --vmlinux <file> [--system-map <file>]
    rowanholt symbols add --kdk <KDK folder> [--kernel kernel.release.t6000]
    rowanholt symbols add --table <isf.json.xz>
    rowanholt symbols list
"""

import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from . import build, cache, resolve
from .banner import parse

logger = logging.getLogger("rowanholt.symbols")

VOL = "/usr/local/bin/vol.py"


def _vol(image: Path, plugin: str) -> str:
    vol = VOL if Path(VOL).exists() else "vol"
    proc = subprocess.run([vol, "-q", "-f", str(image), plugin], capture_output=True)
    return proc.stdout.decode("utf-8", errors="replace")


def fetch(image: Optional[Path], banner: Optional[str]) -> int:
    """Resolve the image's (or the given) banner; for a Windows image, have Volatility fetch
    and keep its PDB."""
    banners = [banner] if banner else resolve.banners_from(_vol(image, "banners.Banners"))
    if not banners:
        logger.info("No Linux or macOS kernel banner in %s; trying it as Windows", image)
        info = _vol(image, "windows.info.Info")
        if "NtBuildLab" in info or "ntkrnl" in info:
            logger.info("Windows: Volatility has its kernel's symbols (fetched from Microsoft's symbol server if they were new)")
            return 0
        logger.error("Neither a Linux or macOS banner nor a Windows kernel found in %s", image)
        return 1
    failed = 0
    for text in banners:
        result = resolve.resolve(text, allow_downloads=True)
        (logger.info if result.ok else logger.error)("%s: %s", result.status, result.message)
        failed += not result.ok
    return 1 if failed else 0


def _banner_in(path: Path) -> str:
    """The Linux banner compiled into a vmlinux (its linux_banner string)."""
    data = path.read_bytes()
    at = data.find(b"Linux version ")
    if at < 0:
        return ""
    return data[at:data.find(b"\n", at)].decode("utf-8", errors="replace")


def _index(os_name: str, table: Path, source: str) -> int:
    banner = resolve.table_banner(table)
    if not parse(banner):
        logger.error("%s doesn't hold a kernel banner, so Rowanholt can't index it", table.name)
        return 1
    entry = cache.add(os_name, banner, table, source)
    cache.log(os_name, f"symbols added {table.name} (sha256 {entry['sha256']}) from {source}")
    logger.info("Added %s for: %s", table.name, banner)
    return 0


def add(vmlinux: Optional[Path], system_map: Optional[Path], kdk: Optional[Path], kernel: str,
        table: Optional[Path]) -> int:
    """Build (or copy in) a table from files the analyst brings, and index it."""
    root = cache.symbols_root()
    if table:
        os_name = "mac" if "Darwin" in resolve.table_banner(table) else "linux"
        target = root / os_name / table.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(table, target)
        return _index(os_name, target, "added")
    if vmlinux:
        found = parse(_banner_in(vmlinux))
        name = found.name if found else vmlinux.name
        target = root / "linux" / f"{name}.json.xz"
        build.linux_table(vmlinux, target, system_map)
        return _index("linux", target, "built (vmlinux)")
    kernels = kdk / "System" / "Library" / "Kernels"
    dwarf = kernels / f"{kernel}.dSYM" / "Contents" / "Resources" / "DWARF" / kernel
    if not dwarf.is_file():
        options = sorted(p.name for p in kernels.glob("*") if p.is_file()) if kernels.is_dir() else []
        logger.error("No %s in the KDK; it has: %s", dwarf, ", ".join(options) or "no kernels")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        built = build.mac_table(dwarf, kernels / kernel, Path(tmp) / "kdk.json.xz")
        found = parse(resolve.table_banner(built))
        target = root / "mac" / f"{found.name if found else kdk.name}.json.xz"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(built), target)
    return _index("mac", target, "built (KDK)")


def listing() -> int:
    """Every table in the linux and mac folders, indexed or not."""
    root = cache.symbols_root()
    for os_name in ("linux", "mac"):
        indexed = {e["file"]: e for e in cache.entries(os_name, root)}
        for table in sorted((root / os_name).glob("*.json*")):
            e = indexed.get(table.name)
            logger.info("%s/%s  %s  %s", os_name, table.name, e["source"] if e else "not indexed",
                        e["banner"] if e else "")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(prog="rowanholt symbols", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    f = sub.add_parser("fetch", help="the table for an image's kernel, or a banner's")
    f.add_argument("image", nargs="?", type=Path)
    f.add_argument("--banner")
    a = sub.add_parser("add", help="build a table from a vmlinux or a KDK, or add one")
    group = a.add_mutually_exclusive_group(required=True)
    group.add_argument("--vmlinux", type=Path)
    group.add_argument("--kdk", type=Path)
    group.add_argument("--table", type=Path)
    a.add_argument("--system-map", type=Path)
    a.add_argument("--kernel", default="kernel", help="the KDK's kernel (default: kernel)")
    sub.add_parser("list", help="the tables Rowanholt has")
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            if not args.image and not args.banner:
                parser.error("fetch needs an image or --banner")
            return fetch(args.image, args.banner)
        if args.command == "add":
            return add(args.vmlinux, args.system_map, args.kdk, args.kernel, args.table)
        return listing()
    except (build.BuildError, OSError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

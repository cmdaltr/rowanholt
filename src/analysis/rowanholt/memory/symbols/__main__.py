"""rowanholt symbols: Volatility 3 symbol tables, run in the worker (the launcher execs it there).

    rowanholt symbols fetch <image>          the table for an image's kernel (Windows: its PDB)
    rowanholt symbols fetch --banner '<b>'   the table for a banner a job reported
    rowanholt symbols what <image>|--banner  what to get when it can't be fetched, and from where
    rowanholt symbols add --package <.ddeb|.deb|.rpm>   a kernel's debug package
    rowanholt symbols add --vmlinux <file> [--system-map <file>]
    rowanholt symbols add --kdk <KDK .dmg|.pkg|folder> [--banner '<b>' | --kernel kernel.release.t6000]
    rowanholt symbols add --table <isf.json.xz>
    rowanholt symbols list

A KDK's .dmg or .pkg is unpacked on the Mac by the launcher, which then hands the folder here.
"""

import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from . import build, cache, guide, resolve
from .banner import parse

logger = logging.getLogger("rowanholt.symbols")

VOL = "/usr/local/bin/vol.py"


def _vol(image: Path, plugin: str) -> str:
    vol = VOL if Path(VOL).exists() else "vol"
    proc = subprocess.run([vol, "-q", "-f", str(image), plugin], capture_output=True)
    return proc.stdout.decode("utf-8", errors="replace")


def _banners(image: Optional[Path], banner: Optional[str]) -> List[str]:
    return [banner] if banner else resolve.banners_from(_vol(image, "banners.Banners"))


def fetch(image: Optional[Path], banner: Optional[str]) -> int:
    """Resolve the image's (or the given) banner; for a Windows image, have Volatility fetch
    and keep its PDB."""
    banners = _banners(image, banner)
    if not banners:
        logger.info("No Linux or macOS kernel banner in %s; trying it as Windows", image)
        info = _vol(image, "windows.info.Info")
        if "NtBuildLab" in info or "ntkrnl" in info:
            logger.info("Windows: Volatility has its kernel's symbols (fetched from Microsoft's symbol server if they were new)")
            return 0
        logger.error("Neither a Linux or macOS banner nor a Windows kernel found in %s", image)
        return 1
    # Most often seen first: the image's own kernel. The first that resolves is the one
    for text in banners[:3]:
        result = resolve.resolve(text, allow_downloads=True)
        (logger.info if result.ok else logger.warning)("%s: %s", result.status, result.message)
        if result.ok:
            return 0
    return 1


def what(image: Optional[Path], banner: Optional[str]) -> int:
    """For each kernel in the image: whether Rowanholt has its table, else what to get."""
    banners = _banners(image, banner)
    if not banners:
        logger.info("No Linux or macOS kernel banner: Windows needs nothing (Volatility fetches its PDB)")
        return 0
    for text in banners:
        kernel = parse(text)
        if kernel is None:
            continue
        entry = cache.find(kernel.os, kernel.banner)
        if entry:
            logger.info("%s: Rowanholt has its table (%s)", kernel.release, entry["file"])
        else:
            logger.info("%s (%s, %s): rowanholt symbols fetch tries the prebuilt collection and the "
                        "distribution's debug package first. Where that can't work, get %s",
                        kernel.release, kernel.distro, kernel.arch, guide.what_to_get(kernel))
    return 0


def _banner_in(path: Path) -> str:
    """The Linux banner compiled into a vmlinux (its linux_banner string)."""
    data = path.read_bytes()
    at = data.find(b"Linux version ")
    if at < 0:
        return ""
    return data[at:data.find(b"\n", at)].decode("utf-8", errors="replace")


def _index(os_name: str, table: Path, source: str, expected: Optional[str] = None) -> int:
    banner = resolve.table_banner(table)
    if not parse(banner):
        logger.error("%s doesn't hold a kernel banner, so Rowanholt can't index it", table.name)
        return 1
    if expected and resolve.sources.normalise_banner(expected) != banner:
        logger.warning("%s serves a different kernel from the one asked for:\n  table: %s\n  asked: %s",
                       table.name, banner, expected)
    entry = cache.add(os_name, banner, table, source)
    cache.log(os_name, f"symbols added {table.name} (sha256 {entry['sha256']}) from {source}")
    logger.info("Added %s for: %s", table.name, banner)
    return 0


def _linux_from_vmlinux(vmlinux: Path, system_map: Optional[Path], source: str) -> int:
    found = parse(_banner_in(vmlinux))
    target = cache.symbols_root() / "linux" / f"{found.name if found else vmlinux.name}.json.xz"
    logger.info("Building a table from %s (a few minutes)", vmlinux.name)
    build.linux_table(vmlinux, target, system_map)
    return _index("linux", target, source)


def add_package(package: Path) -> int:
    """A kernel's debug package (.ddeb, .deb or .rpm) unpacked for its vmlinux and built."""
    kind = build.package_kind(package)
    with tempfile.TemporaryDirectory(prefix="rowanholt-symbols-") as tmp:
        vmlinux = build.extract_vmlinux(package, kind, "", Path(tmp))
        return _linux_from_vmlinux(vmlinux, None, f"built ({package.name})")


def add_kdk(kdk: Path, kernel: Optional[str], banner: Optional[str]) -> int:
    """A table from a KDK folder: the kernel the banner names (or --kernel, or plain kernel)."""
    kernels = next((p for p in [kdk / "System" / "Library" / "Kernels", *kdk.glob("**/System/Library/Kernels")]
                    if p.is_dir()), None)
    name = kernel or (guide.kdk_kernel(banner) if banner else "kernel")
    options = sorted(p.name for p in kernels.iterdir() if p.is_file()) if kernels else []
    if not kernels or name not in options:
        logger.error("No %s in the KDK at %s; it has: %s", name, kdk, ", ".join(options) or "no kernels")
        return 1
    dwarf = kernels / f"{name}.dSYM" / "Contents" / "Resources" / "DWARF" / name
    if not dwarf.is_file():
        logger.error("The KDK has %s but not its debug info (%s)", name, dwarf)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        logger.info("Building a table from the KDK's %s (a few minutes)", name)
        built = build.mac_table(dwarf, kernels / name, Path(tmp) / "kdk.json.xz")
        found = parse(resolve.table_banner(built))
        target = cache.symbols_root() / "mac" / f"{found.name if found else kdk.name}.json.xz"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(built), target)
    return _index("mac", target, "built (KDK)", banner)


def add_table(table: Path) -> int:
    """A ready table copied in and indexed."""
    os_name = "mac" if "Darwin" in resolve.table_banner(table) else "linux"
    target = cache.symbols_root() / os_name / table.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(table, target)
    return _index(os_name, target, "added")


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
    for name, text in (("fetch", "the table for an image's kernel, or a banner's"),
                       ("what", "what to get for an image's kernel when it can't be fetched")):
        p = sub.add_parser(name, help=text)
        p.add_argument("image", nargs="?", type=Path)
        p.add_argument("--banner")
    a = sub.add_parser("add", help="build a table from a debug package, vmlinux or KDK, or add one")
    group = a.add_mutually_exclusive_group(required=True)
    group.add_argument("--package", type=Path, help="a kernel debug package: .ddeb, .deb or .rpm")
    group.add_argument("--vmlinux", type=Path)
    group.add_argument("--kdk", type=Path, help="a KDK folder (the launcher unpacks a .dmg or .pkg)")
    group.add_argument("--table", type=Path)
    a.add_argument("--system-map", type=Path)
    a.add_argument("--kernel", help="the KDK's kernel; default: the one --banner names, else kernel")
    a.add_argument("--banner", help="the image's banner, which picks the KDK kernel and is checked against the table")
    sub.add_parser("list", help="the tables Rowanholt has")
    args = parser.parse_args(argv)
    try:
        if args.command in ("fetch", "what"):
            if not args.image and not args.banner:
                parser.error(f"{args.command} needs an image or --banner")
            return (fetch if args.command == "fetch" else what)(args.image, args.banner)
        if args.command == "add":
            if args.package:
                return add_package(args.package)
            if args.vmlinux:
                return _linux_from_vmlinux(args.vmlinux, args.system_map, "built (vmlinux)")
            if args.kdk:
                return add_kdk(args.kdk, args.kernel, args.banner)
            return add_table(args.table)
        return listing()
    except (build.BuildError, OSError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

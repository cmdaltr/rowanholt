"""Fetching a source's file and turning it into a Volatility 3 symbol table.

A download is checked against the hash its publisher gives before anything opens it. A debug
package is unpacked (dpkg-deb, rpm2cpio | cpio) only for its vmlinux, which dwarf2json turns
into an ISF; macOS tables are built from a Kernel Debug Kit the analyst brings.
"""

import hashlib
import logging
import lzma
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

from .sources import TIMEOUT, USER_AGENT, Download, SourceError

logger = logging.getLogger(__name__)

DWARF2JSON = "dwarf2json"
BUILD_TIMEOUT = 3600


class BuildError(Exception):
    """A download that failed its check, or a package or tool that didn't give a table."""


def download(item: Download, folder: Path) -> Path:
    """Fetch the file into folder, hashing as it comes; a mismatch deletes it and raises."""
    if not item.url.startswith("https://"):
        raise SourceError(f"Not HTTPS: {item.url}")
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / (item.name or item.url.rsplit("/", 1)[-1])
    part = target.with_name(target.name + ".part")
    digest = hashlib.new(item.algorithm)
    request = urllib.request.Request(item.url, headers={"User-Agent": USER_AGENT})
    logger.info("Fetching %s (%s)", item.url, f"{item.size:,} bytes" if item.size else "size not given")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response, open(part, "wb") as out:
        if not response.geturl().startswith("https://"):
            raise SourceError(f"Redirected off HTTPS: {response.geturl()}")
        for block in iter(lambda: response.read(1 << 20), b""):
            digest.update(block)
            out.write(block)
    if digest.hexdigest().lower() != item.digest.lower():
        part.unlink()
        raise BuildError(f"{target.name}: {item.algorithm} {digest.hexdigest()} is not the published {item.digest}")
    part.replace(target)
    return target


def _run(args, **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, check=True, capture_output=True, timeout=BUILD_TIMEOUT, **kwargs)
    except FileNotFoundError:
        raise BuildError(f"{args[0]} isn't installed")
    except subprocess.CalledProcessError as exc:
        raise BuildError(f"{args[0]} failed: {exc.stderr.decode(errors='replace').strip()[-500:]}")
    except subprocess.TimeoutExpired:
        raise BuildError(f"{args[0]} took over {BUILD_TIMEOUT // 60} minutes")


def _find_vmlinux(root: Path, release: str) -> Path:
    # Ubuntu and Debian: usr/lib/debug/boot/vmlinux-<release>; RPMs and Debian's other copy:
    # usr/lib/debug/lib/modules/<release>/vmlinux
    for candidate in (root / "usr/lib/debug/boot" / f"vmlinux-{release}",
                      root / "usr/lib/debug/lib/modules" / release / "vmlinux"):
        if candidate.is_file():
            return candidate
    found = sorted(p for p in root.rglob("vmlinux*") if p.is_file() and release in str(p))
    if not found:
        raise BuildError(f"no vmlinux for {release} in the package")
    return found[0]


def extract_vmlinux(package: Path, kind: str, release: str, workdir: Path) -> Path:
    """The kernel's vmlinux (with its DWARF) out of a .deb/.ddeb or an .rpm."""
    unpacked = workdir / "unpacked"
    unpacked.mkdir(parents=True, exist_ok=True)
    if kind == "deb":
        _run(["dpkg-deb", "-x", str(package), str(unpacked)])
    elif kind == "rpm":
        payload = _run(["rpm2cpio", str(package)]).stdout
        _run(["cpio", "-idm", "--quiet", "--no-absolute-filenames", "*vmlinux*"], input=payload, cwd=unpacked)
    else:
        raise BuildError(f"can't unpack a {kind}")
    return _find_vmlinux(unpacked, release)


def _write_xz(json_bytes: bytes, table: Path) -> Path:
    table.parent.mkdir(parents=True, exist_ok=True)
    tmp = table.with_name(table.name + ".tmp")
    with lzma.open(tmp, "wb") as out:
        out.write(json_bytes)
    tmp.replace(table)
    return table


def linux_table(vmlinux: Path, table: Path, system_map: Optional[Path] = None) -> Path:
    """An ISF (.json.xz) from a vmlinux, and System.map when there is one."""
    args = [DWARF2JSON, "linux", "--elf", str(vmlinux)]
    if system_map:
        args += ["--system-map", str(system_map)]
    return _write_xz(_run(args).stdout, table)


def mac_table(kernel_dwarf: Path, kernel: Path, table: Path) -> Path:
    """An ISF from a KDK: the kernel's dSYM DWARF file and the kernel itself."""
    return _write_xz(_run([DWARF2JSON, "mac", "--macho", str(kernel_dwarf), "--macho-symbols", str(kernel)]).stdout, table)


def table_from(item: Download, release: str, table: Path) -> Path:
    """The source's file as a symbol table at table: a prebuilt one copied in, a debug package
    unpacked and converted. Working files go in a temporary folder that's always removed."""
    with tempfile.TemporaryDirectory(prefix="rowanholt-symbols-") as tmp:
        work = Path(tmp)
        fetched = download(item, work)
        if item.kind == "isf":
            try:
                with lzma.open(fetched) as fh:
                    fh.read(1)
            except lzma.LZMAError:
                raise BuildError(f"{fetched.name} isn't xz")
            table.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fetched, table)
            return table
        logger.info("Building a table for %s from %s", release, fetched.name)
        return linux_table(extract_vmlinux(fetched, item.kind, release, work), table)

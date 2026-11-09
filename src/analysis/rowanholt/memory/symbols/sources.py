"""Where a kernel's symbols come from, each with the hash its publisher gives for the file:

- Prebuilt: Abyss-W4tcher/volatility3-symbols, found by exact banner in its plain index, each
  file a GitHub release asset whose SHA-256 the releases API gives. Fetched, never bundled (the
  collection declares no licence).
- Ubuntu: the kernel's dbgsym .ddeb from Launchpad, SHA-256 from its binaryFileUrls.
- Debian: the -dbg .deb from snapshot.debian.org, by its SHA-1 (all the snapshot API gives).
- Rocky, Alma: kernel-debuginfo from the vault, SHA-256 from the repository's primary.xml.

Fedora, CentOS Stream and RHEL aren't fetched (Koji turns automated clients away and publishes no
file hash; RHEL needs a subscription), nor is macOS (Apple's Kernel Debug Kits need an Apple ID):
for those the analyst builds from files they bring (build.py).
"""

import gzip
import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .banner import Kernel

PREBUILT_INDEX = "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners_plain.json"
GITHUB_RELEASE = "https://api.github.com/repos/Abyss-W4tcher/volatility3-symbols/releases/tags/{tag}"
LAUNCHPAD_BINARIES = ("https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedBinaries"
                      "&binary_name={name}&exact_match=true&version={version}")
LAUNCHPAD_FILES = "https://api.launchpad.net/devel/ubuntu/+archive/primary/+binarypub/{id}?ws.op=binaryFileUrls&include_meta=true"
SNAPSHOT_FILES = "https://snapshot.debian.org/mr/binary/{name}/{version}/binfiles"
SNAPSHOT_FILE = "https://snapshot.debian.org/file/{sha1}"
VAULTS = {
    "rocky": "https://dl.rockylinux.org/vault/rocky/{point}/BaseOS/{arch}/debug/tree/",
    "alma": "https://vault.almalinux.org/{point}/BaseOS/debug/{arch}/",
}
USER_AGENT = "Rowanholt symbol resolver (https://github.com/cmdaltr/rowanholt)"
TIMEOUT = 60

# Fetching JSON or bytes; tests replace these
Fetch = Callable[[str], bytes]


class SourceError(Exception):
    """A source that doesn't have this kernel, or answered with something unexpected."""


@dataclass(frozen=True)
class Download:
    """A file to fetch and the hash its publisher gives for it."""
    url: str
    algorithm: str      # sha256, sha1
    digest: str
    kind: str           # isf (a ready symbol table), deb, rpm
    source: str         # prebuilt, ubuntu, debian, rocky, alma
    size: int = 0
    name: str = ""


def fetch(url: str) -> bytes:
    """GET over HTTPS (redirects followed), refusing anything else."""
    if not url.startswith("https://"):
        raise SourceError(f"Not HTTPS: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if not response.geturl().startswith("https://"):
            raise SourceError(f"Redirected off HTTPS: {response.geturl()}")
        return response.read()


def _json(url: str, get: Fetch) -> object:
    try:
        return json.loads(get(url))
    except ValueError as exc:
        raise SourceError(f"{url}: not JSON ({exc})")


def normalise_banner(banner: str) -> str:
    """A banner as an index keys it: no trailing NUL or newline."""
    return banner.replace("\x00", "").strip()


def prebuilt(kernel: Kernel, get: Fetch = fetch, index: Optional[Dict[str, List[str]]] = None) -> Download:
    """The collection's table for exactly this banner, with its release asset's SHA-256."""
    index = index if index is not None else _json(PREBUILT_INDEX, get)
    wanted = normalise_banner(kernel.banner)
    urls = next((u for b, u in index.items() if normalise_banner(b) == wanted), None)
    if not urls:
        raise SourceError("not in the prebuilt collection")
    url = urls[0]
    match = re.search(r"/releases/download/([^/]+)/([^/]+)$", url)
    if not match:
        raise SourceError(f"unexpected prebuilt location {url}")
    tag, name = urllib.parse.unquote(match.group(1)), urllib.parse.unquote(match.group(2))
    release = _json(GITHUB_RELEASE.format(tag=urllib.parse.quote(tag)), get)
    asset = next((a for a in release.get("assets", []) if a.get("name") == name), None)
    digest = (asset or {}).get("digest") or ""
    if not digest.startswith("sha256:"):
        raise SourceError(f"no published SHA-256 for {name}")
    return Download(url, "sha256", digest.split(":", 1)[1], "isf", "prebuilt", asset.get("size", 0), name)


def ubuntu(kernel: Kernel, get: Fetch = fetch) -> Download:
    """The dbgsym .ddeb for the kernel (linux-image-unsigned-<release>-dbgsym, or the older
    linux-image-<release>-dbgsym), for the banner's architecture."""
    arch = "amd64" if kernel.arch == "x86_64" else "arm64"
    for name in (f"linux-image-unsigned-{kernel.release}-dbgsym", f"linux-image-{kernel.release}-dbgsym"):
        url = LAUNCHPAD_BINARIES.format(name=urllib.parse.quote(name), version=urllib.parse.quote(kernel.package_version))
        published = [e for e in _json(url, get).get("entries", [])
                     if e.get("distro_arch_series_link", "").endswith(f"/{arch}") and e.get("status") != "Deleted"]
        if not published:
            continue
        pub_id = published[0]["self_link"].rstrip("/").rsplit("/", 1)[-1]
        for f in _json(LAUNCHPAD_FILES.format(id=pub_id), get):
            if f.get("url", "").endswith(".ddeb") and f.get("sha256"):
                return Download(f["url"], "sha256", f["sha256"], "deb", "ubuntu", f.get("size", 0),
                                f["url"].rsplit("/", 1)[-1])
    raise SourceError(f"Launchpad has no dbgsym for {kernel.release} {kernel.package_version} ({arch})")


def debian(kernel: Kernel, get: Fetch = fetch) -> Download:
    """linux-image-<release>-dbg at the banner's version, from snapshot.debian.org."""
    arch = "amd64" if kernel.arch == "x86_64" else "arm64"
    name = f"linux-image-{kernel.release}-dbg"
    files = _json(SNAPSHOT_FILES.format(name=name, version=urllib.parse.quote(kernel.package_version)), get)
    sha1 = next((f["hash"] for f in files.get("result", []) if f.get("architecture") == arch), None)
    if not sha1:
        raise SourceError(f"snapshot.debian.org has no {name} {kernel.package_version} ({arch})")
    return Download(SNAPSHOT_FILE.format(sha1=sha1), "sha1", sha1, "deb", "debian",
                    name=f"{name}_{kernel.package_version}_{arch}.deb")


def rpm_vault(kernel: Kernel, get: Fetch = fetch) -> Download:
    """kernel-debuginfo for a Rocky or Alma kernel, from its point release's vault, by the
    SHA-256 its repository's primary.xml gives."""
    if kernel.distro not in VAULTS or "." not in kernel.point_release:
        raise SourceError(f"no vault for {kernel.distro} {kernel.point_release or '(no point release)'}")
    base = VAULTS[kernel.distro].format(point=kernel.point_release, arch=kernel.arch)
    ns = {"r": "http://linux.duke.edu/metadata/repo", "c": "http://linux.duke.edu/metadata/common"}
    repomd = ET.fromstring(get(base + "repodata/repomd.xml"))
    location = repomd.find("r:data[@type='primary']/r:location", ns)
    if location is None:
        raise SourceError(f"{base}: no primary metadata")
    primary = ET.fromstring(gzip.decompress(get(base + location.get("href"))))
    wanted = f"kernel-debuginfo-{kernel.package_version}.{kernel.arch}.rpm"
    for package in primary.findall("c:package", ns):
        href = package.find("c:location", ns).get("href", "")
        if href.rsplit("/", 1)[-1] == wanted:
            checksum = package.find("c:checksum", ns)
            if checksum is None or checksum.get("type") != "sha256":
                raise SourceError(f"{wanted}: no SHA-256 in the repository's metadata")
            size = package.find("c:size", ns)
            return Download(base + href, "sha256", checksum.text.strip(), "rpm", kernel.distro,
                            int(size.get("package", 0)) if size is not None else 0, wanted)
    raise SourceError(f"{base} has no {wanted}")


def debug_package(kernel: Kernel, get: Fetch = fetch) -> Download:
    """The distribution's debug package for the kernel, or SourceError saying why there isn't one."""
    if kernel.distro == "ubuntu":
        return ubuntu(kernel, get)
    if kernel.distro == "debian":
        return debian(kernel, get)
    if kernel.distro in VAULTS:
        return rpm_vault(kernel, get)
    reasons = {
        "fedora": "Fedora's build system turns automated clients away and publishes no file hash",
        "centos-stream": "CentOS Stream's debug packages aren't fetched automatically",
        "rhel": "RHEL's debug packages need a Red Hat subscription",
        "macos": "Apple's Kernel Debug Kits need an Apple ID sign-in",
    }
    raise SourceError(reasons.get(kernel.distro, f"no known source for a {kernel.distro} kernel"))

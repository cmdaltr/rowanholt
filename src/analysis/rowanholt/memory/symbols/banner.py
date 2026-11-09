"""What a memory image's kernel banner says: the OS, the exact kernel build, the distribution
that built it and the architecture, which is what finding its debug symbols needs.

    Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc ...) #101-Ubuntu SMP ...
    Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) ... Debian 6.1.76-1 (2024-02-01)
    Linux version 5.14.0-362.8.1.el9_3.x86_64 (mockbuild@iad1-prod-build001.bld.equ.rockylinux.org) ...
    Darwin Kernel Version 21.6.0: ... root:xnu-8020.140.41~1/RELEASE_X86_64
"""

import re
from dataclasses import dataclass
from typing import Optional

LINUX = re.compile(r"Linux version (?P<release>\S+) \((?P<builder>[^)]*)\)")
DARWIN = re.compile(r"Darwin Kernel Version (?P<release>[\d.]+).*?xnu-(?P<xnu>[\w.~-]+)/RELEASE_(?P<arch>\w+)")
UBUNTU_BUILD = re.compile(r"#(?P<build>\d+(?:~[\d.]+)?)-Ubuntu\b")
DEBIAN_VERSION = re.compile(r"\bDebian (?P<version>\d[\w.+~-]*)")
EL_RELEASE = re.compile(r"\.el(?P<major>\d+)(?:_(?P<minor>\d+))?")
FEDORA_RELEASE = re.compile(r"\.fc(?P<major>\d+)")
# Which RPM distribution built an .elN kernel, from the build host in the banner
RPM_BUILDERS = (("rockylinux.org", "rocky"), ("almalinux.org", "alma"), ("centos.org", "centos-stream"),
                ("redhat.com", "rhel"), ("oracle.com", "oracle"))


@dataclass(frozen=True)
class Kernel:
    """One kernel build, as its banner gives it."""
    os: str                        # linux, mac
    release: str                   # uname -r: 5.15.0-91-generic, 6.1.0-18-amd64, 5.14.0-362.8.1.el9_3.x86_64
    distro: str                    # ubuntu, debian, rocky, alma, centos-stream, rhel, oracle, fedora, unknown; macos
    arch: str                      # x86_64, aarch64
    package_version: str = ""      # the debug package's version: 5.15.0-91.101, 6.1.76-1; xnu build on macOS
    point_release: str = ""        # 9.3 for .el9_3; Fedora's 39; "" when the banner doesn't say
    banner: str = ""

    @property
    def name(self) -> str:
        """A file name for its symbol table: ubuntu-5.15.0-91-generic-x86_64."""
        return f"{self.distro}-{self.release}-{self.arch}".replace("/", "_")


def _arch(text: str) -> str:
    if re.search(r"aarch64|arm64", text):
        return "aarch64"
    return "x86_64"


def parse(banner: str) -> Optional[Kernel]:
    """The kernel a banner describes, or None when it isn't a Linux or Darwin banner."""
    banner = banner.strip()
    darwin = DARWIN.search(banner)
    if darwin:
        arch = "aarch64" if darwin.group("arch").upper().startswith("ARM") else "x86_64"
        return Kernel("mac", darwin.group("release"), "macos", arch, package_version=darwin.group("xnu"), banner=banner)
    linux = LINUX.search(banner)
    if not linux:
        return None
    release, builder = linux.group("release"), linux.group("builder")
    arch = _arch(release + " " + builder)

    ubuntu = UBUNTU_BUILD.search(banner)
    if ubuntu:
        # 5.15.0-91-generic built as #101: package 5.15.0-91.101; HWE #50~20.04.1: 5.8.0-44.50~20.04.1
        abi = re.match(r"(\d+\.\d+\.\d+-\d+)", release)
        version = f"{abi.group(1)}.{ubuntu.group('build')}" if abi else ""
        return Kernel("linux", release, "ubuntu", arch, version, banner=banner)

    # The kernel's version comes last: an earlier "Debian 12.2.0-14" is the compiler's
    debian = DEBIAN_VERSION.findall(banner.split("#", 1)[-1])
    if debian and "debian" in builder.lower():
        return Kernel("linux", release, "debian", arch, debian[-1], banner=banner)

    fedora = FEDORA_RELEASE.search(release)
    if fedora:
        return Kernel("linux", release, "fedora", arch, release.rsplit(".", 1)[0], fedora.group("major"), banner=banner)

    el = EL_RELEASE.search(release)
    if el:
        distro = next((name for domain, name in RPM_BUILDERS if domain in builder), "unknown")
        point = f"{el.group('major')}.{el.group('minor')}" if el.group("minor") else el.group("major")
        return Kernel("linux", release, distro, arch, release.rsplit(".", 1)[0], point, banner=banner)

    return Kernel("linux", release, "unknown", arch, banner=banner)

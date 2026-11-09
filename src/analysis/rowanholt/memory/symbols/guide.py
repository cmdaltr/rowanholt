"""What the analyst has to get when Rowanholt can't fetch a kernel's symbols itself: the exact
file, where it's published, and the one command that turns it into a table.
"""

import re
from .banner import Kernel
from .sources import VAULTS

DARWIN_ARCH = re.compile(r"RELEASE_(?P<arch>\w+)")


def macos_version(darwin: str) -> str:
    """The macOS release a Darwin version belongs to: 23.4.0 is 14.4, 19.6.0 is 10.15.6, and
    Darwin 25 is macOS 26 (Apple's numbering jumped)."""
    parts = [int(p) for p in darwin.split(".")[:3] if p.isdigit()]
    if not parts:
        return ""
    major = parts[0]
    minor = parts[1] if len(parts) > 1 else 0
    if major >= 25:
        return f"{major + 1}.{minor}"
    if major >= 20:
        return f"{major - 9}.{minor}"
    if major >= 4:
        return f"10.{major - 4}.{minor}"
    return ""


def kdk_kernel(banner: str) -> str:
    """The KDK kernel that matches a banner: kernel for RELEASE_X86_64, kernel.release.t6000 for
    RELEASE_ARM64_T6000 (and the like), kernel.release.vmapple for a virtual machine."""
    match = DARWIN_ARCH.search(banner)
    if not match or match.group("arch").upper() == "X86_64":
        return "kernel"
    soc = match.group("arch").split("_", 1)[-1].lower()
    return f"kernel.release.{soc}"


def _deb_arch(kernel: Kernel) -> str:
    return "amd64" if kernel.arch == "x86_64" else "arm64"


def what_to_get(kernel: Kernel) -> str:
    """Instructions for this kernel: the file to get, where from, and the command that adds it."""
    package = "rowanholt symbols add --package <the file>"
    if kernel.os == "mac":
        version = macos_version(kernel.release)
        return (f"the Kernel Debug Kit for macOS {version or '(Darwin ' + kernel.release + ')'}, the one for its exact "
                f"build (this kernel is Darwin {kernel.release}, xnu-{kernel.package_version}), from "
                "https://developer.apple.com/download/all/ (search 'Kernel Debug Kit'; an Apple ID sign-in). "
                f"Then, on the Mac: rowanholt symbols add --kdk <the .dmg> --kernel {kdk_kernel(kernel.banner)}")
    if kernel.distro == "ubuntu":
        name = f"linux-image-unsigned-{kernel.release}-dbgsym_{kernel.package_version}_{_deb_arch(kernel)}.ddeb"
        return (f"{name} from https://launchpad.net/ubuntu/+archive/primary/+files/{name} (older kernels: "
                f"linux-image-{kernel.release}-dbgsym). Then: {package}")
    if kernel.distro == "debian":
        return (f"linux-image-{kernel.release}-dbg {kernel.package_version} ({_deb_arch(kernel)}) from "
                f"https://snapshot.debian.org/binary/linux-image-{kernel.release}-dbg/. Then: {package}")
    rpm = f"kernel-debuginfo-{kernel.package_version}.{kernel.arch}.rpm"
    if kernel.distro in VAULTS and "." in kernel.point_release:
        base = VAULTS[kernel.distro].format(point=kernel.point_release, arch=kernel.arch)
        where = base + ("Packages/k/" if kernel.distro == "rocky" else "Packages/")
        return f"{rpm} from {where}{rpm}. Then: {package}"
    if kernel.distro == "fedora":
        version, _, release = kernel.package_version.partition("-")
        return (f"{rpm} from https://kojipkgs.fedoraproject.org/packages/kernel/{version}/{release}/{kernel.arch}/{rpm} "
                f"(a browser: Koji checks for one). Then: {package}")
    if kernel.distro == "centos-stream":
        major = kernel.point_release.split(".")[0]
        return (f"{rpm} from https://mirror.stream.centos.org/{major}-stream/BaseOS/{kernel.arch}/debug/tree/Packages/{rpm} "
                f"(an older build may only be on a mirror's archive). Then: {package}")
    if kernel.distro == "rhel":
        return (f"{rpm}, on a RHEL host with a subscription: dnf download --enablerepo='*debug*' "
                f"kernel-debuginfo-{kernel.package_version}. Then: {package}")
    if kernel.distro == "oracle":
        major = kernel.point_release.split(".")[0]
        return f"{rpm} from https://oss.oracle.com/ol{major}/debuginfo/{rpm}. Then: {package}"
    return (f"the debug symbols for {kernel.release} from whoever built it: its debug package, or the vmlinux with "
            "debug info from the build. Then: rowanholt symbols add --package <file>, or --vmlinux <file>")


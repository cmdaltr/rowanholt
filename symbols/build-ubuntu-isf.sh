#!/bin/bash
# Build a Volatility 3 ISF for an Ubuntu kernel from its dbgsym package, in a throwaway
# container, into symbols/linux/. Defaults to the kernel of the test image
# 5.8.0-44-generic.mem (banner: 5.8.0-44-generic #50~20.04.1-Ubuntu).
#
#   symbols/build-ubuntu-isf.sh [kernel] [package version] [source package] [scratch dir]
#   symbols/build-ubuntu-isf.sh 5.8.0-44-generic 5.8.0-44.50~20.04.1 linux-hwe-5.8
#
# Downloads about 1 GB (the ddeb) into the scratch directory; recreate the worker after.
set -euo pipefail

kernel="${1:-5.8.0-44-generic}"
version="${2:-5.8.0-44.50~20.04.1}"
source_package="${3:-linux-hwe-5.8}"
scratch="${4:-${TMPDIR:-/tmp}/rivendell-isf}"
here="$(cd "$(dirname "$0")" && pwd)"
ddeb="linux-image-unsigned-${kernel}-dbgsym_${version}_amd64.ddeb"
url="http://ddebs.ubuntu.com/pool/main/l/${source_package}/${ddeb}"
# ddebs.ubuntu.com drops old kernels; Launchpad keeps every published ddeb
fallback="https://launchpad.net/ubuntu/+archive/primary/+files/${ddeb}"

mkdir -p "$scratch" "$here/linux"
docker run --rm -v "$scratch:/work" -v "$here/linux:/out" -e URL="$url" -e FALLBACK="$fallback" -e DDEB="$ddeb" -e KERNEL="$kernel" \
    golang:1.22 bash -euo pipefail -c '
        apt-get -qq update >/dev/null && apt-get -qq install -y xz-utils >/dev/null
        cd /work
        [ -s "$DDEB" ] || wget -nv -O "$DDEB" "$URL" || wget -nv -O "$DDEB" "$FALLBACK" || \
            { rm -f "$DDEB"; echo "download failed: $URL and $FALLBACK" >&2; exit 1; }
        rm -rf x && mkdir x && dpkg-deb -x "$DDEB" x
        vmlinux=$(find x -name "vmlinux-$KERNEL" | head -1)
        [ -n "$vmlinux" ] || { echo "no vmlinux-$KERNEL in $DDEB" >&2; exit 1; }
        GOBIN=/work/bin go install github.com/volatilityfoundation/dwarf2json@latest
        /work/bin/dwarf2json linux --elf "$vmlinux" | xz -T0 > "/out/ubuntu-$KERNEL.json.xz"
        rm -rf x
    '
ls -lh "$here/linux/ubuntu-${kernel}.json.xz"
echo "Recreate the worker so Volatility sees it, then rerun linux_memory."

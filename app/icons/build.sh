#!/usr/bin/env bash
# Regenerate the app icons (rivendell.icns, rivendell.ico, rivendell.png) from the logo.
# macOS only (swift, sips, iconutil); the outputs are committed so the installers need none of it.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

swift "$HERE/make-icon.swift" "$ROOT/docs/images/rivendell.png" "$WORK/icon-1024.png"

ICONSET="$WORK/rivendell.iconset"
mkdir "$ICONSET"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$WORK/icon-1024.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$WORK/icon-1024.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$HERE/rivendell.icns"

sips -z 512 512 "$WORK/icon-1024.png" --out "$HERE/rivendell.png" >/dev/null

# ICO with PNG-compressed entries (Vista onwards reads these at every size)
for size in 16 24 32 48 64 128 256; do
    sips -z "$size" "$size" "$WORK/icon-1024.png" --out "$WORK/ico-$size.png" >/dev/null
done
python3 - "$WORK" "$HERE/rivendell.ico" <<'EOF'
import struct, sys
from pathlib import Path

work, out = Path(sys.argv[1]), Path(sys.argv[2])
sizes = [16, 24, 32, 48, 64, 128, 256]
images = [(work / f"ico-{s}.png").read_bytes() for s in sizes]
header = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
entries = b""
for size, data in zip(sizes, images):
    dim = 0 if size == 256 else size
    entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
out.write_bytes(header + entries + b"".join(images))
EOF

echo "Icons written to $HERE"

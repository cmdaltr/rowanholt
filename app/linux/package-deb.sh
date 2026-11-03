#!/usr/bin/env bash
# Release package for Debian and Ubuntu: rivendell_<version>_all.deb, installing the
# launcher, icon and source tree under /opt/rivendell and the menu entry system-wide.
# Double-clicking it opens the distribution's software installer.
# Usage: package-deb.sh --version V --source rivendell-src.tar.gz <out-dir>
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VERSION=""
SOURCE=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift ;;
        --source) SOURCE="$2"; shift ;;
        *) OUT="$1" ;;
    esac
    shift
done
[ -n "$VERSION" ] && [ -f "$SOURCE" ] && [ -n "$OUT" ] || {
    echo "usage: package-deb.sh --version V --source rivendell-src.tar.gz <out-dir>" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "Error: dpkg-deb not found (build on Debian or Ubuntu)." >&2; exit 1; }
mkdir -p "$OUT"

# Debian versions can't contain '-' in the upstream part without a revision; 1.4.0-rc1 → 1.4.0~rc1
DEB_VERSION="$(printf '%s' "$VERSION" | tr - '~')"
PKG="$(mktemp -d)/rivendell"
trap 'rm -rf "$(dirname "$PKG")"' EXIT
OPT="$PKG/opt/rivendell"
mkdir -p "$PKG/DEBIAN" "$OPT" "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/512x512/apps"

install -m 755 "$HERE/rivendell-app.sh" "$OPT/rivendell-app.sh"
install -m 644 "$SOURCE" "$OPT/rivendell-src.tar.gz"
install -m 644 "$ROOT/app/icons/rivendell.png" "$OPT/rivendell.png"
install -m 644 "$ROOT/app/icons/rivendell.png" "$PKG/usr/share/icons/hicolor/512x512/apps/rivendell.png"
echo "$VERSION" > "$OPT/VERSION"
"$HERE/desktop-entry.sh" /opt/rivendell/rivendell-app.sh > "$PKG/usr/share/applications/rivendell.desktop"

cat > "$PKG/DEBIAN/control" <<EOF
Package: rivendell
Version: $DEB_VERSION
Section: utils
Priority: optional
Architecture: all
Maintainer: cmdaltr <cmdaltr@users.noreply.github.com>
Homepage: https://github.com/cmdaltr/rivendell
Depends: bash, curl, tar, gzip, xdg-utils
Recommends: zenity, libnotify-bin
Suggests: docker.io, docker-compose-v2
Description: Rivendell DFIR platform (desktop launcher)
 Gandalf acquires, Elrond analyses and Eru answers. This package adds Rivendell to
 the application menu: on first launch it checks for Docker, puts Rivendell's files
 in a folder you choose, and opens the web UI in its own window.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
EOF
cp "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/postrm"
chmod 755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$PKG" "$OUT/rivendell_${DEB_VERSION}_all.deb"

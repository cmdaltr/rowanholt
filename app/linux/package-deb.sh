#!/usr/bin/env bash
# Release package for Debian and Ubuntu: rowanholt_<version>-1_all.deb, installing the
# launcher, icon and source tree under /opt/rowanholt and the menu entry system-wide.
# Double-clicking it opens the distribution's software installer.
# Usage: package-deb.sh --version V --source rowanholt-src.tar.gz <out-dir>
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
    echo "usage: package-deb.sh --version V --source rowanholt-src.tar.gz <out-dir>" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "Error: dpkg-deb not found (build on Debian or Ubuntu)." >&2; exit 1; }
mkdir -p "$OUT"

# Debian versions can't contain '-' in the upstream part without a revision; 1.4.0-rc1 → 1.4.0~rc1
DEB_VERSION="$(printf '%s' "$VERSION" | tr - '~')"
PKG="$(mktemp -d)/rowanholt"
trap 'rm -rf "$(dirname "$PKG")"' EXIT
OPT="$PKG/opt/rowanholt"
mkdir -p "$PKG/DEBIAN" "$OPT" "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/512x512/apps" \
    "$PKG/usr/share/doc/rowanholt"

install -m 755 "$HERE/rowanholt-app.sh" "$OPT/rowanholt-app.sh"
install -m 644 "$SOURCE" "$OPT/rowanholt-src.tar.gz"
install -m 644 "$ROOT/app/icons/rowanholt.png" "$OPT/rowanholt.png"
install -m 644 "$ROOT/app/icons/rowanholt.png" "$PKG/usr/share/icons/hicolor/512x512/apps/rowanholt.png"
echo "$VERSION" > "$OPT/VERSION"
# The licence where Debian keeps one (/usr/share/doc/<package>/copyright), and beside the launcher:
# the terms ship with the package, so using it is accepting them (README)
install -m 644 "$ROOT/LICENSE" "$PKG/usr/share/doc/rowanholt/copyright"
install -m 644 "$ROOT/LICENSE" "$OPT/LICENSE"
# desktop/install.sh and desktop/uninstall.sh (the release installer, not app/linux/install.sh) side by side, so an installed copy can upgrade (--clean) or remove itself
install -m 755 "$ROOT/desktop/install.sh" "$ROOT/desktop/uninstall.sh" "$OPT/"
"$HERE/desktop-entry.sh" /opt/rowanholt/rowanholt-app.sh > "$PKG/usr/share/applications/rowanholt.desktop"

cat > "$PKG/DEBIAN/control" <<EOF
Package: rowanholt
Version: $DEB_VERSION-1
Section: utils
Priority: optional
Architecture: all
Maintainer: cmdaltr <cmdaltr@users.noreply.github.com>
Homepage: https://github.com/cmdaltr/rowanholt
Depends: bash, curl, tar, gzip, xdg-utils
Recommends: zenity, libnotify-bin
Suggests: docker.io, docker-compose-v2
Description: Rowanholt DFIR platform (desktop launcher)
 Gandalf acquires, Elrond analyses and Aulë answers. This package adds Rowanholt to
 the application menu: on first launch it checks for Docker, puts Rowanholt's files
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

dpkg-deb --root-owner-group --build "$PKG" "$OUT/rowanholt_${DEB_VERSION}-1_all.deb"

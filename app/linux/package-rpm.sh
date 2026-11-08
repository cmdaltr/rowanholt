#!/usr/bin/env bash
# Release package for Rocky Linux, RHEL and Alma 9: rowanholt-<version>-1.noarch.rpm, the
# same files as the .deb (package-deb.sh): the launcher, icon and source tree under
# /opt/rowanholt and the menu entry system-wide. `sudo dnf install ./rowanholt-*.rpm`.
# Usage: package-rpm.sh --version V --source rowanholt-src.tar.gz <out-dir>
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
    echo "usage: package-rpm.sh --version V --source rowanholt-src.tar.gz <out-dir>" >&2; exit 1; }
command -v rpmbuild >/dev/null || { echo "Error: rpmbuild not found (dnf install rpm-build)." >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# RPM versions can't contain '-'; a tilde sorts before the release, as in the .deb: 1.4.0-rc1 → 1.4.0~rc1
RPM_VERSION="$(printf '%s' "$VERSION" | tr - '~')"
TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
STAGE="$TOP/stage"
mkdir -p "$TOP/SPECS" "$TOP/RPMS" "$STAGE/opt/rowanholt" "$STAGE/usr/share/applications" \
    "$STAGE/usr/share/icons/hicolor/512x512/apps"

install -m 755 "$HERE/rowanholt-app.sh" "$STAGE/opt/rowanholt/rowanholt-app.sh"
install -m 644 "$SOURCE" "$STAGE/opt/rowanholt/rowanholt-src.tar.gz"
install -m 644 "$ROOT/app/icons/rowanholt.png" "$STAGE/opt/rowanholt/rowanholt.png"
install -m 644 "$ROOT/app/icons/rowanholt.png" "$STAGE/usr/share/icons/hicolor/512x512/apps/rowanholt.png"
echo "$VERSION" > "$STAGE/opt/rowanholt/VERSION"
"$HERE/desktop-entry.sh" /opt/rowanholt/rowanholt-app.sh > "$STAGE/usr/share/applications/rowanholt.desktop"

# Docker Engine isn't in the distribution's repositories (it ships Podman), so the weak
# dependencies are on Docker's own packages: dnf skips them when Docker's repository isn't set up
cat > "$TOP/SPECS/rowanholt.spec" <<EOF
Name:           rowanholt
Version:        $RPM_VERSION
Release:        1
Summary:        DFIR platform: desktop launcher
License:        MIT
URL:            https://github.com/cmdaltr/rowanholt
BuildArch:      noarch
Requires:       bash, curl, tar, gzip, xdg-utils
Recommends:     zenity, libnotify, docker-ce, docker-compose-plugin

%global debug_package %{nil}
%global __brp_mangle_shebangs %{nil}

%description
Gandalf acquires, Elrond analyses and Eru answers. This package adds
Rowanholt to the application menu: on first launch it checks for Docker,
puts Rowanholt's files in a folder you choose, and opens the web UI in
its own window.

%install
cp -a "$STAGE"/. %{buildroot}/

%files
%dir /opt/rowanholt
/opt/rowanholt/rowanholt-app.sh
/opt/rowanholt/rowanholt-src.tar.gz
/opt/rowanholt/rowanholt.png
/opt/rowanholt/VERSION
/usr/share/applications/rowanholt.desktop
/usr/share/icons/hicolor/512x512/apps/rowanholt.png

%post
command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true

%postun
command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true

%changelog
* $(LC_ALL=C date -u '+%a %b %d %Y') cmdaltr <cmdaltr@users.noreply.github.com> - $RPM_VERSION-1
- Release $VERSION
EOF

rpmbuild --quiet --define "_topdir $TOP" -bb "$TOP/SPECS/rowanholt.spec"
cp "$TOP"/RPMS/noarch/rowanholt-*.noarch.rpm "$OUT/"
ls "$OUT"/rowanholt-"$RPM_VERSION"-1.noarch.rpm

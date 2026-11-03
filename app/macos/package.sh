#!/usr/bin/env bash
# Release package for macOS: Rivendell-<version>.dmg holding a universal Rivendell.app
# that carries the source tree. Signs and notarises when the environment has the means:
#   MACOS_SIGN_IDENTITY                          "Developer ID Application: ..." in the keychain
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD  notarytool credentials (an app-specific password)
# Without them the app is ad-hoc signed: it runs, but Gatekeeper makes users approve it in
# System Settings › Privacy & Security the first time.
# Usage: package.sh --version V --source rivendell-src.tar.gz <out-dir>
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
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
    echo "usage: package.sh --version V --source rivendell-src.tar.gz <out-dir>" >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

"$HERE/build.sh" --release --version "$VERSION" --source "$SOURCE" "$STAGE"
APP="$STAGE/Rivendell.app"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
    echo "Signing with $MACOS_SIGN_IDENTITY..."
    codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP"
    codesign --verify --strict "$APP"
fi

ln -s /Applications "$STAGE/Applications"
DMG="$OUT/Rivendell-$VERSION.dmg"
rm -f "$DMG"
hdiutil create -volname "Rivendell $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
    codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$DMG"
    if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
        echo "Notarising (this waits for Apple)..."
        xcrun notarytool submit "$DMG" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
            --password "$APPLE_APP_PASSWORD" --wait
        xcrun stapler staple "$DMG"
    else
        echo "Signed but not notarised: set APPLE_ID, APPLE_TEAM_ID and APPLE_APP_PASSWORD to notarise."
    fi
else
    echo "Ad-hoc signed: set MACOS_SIGN_IDENTITY to sign with a Developer ID."
fi
echo "Wrote $DMG"

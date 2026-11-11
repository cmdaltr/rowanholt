#!/usr/bin/env bash
# Build Rowanholt.app from Rowanholt.swift and Setup.swift.
#
#   build.sh [--dock] [dest-dir]     Local build for this checkout (the repo path goes into
#                                    Info.plist), installed into /Applications or ~/Applications
#   build.sh --uninstall [dest-dir]  Remove it
#   build.sh --release --version V --source rowanholt-src.tar.gz <dest-dir>
#                                    Release build: universal binary carrying the source tree,
#                                    which setup unpacks wherever the user chooses (package.sh)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ADD_TO_DOCK=false
UNINSTALL=false
RELEASE=false
VERSION=""
SOURCE=""
DEST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dock) ADD_TO_DOCK=true ;;
        --uninstall) UNINSTALL=true ;;
        --release) RELEASE=true ;;
        --version) VERSION="$2"; shift ;;
        --source) SOURCE="$2"; shift ;;
        -*) echo "Error: unknown option: $1" >&2; exit 1 ;;
        *) DEST="$1" ;;
    esac
    shift
done
if [ -z "$DEST" ]; then
    $RELEASE && { echo "Error: --release needs a destination directory" >&2; exit 1; }
    if [ -w /Applications ]; then DEST=/Applications; else DEST="$HOME/Applications"; fi
fi
APP="$DEST/Rowanholt.app"

if $UNINSTALL; then
    if [ -d "$APP" ]; then rm -rf "$APP"; echo "Removed $APP"; else echo "No Rowanholt.app in $DEST"; fi
    exit 0
fi

command -v swiftc >/dev/null || { echo "Error: swiftc not found; run 'xcode-select --install'." >&2; exit 1; }
if $RELEASE; then
    [ -f "$SOURCE" ] || { echo "Error: --release needs --source <rowanholt-src.tar.gz>" >&2; exit 1; }
    [ -n "$VERSION" ] || { echo "Error: --release needs --version" >&2; exit 1; }
fi

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/pyproject.toml" | head -1)"
    VERSION="${VERSION:-1.0.0}"
fi
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
BUNDLE="$BUILD/Rowanholt.app"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"

compile() {
    swiftc -O -swift-version 5 -parse-as-library -target "$1-apple-macos12.0" \
        -framework AppKit -framework WebKit \
        "$HERE/Rowanholt.swift" "$HERE/Setup.swift" -o "$2"
}

echo "Compiling Rowanholt.app..."
if $RELEASE; then
    compile arm64 "$BUILD/Rowanholt-arm64"
    compile x86_64 "$BUILD/Rowanholt-x86_64"
    lipo -create "$BUILD/Rowanholt-arm64" "$BUILD/Rowanholt-x86_64" -output "$BUNDLE/Contents/MacOS/Rowanholt"
    cp "$SOURCE" "$BUNDLE/Contents/Resources/rowanholt-src.tar.gz"
    BUNDLE_ID="io.github.cmdaltr.rowanholt"
    ROOT_ENTRY=""
else
    compile "$(uname -m)" "$BUNDLE/Contents/MacOS/Rowanholt"
    # Its own bundle ID, so a release install's chosen copy and logins don't leak into it
    BUNDLE_ID="io.github.cmdaltr.rowanholt.local"
    ROOT_XML="$(printf '%s' "$ROOT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"
    ROOT_ENTRY="<key>RowanholtRoot</key><string>$ROOT_XML</string>"
fi

cp "$ROOT/app/icons/rowanholt.icns" "$BUNDLE/Contents/Resources/Rowanholt.icns"
cp "$ROOT/docs/images/rowanholt-tm.png" "$BUNDLE/Contents/Resources/rowanholt.png"  # the logo, with its ™ (the icon stays plain)
cp "$HERE/setup.html" "$HERE/journey.html" "$BUNDLE/Contents/Resources/"
# The Elastic License travels with the app, as Shikari's does: Help › Licence shows it
cp "$ROOT/LICENSE" "$BUNDLE/Contents/Resources/LICENSE"
# desktop/install.sh and desktop/uninstall.sh (the release installer, not app/linux/install.sh) side by side, so an installed app can upgrade (--clean) or remove itself
cp "$ROOT/desktop/install.sh" "$ROOT/desktop/uninstall.sh" "$BUNDLE/Contents/Resources/"
# The journey's map: the Shire to the Misty Mountains, cut from the Middle-earth map
sips -c 300 520 --cropOffset 150 120 "$ROOT/docs/images/middle_earth.png" --out "$BUNDLE/Contents/Resources/journey.png" >/dev/null

cat > "$BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Rowanholt</string>
    <key>CFBundleDisplayName</key><string>Rowanholt</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleExecutable</key><string>Rowanholt</string>
    <key>CFBundleIconFile</key><string>Rowanholt</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>Rowanholt DFIR platform, @cmdaltr</string>
    <key>NSAppTransportSecurity</key>
    <dict><key>NSAllowsLocalNetworking</key><true/></dict>
    $ROOT_ENTRY
</dict>
</plist>
EOF

# Ad-hoc signature (package.sh re-signs release builds with a Developer ID when it has one).
# Files copied out of OneDrive carry xattrs codesign refuses to sign over.
xattr -cr "$BUNDLE"
codesign --force --sign - "$BUNDLE" 2>"$BUILD/codesign.log" || { cat "$BUILD/codesign.log" >&2; exit 1; }

mkdir -p "$DEST"
rm -rf "$APP"
cp -R "$BUNDLE" "$APP"
touch "$APP"  # nudge Finder and the Dock to pick up the icon
echo "Built $APP"
$RELEASE && exit 0

if $ADD_TO_DOCK; then
    if defaults read com.apple.dock persistent-apps 2>/dev/null | grep -q "Rowanholt.app"; then
        echo "Already in the Dock."
    else
        defaults write com.apple.dock persistent-apps -array-add \
            "<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>file://$APP/</string><key>_CFURLStringType</key><integer>15</integer></dict></dict></dict>"
        killall Dock
        echo "Added to the Dock."
    fi
else
    echo "Open it from Launchpad or Spotlight; right-click its Dock icon › Options › Keep in Dock to pin it."
fi

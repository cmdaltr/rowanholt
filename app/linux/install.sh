#!/usr/bin/env bash
# Install (or --uninstall) the Dernvale desktop entry and icon for the current user, so
# this checkout appears in the application menu and can be pinned to the dock (GNOME,
# KDE, XFCE, ...). The .deb (package-deb.sh) is the install for everyone else.
set -euo pipefail

HERE="$(cd -P "$(dirname "$0")" && pwd)"
ROOT="$(cd -P "$HERE/../.." && pwd)"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
DESKTOP="$DATA/applications/dernvale.desktop"
ICON="$DATA/icons/hicolor/512x512/apps/dernvale.png"

refresh() {
    command -v update-desktop-database &>/dev/null && update-desktop-database -q "$DATA/applications" || true
    command -v gtk-update-icon-cache &>/dev/null && gtk-update-icon-cache -q -t "$DATA/icons/hicolor" 2>/dev/null || true
}

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$DESKTOP" "$ICON"
    refresh
    echo "Removed the Dernvale desktop entry."
    exit 0
fi

command -v curl &>/dev/null || echo "Warning: curl isn't installed; the launcher needs it to see whether Dernvale is up." >&2

mkdir -p "$(dirname "$DESKTOP")" "$(dirname "$ICON")"
cp "$ROOT/app/icons/dernvale.png" "$ICON"
chmod +x "$HERE/dernvale-app.sh"
"$HERE/desktop-entry.sh" "$HERE/dernvale-app.sh" > "$DESKTOP"
chmod +x "$DESKTOP"
refresh

echo "Installed $DESKTOP"
echo "Find Dernvale in your application menu; right-click its dock icon to pin it."

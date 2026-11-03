#!/usr/bin/env bash
# Print rivendell.desktop for a launcher path: desktop-entry.sh <path-to-rivendell-app.sh>
# Exec arguments are quoted per the Desktop Entry spec, so a path with spaces works.
set -euo pipefail

HERE="$(cd -P "$(dirname "$0")" && pwd)"
quoted="\"$(printf '%s' "$1" | sed 's/\\/\\\\\\\\/g; s/"/\\\\"/g; s/`/\\\\`/g; s/\$/\\\\$/g')\""
# \, & and | are special in the replacement and delimiter of the sed below
quoted="$(printf '%s' "$quoted" | sed 's/[\\&|]/\\&/g')"
sed "s|@EXEC@|$quoted|g" "$HERE/rivendell.desktop.in"

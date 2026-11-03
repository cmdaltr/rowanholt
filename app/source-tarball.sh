#!/usr/bin/env bash
# Write the source tree release builds carry (git archive of HEAD, under rivendell/) to
# the given .tar.gz. Tracked files only, so .env and local state never ship.
set -euo pipefail

OUT="${1:?usage: source-tarball.sh <out.tar.gz>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
git -C "$ROOT" archive --format=tar.gz --prefix=rivendell/ -o "$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")" HEAD

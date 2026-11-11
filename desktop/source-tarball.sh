#!/usr/bin/env bash
# Write the source tree release builds carry to OUT: git archive of HEAD, so tracked files only,
# and .env and local state never ship; nor do .claude/ and tests/. A release publishes it as rowanholt-<version>-source.tar.gz
# beside the packages (as Shikari and Ostraka do); the packages carry it as rowanholt-src.tar.gz.
#
# Everything is under one top folder, rowanholt-<version>/, so unpacking never spills into the
# target directory; the launchers strip that one component (tar --strip-components 1), whatever
# its name. VERSION defaults to pyproject.toml's; CI passes its build's, e.g. 2.1.0-dev.57.
#
#   desktop/source-tarball.sh dist/rowanholt-2.1.0-source.tar.gz [VERSION]
set -euo pipefail

OUT="${1:?usage: source-tarball.sh <out.tar.gz> [version]}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${2:-$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/pyproject.toml" | head -1)}"
[ -n "$VERSION" ] || { echo "source-tarball.sh: no version given or in pyproject.toml" >&2; exit 1; }

# What a running install never uses, as Ostraka's leaves out: the agent's notes and the unit tests
exclude=(.claude tests)
pathspec=(.)
for p in "${exclude[@]}"; do pathspec+=(":(exclude)$p"); done

mkdir -p "$(dirname "$OUT")"
git -C "$ROOT" archive --format=tar.gz --prefix="rowanholt-$VERSION/" \
    -o "$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")" HEAD -- "${pathspec[@]}"

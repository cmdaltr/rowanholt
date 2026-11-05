#!/bin/bash
# Process one collected file with this checkout's Elrond and print what it cooks (no VMs, no full run)
#
#   rowanholt elrond process-one <case>/<host>/artefacts/raw/<path> [--os Windows|Linux|macOS] [--rows N] [--keep DIR]
#
# Runs src/analysis/process_one.py in a throwaway container from the worker image, with the checkout's
# src/analysis mounted over the image's, so a parser edit is tested without rebuilding the worker; the
# worker's tools (Artemis, RegRipper, Plaso) are there for the processors that need them. The case's
# raw/ is mounted read-only. Use any Elrond case on disk, e.g. a stacking-eval case's elrond/ folder.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${ROWANHOLT_WORKER_IMAGE:-rowanholt-celery-worker}"
[ $# -ge 1 ] || { sed -n '4p' "$0" | sed 's/^# *//'; exit 2; }

file="$1"; shift
# the launcher runs scripts from the checkout; a relative path was meant from where you typed it
case "$file" in /*) ;; *) file="${OLDPWD:-$PWD}/$file" ;; esac
[ -f "$file" ] || { echo "No such file: $file" >&2; exit 2; }
case "$file" in */artefacts/raw/*) ;; *) echo "Not under <case>/<host>/artefacts/raw/: $file" >&2; exit 2 ;; esac
raw="${file%%/artefacts/raw/*}/artefacts/raw"
keep=()
args=("$@")
for i in "${!args[@]}"; do
    if [ "${args[$i]}" = --keep ] && [ -n "${args[$((i + 1))]:-}" ]; then
        mkdir -p "${args[$((i + 1))]}"
        dir="$(cd "${args[$((i + 1))]}" && pwd)"
        args[$((i + 1))]="$dir"
        keep=(-v "$dir:$dir")
    fi
done

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "No $IMAGE image: ./rowanholt start builds it" >&2; exit 1; }
exec docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$ROOT/src/analysis:/opt/elrond-src:ro" -v "$raw:$raw:ro" ${keep[@]+"${keep[@]}"} \
    --entrypoint python3 "$IMAGE" /opt/elrond-src/process_one.py "$file" ${args[@]+"${args[@]}"}

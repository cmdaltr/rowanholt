#!/usr/bin/env bash
# Stop the Rowanholt team server that deploy/linux/install.sh (`rowanholt server init`) set up.
# Keeps data by default.
#
# Usage, as root or a member of the docker group:
#     deploy/linux/uninstall.sh [--dir DIR] [--purge [--yes]]
#     rowanholt server uninstall [--purge [--yes]]
#
# --purge also removes the stack's volumes (Postgres with every job, finding and note, Redis,
# Elastic, Splunk, the Navigator's layers, Caddy's certificates), .env with its secrets, and the
# backend's data folder (accounts, API tokens, the licence, webhooks, brands), after asking unless
# --yes is given. Case output and evidence folders are never touched, nor is the code in DIR.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PURGE=""
YES=""
PROJECT=rowanholt  # docker-compose.yml's name: the same project on a server as on a laptop

usage() { sed -n '2,13s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"; }
die() { printf 'uninstall.sh: %s\n' "$1" >&2; exit "${2:-1}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --dir) DIR=${2:?--dir needs a directory}; shift ;;
        --dir=*) DIR=${1#*=} ;;
        --purge) PURGE=1 ;;
        --yes|-y) YES=1 ;;
        *) die "unknown option '$1'. See --help." 2 ;;
    esac
    shift
done
DIR=${DIR%/}

[ -f "$DIR/docker-compose.yml" ] && [ -x "$DIR/rowanholt" ] || die "$DIR isn't a Rowanholt tree. Give --dir."
command -v docker >/dev/null 2>&1 || die "Docker isn't installed, so there's no stack to stop."
grep -q '^ROWANHOLT_DEPLOYMENT=server' "$DIR/.env" 2>/dev/null \
    || echo "    $DIR isn't marked as a server in .env; stopping its stack anyway"

confirm() {
    [ -z "$YES" ] || return 0
    # /dev/tty exists even without a terminal; opening it is what fails
    { : </dev/tty; } 2>/dev/null || die "--purge deletes every job, finding and note on this server. Run it from a terminal to confirm, or add --yes." 2
    local answer=""
    printf 'Delete all of Rowanholt'\''s data (the database with every job, finding and note, the search indexes, accounts, the licence) and .env? Case output and evidence stay. This cannot be undone. [y/N] ' >/dev/tty
    read -r answer </dev/tty || true
    case "$answer" in y|Y|yes|YES) ;; *) die "Nothing removed." ;; esac
}

[ -z "$PURGE" ] || confirm

if [ -n "$PURGE" ]; then
    echo "==> stopping Rowanholt (project $PROJECT) and removing its volumes"
    # By project, not compose file: down finds the containers by label whichever overrides
    # (server, service, SELinux) started them
    docker compose -p "$PROJECT" down --volumes --remove-orphans
    left=$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")
    # shellcheck disable=SC2086  # one volume name per word
    [ -z "$left" ] || docker volume rm $left >/dev/null
    rm -f "$DIR/.env"
    data="$DIR/src/web/backend/data"
    if [ -d "$data" ]; then
        find "$data" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
    fi
    echo "    removed the volumes, $DIR/.env and $data's contents"
else
    echo "==> stopping Rowanholt (project $PROJECT)"
    docker compose -p "$PROJECT" down --remove-orphans
    echo "    kept the data (the $PROJECT volumes, .env, src/web/backend/data). Re-run with --purge to remove it."
fi
echo "    left the code in $DIR; remove it by hand if you want it gone."
echo "    firewalld ports, a Tailscale Service and any certificate-renewal cron line that server init or"
echo "    you added are left as they are (docs/SERVER.md)."

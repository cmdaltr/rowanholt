#!/usr/bin/env bash
# Back up a server's own state: the database, the user store and the settings
#
#   rowanholt server backup <folder> [--keep N]
#
# Writes <folder>/rowanholt-<date>-<time>/: rowanholt.pgdump (jobs, findings, notes, case
# activity, API tokens, threat intelligence), users.json (the accounts), .env (the secrets,
# so the backup is mode 700: keep it off shared storage) and docker-compose.local.yml if
# there is one. The dump is read back before it counts; the newest N backups are kept
# (default 14). Case output and evidence aren't included: they live on the evidence storage,
# which needs a backup of its own.
#
# Restore on a fresh checkout: put .env, users.json (src/web/backend/data/) and
# docker-compose.local.yml back, rowanholt start, then
#   docker exec -i rowanholt-postgres pg_restore -U rowanholt -d rowanholt --clean --if-exists --no-owner < rowanholt.pgdump
# and docker restart rowanholt-backend.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST=""
KEEP=14
while [ $# -gt 0 ]; do
    case "$1" in
        --keep) KEEP="$2"; shift ;;
        -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Error: unknown option: $1" >&2; exit 1 ;;
        *) DEST="$1" ;;
    esac
    shift
done
[ -n "$DEST" ] || { echo "Usage: rowanholt server backup <folder> [--keep N]" >&2; exit 1; }
[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || { echo "Error: --keep takes a number of backups (1 or more)" >&2; exit 1; }
[ -n "$(docker ps -q -f name='^rowanholt-postgres$')" ] || {
    echo "Error: rowanholt-postgres isn't running: rowanholt start first" >&2; exit 1; }

umask 077
mkdir -p "$DEST"
OUT="$DEST/rowanholt-$(date +%Y%m%d-%H%M%S)"
mkdir "$OUT"
DONE=false
trap '$DONE || rm -rf "$OUT"' EXIT  # a half-made backup never stays to be mistaken for one

docker exec rowanholt-postgres pg_dump -U rowanholt -d rowanholt -Fc > "$OUT/rowanholt.pgdump"
docker exec -i rowanholt-postgres pg_restore --list < "$OUT/rowanholt.pgdump" > /dev/null || {
    echo "Error: the database dump doesn't read back" >&2; exit 1; }
for file in .env docker-compose.local.yml; do
    [ -f "$ROOT/$file" ] && cp "$ROOT/$file" "$OUT/$file"
done
# The backend writes the user store as root, mode 600: a backup run as the server's user
# reads it through the backend instead
USERS="$ROOT/src/web/backend/data/users.json"
if [ -r "$USERS" ]; then
    cp "$USERS" "$OUT/users.json"
elif [ -e "$USERS" ]; then
    docker exec rowanholt-backend cat /app/data/users.json > "$OUT/users.json"
fi
DONE=true

# Oldest first past the newest KEEP (the names sort by time)
find "$DEST" -maxdepth 1 -type d -name 'rowanholt-[0-9]*' | sort -r | tail -n +"$((KEEP + 1))" | while read -r old; do
    rm -rf "$old"
done
echo "Backed up to $OUT ($(du -sh "$OUT" | cut -f1)); keeping the newest $KEEP"

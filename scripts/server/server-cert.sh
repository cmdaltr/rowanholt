#!/usr/bin/env bash
# Renew the server's Tailscale certificate (server init --tls tailscale), restarting the proxy if it changed
#
#   rowanholt server cert
#
# Tailscale's certificates are Let's Encrypt's and last 90 days; tailscale cert hands back
# the same one until it's due, so weekly is enough, e.g. from cron:
#   17 4 * * 1 <checkout>/rowanholt server cert
# Caddy reads deploy/server/certs at start, hence the restart. Other apps on the same
# tailnet node serve the same certificate and need their own restart.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="$ROOT/.env"
CERTS="$ROOT/deploy/server/certs"
current() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1; }

NAME="$(current ROWANHOLT_HOSTNAME)"
[ "$(current ROWANHOLT_TLS_SOURCE)" = tailscale ] || {
    echo "Error: this server's certificate isn't Tailscale's (rowanholt server init <name> --tls tailscale)" >&2; exit 1; }
command -v tailscale >/dev/null || { echo "Error: tailscale isn't installed on this host" >&2; exit 1; }
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
$SUDO tailscale cert --cert-file "$tmp/rowanholt.crt" --key-file "$tmp/rowanholt.key" "$NAME" >/dev/null 2>&1 || {
    echo "Error: tailscale cert failed for $NAME: is HTTPS on for the tailnet (admin console, DNS, HTTPS Certificates)?" >&2
    exit 1
}
$SUDO chown "$(id -u):$(id -g)" "$tmp/rowanholt.crt" "$tmp/rowanholt.key"
expiry="$(openssl x509 -noout -enddate -in "$tmp/rowanholt.crt" | sed 's/^notAfter=//')"
if cmp -s "$tmp/rowanholt.crt" "$CERTS/rowanholt.crt"; then
    echo "Certificate for $NAME unchanged (until $expiry)"
    exit 0
fi
mkdir -p "$CERTS"
install -m 644 "$tmp/rowanholt.crt" "$CERTS/rowanholt.crt"
install -m 600 "$tmp/rowanholt.key" "$CERTS/rowanholt.key"
echo "Certificate for $NAME installed (until $expiry)"

[ "${1:-}" = --no-restart ] && exit 0
cd "$ROOT"
if docker compose version &>/dev/null; then DC=(docker compose); else DC=(docker-compose); fi
if [ -n "$("${DC[@]}" -f docker-compose.yml -f deploy/server/docker-compose.server.yml ps -q proxy 2>/dev/null)" ]; then
    "${DC[@]}" -f docker-compose.yml -f deploy/server/docker-compose.server.yml restart proxy >/dev/null
    echo "Proxy restarted"
fi

#!/usr/bin/env bash
# Print the root certificate of the server's own CA (DERNVALE_TLS=internal), to trust on clients
#
#   dernvale server ca > dernvale-root.crt
#
# Then trust it: macOS, double-click and set it to Always Trust in Keychain Access (or
# deploy it by MDM); Windows, certutil -addstore Root dernvale-root.crt (or Group
# Policy); Ubuntu, copy it to /usr/local/share/ca-certificates/ and run
# update-ca-certificates. Browsers and the Dernvale app then accept the server.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
if docker compose version &>/dev/null; then DC=(docker compose); else DC=(docker-compose); fi
exec "${DC[@]}" -f docker-compose.yml -f deploy/server/docker-compose.server.yml \
    exec -T proxy cat /data/caddy/pki/authorities/local/root.crt

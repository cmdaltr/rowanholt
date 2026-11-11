#!/usr/bin/env bash
# A team server's licence from the host (show, install, remove)
#
#   rowanholt server licence show
#   rowanholt server licence install FILE --accept-terms "Your Name <you@example.org>"
#   rowanholt server licence remove
#
# Installing accepts the Rowanholt Commercial Licence (COMMERCIAL-LICENSE.md) on the licensee's
# behalf. The file is read here and passed on stdin, since the backend container can't see the
# host's files. Works when nobody can sign in to use the Licence page.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
if docker compose version &>/dev/null; then DC=(docker compose); else DC=(docker-compose); fi
DC+=(-f docker-compose.yml -f deploy/server/docker-compose.server.yml)

if [[ "${1:-}" == "install" && -n "${2:-}" && "${2:-}" != "-" ]]; then
    file="$2"
    [[ -r "$file" ]] || { echo "Error: can't read $file" >&2; exit 1; }
    shift 2
    exec "${DC[@]}" exec -T backend python -m manage_licence install - "$@" < "$file"
fi
exec "${DC[@]}" exec backend python -m manage_licence "$@"

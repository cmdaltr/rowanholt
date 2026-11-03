#!/usr/bin/env bash
# Administer a server's users from the host (list, add, password, role, disable, enable)
#
#   rivendell server users list
#   rivendell server users add <username> <email> [--admin]
#   rivendell server users password|disable|enable <username>
#   rivendell server users role <username> admin|user
#
# Works when nobody can sign in: a locked-out admin, or single sign-on down.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
if docker compose version &>/dev/null; then DC=(docker compose); else DC=(docker-compose); fi
exec "${DC[@]}" -f docker-compose.yml -f deploy/server/docker-compose.server.yml \
    exec backend python -m auth.manage_users "$@"

#!/usr/bin/env bash
# Administer a server's users from the host (list, first-admin, has-admin, invite, invitations,
# revoke-invitation, role, disable, enable, mfa-reset, reset-access)
#
#   rowanholt server users list
#   rowanholt server users first-admin <email> [--force]   (no admin yet: the first admin's one-time link)
#   rowanholt server users invite <email> [--role user|admin] [--name NAME]   (a one-time link)
#   rowanholt server users invitations                 (pending ones)
#   rowanholt server users revoke-invitation <id>
#   rowanholt server users disable|enable <username>   (disable ends their sessions and revokes their API tokens)
#   rowanholt server users role <username> admin|user
#   rowanholt server users mfa-reset <username>   (lost authenticator and backup codes)
#   rowanholt server users reset-access <username|email>   (a one-time link: new password and authenticator)
#
# Works when nobody can sign in: a locked-out admin, or single sign-on down. Nobody sets another
# person's password: there is no add or password command (reset-access gives them a link).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
if docker compose version &>/dev/null; then DC=(docker compose); else DC=(docker-compose); fi
exec "${DC[@]}" -f docker-compose.yml -f deploy/server/docker-compose.server.yml \
    exec backend python -m auth.manage_users "$@"

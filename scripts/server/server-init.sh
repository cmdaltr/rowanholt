#!/usr/bin/env bash
# Set this Rivendell up as a team's shared server (writes the server settings into .env)
#
#   rivendell server init <hostname> [--tls internal|<acme-email>|files]
#
# <hostname> is the name people will open, e.g. rivendell.dfir.example.org. --tls picks
# the certificate: Caddy's own CA (internal, the default), Let's Encrypt for a public
# name (an email address), or your organisation's own (files: deploy/server/certs/
# rivendell.crt and rivendell.key). Afterwards `rivendell start` runs the server profile.
#
# Secrets are generated once and kept: SECRET_KEY, the first admin's password (printed
# once), and the Postgres, Elastic and Splunk passwords for stores that don't exist yet.
# Stores created earlier keep their passwords, since changing them would lock Rivendell
# out of its own data; on a server those stores aren't reachable from the network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="$ROOT/.env"
HOSTNAME_ARG=""
TLS="internal"
while [ $# -gt 0 ]; do
    case "$1" in
        --tls) TLS="$2"; shift ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Error: unknown option: $1" >&2; exit 1 ;;
        *) HOSTNAME_ARG="$1" ;;
    esac
    shift
done
[ -n "$HOSTNAME_ARG" ] || { echo "Usage: rivendell server init <hostname> [--tls internal|<acme-email>|files]" >&2; exit 1; }
[[ "$HOSTNAME_ARG" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Error: '$HOSTNAME_ARG' isn't a hostname" >&2; exit 1; }

case "$TLS" in
    internal) TLS_VALUE="internal" ;;
    files)
        TLS_VALUE="/certs/rivendell.crt /certs/rivendell.key"
        for f in rivendell.crt rivendell.key; do
            [ -f "$ROOT/deploy/server/certs/$f" ] || echo "Note: put $f in deploy/server/certs before starting." >&2
        done
        ;;
    *@*) TLS_VALUE="$TLS" ;;
    *) echo "Error: --tls is internal, an email address (Let's Encrypt) or files" >&2; exit 1 ;;
esac

umask 077
touch "$ENV_FILE"
[ -s "$ENV_FILE" ] || { [ -f "$ROOT/.env.example" ] && cp "$ROOT/.env.example" "$ENV_FILE"; }
chmod 600 "$ENV_FILE"

current() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }
set_value() {
    local key="$1" value="$2" tmp
    tmp="$(mktemp)"
    grep -v "^$key=" "$ENV_FILE" > "$tmp" || true
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
}
secret() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }
store_exists() { docker volume ls -q 2>/dev/null | grep -qE "(^|_)$1\$"; }

set_value RIVENDELL_DEPLOYMENT server
set_value RIVENDELL_HOSTNAME "$HOSTNAME_ARG"
set_value RIVENDELL_TLS "$TLS_VALUE"

key="$(current SECRET_KEY)"
case "$key" in ""|change-this-to-a-random-secret-key|your-secret-key-change-in-production) set_value SECRET_KEY "$(secret)$(secret)" ;; esac

ADMIN_PASSWORD=""
if [ -z "$(current RIVENDELL_ADMIN_PASSWORD)" ]; then
    ADMIN_PASSWORD="$(secret)"
    set_value RIVENDELL_ADMIN_PASSWORD "$ADMIN_PASSWORD"
fi

kept=()
for pair in POSTGRES_PASSWORD:postgres_data ELASTIC_PASSWORD:elastic_data KIBANA_PASSWORD:elastic_data SPLUNK_PASSWORD:splunk_var; do
    var="${pair%%:*}" volume="${pair#*:}"
    value="$(current "$var")"
    if [ -n "$value" ] && [ "$value" != rivendell ] && [ "$value" != changeme ]; then
        continue
    fi
    if store_exists "$volume"; then
        kept+=("$var")
    else
        set_value "$var" "$(secret)"
    fi
done

echo "Rivendell is set up as a server for https://$HOSTNAME_ARG"
echo ""
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "  First admin:  admin / $ADMIN_PASSWORD"
    echo "  (shown once; it's also RIVENDELL_ADMIN_PASSWORD in .env until you change it after signing in)"
    echo ""
fi
if [ ${#kept[@]} -gt 0 ]; then
    echo "  Kept the existing passwords of: ${kept[*]} (their data stores already exist)."
    echo ""
fi
case "$TLS_VALUE" in
    internal) echo "  Certificates: Caddy's own CA. After 'rivendell start', 'rivendell server ca' prints its root to trust on clients." ;;
    /certs/*) echo "  Certificates: deploy/server/certs/rivendell.crt and rivendell.key." ;;
    *) echo "  Certificates: Let's Encrypt for $TLS_VALUE; $HOSTNAME_ARG must reach this host on ports 80 and 443." ;;
esac
echo ""
echo "Next: rivendell start    (with Splunk and Elastic: COMPOSE_PROFILES=siem rivendell start)"
echo "Single sign-on: set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET in .env (docs/SERVER.md)."

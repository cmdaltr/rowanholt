#!/usr/bin/env bash
# Set this Rowanholt up as a team's shared server (writes the server settings into .env)
#
#   rowanholt server init <hostname> [--tls internal|<acme-email>|files|tailscale] [--https-port N]
#
# <hostname> is the name people will open, e.g. rowanholt.dfir.example.org. --tls picks
# the certificate: Caddy's own CA (internal, the default), Let's Encrypt for a public
# name (an email address), your organisation's own (files: deploy/server/certs/
# rowanholt.crt and rowanholt.key), or, for a server on a tailnet named by MagicDNS
# (<host>.<tailnet>.ts.net), Tailscale's (tailscale; renew with rowanholt server cert).
# --https-port serves Rowanholt on another port than 443 and leaves 80 free, for a host where
# something else is the front door; once given it's kept until given again (443 to go back).
# Afterwards `rowanholt start` runs the server profile.
#
# Secrets are generated once and kept: SECRET_KEY, the first admin's password (printed
# once), and the Postgres, Elastic and Splunk passwords for stores that don't exist yet.
# Stores created earlier keep their passwords, since changing them would lock Rowanholt
# out of its own data; on a server those stores aren't reachable from the network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="$ROOT/.env"
HOSTNAME_ARG=""
TLS="internal"
HTTPS_PORT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tls) TLS="$2"; shift ;;
        --https-port) HTTPS_PORT="$2"; shift ;;
        -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Error: unknown option: $1" >&2; exit 1 ;;
        *) HOSTNAME_ARG="$1" ;;
    esac
    shift
done
[ -n "$HOSTNAME_ARG" ] || { echo "Usage: rowanholt server init <hostname> [--tls internal|<acme-email>|files|tailscale]" >&2; exit 1; }
[[ "$HOSTNAME_ARG" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Error: '$HOSTNAME_ARG' isn't a hostname" >&2; exit 1; }
if [ -n "$HTTPS_PORT" ]; then
    [[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && [ "$HTTPS_PORT" -ge 1 ] && [ "$HTTPS_PORT" -le 65535 ] \
        || { echo "Error: --https-port takes a port number" >&2; exit 1; }
    case "$HTTPS_PORT" in 80|5601|5602|7755) echo "Error: port $HTTPS_PORT is already the proxy's" >&2; exit 1 ;; esac
fi
# Caddy hands *.ts.net names to the Tailscale daemon, which its container can't reach: with
# internal or an email address it serves no certificate at all (TLS alert 80)
case "$HOSTNAME_ARG:$TLS" in
    *.ts.net:internal|*.ts.net:*@*)
        echo "Error: $HOSTNAME_ARG is a Tailscale name: use --tls tailscale (or files)" >&2; exit 1 ;;
esac

TLS_SOURCE=""
case "$TLS" in
    internal) TLS_VALUE="internal" ;;
    tailscale)
        [[ "$HOSTNAME_ARG" == *.ts.net ]] || { echo "Error: --tls tailscale is for the server's MagicDNS name (<host>.<tailnet>.ts.net)" >&2; exit 1; }
        command -v tailscale >/dev/null || { echo "Error: tailscale isn't installed on this host" >&2; exit 1; }
        TLS_VALUE="/certs/rowanholt.crt /certs/rowanholt.key"
        TLS_SOURCE="tailscale"
        ;;
    files)
        TLS_VALUE="/certs/rowanholt.crt /certs/rowanholt.key"
        for f in rowanholt.crt rowanholt.key; do
            [ -f "$ROOT/deploy/server/certs/$f" ] || echo "Note: put $f in deploy/server/certs before starting." >&2
        done
        ;;
    *@*) TLS_VALUE="$TLS" ;;
    *) echo "Error: --tls is internal, an email address (Let's Encrypt), files or tailscale" >&2; exit 1 ;;
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

set_value ROWANHOLT_DEPLOYMENT server
set_value ROWANHOLT_HOSTNAME "$HOSTNAME_ARG"
set_value ROWANHOLT_TLS "$TLS_VALUE"
set_value ROWANHOLT_TLS_SOURCE "$TLS_SOURCE"
[ "$TLS_SOURCE" = tailscale ] && bash "$ROOT/scripts/server/server-cert.sh" --no-restart

HTTPS_PORT="${HTTPS_PORT:-$(current ROWANHOLT_HTTPS_PORT)}"
HTTPS_PORT="${HTTPS_PORT:-443}"
set_value ROWANHOLT_HTTPS_PORT "$HTTPS_PORT"
if [ "$HTTPS_PORT" = 443 ]; then
    PUBLIC_URL="https://$HOSTNAME_ARG"
    set_value ROWANHOLT_HTTP_PUBLISH 80
else
    PUBLIC_URL="https://$HOSTNAME_ARG:$HTTPS_PORT"
    set_value ROWANHOLT_HTTP_PUBLISH 127.0.0.1:8080  # its redirect isn't wanted; 80 stays free
fi
set_value ROWANHOLT_PUBLIC_URL "$PUBLIC_URL"

key="$(current SECRET_KEY)"
case "$key" in ""|change-this-to-a-random-secret-key|your-secret-key-change-in-production) set_value SECRET_KEY "$(secret)$(secret)" ;; esac

ADMIN_PASSWORD=""
if [ -z "$(current ROWANHOLT_ADMIN_PASSWORD)" ]; then
    ADMIN_PASSWORD="$(secret)"
    set_value ROWANHOLT_ADMIN_PASSWORD "$ADMIN_PASSWORD"
fi

kept=()
for pair in POSTGRES_PASSWORD:postgres_data ELASTIC_PASSWORD:elastic_data KIBANA_PASSWORD:elastic_data SPLUNK_PASSWORD:splunk_var; do
    var="${pair%%:*}" volume="${pair#*:}"
    value="$(current "$var")"
    if [ -n "$value" ] && [ "$value" != rowanholt ] && [ "$value" != changeme ]; then
        continue
    fi
    if store_exists "$volume"; then
        kept+=("$var")
    else
        set_value "$var" "$(secret)"
    fi
done

echo "Rowanholt is set up as a server for $PUBLIC_URL"
echo ""
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "  First admin:  admin / $ADMIN_PASSWORD"
    echo "  (shown once; it's also ROWANHOLT_ADMIN_PASSWORD in .env until you change it after signing in)"
    echo ""
fi
if [ ${#kept[@]} -gt 0 ]; then
    echo "  Kept the existing passwords of: ${kept[*]} (their data stores already exist)."
    echo ""
fi
case "$TLS_SOURCE:$TLS_VALUE" in
    tailscale:*)
        echo "  Certificates: Tailscale's (Let's Encrypt, 90 days), trusted by every client on the tailnet."
        echo "  Renew with 'rowanholt server cert'; weekly from cron is enough: 17 4 * * 1 $ROOT/rowanholt server cert" ;;
    *:internal) echo "  Certificates: Caddy's own CA. After 'rowanholt start', 'rowanholt server ca' prints its root to trust on clients." ;;
    *:/certs/*) echo "  Certificates: deploy/server/certs/rowanholt.crt and rowanholt.key." ;;
    *) echo "  Certificates: Let's Encrypt for $TLS_VALUE; $HOSTNAME_ARG must reach this host on ports 80 and 443." ;;
esac
echo ""
echo "Next: rowanholt start    (with Splunk and Elastic: COMPOSE_PROFILES=siem rowanholt start)"
echo "Single sign-on: set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET in .env (docs/SERVER.md)."

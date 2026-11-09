#!/usr/bin/env bash
# Set this Rowanholt up as a team's shared server (writes the server settings into .env)
#
#   rowanholt server init <hostname> [--tls internal|<acme-email>|files|tailscale] [--https-port N]
#                                    [--service <name>|off]
#
# <hostname> is the name people will open, e.g. rowanholt.dfir.example.org. --tls picks
# the certificate: Caddy's own CA (internal, the default), Let's Encrypt for a public
# name (an email address), your organisation's own (files: deploy/server/certs/
# rowanholt.crt and rowanholt.key), or, for a server on a tailnet named by MagicDNS
# (<host>.<tailnet>.ts.net), Tailscale's (tailscale; renew with rowanholt server cert).
# --https-port serves Rowanholt on another port than 443 and leaves 80 free, for a host where
# something else is the front door; once given it's kept until given again (443 to go back).
# --service, with --tls tailscale, also gives the server a Tailscale Service name of its own,
# https://<name>.<tailnet>.ts.net with no port, which becomes the URL people open; the
# host-and-port address keeps working. Kept like --https-port; --service off drops it.
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
SERVICE_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tls) TLS="$2"; shift ;;
        --https-port) HTTPS_PORT="$2"; shift ;;
        --service) SERVICE_ARG="$2"; shift ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# A Tailscale Service: Tailscale terminates TLS for the name and hands each port to one of the
# proxy's loopback sites (deploy/server/Caddyfile.service): the web app, Splunk, Kibana, the Navigator
SERVICE_PORTS="443:5680 7755:5681 5601:5682 5602:5683"
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
serve_service() {
    local pair err
    err="$(mktemp)"
    for pair in $SERVICE_PORTS; do
        if ! $SUDO tailscale serve --service="svc:$1" --https="${pair%%:*}" "http://127.0.0.1:${pair#*:}" \
                </dev/null >/dev/null 2>"$err"; then
            echo "Error: Tailscale won't serve svc:$1: $(head -3 "$err")" >&2
            echo "  The server must be a tagged device, and the tailnet policy must auto-approve svc:$1 for its" >&2
            echo "  tag and grant it ports 443, 7755, 5601 and 5602 (docs/SERVER.md, A name of its own)." >&2
            rm -f "$err"
            return 1
        fi
    done
    rm -f "$err"
}
unserve_service() {
    { $SUDO tailscale serve drain "svc:$1"; $SUDO tailscale serve clear "svc:$1"; } </dev/null >/dev/null 2>&1 || true
}

OLD_SERVICE="$(current ROWANHOLT_SERVICE)"
case "$SERVICE_ARG" in
    off) SERVICE="" ;;
    "") SERVICE="$OLD_SERVICE" ;;
    *) SERVICE="$SERVICE_ARG" ;;
esac
if [ -n "$SERVICE" ]; then
    [[ "$SERVICE" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
        || { echo "Error: --service takes a DNS label (lower case letters, digits and hyphens), or off" >&2; exit 1; }
    [ "$TLS_SOURCE" = tailscale ] \
        || { echo "Error: --service is for a server on a tailnet with --tls tailscale (or --service off)" >&2; exit 1; }
    [ "$SERVICE.${HOSTNAME_ARG#*.}" != "$HOSTNAME_ARG" ] \
        || { echo "Error: the Service needs a name of its own, not the server's ($SERVICE)" >&2; exit 1; }
    serve_service "$SERVICE" || exit 1
fi
if [ -n "$OLD_SERVICE" ] && [ "$OLD_SERVICE" != "$SERVICE" ]; then unserve_service "$OLD_SERVICE"; fi
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
# firewalld (Rocky, RHEL, Alma): the proxy's ports open in the default zone, nothing else
OPENED=()
if command -v firewall-cmd >/dev/null && $SUDO firewall-cmd --state >/dev/null 2>&1; then
    ports="$HTTPS_PORT 7755 5601 5602"
    [ "$HTTPS_PORT" = 443 ] && ports="80 $ports"
    for port in $ports; do
        $SUDO firewall-cmd --query-port="$port/tcp" >/dev/null 2>&1 && continue
        $SUDO firewall-cmd --permanent --add-port="$port/tcp" >/dev/null \
            || { echo "Error: firewalld won't open $port/tcp" >&2; exit 1; }
        OPENED+=("$port")
    done
    [ ${#OPENED[@]} -eq 0 ] || $SUDO firewall-cmd --reload >/dev/null
fi
set_value ROWANHOLT_SERVICE "$SERVICE"
if [ -n "$SERVICE" ]; then
    set_value ROWANHOLT_OTHER_URLS "$PUBLIC_URL"
    PUBLIC_URL="https://$SERVICE.${HOSTNAME_ARG#*.}"
else
    set_value ROWANHOLT_OTHER_URLS ""
fi
set_value ROWANHOLT_PUBLIC_URL "$PUBLIC_URL"
# A server's worker doesn't fetch symbol tables (or Windows PDBs) for memory images unless an
# administrator turns it on: a job that needs one names the rowanholt symbols command instead.
# Only when unset, so a re-run keeps the administrator's choice
[ -n "$(current ROWANHOLT_SYMBOL_DOWNLOADS)" ] || set_value ROWANHOLT_SYMBOL_DOWNLOADS off

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
if [ -n "$SERVICE" ]; then
    echo "  Tailscale Service svc:$SERVICE; also at $(current ROWANHOLT_OTHER_URLS). Splunk, Kibana and the"
    echo "  Navigator are on the name's 7755, 5601 and 5602. MCP clients and an SSO redirect URI move to the name."
    echo ""
elif [ -n "$OLD_SERVICE" ]; then
    echo "  Tailscale Service svc:$OLD_SERVICE dropped: MCP clients and an SSO redirect URI move back to $PUBLIC_URL."
    echo ""
fi
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "  First admin:  admin / $ADMIN_PASSWORD"
    echo "  (shown once; it's also ROWANHOLT_ADMIN_PASSWORD in .env until you change it after signing in)"
    echo ""
fi
if [ ${#OPENED[@]} -gt 0 ]; then
    echo "  firewalld: opened ${OPENED[*]/%//tcp} in the default zone ($($SUDO firewall-cmd --get-default-zone))."
    echo ""
fi
if [ -f /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then
    echo "  SELinux is enforcing: the services that mount host folders run unlabelled"
    echo "  (deploy/docker-compose.selinux.yml), so evidence folders aren't relabelled."
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

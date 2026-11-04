#!/usr/bin/env bash
# Move an install from before the rename (Rivendell) to Rowanholt: settings, volumes, database
#
#   rowanholt migrate from-rivendell [--yes]
#
# Run it once, before the first `rowanholt start`.
#
# It stops the old stack, renames the RIVENDELL_* settings in .env (keeping a backup),
# copies the old Docker volumes into the new ones, copies the database into the new
# Postgres (rowanholt/rowanholt), points jobs that used /tmp/rivendell at /tmp/rowanholt
# and moves that folder, the start history and the Linux app's settings. The old volumes
# are left as they were: remove them yourself once the new stack looks right (the last
# lines print the command). Run again, it skips whatever is already done.
#
# ENV_FILE and STATE_HOME change where it looks, for testing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
STATE_HOME="${STATE_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}}"
PG_IMAGE="postgres:16-alpine"  # docker-compose.yml's
OLD_PG="rowanholt-migrate-rivendell-db"
YES=false
[ "${1:-}" = "--yes" ] && YES=true

if docker compose version &>/dev/null; then DC=(docker compose); else DC=(docker-compose); fi

say() { echo "  $*"; }
confirm() {
    $YES && return 0
    local answer
    read -r -p "$1 [y/N] " answer
    [[ "$answer" =~ ^[Yy] ]]
}
volume_exists() { docker volume inspect "$1" &>/dev/null; }
volume_empty() {
    [ -z "$(docker run --rm -v "$1":/v:ro "$PG_IMAGE" sh -c 'ls -A /v' 2>/dev/null)" ]
}

docker info &>/dev/null || { echo "Error: Docker isn't running." >&2; exit 1; }

echo "Moving this install from Rivendell to Rowanholt."
confirm "Stop the old stack and go ahead?" || { echo "Nothing changed."; exit 1; }

# ── 1. The old stack ─────────────────────────────────────────────────────────
old=$(docker ps -aq --filter label=com.docker.compose.project=rivendell)
if [ -n "$old" ]; then
    echo "Stopping the old stack..."
    # shellcheck disable=SC2086 # one container ID per word
    docker rm -f $old >/dev/null
fi

# ── 2. .env ──────────────────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ] && grep -q '^RIVENDELL_' "$ENV_FILE"; then
    cp -p "$ENV_FILE" "$ENV_FILE.rivendell-backup"
    sed -i.tmp 's/^RIVENDELL_/ROWANHOLT_/' "$ENV_FILE" && rm -f "$ENV_FILE.tmp"
    say ".env: RIVENDELL_* settings renamed ROWANHOLT_* (backup: $(basename "$ENV_FILE").rivendell-backup)"
fi
# Splunk and Elasticsearch keep the admin password they were first started with, which
# was 'rivendell' unless .env set one: keep using it with the copied data
for pair in "SPLUNK_PASSWORD:splunk_etc" "ELASTIC_PASSWORD:elastic_data"; do
    key="${pair%%:*}"; vol="rivendell_${pair#*:}"
    if volume_exists "$vol" && ! grep -q "^$key=" "$ENV_FILE" 2>/dev/null; then
        [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ] && echo >> "$ENV_FILE"
        echo "$key=rivendell" >> "$ENV_FILE"
        say ".env: $key=rivendell added (the password ${vol#rivendell_}'s data still has)"
    fi
done

# ── 3. Volumes ───────────────────────────────────────────────────────────────
# Redis holds only the queue, sign-in throttling and locks: nothing to keep
for name in rivendell_output rivendell_uploads splunk_etc splunk_var elastic_data navigator_data anduril_token; do
    from="rivendell_$name"
    short="${name/rivendell_/rowanholt_}"
    to="rowanholt_$short"
    volume_exists "$from" || continue
    if volume_exists "$to" && ! volume_empty "$to"; then
        say "volume $to already has data: left alone"
        continue
    fi
    volume_exists "$to" || docker volume create \
        --label com.docker.compose.project=rowanholt --label com.docker.compose.volume="$short" "$to" >/dev/null
    docker run --rm -v "$from":/from:ro -v "$to":/to "$PG_IMAGE" sh -c 'cp -a /from/. /to/'
    say "volume $from copied to $to"
done

# ── 4. The database ──────────────────────────────────────────────────────────
wait_for() {  # container user database
    local i
    for i in $(seq 1 60); do
        # The image restarts Postgres once after initdb: ask twice, a second apart
        if docker exec "$1" psql -U "$2" -d "$3" -tAc 'select 1' &>/dev/null; then
            sleep 1
            docker exec "$1" psql -U "$2" -d "$3" -tAc 'select 1' &>/dev/null && return 0
        fi
        sleep 1
    done
    echo "Error: Postgres in $1 didn't come up." >&2
    return 1
}

if volume_exists rivendell_postgres_data; then
    "${DC[@]}" -f docker-compose.yml up -d postgres >/dev/null
    wait_for rowanholt-postgres rowanholt rowanholt
    tables=$(docker exec rowanholt-postgres psql -U rowanholt -d rowanholt -tAc \
        "select count(*) from information_schema.tables where table_schema='public'")
    if [ "$tables" != 0 ]; then
        say "the new database already has tables: left alone"
    else
        docker rm -f "$OLD_PG" &>/dev/null || true
        docker run -d --name "$OLD_PG" -v rivendell_postgres_data:/var/lib/postgresql/data "$PG_IMAGE" >/dev/null
        trap 'docker rm -f "$OLD_PG" &>/dev/null || true' EXIT
        wait_for "$OLD_PG" rivendell rivendell
        docker exec "$OLD_PG" pg_dump -U rivendell -d rivendell --no-owner --no-privileges \
            | docker exec -i rowanholt-postgres psql -q -v ON_ERROR_STOP=1 -U rowanholt -d rowanholt >/dev/null
        docker exec rowanholt-postgres psql -q -v ON_ERROR_STOP=1 -U rowanholt -d rowanholt -c "
            UPDATE jobs SET
                source_paths = replace(source_paths::text, '/tmp/rivendell', '/tmp/rowanholt')::json,
                destination_path = replace(destination_path, '/tmp/rivendell', '/tmp/rowanholt'),
                options = replace(options::text, '/tmp/rivendell', '/tmp/rowanholt')::json,
                result = replace(result::text, '/tmp/rivendell', '/tmp/rowanholt')::json
            WHERE concat(source_paths::text, destination_path, options::text, result::text) LIKE '%/tmp/rivendell%'"
        jobs=$(docker exec rowanholt-postgres psql -U rowanholt -d rowanholt -tAc 'select count(*) from jobs')
        say "database copied ($jobs jobs)"
    fi
    "${DC[@]}" -f docker-compose.yml stop postgres >/dev/null
fi

# ── 5. Folders on this machine ───────────────────────────────────────────────
move() {  # from to what
    [ -e "$1" ] || return 0
    if [ -e "$2" ]; then
        say "$3: $2 already exists, $1 left alone"
    elif mv "$1" "$2" 2>/dev/null; then
        say "$3: $1 moved to $2"
    else
        say "$3: couldn't move $1 (try: sudo mv $1 $2)"
    fi
}
move /tmp/rivendell /tmp/rowanholt "case output"
move "$STATE_HOME/rivendell" "$STATE_HOME/rowanholt" "start history"
move "${XDG_CONFIG_HOME:-$HOME/.config}/rivendell" "${XDG_CONFIG_HOME:-$HOME/.config}/rowanholt" "app settings"
move "${XDG_DATA_HOME:-$HOME/.local/share}/rivendell" "${XDG_DATA_HOME:-$HOME/.local/share}/rowanholt" "app data"
for marker in version built; do
    move "$ROOT/.rivendell-$marker" "$ROOT/.rowanholt-$marker" "app copy marker"
done

# ── 6. The test lab (lab/), if this machine has one ──────────────────────────
# Its infrastructure is renamed; the evidence seeded into its targets (rivendell-lab.test,
# /etc/rivendell-lab/expected.json) isn't, so built VMs stay valid without re-provisioning
OLD_LAB="$HOME/.config/rivendell-lab"
NEW_LAB="$HOME/.config/rowanholt-lab"
utm_note=""
# Running the new lab.sh before this creates the folder empty: that isn't a migrated lab
[ -d "$NEW_LAB" ] && rmdir "$NEW_LAB" 2>/dev/null || true
if [ -d "$OLD_LAB" ] && [ ! -e "$NEW_LAB" ]; then
    if [ -f "$OLD_LAB/run/agent.pid" ] && kill -0 "$(cat "$OLD_LAB/run/agent.pid")" 2>/dev/null; then
        kill "$(cat "$OLD_LAB/run/agent.pid")" && say "lab: agent stopped"
    fi
    old=$(docker ps -aq --filter label=com.docker.compose.project=rivendell-lab)
    # shellcheck disable=SC2086 # one container ID per word
    [ -n "$old" ] && docker rm -f $old >/dev/null && say "lab: old target containers removed (rebuilt from the images)"
    for image in $(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^rivendell-lab-' || true); do
        docker tag "$image" "rowanholt-lab-${image#rivendell-lab-}"
    done
    mv "$OLD_LAB" "$NEW_LAB"
    [ -f "$NEW_LAB/rivendell-tests.env" ] && mv "$NEW_LAB/rivendell-tests.env" "$NEW_LAB/rowanholt-tests.env"
    say "lab: settings moved to $NEW_LAB"

    # The password, under the new Keychain service name (the old entry is left)
    if [ "$(uname)" = Darwin ]; then
        if pw=$(security find-generic-password -s rivendell-lab -a gandalf -w 2>/dev/null); then
            security add-generic-password -U -s rowanholt-lab -a gandalf -w "$pw" -l "Rowanholt test lab" && say "lab: password copied in the Keychain"
        fi
    elif command -v secret-tool &>/dev/null; then
        if pw=$(secret-tool lookup service rivendell-lab account gandalf 2>/dev/null) && [ -n "$pw" ]; then
            printf '%s' "$pw" | secret-tool store --label "Rowanholt test lab" service rowanholt-lab account gandalf \
                && say "lab: password copied in the keyring"
        fi
    fi
    unset pw

    # The VMs. Tart and VirtualBox rename in place; UTM tracks a VM by its bundle's path,
    # so the lab keeps driving the Windows VM under its old name (WINDOWS_UTM_VM)
    # shellcheck source=../../lab/lib/common.sh
    ( . "$ROOT/lab/lib/common.sh"; load_config >/dev/null 2>&1 || true
      if command -v tart &>/dev/null; then
          for vm in $(tart list --format json 2>/dev/null | grep -o '"Name" *: *"rivendell-lab-[^"]*"' | sed 's/.*"\(rivendell-lab-[^"]*\)"/\1/'); do
              tart stop "$vm" &>/dev/null || true
              tart rename "$vm" "rowanholt-lab-${vm#rivendell-lab-}" && say "lab: Tart VM $vm renamed"
          done
      fi
      if command -v VBoxManage &>/dev/null; then
          for vm in $(VBoxManage list vms | sed -n 's/^"\(rivendell-lab-[^"]*\)".*/\1/p'); do
              VBoxManage modifyvm "$vm" --name "rowanholt-lab-${vm#rivendell-lab-}" && say "lab: VirtualBox VM $vm renamed"
          done
      fi )
    utm=$(ls -d "$(sed -n 's/^LAB_VM_DIR=//p' "$NEW_LAB/lab.conf" 2>/dev/null | tr -d '"')"/utm/rivendell-lab-*.utm 2>/dev/null || true)
    if [ -n "$utm" ]; then
        grep -q '^WINDOWS_UTM_VM=' "$NEW_LAB/lab.conf" 2>/dev/null \
            || echo 'WINDOWS_UTM_VM="rivendell-lab-win11"' >> "$NEW_LAB/lab.conf"
        if echo "$utm" | grep -q 'rivendell-lab-win11-clean'; then
            grep -q '^WINDOWS_CLEAN_PREFIX=' "$NEW_LAB/lab.conf" 2>/dev/null \
                || echo 'WINDOWS_CLEAN_PREFIX="rivendell-lab-win11-clean"' >> "$NEW_LAB/lab.conf"
        fi
        utm_note="The lab's UTM VMs keep their old names (lab.conf WINDOWS_UTM_VM, WINDOWS_CLEAN_PREFIX): $(echo "$utm" | xargs -n1 basename | tr '\n' ' ')"
    fi
    move "$HOME/rivendell-lab-data" "$HOME/rowanholt-lab-data" "lab data"
    say "lab: start the agent again with: lab/lab.sh agent start"
fi

echo ""
[ -n "$utm_note" ] && echo "$utm_note" && echo ""
echo "Done. Start it with: rowanholt start"
left=$(docker volume ls -q --filter name='^rivendell_')
if [ -n "$left" ]; then
    echo "Once it looks right, remove the old volumes:"
    echo "  docker volume rm" $left
fi

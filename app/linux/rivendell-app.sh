#!/usr/bin/env bash
# What the Rivendell desktop entry runs: start the Docker stack if the web UI isn't
# answering, then open the UI in its own window (a Chromium-family browser in app mode,
# or the default browser). Progress goes to desktop notifications and the log below.
#
# From a checkout it runs that checkout. Installed from the .deb (/opt/rivendell, next to
# rivendell-src.tar.gz), it runs what setup chose: zenity dialogs that either take a team
# server's address, or check for Docker, unpack the bundled source (or take an existing
# checkout) and mount evidence. A server (RIVENDELL_SERVER, or the one setup saved)
# needs nothing local: the window opens on it.
#   rivendell-app.sh [--setup | --stop]

SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
HERE="$(cd -P "$(dirname "$SOURCE")" && pwd)"
URL="http://localhost:5687"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/rivendell"
CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/rivendell"
LOG="$STATE/app.log"
PROFILE="${XDG_DATA_HOME:-$HOME/.local/share}/rivendell/browser"
BUNDLED="$HERE/rivendell-src.tar.gz"
LOCAL_HEADER="# Written by Rivendell's desktop setup"
mkdir -p "$STATE" "$PROFILE" "$CONFIG"

if [ -f "$HERE/rivendell.png" ]; then ICON="$HERE/rivendell.png"; else ICON="$HERE/../icons/rivendell.png"; fi

notify() {
    command -v notify-send &>/dev/null && notify-send -a Rivendell -i "$ICON" "Rivendell" "$1"
    echo "[$(date '+%F %T')] $1" >> "$LOG"
}

has_zenity() { command -v zenity &>/dev/null; }

say() {
    # say <info|error|warning> <text>
    if has_zenity; then zenity "--$1" --title=Rivendell --width=420 --text="$2" 2>/dev/null; else notify "$2"; fi
}

is_copy() { [ -x "$1/rivendell" ] && [ -f "$1/docker-compose.yml" ]; }

app_version() { cat "$HERE/VERSION" 2>/dev/null || echo 0; }

up() { curl -s -o /dev/null --max-time 2 "$URL"; }

saved_server() {
    if [ -n "${RIVENDELL_SERVER:-}" ]; then echo "$RIVENDELL_SERVER"; return; fi
    cat "$CONFIG/server" 2>/dev/null
}

# A typed address as https://host[:port], or nothing if it isn't one (http for localhost only)
normalise_server() {
    local text="$1" scheme rest host
    text="$(printf '%s' "$text" | tr -d '[:space:]')"
    [[ "$text" == *://* ]] || text="https://$text"
    scheme="${text%%://*}"; rest="${text#*://}"; host="${rest%%/*}"
    [[ "$host" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || return 1
    case "$scheme" in
        https) ;;
        http) [[ "${host%%:*}" =~ ^(localhost|127\.0\.0\.1)$ ]] || return 1 ;;
        *) return 1 ;;
    esac
    echo "$scheme://$host"
}

setup_server() {
    local typed server
    typed="$(zenity --entry --title="Set up Rivendell" --width=440 \
        --text="Your team's Rivendell server (https):" --entry-text="$(saved_server)" 2>/dev/null)" || exit 1
    server="$(normalise_server "$typed")" || { say error "'$typed' isn't a server address, e.g. rivendell.example.org (https only)."; exit 1; }
    printf '%s\n' "$server" > "$CONFIG/server"
    say info "Rivendell will open $server. If the browser warns about its certificate, ask the server's admin for its root certificate."
}

# ── Setup (the packaged app) ──────────────────────────────────────────────────
check_docker() {
    if ! command -v docker &>/dev/null; then
        if ! has_zenity; then
            notify "Rivendell needs Docker: https://docs.docker.com/engine/install/"
        elif zenity --question --title=Rivendell --width=440 --ok-label="Open install guide" --cancel-label=Close \
            --text="Rivendell runs on Docker, which isn't installed.\n\nInstall Docker Engine and its compose plugin (your distribution's docker.io and docker-compose-v2 packages, or Docker's own), then open Rivendell again." 2>/dev/null; then
            xdg-open https://docs.docker.com/engine/install/ &>/dev/null &
        fi
        exit 1
    fi
    local info
    info="$(docker info 2>&1)"
    if echo "$info" | grep -qi "permission denied"; then
        say error "Docker is installed, but you're not allowed to use it.\n\nAdd yourself to the docker group, then log out and back in:\n\n    sudo usermod -aG docker $USER"
        exit 1
    fi
    if ! docker compose version &>/dev/null && ! command -v docker-compose &>/dev/null; then
        say error "Docker's compose plugin isn't installed (docker-compose-v2 on Ubuntu and Debian, docker-compose-plugin from Docker's repository)."
        exit 1
    fi
}

unpack_to() {
    local target="$1"
    mkdir -p "$target" || return 1
    tar -xzf "$BUNDLED" -C "$target" --strip-components 1 || return 1
    app_version > "$target/.rivendell-version"
}

json_quote() {
    local s="${1//\\/\\\\}"
    printf '"%s"' "${s//\"/\\\"}"
}

write_evidence() {
    # write_evidence <root> <folder>...: each folder at its own path in the backend
    # (read-only) and the worker; leaves a hand-written docker-compose.local.yml alone
    local root="$1" file="$1/docker-compose.local.yml" service folder
    shift
    if [ -f "$file" ] && ! head -1 "$file" | grep -qF "$LOCAL_HEADER"; then
        say warning "$file was written by hand, so setup left its mounts alone."
        return 0
    fi
    if [ $# -eq 0 ]; then rm -f "$file"; return 0; fi
    {
        echo "$LOCAL_HEADER: evidence folders, mounted at the same path inside the containers."
        echo "services:"
        for service in backend celery-worker; do
            echo "  $service:"
            echo "    volumes:"
            for folder in "$@"; do
                echo "      - type: bind"
                echo "        source: $(json_quote "$folder")"
                echo "        target: $(json_quote "$folder")"
                [ "$service" = backend ] && echo "        read_only: true"
            done
        done
    } > "$file"
}

setup() {
    local root="" choice target folders=()
    if has_zenity; then
        choice="$(zenity --list --radiolist --title="Set up Rivendell" --width=560 --height=300 \
            --text="Where does Rivendell run?" --column="" --column="Option" \
            TRUE "Install Rivendell $(app_version) on this computer" \
            FALSE "Use a copy I already have (a git clone, for instance)" \
            FALSE "Connect to my team's Rivendell server" 2>/dev/null)" || exit 1
        if [[ "$choice" == Connect* ]]; then
            setup_server
            return
        fi
        rm -f "$CONFIG/server"
        check_docker
        if [[ "$choice" == Use* ]]; then
            root="$(zenity --file-selection --directory --title="Choose your Rivendell folder" 2>/dev/null)" || exit 1
            is_copy "$root" || { say error "$root doesn't look like Rivendell: there's no rivendell launcher and docker-compose.yml in it."; exit 1; }
        else
            target="$(zenity --file-selection --directory --title="Choose where to put the Rivendell folder" \
                --filename="$HOME/" 2>/dev/null)" || exit 1
            root="${target%/}/Rivendell"
        fi
    else
        check_docker
        root="$HOME/Rivendell"
        notify "Installing Rivendell into $root (install zenity to choose)"
    fi

    if [ ! -e "$root" ] || { is_copy "$root" && [ -f "$root/.rivendell-version" ] && [ ! -d "$root/.git" ]; }; then
        [ -f "$BUNDLED" ] || { say error "This install doesn't carry Rivendell's files."; exit 1; }
        notify "Copying Rivendell into $root…"
        unpack_to "$root" || { say error "Couldn't unpack Rivendell into $root. See $LOG"; exit 1; }
    elif ! is_copy "$root"; then
        say error "$root already exists and isn't Rivendell. Choose another folder."
        exit 1
    fi

    if has_zenity && zenity --question --title=Rivendell --width=440 --ok-label="Choose folders" --cancel-label=Skip \
        --text="Mount folders of evidence (disk images, memory dumps, Gandalf archives) into Rivendell at the same paths?\n\nOptional: run Set Up Rivendell again to change them." 2>/dev/null; then
        local picked
        picked="$(zenity --file-selection --directory --multiple --separator=$'\n' --title="Evidence folders" 2>/dev/null)" || true
        while IFS= read -r line; do [ -n "$line" ] && folders+=("$line"); done <<< "$picked"
    fi
    write_evidence "$root" "${folders[@]}"
    printf '%s\n' "$root" > "$CONFIG/root"
    echo "$root"
}

# ── Which copy to run ─────────────────────────────────────────────────────────
resolve_root() {
    if [ -n "${RIVENDELL_ROOT:-}" ] && is_copy "$RIVENDELL_ROOT"; then echo "$RIVENDELL_ROOT"; return; fi
    # A checkout's own app/linux: run that checkout
    if [ ! -f "$BUNDLED" ] && is_copy "$HERE/../.."; then (cd -P "$HERE/../.." && pwd); return; fi
    local saved
    saved="$(cat "$CONFIG/root" 2>/dev/null)"
    if [ -n "$saved" ] && is_copy "$saved"; then echo "$saved"; return; fi
    [ -f "$BUNDLED" ] || { say error "Can't find Rivendell. Set RIVENDELL_ROOT or reinstall."; exit 1; }
    setup
}

maybe_update() {
    local root="$1"
    [ -f "$BUNDLED" ] && [ -f "$root/.rivendell-version" ] && [ ! -d "$root/.git" ] || return 0
    [ "$(cat "$root/.rivendell-version")" = "$(app_version)" ] && return 0
    if ! has_zenity || zenity --question --title=Rivendell --width=440 --ok-label=Update --cancel-label="Not now" \
        --text="Update Rivendell in $root to $(app_version)?\n\nYour .env, evidence folders and cases are kept. The images are rebuilt on this start, which takes a while." 2>/dev/null; then
        notify "Updating Rivendell's files…"
        unpack_to "$root" || notify "Couldn't update $root. See $LOG"
    fi
}

open_window() {
    local browser
    # --class (with its own profile) gives the window WM_CLASS Rivendell, which the
    # desktop entry's StartupWMClass matches, so the dock shows Rivendell's icon
    for browser in chromium chromium-browser google-chrome google-chrome-stable brave-browser microsoft-edge; do
        if command -v "$browser" &>/dev/null; then
            exec "$browser" --app="$URL" --class=Rivendell --user-data-dir="$PROFILE" --no-first-run
        fi
    done
    exec xdg-open "$URL"
}

case "${1:-}" in
    --setup)
        [ -f "$BUNDLED" ] || { say info "This is a checkout's launcher: it always runs $(cd -P "$HERE/../.." && pwd)."; exit 0; }
        setup >/dev/null
        [ -n "$(saved_server)" ] || exit 0
        ;;
    --stop)
        if [ -n "$(saved_server)" ]; then
            say info "Rivendell runs on $(saved_server); its admins start and stop it."
            exit 0
        fi
        ROOT="$(resolve_root)" || exit 1
        notify "Stopping Rivendell…"
        "$ROOT/rivendell" stop >> "$LOG" 2>&1 && notify "Rivendell is stopped."
        exit 0
        ;;
esac

SERVER="$(saved_server)"
if [ -n "$SERVER" ]; then
    URL="$SERVER"
    open_window
fi

ROOT="$(resolve_root)" || exit 1
# Setup may just have chosen a server
SERVER="$(saved_server)"
if [ -n "$SERVER" ]; then
    URL="$SERVER"
    open_window
fi
maybe_update "$ROOT"

if ! up; then
    if has_zenity; then
        # The road to Rivendell: phases and an ETA from this machine's earlier starts
        "$ROOT/rivendell" start --progress=zenity 2>&1 | tee -a "$LOG" |
            zenity --progress --title="The road to Rivendell" --width=480 --auto-close --no-cancel \
                --text="Gandalf sets out from the Shire" --percentage=0 2>/dev/null
        status=${PIPESTATUS[0]}
    else
        notify "Starting the Docker stack…"
        "$ROOT/rivendell" start >> "$LOG" 2>&1
        status=$?
    fi
    if [ "$status" -ne 0 ]; then
        notify "'rivendell start' failed. See $LOG"
        exit 1
    fi
    for _ in $(seq 1 450); do
        up && break
        sleep 2
    done
    if ! up; then
        notify "The stack started but nothing answered on $URL. Try 'rivendell status'."
        exit 1
    fi
fi

open_window

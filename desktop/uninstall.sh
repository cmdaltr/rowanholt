#!/bin/sh
# Remove the Rowanholt desktop app from macOS or Linux (app/README.md).
#
#   sh desktop/uninstall.sh              remove the app, then ask before deleting its files folder and
#                                Rowanholt's Docker data
#   sh desktop/uninstall.sh --keep-data  remove the app only: the files folder and Docker data stay for a reinstall
#   sh desktop/uninstall.sh --yes        don't ask: delete the files folder and the Docker data too
#
# The files folder is the copy of Rowanholt the app unpacked (~/Rowanholt unless setup chose another):
# .env, the evidence mounts in docker-compose.local.yml, the stack's source. The Docker data is the
# stack's volumes and images: the job database (users, jobs, cases' findings and notes), uploads, and
# Splunk and Elastic indexes. Without a terminal to ask on, both are kept unless --yes says otherwise.
# Never touched: a git checkout setup was pointed at, a stack run from a checkout, case output
# folders and evidence (they live wherever the jobs put them), and a checkout's own app
# (`rowanholt app install`; `rowanholt app uninstall` removes that).
set -eu

data=ask
while [ $# -gt 0 ]; do
    case "$1" in
        --keep-data) data=keep; shift ;;
        --yes|-y) data=delete; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) printf 'uninstall.sh: unknown option %s\n' "$1" >&2; exit 1 ;;
    esac
done

if [ -t 1 ]; then c=$(printf '\033[36m'); g=$(printf '\033[32m'); d=$(printf '\033[2m'); r=$(printf '\033[31m'); o=$(printf '\033[0m')
else c= g= d= r= o=; fi
n=0
steps=4
step() { n=$((n + 1)); printf '\n%s[%d/%d] %s%s\n' "$c" "$n" "$steps" "$*" "$o"; }
ok() { printf '      %sOK  %s%s\n' "$g" "$*" "$o"; }
note() { printf '      %s%s%s\n' "$d" "$*" "$o"; }
die() { printf '\n%suninstall.sh: %s%s\n' "$r" "$*" "$o" >&2; exit 1; }

# Asks once per question; anything but y, or no terminal, is no
confirm() {
    [ $data = delete ] && return 0
    [ $data = keep ] && return 1
    [ -t 0 ] || return 1
    printf '      %s [y/N] ' "$1"
    read -r answer
    case "$answer" in [yY]*) return 0 ;; *) return 1 ;; esac
}

BUNDLE_ID=io.github.cmdaltr.rowanholt  # the release app's (app/macos/build.sh); a checkout's ends .local
case "$(uname -s)" in
    Darwin) os=mac ;;
    Linux) os=linux; config="${XDG_CONFIG_HOME:-$HOME/.config}/rowanholt" ;;
    *) die "no Rowanholt desktop app for $(uname -s)" ;;
esac

# The files folder setup chose, read before the app (and the preferences that record it) go
root="${ROWANHOLT_ROOT:-}"
if [ -z "$root" ]; then
    if [ $os = mac ]; then root=$(defaults read "$BUNDLE_ID" RowanholtRoot 2>/dev/null || true)
    else root=$(cat "$config/root" 2>/dev/null || true); fi
fi
[ -n "$root" ] || root="$HOME/Rowanholt"

# Whose stack is running: compose records the folder it was started from on each container. The app's
# copy is ours to stop and clear; a git checkout's is someone's working tree, and shares the volume
# names, so then the Docker data is left alone too
docker_ok=
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker_ok=1
stack_dirs=
[ -n "$docker_ok" ] && stack_dirs=$(docker ps -a --filter label=com.docker.compose.project=rowanholt \
    --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null | sort -u || true)
checkout_stack=$(printf '%s\n' "$stack_dirs" | while IFS= read -r dir; do
    [ -n "$dir" ] && [ -d "$dir/.git" ] && { printf '%s\n' "$dir"; break; }
done)

printf '\n  Rowanholt: desktop app uninstaller\n'

step "Stopping Rowanholt"
if [ $os = mac ] && pgrep -xq Rowanholt; then
    osascript -e 'quit app "Rowanholt"' >/dev/null 2>&1 || true; sleep 2; pkill -x Rowanholt || true
    note "Quit the app"
fi
if [ -z "$docker_ok" ]; then
    ok "Docker isn't running: nothing to stop"
elif [ -n "$checkout_stack" ]; then
    ok "The stack running is the checkout at $checkout_stack, not the app's: left running"
elif [ -n "$stack_dirs" ]; then
    # Stopping ends any analysis mid-run, as `rowanholt stop` does; the volumes stay until step 4
    docker compose -p rowanholt down --remove-orphans >/dev/null 2>&1 || die "couldn't stop the stack (docker compose -p rowanholt down)"
    ok "Stack stopped"
else
    ok "Not running"
fi

step "Removing the app"
if [ $os = mac ]; then
    removed=
    for app in /Applications/Rowanholt.app "$HOME/Applications/Rowanholt.app"; do
        [ -d "$app" ] || continue
        id=$(defaults read "$app/Contents/Info" CFBundleIdentifier 2>/dev/null || true)
        if [ "$id" != "$BUNDLE_ID" ]; then
            note "$app is a checkout's build ($id): left for rowanholt app uninstall"
            continue
        fi
        if [ -w "$(dirname "$app")" ]; then rm -rf "$app"
        else note "$(dirname "$app") needs administrator rights: sudo may ask for your password"; sudo rm -rf "$app"; fi
        ok "$app"
        removed=1
    done
    [ -n "$removed" ] || ok "No release Rowanholt.app in /Applications or ~/Applications"
    # What macOS keeps per app outside the files folder: WKWebView's storage, web logins, window state.
    # The preferences go through defaults first, or cfprefsd writes its cached copy back
    defaults delete "$BUNDLE_ID" >/dev/null 2>&1 || true
    for f in "$HOME/Library/Caches/$BUNDLE_ID" "$HOME/Library/WebKit/$BUNDLE_ID" \
             "$HOME/Library/HTTPStorages/$BUNDLE_ID" "$HOME/Library/HTTPStorages/$BUNDLE_ID".binarycookies* \
             "$HOME/Library/Preferences/$BUNDLE_ID.plist" \
             "$HOME/Library/Saved Application State/$BUNDLE_ID.savedState"; do
        [ -e "$f" ] || continue
        rm -rf "$f"
        note "Removed $f"
    done
else
    if dpkg -s rowanholt >/dev/null 2>&1; then
        sudo=""
        if [ "$(id -u)" -ne 0 ]; then
            sudo=sudo
            note "apt needs administrator rights: sudo may ask for your password"
        fi
        $sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq rowanholt >/dev/null || die "apt couldn't remove rowanholt"
        ok "rowanholt package purged"
        note "zenity and the rest stay: other apps use them (sudo apt autoremove clears what nothing needs)"
    else
        ok "The rowanholt package isn't installed"
    fi
    # The launcher's own per-user state: the saved files folder and server, its browser profile (web
    # logins) and log. The start-time history in ~/.local/state/rowanholt is shared with checkouts: kept
    for f in "$config" "${XDG_DATA_HOME:-$HOME/.local/share}/rowanholt/browser" \
             "${XDG_STATE_HOME:-$HOME/.local/state}/rowanholt/app.log"; do
        [ -e "$f" ] || continue
        rm -rf "$f"
        note "Removed $f"
    done
fi

step "The files folder"
if [ ! -d "$root" ]; then
    ok "None at $root"
elif [ -d "$root/.git" ]; then
    # Setup can run an existing checkout instead of unpacking a copy: that's your working tree
    ok "Kept $root: it's a git checkout, not a copy the app unpacked"
elif [ ! -f "$root/.rowanholt-version" ]; then
    ok "Kept $root: it isn't a copy the app unpacked (no .rowanholt-version)"
else
    size=$(du -sh "$root" 2>/dev/null | cut -f1 | tr -d ' ')
    if confirm "Delete $root ($size): .env, the evidence mounts and the stack's files? It can't be undone."; then
        rm -rf "$root"
        ok "Deleted $root ($size)"
    else
        ok "Kept $root ($size): delete it to start again, or reinstall to carry on"
    fi
fi

step "Rowanholt's Docker data"
if [ -z "$docker_ok" ]; then
    ok "Docker isn't running: nothing checked (start it and run this again to remove the data)"
elif [ -n "$checkout_stack" ]; then
    ok "Kept: the checkout at $checkout_stack uses the same volumes"
else
    volumes=$(docker volume ls -q --filter label=com.docker.compose.project=rowanholt 2>/dev/null || true)
    images=$( { docker images -q --filter label=com.docker.compose.project=rowanholt
                docker images --format '{{.Repository}} {{.ID}}' | awk '$1 ~ /^rowanholt-/ { print $2 }'; } 2>/dev/null | sort -u)
    nv=$(printf '%s\n' "$volumes" | grep -c . || true)
    ni=$(printf '%s\n' "$images" | grep -c . || true)
    if [ "$nv" -eq 0 ] && [ "$ni" -eq 0 ]; then
        ok "None"
    elif confirm "Remove $nv volume(s) and $ni image(s): the job database (users, jobs, cases' findings and notes), uploads and SIEM indexes? Case output folders and evidence aren't touched. It can't be undone."; then
        # shellcheck disable=SC2086  # one id per word
        if [ -n "$volumes" ]; then docker volume rm $volumes >/dev/null || die "couldn't remove the volumes (is a container still using them?)"; fi
        # shellcheck disable=SC2086
        [ -n "$images" ] && docker rmi -f $images >/dev/null 2>&1 || true
        ok "Removed $nv volume(s) and $ni image(s)"
    else
        ok "Kept $nv volume(s) and $ni image(s): a reinstall picks up the cases where they were"
    fi
fi

printf '\n  %sRowanholt is uninstalled.%s\n' "$g" "$o"

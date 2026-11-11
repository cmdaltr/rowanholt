#!/bin/sh
# Install or upgrade the Rowanholt desktop app on macOS or Linux from a GitHub release (app/README.md).
#
#   sh app/install.sh                    the latest release
#   sh app/install.sh --version v1.4.0   a given release
#   sh app/install.sh --file Rowanholt-1.4.0-macos-universal.dmg
#                                    an installer already downloaded (no checksum: you chose the file)
#   sh app/install.sh --launch           open Rowanholt when it's installed
#   sh app/install.sh --clean            a clean install: once the new installer is downloaded and checked,
#                                    remove the current app, its files folder and Rowanholt's Docker
#                                    data (the job database: cases' findings and notes) first
#
# The repository is public, so no token is needed; GH_TOKEN, GITHUB_TOKEN or a logged-in gh is used
# when there is one, for GitHub's higher rate limit (as app/install.ps1). The installer is checked
# against the release's SHA256SUMS before use.
set -eu

REPO="${ROWANHOLT_REPO:-cmdaltr/rowanholt}"
version=latest
file=
launch=
clean=
dry=
started=$(date +%s)

# Numbered steps, so it's clear how far through the install is. Colour only on a terminal.
if [ -t 1 ]; then c=$(printf '\033[36m'); g=$(printf '\033[32m'); d=$(printf '\033[2m'); r=$(printf '\033[31m'); o=$(printf '\033[0m')
else c= g= d= r= o=; fi
n=0
steps=0
step() { n=$((n + 1)); printf '\n%s[%d/%d] %s%s\n' "$c" "$n" "$steps" "$*" "$o"; }
ok() { printf '      %sOK  %s%s\n' "$g" "$*" "$o"; }
note() { printf '      %s%s%s\n' "$d" "$*" "$o"; }
die() { printf '\n%sinstall.sh: %s%s\n' "$r" "$*" "$o" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a tag}"; shift 2 ;;
        --file) file="${2:?--file needs a path}"; shift 2 ;;
        --launch) launch=1; shift ;;
        --clean) clean=1; shift ;;
        --dry-run) dry=1; shift ;;  # undocumented: say what would be installed, change nothing
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

# One package per platform runs on every CPU (app/README.md): the packages hold the launcher and the
# source tree, and Docker builds the stack's images for this machine when it first starts
case "$(uname -s)" in
    Darwin) kind=dmg; suffix=-macos-universal.dmg ;;
    Linux)
        if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
            kind=deb; suffix=_all.deb
        elif command -v dnf >/dev/null 2>&1; then
            # The desktop app is Debian and Ubuntu's, as Shikari's is; Rocky, RHEL and Alma run team servers
            die "the desktop app is for Debian and Ubuntu. On Rocky, RHEL or Alma, run Rowanholt as a team server from a checkout: git clone https://github.com/$REPO && ./rowanholt server init (docs/SERVER.md)"
        else
            die "this installer needs apt (Debian or Ubuntu). Run Rowanholt from a checkout: git clone https://github.com/$REPO && ./rowanholt start"
        fi
        ;;
    *) die "no Rowanholt desktop app for $(uname -s)" ;;
esac

if [ -n "$dry" ]; then
    printf 'platform: %s %s\nrelease: %s of %s\nasset: *%s\nfile: %s\nclean: %s\nlaunch: %s\n' \
        "$(uname -s)" "$(uname -m)" "$version" "$REPO" "$suffix" "${file:-(download)}" "${clean:-no}" "${launch:-no}"
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --clean runs the uninstaller beside this script (the repository's app/, or the installed app's
# Resources or /opt/rowanholt). Copied out first: it deletes the app this script may be running from
if [ -n "$clean" ]; then
    [ -f "$(dirname "$0")/uninstall.sh" ] || die "--clean needs uninstall.sh beside install.sh: app/uninstall.sh in the repository, Rowanholt.app/Contents/Resources/uninstall.sh or /opt/rowanholt/uninstall.sh"
    cp "$(dirname "$0")/uninstall.sh" "$tmp/uninstall.sh"
fi

# Find, download and check the installer when there's no --file, (clean,) install it, done
[ -n "$file" ] && steps=1 || steps=4
[ -n "$clean" ] && steps=$((steps + 1))
printf '\n  Rowanholt: desktop app installer\n'
printf '  %sThe rowan wood: Gandalf acquires, Elrond analyses, Aul\303\253 answers%s\n' "$d" "$o"

# Picks a field out of the release JSON on stdin. macOS has no python3 without the developer
# tools, but always has JavaScript for Automation; Debian and Ubuntu always have python3.
# Prints "<name>\t<api url>" per asset.
assets() {
    if [ "$(uname -s)" = Darwin ]; then
        osascript -l JavaScript -e 'function run(argv) {
            var r = JSON.parse($.NSString.alloc.initWithDataEncoding($.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile, $.NSUTF8StringEncoding).js);
            if (!r.assets) throw new Error(r.message || "no release");
            return r.assets.map(function (a) { return a.name + "\t" + a.url; }).join("\n");
        }'
    else
        python3 -c 'import json, sys
r = json.load(sys.stdin)
if "assets" not in r: sys.exit(r.get("message", "no release"))
print("\n".join(a["name"] + "\t" + a["url"] for a in r["assets"]))'
    fi
}

if [ -z "$file" ]; then
    token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    if [ -z "$token" ] && command -v gh >/dev/null 2>&1; then
        token=$(gh auth token 2>/dev/null || true)
    fi
    if [ -n "$token" ]; then
        get() { curl -fsSL -H "Authorization: Bearer $token" "$@"; }
        bar() { curl -fL -# -H "Authorization: Bearer $token" "$@"; }
    else
        get() { curl -fsSL "$@"; }
        bar() { curl -fL -# "$@"; }
    fi

    step "Finding the $version release of $REPO"
    [ "$version" = latest ] && path=releases/latest || path="releases/tags/$version"
    get -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$path" > "$tmp/release.json" \
        || die "couldn't read $version from $REPO"
    assets < "$tmp/release.json" > "$tmp/assets" || die "couldn't read the release's assets"

    name=$(awk -F '\t' -v s="$suffix" 'substr($1, length($1) - length(s) + 1) == s { print $1; exit }' "$tmp/assets")
    [ -n "$name" ] || die "the $version release has no *$suffix"
    url() { awk -F '\t' -v n="$1" '$1 == n { print $2; exit }' "$tmp/assets"; }
    [ -n "$(url SHA256SUMS)" ] || die "the $version release has no SHA256SUMS"
    ok "$name"

    step "Downloading $name"
    # curl's own bar on a terminal (get's -s would hide it); quiet in a log
    if [ -t 2 ]; then
        bar -H "Accept: application/octet-stream" -o "$tmp/$name" "$(url "$name")"
    else
        get -H "Accept: application/octet-stream" -o "$tmp/$name" "$(url "$name")"
    fi
    get -H "Accept: application/octet-stream" -o "$tmp/SHA256SUMS" "$(url SHA256SUMS)"
    ok "$(du -h "$tmp/$name" | cut -f1 | tr -d ' ') downloaded"

    step "Checking it against the release's SHA256SUMS"
    expected=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$tmp/SHA256SUMS")
    actual=$(shasum -a 256 "$tmp/$name" 2>/dev/null || sha256sum "$tmp/$name")
    [ -n "$expected" ] && [ "${actual%% *}" = "$expected" ] || die "$name doesn't match SHA256SUMS: not installing it"
    ok "SHA-256 matches"
    file="$tmp/$name"
fi
[ -f "$file" ] || die "no such file: $file"
case "$file" in /*) ;; *) file="$PWD/$file" ;; esac

if [ -n "$clean" ]; then
    step "Removing the current install, its files folder and Rowanholt's Docker data"
    sh "$tmp/uninstall.sh" --yes < /dev/null | grep '^      ' || true
fi

step "Installing $(basename "$file")"

case "$kind" in
    dmg)
        mnt="$tmp/mnt"
        mkdir -p "$mnt"
        note "Opening the disk image"
        hdiutil attach -nobrowse -quiet -mountpoint "$mnt" "$file"
        # /Applications needs an admin account; anyone else gets their own Applications folder
        dest=/Applications
        [ -w "$dest" ] || { dest="$HOME/Applications"; mkdir -p "$dest"; }
        pgrep -xq Rowanholt && note "Rowanholt is running: quit it to use the new version (the stack keeps running)"
        note "Copying Rowanholt.app to $dest"
        rm -rf "$dest/Rowanholt.app"
        ditto "$mnt/Rowanholt.app" "$dest/Rowanholt.app"
        hdiutil detach -quiet "$mnt"
        ok "$dest/Rowanholt.app"
        where="Open it from Launchpad or $dest"
        ;;
    deb)
        # apt rather than dpkg, so the launcher's dependencies (curl, xdg-utils, zenity) come with it
        sudo=""
        if [ "$(id -u)" -ne 0 ]; then
            sudo=sudo
            note "apt needs administrator rights: sudo may ask for your password"
            sudo true || die "no administrator rights"
        fi
        # apt's own output is long: keep it in a log, show a clock so it doesn't look stuck, and print
        # the end of the log if it fails
        note "apt is installing it with what the launcher needs"
        $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$file" > "$tmp/apt.log" 2>&1 &
        pid=$!
        t=0
        while kill -0 "$pid" 2>/dev/null; do
            [ -t 1 ] && printf '\r      %s%dm %02ds%s' "$d" $((t / 60)) $((t % 60)) "$o"
            sleep 1
            t=$((t + 1))
        done
        [ -t 1 ] && printf '\r              \r'
        if ! wait "$pid"; then
            tail -n 25 "$tmp/apt.log" >&2
            die "apt couldn't install $(basename "$file")"
        fi
        ok "Installed, with $(grep -c '^Setting up' "$tmp/apt.log") package(s)"
        where="Open Rowanholt from the applications menu"
        ;;
esac

took=$(( $(date +%s) - started ))
printf '\n  %sRowanholt is installed (%dm %ds). %s.%s\n' "$g" $((took / 60)) $((took % 60)) "$where" "$o"
printf '  %sThe first launch sets up Docker and Rowanholt'\''s files; the first start builds the stack (a while), then seconds.%s\n' "$d" "$o"
if [ -n "$launch" ]; then
    case "$kind" in dmg) open "$dest/Rowanholt.app" ;; deb) (/opt/rowanholt/rowanholt-app.sh >/dev/null 2>&1 &) ;; esac
fi

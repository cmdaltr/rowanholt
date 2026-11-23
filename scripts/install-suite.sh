#!/bin/sh
# Install or upgrade the suite on macOS or Linux: Ostraka (incident record), Rowanholt (evidence and
# analysis) and Shikari (detection and hunting), each from its latest GitHub release.
#
# The same file is in all three repositories (scripts/install-suite.sh); change it in all three.
# It doesn't install anything itself: for each product it finds the latest release, fetches that
# release's own desktop/install.sh (from the release's tag, so the installer matches the packages),
# and runs it with --version <tag>. Each product's installer picks the package for this machine and
# checks it against the release's SHA256SUMS, as when it's run alone.
#
#   curl -fsSLO https://raw.githubusercontent.com/cmdaltr/ostraka/main/scripts/install-suite.sh
#   sh install-suite.sh                         all three
#   sh install-suite.sh --only ostraka,shikari  some of them
#   sh install-suite.sh --skip rowanholt        all but some
#   sh install-suite.sh --launch                open each one once it's installed
#   sh install-suite.sh --dry-run               say what would be installed, install nothing
#
# All three repositories are public, so no token is needed; GH_TOKEN, GITHUB_TOKEN or a logged-in gh
# is used when there is one, for GitHub's higher rate limit. Run it as a file; don't pipe it into a
# shell: each installer may ask before replacing something.
set -eu

ALL="ostraka rowanholt shikari"
OWNER="${SUITE_OWNER:-cmdaltr}"
# Only the tests point these elsewhere (file:// trees shaped like the API and raw.githubusercontent.com)
API="${SUITE_GITHUB_API:-https://api.github.com}"
RAW="${SUITE_GITHUB_RAW:-https://raw.githubusercontent.com}"
only=
skip=
launch=
dry_run=

if [ -t 1 ]; then c=$(printf '\033[36m'); g=$(printf '\033[32m'); d=$(printf '\033[2m'); r=$(printf '\033[31m'); o=$(printf '\033[0m')
else c='' g='' d='' r='' o=''; fi
say() { printf '%s%s%s\n' "$c" "$*" "$o"; }
note() { printf '  %s%s%s\n' "$d" "$*" "$o"; }
die() { printf '\n%sinstall-suite.sh: %s%s\n' "$r" "$*" "$o" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --only) only="${2:?--only needs a list, such as ostraka,shikari}"; shift 2 ;;
        --skip) skip="${2:?--skip needs a list, such as rowanholt}"; shift 2 ;;
        --launch) launch=1; shift ;;
        --dry-run) dry_run=1; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

listed() { # listed NAME "a,b c": whether NAME is in a comma- or space-separated list
    for _entry in $(printf "%s" "$2" | tr "," " "); do [ "$_entry" = "$1" ] && return 0; done
    return 1
}
for item in $(printf '%s %s' "$only" "$skip" | tr ',' ' '); do
    listed "$item" "$ALL" || die "there's no $item in the suite: choose from ostraka, rowanholt, shikari"
done
chosen=
for product in $ALL; do
    if [ -n "$only" ] && ! listed "$product" "$only"; then continue; fi
    if listed "$product" "$skip"; then continue; fi
    chosen="$chosen $product"
done
[ -n "$chosen" ] || die "nothing left to install"

command -v curl >/dev/null 2>&1 || die "curl is needed"
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$token" ] && command -v gh >/dev/null 2>&1; then token=$(gh auth token 2>/dev/null || true); fi

get() { # get URL OUT
    if [ -n "$token" ] && [ "${1#https://api.github.com}" != "$1" ]; then
        curl -fsSL -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" -o "$2" "$1"
    else
        curl -fsSL -o "$2" "$1"
    fi
}

work=$(mktemp -d "${TMPDIR:-/tmp}/install-suite.XXXXXX")
trap 'rm -rf "$work"' EXIT

latest_tag() { # latest_tag REPO: the tag of the repository's latest release
    get "$API/repos/$1/releases/latest" "$work/latest.json" || return 1
    sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$work/latest.json" | head -1
}

name_of() {
    case "$1" in ostraka) echo Ostraka ;; rowanholt) echo Rowanholt ;; shikari) echo Shikari ;; esac
}

installed=
failed=
for product in $chosen; do
    name=$(name_of "$product")
    repo="$OWNER/$product"
    say "$name"
    tag=$(latest_tag "$repo") || tag=
    if [ -z "$tag" ]; then
        printf '  %scouldn'"'"'t find a release of %s%s\n' "$r" "$repo" "$o" >&2
        failed="$failed $name"
        continue
    fi
    case "$tag" in v[0-9]*) ;; *) die "$repo's latest release has an unexpected tag: $tag" ;; esac
    note "latest release $tag"
    if [ -n "$dry_run" ]; then
        note "would run $RAW/$repo/$tag/desktop/install.sh --version $tag${launch:+ --launch}"
        continue
    fi
    installer="$work/$product-install.sh"
    if ! get "$RAW/$repo/$tag/desktop/install.sh" "$installer"; then
        printf '  %scouldn'"'"'t fetch %s'"'"'s installer for %s%s\n' "$r" "$name" "$tag" "$o" >&2
        failed="$failed $name"
        continue
    fi
    if sh "$installer" --version "$tag" ${launch:+--launch}; then
        installed="$installed $name"
    else
        failed="$failed $name"
    fi
    echo
done

[ -n "$dry_run" ] && exit 0
[ -n "$installed" ] && printf '%sInstalled:%s%s\n' "$g" "$installed" "$o"
if [ -n "$failed" ]; then
    printf '%sNot installed:%s%s\n' "$r" "$failed" "$o" >&2
    exit 1
fi

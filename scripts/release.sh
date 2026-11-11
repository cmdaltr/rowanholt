#!/usr/bin/env bash
# Build Rowanholt's release files on this machine into dist/<version>/, with SHA256SUMS, for testing
# them locally before a tag (as Ostraka's scripts/release.sh). Nothing goes to GitHub: a pushed v* tag
# builds the same files there (.github/workflows/desktop-release.yml), smoke-tests each on its own
# runner and attaches them to a draft release.
#
#   rowanholt release                    a dev build: pyproject.toml's version plus -dev.<commits>
#   rowanholt release --version 2.1.0    that version (it must be pyproject.toml's, or a pre-release of it)
#
# The files, named as desktop/README.md gives them: rowanholt-<v>-source.tar.gz,
# Rowanholt-<v>-macos-universal.dmg (on a Mac), rowanholt_<v>-1_all.deb (dpkg-deb here, or in an
# Ubuntu container when Docker is running), and Rowanholt-<v>-windows-universal.msi, which only
# builds on Windows (WiX writes MSIs through Windows' own msi.dll): it's skipped here with the command
# to run there. Packages are git archive HEAD, so the working tree must be committed first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

version=
while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a version, e.g. 2.1.0}"; shift 2 ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "release.sh: unknown option $1" >&2; exit 1 ;;
    esac
done

if [ -t 1 ]; then c=$'\033[36m'; g=$'\033[32m'; y=$'\033[33m'; r=$'\033[31m'; o=$'\033[0m'
else c='' g='' y='' r='' o=''; fi
step() { printf '\n%s== %s%s\n' "$c" "$*" "$o"; }
ok() { printf '   %sOK%s    %s\n' "$g" "$o" "$*"; }
skip() { printf '   %sSKIP%s  %s\n' "$y" "$o" "$*"; }
die() { printf '\n%srelease.sh: %s%s\n' "$r" "$*" "$o" >&2; exit 1; }

code_version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' pyproject.toml | head -1)
[ -n "$code_version" ] || die "no version in pyproject.toml"
if [ -z "$version" ]; then
    version="$code_version-dev.$(git rev-list --count HEAD)"
else
    version="${version#v}"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
    || die "--version $version isn't n.n.n or n.n.n-pre (a pre-release is 2.1.0-rc1, with a hyphen)"
[ "${version%%-*}" = "$code_version" ] \
    || die "--version $version isn't pyproject.toml's $code_version: bump it there and commit first"

# A package is git archive HEAD: an uncommitted change would be in the files' names but not in them
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    git status --short --untracked-files=no >&2
    die "the working tree has uncommitted changes: commit or stash them first"
fi

out="$ROOT/dist/$version"
rm -rf "$out"  # a fresh folder, so SHA256SUMS never lists a file from an earlier build
mkdir -p "$out"
started=$(date +%s)
printf '\n  Rowanholt %s, built locally from %s\n' "$version" "$(git rev-parse --short=12 HEAD)"

step "Source tree"
source="rowanholt-$version-source.tar.gz"
desktop/source-tarball.sh "$out/$source" "$version"
ok "$source"

docker_up=
docker info >/dev/null 2>&1 && docker_up=1

step "Rowanholt-$version-macos-universal.dmg"
if [ "$(uname -s)" = Darwin ]; then
    desktop/macos/package.sh --version "$version" --source "$out/$source" "$out" >"$out/.macos.log" 2>&1 \
        || { tail -20 "$out/.macos.log" >&2; die "the DMG didn't build (log: $out/.macos.log)"; }
    ok "Rowanholt-$version-macos-universal.dmg (ad-hoc signed unless MACOS_SIGN_IDENTITY is set)"
else
    skip "needs macOS (swiftc, hdiutil): build it on a Mac"
fi

step "rowanholt_$version-1_all.deb"
if command -v dpkg-deb >/dev/null 2>&1; then
    desktop/linux/package-deb.sh --version "$version" --source "$out/$source" "$out" >/dev/null
    ok "rowanholt_$version-1_all.deb"
elif [ -n "$docker_up" ]; then
    # In a throwaway Ubuntu 22.04 container (the oldest the .deb supports), files handed back to this user
    docker run --rm -v "$ROOT:/src" -w /src ubuntu:22.04 bash -euo pipefail -c "
        apt-get -qq update >/dev/null && apt-get -qq install -y dpkg-dev >/dev/null
        desktop/linux/package-deb.sh --version '$version' --source 'dist/$version/$source' 'dist/$version' >/dev/null
        chown -R $(id -u):$(id -g) dist"
    ok "rowanholt_$version-1_all.deb (built in an ubuntu:22.04 container)"
else
    skip "needs dpkg-deb, or Docker running to use it in a container"
fi

step "Rowanholt-$version-windows-universal.msi"
skip "builds on Windows only: there, with the .NET SDK and WiX 5.0.2 (desktop/windows/build-msi.ps1):"
printf '         powershell -File desktop\\windows\\build-msi.ps1 -Version %s -Tarball dist\\%s\\%s -OutDir dist\\%s\n' \
    "$version" "$version" "$source" "$version"

step "SHA256SUMS"
rm -f "$out/.macos.log"
(cd "$out" && shasum -a 256 -- * > SHA256SUMS && sed 's/^/   /' SHA256SUMS)

printf '\n  %sBuilt in %ds:%s %s\n' "$g" "$(( $(date +%s) - started ))" "$o" "$out"
printf '  Try one with the release installers: sh desktop/install.sh --file %s/<file>\n' "dist/$version"

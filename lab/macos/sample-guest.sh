#!/bin/sh
# Inside the macOS sample VM, as root: sample.sh copies it in and runs
#   sudo -n sh sample-guest.sh prepare <hostname> <pwsh-version> <pwsh-sha256> <module-version> <atomics-commit> <atomics-dir> <T1,T2>
# Names the machine, checks it can reach GitHub, installs PowerShell 7 (the release package,
# checked against its SHA-256), Invoke-AtomicRedTeam (PowerShell Gallery) and the atomics at one
# commit, checks every technique has macOS tests, then whether eslogger may run. Prints markers
# sample.sh reads: NO-INTERNET, NO-MACOS-TESTS <ids>, TESTS <n>, ES=ok or ES=denied.
set -eu
[ "${1:-}" = prepare ] || { echo "usage: sample-guest.sh prepare ..." >&2; exit 2; }
name="$2" pwsh_version="$3" pwsh_sha="$4" module_version="$5" commit="$6" atomics="$7" techniques="$8"
owner="${SUDO_USER:-admin}"

scutil --set ComputerName "$name"
scutil --set HostName "$name"
scutil --set LocalHostName "$name"

curl -fsI --max-time 20 https://github.com >/dev/null 2>&1 || { echo NO-INTERNET; exit 3; }

if [ "$(/usr/local/bin/pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null || true)" != "$pwsh_version" ]; then
  echo "Installing PowerShell $pwsh_version"
  pkg=/tmp/powershell-$pwsh_version-osx-arm64.pkg
  curl -fsSL --retry 3 -o "$pkg" "https://github.com/PowerShell/PowerShell/releases/download/v$pwsh_version/powershell-$pwsh_version-osx-arm64.pkg"
  echo "$pwsh_sha  $pkg" | shasum -a 256 -c - >/dev/null || { echo "PowerShell's package doesn't match its SHA-256 ($pwsh_sha)"; exit 4; }
  installer -pkg "$pkg" -target / >/dev/null
  rm -f "$pkg"
fi

echo "Installing Invoke-AtomicRedTeam $module_version"
MODULE_VERSION="$module_version" /usr/local/bin/pwsh -NoProfile -Command '
  if (-not (Get-Module -ListAvailable invoke-atomicredteam | Where-Object { $_.Version -eq $env:MODULE_VERSION })) {
    Install-Module invoke-atomicredteam -RequiredVersion $env:MODULE_VERSION -Scope AllUsers -Force
  }'

# The atomics with their payloads (src/: the plists the launch agent tests copy), at one commit,
# so a rebuild runs the same tests. A plain download and unzip: no installer script fetched and run
if [ "$(cat "$atomics/.commit" 2>/dev/null || true)" != "$commit" ]; then
  echo "Downloading the atomics at $commit"
  zip=/tmp/atomic-red-team-$commit.zip unpacked=/tmp/atomic-red-team-unpacked
  curl -fsSL --retry 3 -o "$zip" "https://github.com/redcanaryco/atomic-red-team/archive/$commit.zip"
  rm -rf "$unpacked"
  unzip -q "$zip" "atomic-red-team-$commit/atomics/*" -d "$unpacked"
  rm -rf "$atomics"
  mkdir -p "$(dirname "$atomics")"
  mv "$unpacked/atomic-red-team-$commit/atomics" "$atomics"
  echo "$commit" > "$atomics/.commit"
  chown -R "$owner" "$(dirname "$atomics")"
  rm -rf "$zip" "$unpacked"
fi

# Invoke-MordorRecord.ps1 only warns about a technique with nothing to run; here that's a stop.
# ATT&CK v20 moved some IDs (log clearing is T1685.006, no longer T1070.002), and the atomics with them
TECHNIQUES="$techniques" ATOMICS="$atomics" /usr/local/bin/pwsh -NoProfile -Command '
  Import-Module invoke-atomicredteam
  $count = 0; $missing = @()
  foreach ($t in $env:TECHNIQUES -split ",") {
    $yaml = Join-Path $env:ATOMICS "$t/$t.yaml"
    $n = 0
    if (Test-Path $yaml) {
      $n = @((Get-AtomicTechnique -Path $yaml).atomic_tests | Where-Object { $_.supported_platforms -contains "macos" -and $_.executor.name -ne "manual" }).Count
    }
    if ($n -eq 0) { $missing += $t } else { "  $t  $n macOS tests"; $count += $n }
  }
  if ($missing) { "NO-MACOS-TESTS " + ($missing -join ","); exit 5 }
  "TESTS $count"'

# eslogger needs Full Disk Access for whatever is responsible for it: here sshd, which has none
# unless it was granted in the GUI (System Settings, Remote Login) or TCC.db, which SIP protects
err=/tmp/eslogger-check.err
/usr/bin/eslogger exec >/dev/null 2>"$err" &
pid=$!
sleep 3
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  echo ES=ok
else
  echo ES=denied
  sed 's/^/  eslogger: /' "$err"
fi
rm -f "$err"

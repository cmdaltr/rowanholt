#!/usr/bin/env bash
# Shared helpers for the Rivendell test lab. Sourced by lab.sh and scripts/*.sh.
# Written for macOS's stock bash 3.2: no associative arrays, mapfile or ${x,,}.

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${RIVENDELL_REPO:-$(cd "$LAB_ROOT/.." && pwd)}"  # RIVENDELL_REPO: test another checkout
LAB_CONFIG_DIR="${HOME}/.config/rivendell-lab"
LAB_CONFIG="${LAB_CONFIG_DIR}/lab.conf"
KEYCHAIN_SERVICE="rivendell-lab"
KEYCHAIN_ACCOUNT="gandalf"
# Every lab target listens on loopback or a host-only network, so a well-known
# default is fine; set your own with ./lab.sh configure.
LAB_DEFAULT_PASSWORD="mellon"
COMPOSE_PROJECT="rivendell-lab"

if [ -t 1 ]; then
  C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'; C_BLU=$'\033[1;34m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_OFF=""
fi

info()  { printf '%s[*]%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YEL" "$C_OFF" "$*"; }
fail()  { printf '%s[x]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
die()   { fail "$*"; exit 1; }
step()  { printf '\n%s== %s ==%s\n' "$C_BLU" "$*" "$C_OFF"; }

# confirm "Question?" [default y|n] -> 0 for yes.
#   LAB_YES=1    answer every question with its default
#   LAB_FORCE=1  answer yes (the web UI asks the person first, then sets this)
confirm() {
  local q="$1" def="${2:-n}" ans hint="[y/N]"
  [ "$def" = "y" ] && hint="[Y/n]"
  if [ "${LAB_FORCE:-0}" = "1" ]; then printf '[?] %s -> yes\n' "$q"; return 0; fi
  if [ "${LAB_YES:-0}" = "1" ]; then [ "$def" = "y" ]; return; fi
  read -r -p "$(printf '%s[?]%s %s %s ' "$C_YEL" "$C_OFF" "$q" "$hint")" ans || die "No input for: $q (set LAB_YES=1 or LAB_FORCE=1 to run unattended)"
  ans="$(printf '%s' "${ans:-$def}" | tr '[:upper:]' '[:lower:]')"
  [ "$ans" = "y" ] || [ "$ans" = "yes" ]
}

# ask VAR "Prompt" "default"
ask() {
  local __var="$1" q="$2" def="${3:-}" ans
  if [ "${LAB_YES:-0}" = "1" ] && [ -n "$def" ]; then printf -v "$__var" '%s' "$def"; return; fi
  read -r -p "$(printf '%s[?]%s %s%s: ' "$C_YEL" "$C_OFF" "$q" "${def:+ [$def]}")" ans || die "No input for: $q"
  printf -v "$__var" '%s' "${ans:-$def}"
}

# menu "Title" "option 1" "option 2" ... -> sets MENU_CHOICE to the 1-based index (0 = back)
menu() {
  local title="$1"; shift
  local i=1 opt choice
  printf '\n%s%s%s\n' "$C_BLU" "$title" "$C_OFF"
  for opt in "$@"; do printf '  %2d) %s\n' "$i" "$opt"; i=$((i + 1)); done
  printf '   0) Back / quit\n'
  while true; do
    read -r -p "Choose: " choice || die "No input (menus need a terminal; pass a command instead, e.g. ./lab.sh status)"
    case "$choice" in
      ''|*[!0-9]*) warn "Enter a number." ;;
      *) if [ "$choice" -ge 0 ] && [ "$choice" -le $# ]; then MENU_CHOICE="$choice"; return; fi; warn "Out of range." ;;
    esac
  done
}

need() { command -v "$1" >/dev/null 2>&1; }
require() { need "$1" || die "'$1' is not installed. Run: ./lab.sh install"; }

# --- host -------------------------------------------------------------------------

host_os() { case "$(uname -s)" in Darwin) echo macos ;; Linux) echo linux ;; MINGW*|MSYS*|CYGWIN*) echo windows ;; *) echo unknown ;; esac; }
host_arch() { case "$(uname -m)" in x86_64|amd64) echo x86_64 ;; arm64|aarch64) echo arm64 ;; *) uname -m ;; esac; }

# One profile per supported host; every OS/arch-specific choice keys off this.
#   macos-x86_64  Vagrant + VirtualBox: Windows x64, Linux VM; macOS target = this Mac
#   macos-arm64   Tart: Linux and macOS VMs; Windows 11 ARM via UTM (guided)
#   linux-x86_64  Vagrant + VirtualBox: Windows x64, Linux VM
#   linux-arm64   containers only (no unattended Windows/macOS VM option)
host_profile() {
  local p; p="$(host_os)-$(host_arch)"
  case "$p" in macos-x86_64|macos-arm64|linux-x86_64|linux-arm64) echo "$p" ;; *) echo unsupported ;; esac
}
host_label() {
  case "$(host_profile)" in
    macos-x86_64) echo "macOS on Intel" ;; macos-arm64) echo "macOS on Apple silicon" ;;
    linux-x86_64) echo "Linux x86-64" ;; linux-arm64) echo "Linux arm64" ;; *) echo "unsupported host ($(uname -sm))" ;;
  esac
}
is_macos() { [ "$(host_os)" = macos ]; }
uses_vagrant() { case "$(host_profile)" in macos-x86_64|linux-x86_64) return 0 ;; *) return 1 ;; esac; }
uses_tart() { [ "$(host_profile)" = macos-arm64 ]; }
# Kept for readability in messages: Intel/x86-64 hosts run x64 Windows.
is_intel() { uses_vagrant; }
is_arm() { uses_tart; }

host_ram_gb() {
  if is_macos; then echo $(( $(sysctl -n hw.memsize) / 1073741824 ))
  else awk '/MemTotal/ {printf "%d", $2 / 1048576}' /proc/meminfo; fi
}
free_gb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {printf "%d", $4 / 1048576}'; }
os_version() {
  if is_macos; then echo "macOS $(sw_vers -productVersion)"
  elif [ -r /etc/os-release ]; then . /etc/os-release; echo "${PRETTY_NAME:-Linux}"
  else uname -sr; fi
}

# Where Vagrant forwards VM ports so the controller container can reach them via
# host.docker.internal: loopback on macOS (Docker Desktop/OrbStack route it), the
# docker0 gateway on Linux (loopback isn't reachable from containers there).
forward_ip() {
  if is_macos; then echo 127.0.0.1
  else docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo 172.17.0.1; fi
}

# UTM, opened in the background and kept out of the Dock when the lab is what launches
# it. UTM reads HideDockIcon as it starts, so the setting is put back once it's running and
# opening UTM yourself later shows its icon as usual. utmctl then drives it, with --hide.
utm_up() {
  pgrep -xq UTM && return 0
  local previous
  previous="$(defaults read com.utmapp.UTM HideDockIcon 2>/dev/null || echo unset)"
  defaults write com.utmapp.UTM HideDockIcon -bool true
  open -g -j -a UTM
  local _
  for _ in $(seq 1 30); do pgrep -xq UTM && break; sleep 1; done
  sleep 3  # past its launch, where the setting is read
  if [ "$previous" = unset ]; then
    defaults delete com.utmapp.UTM HideDockIcon 2>/dev/null || true
  else
    defaults write com.utmapp.UTM HideDockIcon -bool "$previous"
  fi
}

tart_bin() {
  if need tart; then command -v tart; elif [ -x /Applications/tart.app/Contents/MacOS/tart ]; then echo /Applications/tart.app/Contents/MacOS/tart; fi
}

# --- config -------------------------------------------------------------------------

load_config() {
  # Values exported in the environment win over lab.conf (CI, one-off runs).
  local _v _saved=""
  for _v in LAB_DATA_DIR TEST_IMAGES_PATH LAB_VM_DIR WINDOWS_VM_MEMORY_MB WINDOWS_VM_CPUS LINUX_VM_MEMORY_MB WINDOWS_UTM_VM LAB_TART_HOME LAB_HIDDEN_MACHINES; do
    eval "if [ -n \"\${$_v:-}\" ]; then _saved=\"\$_saved $_v=\$(printf %q \"\${$_v}\")\"; fi"
  done
  # Defaults; lab.conf (written by `./lab.sh configure`) overrides them.
  LAB_DATA_DIR="${LAB_DATA_DIR:-$HOME/rivendell-lab-data}"
  TEST_IMAGES_PATH="${TEST_IMAGES_PATH:-}"
  WINDOWS_VM_MEMORY_MB="${WINDOWS_VM_MEMORY_MB:-6144}"
  WINDOWS_VM_CPUS="${WINDOWS_VM_CPUS:-2}"
  LINUX_VM_MEMORY_MB="${LINUX_VM_MEMORY_MB:-2048}"
  WINDOWS_UTM_VM="${WINDOWS_UTM_VM:-rivendell-lab-win11}"  # Apple silicon: the UTM VM the lab drives
  LAB_TART_HOME="${LAB_TART_HOME:-}"  # Tart VMs elsewhere than LAB_VM_DIR (e.g. the internal SSD)
  LAB_HIDDEN_MACHINES="${LAB_HIDDEN_MACHINES:-}"  # VMs on this host the web UI leaves out (yours, not the lab's)
  # shellcheck disable=SC1090
  [ -f "$LAB_CONFIG" ] && . "$LAB_CONFIG"
  if [ -n "$_saved" ]; then eval "$_saved"; fi
  LAB_VM_DIR="${LAB_VM_DIR:-$LAB_DATA_DIR/vms}"
  ACQ_ROOT="${TEST_IMAGES_PATH:-$LAB_DATA_DIR}/gandalf"
  MORDOR_ROOT="${TEST_IMAGES_PATH:-$LAB_DATA_DIR}/mordor"
  export LAB_DATA_DIR TEST_IMAGES_PATH LAB_VM_DIR ACQ_ROOT MORDOR_ROOT LAB_TART_HOME
  set_vm_homes
}

# Keep VM disks and boxes under LAB_VM_DIR, except where lab VMs already exist in
# the tools' default locations: those are left in place rather than orphaned.
set_vm_homes() {
  if [ -n "${LAB_TART_HOME:-}" ]; then
    export TART_HOME="${TART_HOME:-$LAB_TART_HOME}"
  elif ls -d "$HOME/.tart/vms/rivendell-lab-"* >/dev/null 2>&1; then
    export TART_HOME="${TART_HOME:-$HOME/.tart}"
  else
    export TART_HOME="${TART_HOME:-$LAB_VM_DIR/tart}"
  fi
  if [ -d "$HOME/.vagrant.d/boxes" ] && ls "$HOME/.vagrant.d/boxes" | grep -q .; then
    export VAGRANT_HOME="${VAGRANT_HOME:-$HOME/.vagrant.d}"
  else
    export VAGRANT_HOME="${VAGRANT_HOME:-$LAB_VM_DIR/vagrant.d}"
  fi
  if VBoxManage list vms 2>/dev/null | grep -q rivendell-lab-; then
    :  # existing lab VMs registered in the user's VirtualBox: leave them there
  else
    # A lab-only VirtualBox home, so lab VMs don't touch the user's own VirtualBox setup.
    export VBOX_USER_HOME="${VBOX_USER_HOME:-$LAB_VM_DIR/virtualbox}"
  fi
}

prepare_vm_dirs() {
  mkdir -p "$LAB_VM_DIR" "$TART_HOME" "$VAGRANT_HOME" || die "Can't create $LAB_VM_DIR (is the drive mounted?)"
  if [ -n "${VBOX_USER_HOME:-}" ] && need VBoxManage; then
    mkdir -p "$VBOX_USER_HOME/machines"
    VBoxManage setproperty machinefolder "$VBOX_USER_HOME/machines" >/dev/null
  fi
}

save_config() {
  mkdir -p "$LAB_CONFIG_DIR"
  cat > "$LAB_CONFIG" <<EOF
# Rivendell test lab settings (no secrets here; the lab password is in the macOS Keychain).
LAB_DATA_DIR="$LAB_DATA_DIR"
TEST_IMAGES_PATH="$TEST_IMAGES_PATH"
LAB_VM_DIR="$LAB_VM_DIR"
WINDOWS_VM_MEMORY_MB="$WINDOWS_VM_MEMORY_MB"
WINDOWS_VM_CPUS="$WINDOWS_VM_CPUS"
LINUX_VM_MEMORY_MB="$LINUX_VM_MEMORY_MB"
WINDOWS_UTM_VM="$WINDOWS_UTM_VM"
LAB_TART_HOME="$LAB_TART_HOME"
LAB_HIDDEN_MACHINES="$LAB_HIDDEN_MACHINES"
EOF
  ok "Saved $LAB_CONFIG"
}

# --- lab password (macOS Keychain; never written to disk by the lab) -------------

# macOS Keychain, or the Secret Service (secret-tool) on Linux. With neither, the
# password is asked for once per run and kept in memory only.
lab_password() {
  # No stored password is normal (the default is in use): the lookups' "not found"
  # exit codes (44 from security) mustn't end a `set -e` caller
  if is_macos; then
    security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w 2>/dev/null || true
  elif need secret-tool; then
    secret-tool lookup service "$KEYCHAIN_SERVICE" account "$KEYCHAIN_ACCOUNT" 2>/dev/null || true
  fi
}

store_password() {
  if is_macos; then
    security add-generic-password -U -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w "$1" \
      -j "Rivendell test lab: password for the gandalf user on lab targets" >/dev/null && echo "the login Keychain"
  elif need secret-tool; then
    printf '%s' "$1" | secret-tool store --label "Rivendell test lab" service "$KEYCHAIN_SERVICE" account "$KEYCHAIN_ACCOUNT" && echo "the Secret Service keyring"
  fi
}

delete_password() {
  if is_macos; then security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1
  elif need secret-tool; then secret-tool clear service "$KEYCHAIN_SERVICE" account "$KEYCHAIN_ACCOUNT"; fi
}

set_lab_password() {
  local p1 p2
  while true; do
    read -r -s -p "Lab password for the 'gandalf' user on every target (Enter for the default, '$LAB_DEFAULT_PASSWORD'): " p1 || die "No input for the lab password (set LAB_PASSWORD to run unattended)"; echo
    if [ -z "$p1" ]; then
      delete_password; LAB_PASSWORD="$LAB_DEFAULT_PASSWORD"; export LAB_PASSWORD
      ok "Using the default lab password '$LAB_DEFAULT_PASSWORD'."
      return
    fi
    case "$p1" in *"'"*|*'"'*|*\\*|*' '*) warn "Avoid quotes, backslashes and spaces; the password is passed to remote shells."; continue ;; esac
    read -r -s -p "Again: " p2 || die "No input"; echo
    [ "$p1" = "$p2" ] && break
    warn "They didn't match."
  done
  local where; where="$(store_password "$p1")"
  if [ -n "$where" ]; then
    ok "Stored in $where (service '$KEYCHAIN_SERVICE')."
  else
    warn "No keyring available (install libsecret-tools for secret-tool); using it for this run only."
  fi
  LAB_PASSWORD="$p1"; export LAB_PASSWORD
}

require_password() {
  # An exported LAB_PASSWORD wins (CI, or testing without touching the Keychain),
  # then a custom one in the keyring, then the default.
  [ -n "${LAB_PASSWORD:-}" ] && { export LAB_PASSWORD; return; }
  LAB_PASSWORD="$(lab_password)"
  [ -n "$LAB_PASSWORD" ] || LAB_PASSWORD="$LAB_DEFAULT_PASSWORD"
  export LAB_PASSWORD
}

# --- docker ---------------------------------------------------------------------------

# Use the engine Rivendell runs on, so the lab and Rivendell share one host.
pick_docker_context() {
  require docker
  local ctx
  for ctx in $(docker context ls --format '{{.Name}}' 2>/dev/null); do
    if docker --context "$ctx" ps --format '{{.Names}}' 2>/dev/null | grep -qx rivendell-backend; then
      export DOCKER_CONTEXT="$ctx"; return
    fi
  done
  docker info >/dev/null 2>&1 || die "No Docker engine is running. Start Docker Desktop or OrbStack first."
  export DOCKER_CONTEXT="$(docker context show)"
}

# Build by streaming a tar of the context into `docker build -`. BuildKit's own
# context sync can stall for minutes on cloud-synced folders (OneDrive, iCloud).
build_image() {  # build_image <tag> <context dir> [build-arg ...]
  local tag="$1" ctx="$2"; shift 2
  local args=() a
  for a in "$@"; do args+=(--build-arg "$a"); done
  info "Building $tag"
  # Plain ustar without macOS extended attributes: docker only recognises the
  # stream as a context archive (not a Dockerfile) in that format.
  local tarflags="--format ustar"
  is_macos && tarflags="$tarflags --no-xattrs --no-mac-metadata"
  # shellcheck disable=SC2086
  COPYFILE_DISABLE=1 tar $tarflags -C "$ctx" -cf - . | docker build -q -t "$tag" "${args[@]+"${args[@]}"}" - >/dev/null
}

build_lab_images() {
  local d base
  for d in ubuntu rocky; do
    case "$d" in ubuntu) base=ubuntu:24.04 ;; rocky) base=rockylinux:9 ;; esac
    build_image "rivendell-lab-target:$d" "$LAB_ROOT/linux-targets" "BASE=$base" || return 1
  done
  build_image rivendell-lab-target:ubuntu-clean "$LAB_ROOT/linux-targets" "BASE=ubuntu:24.04" "SEED=0" || return 1
  build_image rivendell-lab-controller "$LAB_ROOT/controller"
}

lab_compose() {
  docker compose -p "$COMPOSE_PROJECT" -f "$LAB_ROOT/linux-targets/docker-compose.yml" "$@"
}

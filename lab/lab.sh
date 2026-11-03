#!/usr/bin/env bash
# Dernvale test lab: targets for Gandalf and datasets for Mordor, on one Mac.
#
#   ./lab.sh            interactive menu
#   ./lab.sh <command>  run one step (./lab.sh help lists them)
#
# Everything runs locally: containers on the Docker engine Dernvale uses,
# VMs on this Mac (Vagrant + VirtualBox on Intel, Tart on Apple silicon), and
# only loopback or host-only networking. See lab/README.md.
set -uo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib/common.sh"
load_config

VAGRANT_DIR="$LAB_ROOT/vagrant"
TESTS_ENV="$LAB_CONFIG_DIR/dernvale-tests.env"
LINUX_CONTAINERS="lab-ubuntu lab-rocky lab-ubuntu-clean1 lab-ubuntu-clean2"

vagrant_env() {
  require_password
  LAB_FORWARD_IP="$(forward_ip)"
  export REPO_ROOT ACQ_ROOT MORDOR_ROOT LAB_PASSWORD WINDOWS_VM_MEMORY_MB WINDOWS_VM_CPUS LINUX_VM_MEMORY_MB LAB_FORWARD_IP
  export VAGRANT_CWD="$VAGRANT_DIR"
  mkdir -p "$ACQ_ROOT" "$MORDOR_ROOT"
  prepare_vm_dirs
}

# ------------------------------------------------------------------------------- check

cmd_check() {
  step "Host"
  local ram; ram="$(host_ram_gb)"
  echo "  $(os_version), $(host_arch), ${ram} GB RAM -> profile: $(host_profile) ($(host_label))"
  case "$(host_profile)" in
    macos-x86_64)
      echo "  Windows x64 + Linux VMs via Vagrant/VirtualBox. DumpIt memory acquisition works."
      echo "  macOS target: this Mac itself (optional), since Tart needs Apple silicon." ;;
    macos-arm64)
      echo "  Linux + macOS VMs via Tart. Windows 11 ARM via UTM (guided, not unattended);"
      echo "  DumpIt is x64 and won't run there, so Windows memory acquisition can't be tested." ;;
    linux-x86_64)
      echo "  Windows x64 + Linux VMs via Vagrant/VirtualBox. No macOS target (Apple only licenses macOS VMs on Macs)." ;;
    linux-arm64)
      echo "  Linux container targets and Mordor downloads only; no unattended VM option on this host." ;;
    *) die "This host isn't supported: $(uname -sm). Use macOS (Intel/Apple silicon) or Linux (x86-64/arm64)." ;;
  esac
  [ "$ram" -lt 16 ] && warn "Under 16 GB RAM: run Dernvale without the SIEM profile while VMs are up."

  step "Tools"
  local t
  for t in git python3 expect docker; do
    if need "$t"; then ok "$t"; else fail "$t missing"; fi
  done
  if uses_vagrant; then
    for t in vagrant VBoxManage; do if need "$t"; then ok "$t"; else warn "$t missing (./lab.sh install)"; fi; done
  elif uses_tart; then
    if [ -n "$(tart_bin)" ]; then ok "tart"; else warn "tart missing (./lab.sh install)"; fi
    [ -d /Applications/UTM.app ] && ok "UTM" || warn "UTM missing (only needed for the Windows VM)"
  fi

  step "Docker"
  if need docker && docker info >/dev/null 2>&1; then
    pick_docker_context
    ok "engine: $DOCKER_CONTEXT"
    if docker ps --format '{{.Names}}' | grep -qx dernvale-backend; then ok "Dernvale is running on this engine"; else warn "Dernvale isn't running (start it before running tests)"; fi
  else
    warn "No Docker engine running"
  fi

  step "Lab settings"
  echo "  config:     ${LAB_CONFIG} $([ -f "$LAB_CONFIG" ] || echo '(not yet created: ./lab.sh configure)')"
  echo "  VMs:        $LAB_VM_DIR (Tart: $TART_HOME, Vagrant: $VAGRANT_HOME${VBOX_USER_HOME:+, VirtualBox: $VBOX_USER_HOME})"
  echo "  data:       $LAB_DATA_DIR (free: $(free_gb "$(dirname "$LAB_DATA_DIR")" 2>/dev/null || echo '?') GB)"
  echo "  test root:  ${TEST_IMAGES_PATH:-$LAB_DATA_DIR}"
  echo "  password:   $([ -n "$(lab_password)" ] && echo 'custom (keyring)' || echo "default ($LAB_DEFAULT_PASSWORD)")"
}

# ----------------------------------------------------------------------------- install

brew_install() {  # brew_install formula|--cask name
  if [ "$1" = "--cask" ]; then
    brew list --cask "$2" >/dev/null 2>&1 && { ok "$2 (already installed)"; return; }
    brew install --cask "$2"
  else
    brew list "$1" >/dev/null 2>&1 && { ok "$1 (already installed)"; return; }
    brew install "$1"
  fi
}

install_linux() {
  local sudo=""; [ "$(id -u)" -ne 0 ] && sudo="sudo"
  if need apt-get; then
    info "Debian/Ubuntu: installing packages with apt"
    $sudo apt-get update
    $sudo apt-get install -y git python3 expect rsync netcat-openbsd libsecret-tools curl gnupg
    if ! need docker; then confirm "Install Docker Engine (get.docker.com)?" y && curl -fsSL https://get.docker.com | $sudo sh && $sudo usermod -aG docker "$USER"; fi
    if uses_vagrant; then
      if ! need vagrant; then
        curl -fsSL https://apt.releases.hashicorp.com/gpg | $sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(. /etc/os-release; echo "$VERSION_CODENAME") main" | $sudo tee /etc/apt/sources.list.d/hashicorp.list >/dev/null
        $sudo apt-get update && $sudo apt-get install -y vagrant
      fi
      need VBoxManage || $sudo apt-get install -y virtualbox
    fi
  elif need dnf; then
    info "Fedora/RHEL: installing packages with dnf"
    $sudo dnf install -y git python3 expect rsync nmap-ncat libsecret curl dnf-plugins-core
    if ! need docker; then confirm "Install Docker Engine (get.docker.com)?" y && curl -fsSL https://get.docker.com | $sudo sh && $sudo usermod -aG docker "$USER"; fi
    if uses_vagrant && ! need vagrant; then
      $sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/fedora/hashicorp.repo 2>/dev/null \
        || $sudo dnf config-manager addrepo --from-repofile=https://rpm.releases.hashicorp.com/fedora/hashicorp.repo
      $sudo dnf install -y vagrant
    fi
    uses_vagrant && ! need VBoxManage && warn "Install VirtualBox from https://www.virtualbox.org/wiki/Linux_Downloads (not in Fedora/RHEL repos)."
  else
    die "No apt-get or dnf found; install git, python3, expect, docker, vagrant and VirtualBox yourself."
  fi
  uses_vagrant && warn "VirtualBox and KVM can't share VT-x: unload kvm (sudo modprobe -r kvm_intel kvm_amd) if VirtualBox refuses to start a VM."
  ok "Prerequisites done (log out and back in if you were added to the docker group). Next: ./lab.sh configure"
}

cmd_install() {
  step "Prerequisites for $(host_label)"
  if ! is_macos; then install_linux; return; fi
  if ! need brew; then
    warn "Homebrew is required: https://brew.sh"
    confirm "Install Homebrew now (runs the official installer)?" n || return 1
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
  need git || xcode-select --install
  if ! need docker; then
    warn "No Docker CLI. Dernvale needs Docker Desktop or OrbStack."
    confirm "Install OrbStack?" y && brew_install --cask orbstack
  fi
  if uses_vagrant; then
    info "Intel Mac: Vagrant + VirtualBox"
    brew_install --cask virtualbox
    brew_install --cask vagrant
    warn "If macOS blocked VirtualBox: System Settings > Privacy & Security > Allow 'Oracle America', then reboot."
  else
    info "Apple silicon: Tart for Linux/macOS VMs"
    brew_install cirruslabs/cli/tart
    if confirm "Also install UTM and CrystalFetch for the Windows 11 ARM VM?" y; then
      brew_install --cask utm
      brew_install --cask crystalfetch
    fi
  fi
  ok "Prerequisites done. Next: ./lab.sh configure"
}

# ---------------------------------------------------------------------------- configure

cmd_configure() {
  step "Where lab data lives"
  echo "  Acquisitions and Mordor datasets go here, and Dernvale's worker must be able to"
  echo "  read them. Anything under /Volumes is already shared with Dernvale's containers;"
  echo "  a folder in your home directory needs an extra compose file (generated for you)."
  local opts=("$HOME/dernvale-lab-data (needs the compose override)") paths=("$HOME/dernvale-lab-data") v
  for v in /Volumes/*; do
    [ -d "$v" ] && [ -w "$v" ] && [ "$v" != "/Volumes/Macintosh HD" ] || continue
    opts+=("$v/dernvale-lab (external, $(free_gb "$v") GB free)"); paths+=("$v/dernvale-lab")
  done
  opts+=("Somewhere else")
  menu "Data location" "${opts[@]}"
  if [ "$MENU_CHOICE" = 0 ]; then return; fi
  if [ "$MENU_CHOICE" -eq "${#opts[@]}" ]; then
    ask LAB_DATA_DIR "Full path" "$LAB_DATA_DIR"
  else
    LAB_DATA_DIR="${paths[$((MENU_CHOICE - 1))]}"
  fi
  TEST_IMAGES_PATH="$LAB_DATA_DIR"
  mkdir -p "$LAB_DATA_DIR" || die "Can't create $LAB_DATA_DIR"
  local free; free="$(free_gb "$LAB_DATA_DIR")"
  [ "${free:-0}" -lt 60 ] && warn "Only ${free} GB free there; the Windows box alone is ~15 GB and the macOS image ~25 GB (those live in ~/.vagrant.d or ~/.tart)."

  step "Where VMs live"
  echo "  Boxes, VM disks and Tart images (Windows ~15-25 GB, macOS ~30 GB each)."
  ask LAB_VM_DIR "VM directory" "${LAB_VM_DIR:-$LAB_DATA_DIR/vms}"
  mkdir -p "$LAB_VM_DIR" || die "Can't create $LAB_VM_DIR"

  step "VM sizes"
  local ram; ram="$(host_ram_gb)"
  if [ "$ram" -ge 32 ]; then WINDOWS_VM_MEMORY_MB=8192; WINDOWS_VM_CPUS=4; else WINDOWS_VM_MEMORY_MB=4096; WINDOWS_VM_CPUS=2; fi
  ask WINDOWS_VM_MEMORY_MB "Windows VM memory (MB)" "$WINDOWS_VM_MEMORY_MB"
  ask WINDOWS_VM_CPUS "Windows VM CPUs" "$WINDOWS_VM_CPUS"
  ask LINUX_VM_MEMORY_MB "Linux VM memory (MB)" "$LINUX_VM_MEMORY_MB"
  save_config
  load_config

  step "Lab password"
  if [ -n "$(lab_password)" ]; then
    confirm "A custom lab password is set. Change it (Enter at the prompt goes back to the default)?" n && set_lab_password
  else
    confirm "Using the default lab password '$LAB_DEFAULT_PASSWORD'. Set your own instead?" n && set_lab_password
  fi
  ok "Configured. Next: ./lab.sh linux-targets up"
}

# ------------------------------------------------------------------------ linux targets

cmd_linux_targets() {
  local sub="${1:-}"
  pick_docker_context
  require_password
  export REPO_ROOT ACQ_ROOT
  mkdir -p "$ACQ_ROOT"
  if [ -z "$sub" ]; then
    menu "Linux container targets ($DOCKER_CONTEXT)" "Build and start" "Build and start, with two clean Ubuntu hosts for stacking" "Stop" "Rebuild from scratch (re-seed)" "Status"
    case "$MENU_CHOICE" in 1) sub=up ;; 2) sub=stacking ;; 3) sub=down ;; 4) sub=reset ;; 5) sub=status ;; *) return ;; esac
  fi
  case "$sub" in
    up)     build_lab_images && lab_compose up -d --no-build && ok "Targets up: lab-ubuntu lab-rocky (SSH on 127.0.0.1:2221-2222)" ;;
    stacking) build_lab_images && lab_compose --profile stacking up -d --no-build \
              && ok "Targets up, with two clean Ubuntu hosts for stacking (SSH on 127.0.0.1:2221-2224)" ;;
    down)   lab_compose --profile stacking down && ok "Targets stopped" ;;
    reset)  lab_compose --profile stacking down -v; build_lab_images && lab_compose up -d --no-build --force-recreate && ok "Targets rebuilt and re-seeded" ;;
    status) lab_compose --profile stacking ps ;;
    *) die "linux-targets up|stacking|down|reset|status" ;;
  esac
}

# ----------------------------------------------------------------------------- VMs

cmd_linux_vm() {
  local sub="${1:-}"
  if ! uses_vagrant && ! uses_tart; then warn "No Linux VM option on $(host_label); use the container targets."; return; fi
  if [ -z "$sub" ]; then
    menu "Linux VM (real kernel; SSH on 127.0.0.1:2230)" "Create / provision" "Start" "Stop" "Destroy" "Status"
    case "$MENU_CHOICE" in 1) sub=create ;; 2) sub=start ;; 3) sub=stop ;; 4) sub=delete ;; 5) sub=status ;; *) return ;; esac
  fi
  if uses_vagrant; then
    require vagrant; vagrant_env
    case "$sub" in
      create) vagrant up linux --provision ;;
      start) vagrant up linux ;;
      stop) vagrant halt linux ;;
      delete) confirm "Destroy the Linux VM?" n && vagrant destroy -f linux ;;
      status) vagrant status linux ;;
    esac
  else
    "$LAB_ROOT/macos/tart-vm.sh" "$sub" linux
  fi
}

cmd_macos_vm() {
  local sub="${1:-}"
  if ! is_macos; then
    warn "No macOS target on $(host_label): Apple's licence only allows macOS VMs on Mac hardware."
    return
  fi
  if is_intel; then
    warn "macOS VMs need Apple silicon (Tart). On this Intel Mac you can use the Mac itself as a target:"
    echo "  1. System Settings > General > Sharing > Remote Login: on."
    echo "  2. Create a standard test user 'gandalf' with the lab password, and give it passwordless sudo:"
    echo "       sudo sysadminctl -addUser gandalf -password - -admin"
    echo "       echo 'gandalf ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/gandalf"
    echo "  3. Collect with target 'lab-machost' (./lab.sh gandalf-collect)."
    warn "This touches your real Mac. Remove the user afterwards: sudo sysadminctl -deleteUser gandalf"
    return
  fi
  if [ -z "$sub" ]; then
    menu "macOS VM (Tart; SSH on 127.0.0.1:2231)" "Create / provision (~25 GB download)" "Start" "Stop" "Destroy" "Status"
    case "$MENU_CHOICE" in 1) sub=create ;; 2) sub=start ;; 3) sub=stop ;; 4) sub=delete ;; 5) sub=status ;; *) return ;; esac
  fi
  shift || true
  "$LAB_ROOT/macos/tart-vm.sh" "$sub" macos "$@"
}

windows_arm_guide() {
  cat <<EOF

${C_BLU}Windows 11 ARM on Apple silicon (guided)${C_OFF}
UTM can't be driven unattended the way Vagrant can, so this part is manual.

 1. Open CrystalFetch, choose Windows 11, Arm64, your language, and save the ISO
    to $LAB_DATA_DIR/isos/.
 2. Open UTM > Create a New Virtual Machine > Virtualize > Windows. Pick the ISO,
    tick "Install drivers and SPICE tools", give it ${WINDOWS_VM_MEMORY_MB} MB and ${WINDOWS_VM_CPUS} CPUs.
 3. Under Sharing, share this folder as the VM's shared directory:
      $LAB_DATA_DIR
    It appears in Windows as a WebDAV drive (\\\\localhost@9843\\DavWWWRoot); map it to Z:.
 4. Finish Windows setup with a local account. Then, in an elevated PowerShell:
      Set-ExecutionPolicy -Scope Process Bypass -Force
      Copy-Item -Recurse Z:\\lab-scripts C:\\lab\\scripts
      C:\\lab\\scripts\\Provision-GandalfTarget.ps1
    (./lab.sh copies the scripts and Gandalf's source into $LAB_DATA_DIR for you now.)
 5. Collect: C:\\lab\\scripts\\Run-GandalfLocal.ps1 -GandalfSource Z:\\gandalf-src -AcquisitionsRoot Z:\\gandalf

Memory acquisition (DumpIt) is x64-only and won't work on Windows on ARM.
EOF
  mkdir -p "$LAB_DATA_DIR/isos" "$LAB_DATA_DIR/lab-scripts" "$LAB_DATA_DIR/gandalf-src"
  cp -R "$LAB_ROOT/windows/." "$LAB_DATA_DIR/lab-scripts/"
  rsync -a --delete "$REPO_ROOT/src/acquisition/" "$LAB_DATA_DIR/gandalf-src/"
  ok "Copied lab scripts and Gandalf source into $LAB_DATA_DIR"
  if [ "${LAB_HEADLESS:-0}" != 1 ] && confirm "Open CrystalFetch and UTM now?" y; then open -a CrystalFetch 2>/dev/null; open -a UTM 2>/dev/null; fi
}

cmd_windows_vm() {
  local sub="${1:-}"
  if uses_tart; then
    if [ -z "$sub" ]; then
      menu "Windows 11 ARM VM (UTM; SSH on 127.0.0.1:2232)" "Create / install (needs the ARM64 ISO in $LAB_DATA_DIR/isos)" "Adopt an installed VM (.utm in $LAB_VM_DIR/utm)" "Start" "Stop" "Destroy" "Status" "Manual install instead (guide)"
      case "$MENU_CHOICE" in 1) sub=create ;; 2) sub=adopt ;; 3) sub=start ;; 4) sub=stop ;; 5) sub=delete ;; 6) sub=status ;; 7) windows_arm_guide; return ;; *) return ;; esac
    fi
    [ "$sub" = provision ] && sub=create  # re-running create on an existing VM just starts it and checks it's ready
    shift || true
    "$LAB_ROOT/windows/utm-vm.sh" "$sub" "$@"
    return
  fi
  if ! uses_vagrant; then warn "No Windows VM option on $(host_label)."; return; fi
  if [ -z "$sub" ]; then
    menu "Windows 11 x64 VM (Vagrant + VirtualBox)" "Create / provision (~15 GB box download)" "Start" "Stop" "Re-run provisioning" "Open console (VirtualBox GUI)" "Destroy" "Status"
    case "$MENU_CHOICE" in 1) sub=create ;; 2) sub=start ;; 3) sub=stop ;; 4) sub=provision ;; 5) sub=gui ;; 6) sub=delete ;; 7) sub=status ;; *) return ;; esac
  fi
  require vagrant; vagrant_env
  case "$sub" in
    create) info "First boot of the Windows box takes 10-20 minutes."; vagrant up win --provision ;;
    start) vagrant up win ;;
    stop) vagrant halt win ;;
    provision) vagrant provision win ;;
    gui) VBoxManage startvm dernvale-lab-win11 --type separate 2>/dev/null || open -a VirtualBox ;;
    delete) confirm "Destroy the Windows VM?" n && vagrant destroy -f win ;;
    status) vagrant status win ;;
  esac
}

# ------------------------------------------------------------------------ gandalf

running_targets() {
  local t out=""
  for t in $LINUX_CONTAINERS; do docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$t" && out="$out $t"; done
  local fip; fip="$(forward_ip)"
  nc -z "$fip" 2230 2>/dev/null && out="$out lab-linuxvm"
  nc -z "$fip" 2231 2>/dev/null && out="$out lab-macos"
  echo "$out"
}

cmd_gandalf_collect() {
  pick_docker_context
  require_password
  export REPO_ROOT ACQ_ROOT
  local collector="${1:-}" targets="${2:-}" workarounds="${GANDALF_WORKAROUNDS:-}"
  if [ -z "$collector" ]; then
    menu "Which Gandalf collector?" "Bash (gandalf.sh) against Linux/macOS targets" "Python (gandalf.py) against Linux/macOS targets" "PowerShell (Invoke-Gandalf.ps1) in the Windows VM" "All three"
    case "$MENU_CHOICE" in 1) collector=bash ;; 2) collector=python ;; 3) collector=powershell ;; 4) collector=all ;; *) return ;; esac
  fi
  if [ "$collector" != "powershell" ] && [ -z "$targets" ]; then
    targets="$(running_targets)"
    [ -n "$targets" ] || die "No targets running. Start some: ./lab.sh linux-targets up"
    info "Targets:$targets"
  fi
  if [ -z "$workarounds" ]; then
    echo
    echo "  Known Gandalf gaps (as of this lab's creation): gandalf.sh writes .tar.gz, which Elrond's"
    echo "  --Gandalf mode doesn't read; gandalf.py looks for shire/collect_artefacts-py, which is in python/."
    confirm "Apply lab-side workarounds (repack .tar.gz as .zip, link shire -> python)? No = test Gandalf as shipped" n && workarounds=1 || workarounds=0
  fi
  local wflag=""; [ "$workarounds" = "1" ] && wflag="--workarounds"
  local rc=0 c
  for c in bash python powershell; do
    [ "$collector" = "all" ] || [ "$collector" = "$c" ] || continue
    step "Gandalf $c"
    if [ "$c" = "powershell" ]; then
      if is_intel; then
        vagrant_env
        vagrant winrm win -e -c "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\scripts\\Run-GandalfLocal.ps1" || rc=1
      elif uses_tart; then
        LAB_SSH_TIMEOUT=7200 "$LAB_ROOT/windows/utm-vm.sh" collect || rc=1
      else
        warn "No Windows VM on $(host_label)."
      fi
    else
      # shellcheck disable=SC2086
      docker image inspect dernvale-lab-controller >/dev/null 2>&1 || build_image dernvale-lab-controller "$LAB_ROOT/controller"
      lab_compose --profile controller run --rm --pull never controller "$c" $targets $wflag || rc=1
    fi
  done
  echo
  info "Acquisitions under $ACQ_ROOT:"
  find "$ACQ_ROOT" -maxdepth 4 \( -name '*.zip' -o -name '*.7z' -o -name '*.tar.gz*' \) -exec ls -lh {} \; 2>/dev/null | awk '{print "  " $5 "  " $9}'
  [ "$rc" = 0 ] && ok "Collection finished. Next: ./lab.sh dernvale-env" || warn "Some collections failed; see the collector logs next to the archives."
  return $rc
}

# stacking-eval: the Linux stacking targets collected afresh, Elrond over all four as one case, and
# stacking.csv scored against the plants (lib/stacking_eval.py), with a row added to README.md
cmd_stacking_eval() {
  pick_docker_context
  require_password
  docker ps --format '{{.Names}}' | grep -qx dernvale-celery-worker || die "Dernvale isn't running: ./dernvale start"
  local root="${TEST_IMAGES_PATH:-$LAB_DATA_DIR}" case_id dest acq
  docker exec dernvale-celery-worker test -d "$root" || die "Dernvale's worker can't see $root: run ./lab.sh dernvale-env"
  case_id="STACKEVAL-$(date +%Y%m%d-%H%M)"
  dest="$root/stacking-eval/$case_id"
  # A collection of its own, so hosts left from earlier runs aren't stacked with these
  ACQ_ROOT="$dest/gandalf"
  acq="$ACQ_ROOT/python_collection/acquisitions/"
  mkdir -p "$ACQ_ROOT" "$dest/elrond"
  cmd_linux_targets stacking || return 1
  GANDALF_WORKAROUNDS=0 cmd_gandalf_collect python "lab-ubuntu lab-rocky lab-ubuntu-clean1 lab-ubuntu-clean2" || return 1
  step "Elrond over the four hosts as $case_id"
  docker exec dernvale-celery-worker sh -c 'cd "${ELROND_HOME:-/opt/elrond}" && python3 elrond.py "$@"' elrond \
    "$case_id" "$acq" "$dest/elrond" --Gandalf --Process --Analysis || return 1
  step "Stacking against the plants"
  python3 "$LAB_ROOT/lib/stacking_eval.py" "$dest/elrond" "$acq" --readme "$LAB_ROOT/README.md" \
    --label "Linux containers (python collector)"
}

# ------------------------------------------------------------------------- mordor

cmd_mordor_download() {
  mkdir -p "$MORDOR_ROOT"
  local only=()
  if [ -z "${1:-}" ]; then
    menu "Mordor datasets (OTRF Security-Datasets)" "All datasets the tests reference" "APT29 day 1 + day 2 only" "Atomic tactic sets only" "Show the mapping, download nothing"
    case "$MENU_CHOICE" in
      1) ;;
      2) only=(--only apt29/day1 apt29/day2) ;;
      3) only=(--only atomic/credential_access atomic/defense_evasion atomic/lateral_movement atomic/persistence) ;;
      4) python3 "$LAB_ROOT/mordor/download_datasets.py" --root "$MORDOR_ROOT" --list; return ;;
      *) return ;;
    esac
  else
    only=(--only "$@")
  fi
  python3 "$LAB_ROOT/mordor/download_datasets.py" --root "$MORDOR_ROOT" "${only[@]+"${only[@]}"}"
}

cmd_mordor_sensor() {
  warn "This installs Atomic Red Team and disables Defender real-time protection inside the lab VM."
  confirm "Continue?" n || return
  if uses_tart; then "$LAB_ROOT/windows/utm-vm.sh" sensor; return; fi
  vagrant_env
  vagrant winrm win -e -c "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\scripts\\Install-MordorSensor.ps1"
}

MORDOR_PRESETS="persistence credential_access defense_evasion discovery"

preset_techniques() {
  case "$1" in
    persistence) echo "T1547.001,T1053.005,T1543.003" ;;
    credential_access) echo "T1003.001,T1552.001" ;;
    defense_evasion) echo "T1070.001,T1562.001,T1218.011" ;;
    discovery) echo "T1082,T1087.001,T1016" ;;
  esac
}

cmd_mordor_capture() {
  local name techniques
  # Non-interactive: mordor-capture <preset> | mordor-capture custom <name> <T1,T2>
  if [ -n "${1:-}" ]; then
    if [ "$1" = custom ]; then
      name="${2:?name}"; techniques="${3:?techniques}"
      case "$name$techniques" in *[!A-Za-z0-9_.,-]*) die "Names and technique IDs may only use letters, digits, _ . , -" ;; esac
    else
      techniques="$(preset_techniques "$1")"; [ -n "$techniques" ] || die "Presets: $MORDOR_PRESETS"
      name="lab_$1"
    fi
  else
  menu "Generate a Mordor-style dataset (Atomic Red Team in the Windows VM)" \
    "Persistence: T1547.001 Run key, T1053.005 scheduled task, T1543.003 service" \
    "Credential access: T1003.001 LSASS dump, T1552.001 credentials in files" \
    "Defence evasion: T1070.001 clear logs, T1562.001 disable tools, T1218.011 rundll32" \
    "Discovery: T1082, T1087.001, T1016" \
    "Custom technique list"
  case "$MENU_CHOICE" in
    1) name=lab_persistence; techniques="T1547.001,T1053.005,T1543.003" ;;
    2) name=lab_credential_access; techniques="T1003.001,T1552.001" ;;
    3) name=lab_defense_evasion; techniques="T1070.001,T1562.001,T1218.011" ;;
    4) name=lab_discovery; techniques="T1082,T1087.001,T1016" ;;
    5) ask name "Dataset name" "lab_custom"; ask techniques "Techniques (comma-separated)" "T1059.001" ;;
    *) return ;;
  esac
  fi
  if is_arm; then warn "In the UTM VM: C:\\lab\\scripts\\Invoke-MordorCapture.ps1 -Name $name -Techniques $techniques -OutputRoot Z:\\mordor\\lab"; return; fi
  vagrant_env
  vagrant winrm win -e -c "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\scripts\\Invoke-MordorCapture.ps1 -Name $name -Techniques $techniques" \
    && ok "Dataset: $MORDOR_ROOT/lab/$name (expected.json lists the techniques that ran)"
}

# Recorded telemetry (src/mordor/telemetry): each Atomic Red Team test's logs on their own, so
# the telemetry engine knows which log records which technique. mordor-capture above makes one
# dataset of a whole run for Elrond to analyse; this keeps the tests apart.
TELEMETRY_LAB="${DERNVALE_TELEMETRY_LAB:-$REPO_ROOT/src/mordor/data/telemetry/lab}"

cmd_mordor_record() {
  local preset techniques run=""
  # Non-interactive: mordor-record <preset> | mordor-record custom <name> <T1,T2> [run]
  if [ -n "${1:-}" ]; then
    if [ "$1" = custom ]; then
      preset="${2:?name}"; techniques="${3:?techniques}"; run="${4:-}"
    else
      preset="$1"; techniques="$(preset_techniques "$1")"; [ -n "$techniques" ] || die "Presets: $MORDOR_PRESETS"
    fi
  else
    menu "Record telemetry: Atomic Red Team in the Windows VM, each test's logs kept apart" \
      "Persistence: T1547.001, T1053.005, T1543.003" \
      "Credential access: T1003.001, T1552.001" \
      "Defence evasion: T1070.001, T1562.001, T1218.011" \
      "Discovery: T1082, T1087.001, T1016" \
      "Custom technique list"
    case "$MENU_CHOICE" in
      1) preset=persistence ;; 2) preset=credential_access ;; 3) preset=defense_evasion ;; 4) preset=discovery ;;
      5) ask preset "Run name" "custom"; ask techniques "Techniques (comma-separated)" "T1059.001" ;;
      *) return ;;
    esac
    [ -n "${techniques:-}" ] || techniques="$(preset_techniques "$preset")"
  fi
  case "$preset$techniques$run" in *[!A-Za-z0-9_.,-]*) die "Names and technique IDs may only use letters, digits, _ . , -" ;; esac
  [ -n "$run" ] || run="lab-win11-$preset-$(date +%Y%m%d-%H%M)"
  if uses_tart; then
    "$LAB_ROOT/windows/utm-vm.sh" record "$techniques" "$run" "$TELEMETRY_LAB" || return 1
  else
    vagrant_env
    # C:\lab\mordor is the shared $MORDOR_ROOT
    vagrant winrm win -e -c "powershell -NoProfile -ExecutionPolicy Bypass -Command \"& C:\\lab\\scripts\\Invoke-MordorRecord.ps1 -Techniques $techniques -Run $run -Out C:\\lab\\mordor\\telemetry\"" || return 1
    [ -f "$MORDOR_ROOT/telemetry/$run/manifest.json" ] || die "Nothing was recorded ($MORDOR_ROOT/telemetry/$run)"
    mkdir -p "$TELEMETRY_LAB" && cp -R "$MORDOR_ROOT/telemetry/$run" "$TELEMETRY_LAB/"
  fi
  ( cd "$REPO_ROOT" && DERNVALE_TELEMETRY_LAB="$TELEMETRY_LAB" python3 -m src.mordor.telemetry --build --source lab ) \
    && ok "Recorded telemetry: $TELEMETRY_LAB/$run (source 'Your lab'; see /api/mordor/telemetry)"
}

# mordor-dataset <run>: a recording as a dataset Elrond can analyse, in $MORDOR_ROOT/lab/<run>/
# (acquisitions/ plus expected.json, the tests that ran). See src/mordor/lab/dataset.py.
cmd_mordor_dataset() {
  local run="${1:?run name (a folder in $TELEMETRY_LAB)}"
  case "$run" in *[!A-Za-z0-9_.-]*) die "Run names may only use letters, digits, _ . -" ;; esac
  ( cd "$REPO_ROOT" && python3 -m src.mordor.lab.dataset --run "$run" --src "$TELEMETRY_LAB" --dest "$MORDOR_ROOT/lab" )
}

# ----------------------------------------------------------------------- dernvale

cmd_dernvale_env() {
  step "Environment for tests/scripts/run_test.py"
  mkdir -p "$LAB_CONFIG_DIR"
  cat > "$TESTS_ENV" <<EOF
# Generated by lab/lab.sh. Load with:  set -a; . "$TESTS_ENV"; set +a
TEST_IMAGES_PATH="${TEST_IMAGES_PATH:-$LAB_DATA_DIR}"
TEST_OUTPUT_PATH="${TEST_IMAGES_PATH:-$LAB_DATA_DIR}/test-output"
# Elrond's --Gandalf mode requires a directory ending in /acquisitions/
GANDALF_BASH_PATH="$ACQ_ROOT/bash_collection/acquisitions/"
GANDALF_PYTHON_PATH="$ACQ_ROOT/python_collection/acquisitions/"
GANDALF_POWERSHELL_PATH="$ACQ_ROOT/powershell_collection/acquisitions/"
MORDOR_DATASETS_PATH="$MORDOR_ROOT"
EOF
  ok "Wrote $TESTS_ENV"

  pick_docker_context
  local probe="${TEST_IMAGES_PATH:-$LAB_DATA_DIR}"
  if docker ps --format '{{.Names}}' | grep -qx dernvale-celery-worker; then
    if docker exec dernvale-celery-worker test -d "$probe"; then
      ok "Dernvale's worker can see $probe"
    else
      local override="$LAB_ROOT/docker-compose.lab.yml"
      cat > "$override" <<EOF
# Generated by lab/lab.sh: lets Dernvale read the lab's data directory.
services:
  backend:
    volumes:
      - "$probe:$probe:ro"
  celery-worker:
    volumes:
      - "$probe:$probe"
EOF
      warn "Dernvale's worker can't see $probe. Recreate it with the generated override:"
      echo "    docker compose -f docker-compose.yml [your other -f files] -f lab/docker-compose.lab.yml up -d backend celery-worker"
    fi
  else
    warn "Dernvale isn't running; start it, then re-run this step to check the mounts."
  fi

  cat <<EOF

Run the Gandalf tests against what the lab collected:
    set -a; . "$TESTS_ENV"; set +a
    python3 tests/scripts/run_test.py --run gandalf_bash_basic --wait
    python3 tests/scripts/run_test.py --run-tags gandalf
Each acquisition folder has the target's expected.json (seeded artefacts, ATT&CK IDs,
IOCs) to check Elrond's output against.

Mordor tests: run_test.py builds paths like \$MORDOR_DATASETS_PATH/apt29/day1, which
don't end in /acquisitions/, and Elrond's --Mordor flag currently reuses the Gandalf
reader (Gandalf zips, not OTRF JSON). Expect those tests to fail until Elrond has an
OTRF ingest; the datasets are laid out ready for it.
EOF
}

# ----------------------------------------------------------------------- status/teardown

cmd_status() {
  step "Containers"
  if need docker && docker info >/dev/null 2>&1; then pick_docker_context; lab_compose ps 2>/dev/null || true; fi
  step "VMs"
  if uses_vagrant && need vagrant; then VAGRANT_CWD="$VAGRANT_DIR" REPO_ROOT="$REPO_ROOT" ACQ_ROOT="$ACQ_ROOT" MORDOR_ROOT="$MORDOR_ROOT" vagrant status 2>/dev/null | sed -n '/Current machine states/,/^$/p'; fi
  if uses_tart && [ -n "$(tart_bin)" ]; then "$LAB_ROOT/macos/tart-vm.sh" status linux; "$LAB_ROOT/macos/tart-vm.sh" status macos; fi
  step "Data"
  du -sh "$ACQ_ROOT" "$MORDOR_ROOT" 2>/dev/null || echo "  nothing collected yet"
}

cmd_teardown() {
  warn "This removes lab containers and VMs. Collected data in $LAB_DATA_DIR is kept."
  confirm "Tear down the lab?" n || return
  if need docker && docker info >/dev/null 2>&1; then pick_docker_context; lab_compose --profile controller down -v --rmi local || true; fi
  if uses_vagrant && need vagrant; then vagrant_env; vagrant destroy -f || true; fi
  # LAB_FORCE, not LAB_YES: each delete's own prompt defaults to no, and the
  # teardown was already confirmed above.
  if uses_tart && [ -n "$(tart_bin)" ]; then LAB_FORCE=1 "$LAB_ROOT/macos/tart-vm.sh" delete linux || true; LAB_FORCE=1 "$LAB_ROOT/macos/tart-vm.sh" delete macos || true; fi
  if uses_tart && [ -d /Applications/UTM.app ]; then LAB_FORCE=1 "$LAB_ROOT/windows/utm-vm.sh" delete || true; fi
  [ "${LAB_KEEP_PASSWORD:-0}" = "1" ] || { confirm "Also remove the stored lab password?" n && delete_password && ok "Removed"; }
  ok "Lab torn down"
}

# --------------------------------------------------------------------------- agent

AGENT_PID="$LAB_CONFIG_DIR/run/agent.pid"
AGENT_LOG="$LAB_CONFIG_DIR/run/agent.log"

cmd_agent() {
  mkdir -p "$LAB_CONFIG_DIR/run"
  case "${1:-status}" in
    start)
      if [ -f "$AGENT_PID" ] && kill -0 "$(cat "$AGENT_PID")" 2>/dev/null; then ok "Lab agent already running (pid $(cat "$AGENT_PID"))"; return; fi
      echo "The lab agent lets admin users of the Dernvale web UI run this lab's commands"
      echo "on this machine: start/stop lab containers and VMs, collect with Gandalf, download"
      echo "and generate Mordor datasets. It listens on $(forward_ip):5691 only, for the Dernvale"
      echo "backend, and accepts nothing but the lab commands listed in ./lab.sh help."
      confirm "Start the lab agent?" y || return
      nohup python3 "$LAB_ROOT/agent/lab_agent.py" --bind "$(forward_ip)" >"$AGENT_LOG" 2>&1 &
      echo $! > "$AGENT_PID"
      sleep 1
      kill -0 "$(cat "$AGENT_PID")" 2>/dev/null && ok "Lab agent running (log: $AGENT_LOG). Open Dernvale > Aragorn > Lab." || { fail "Agent failed to start:"; tail -5 "$AGENT_LOG"; }
      ;;
    stop)
      [ -f "$AGENT_PID" ] && kill "$(cat "$AGENT_PID")" 2>/dev/null && rm -f "$AGENT_PID" && ok "Lab agent stopped" || warn "Lab agent wasn't running"
      ;;
    status)
      if [ -f "$AGENT_PID" ] && kill -0 "$(cat "$AGENT_PID")" 2>/dev/null; then ok "Lab agent running (pid $(cat "$AGENT_PID"))"; else echo "Lab agent not running (./lab.sh agent start)"; fi
      ;;
    *) die "agent start|stop|status" ;;
  esac
}


# ------------------------------------------------------- non-interactive (lab agent)

CONFIG_KEYS="LAB_DATA_DIR TEST_IMAGES_PATH LAB_VM_DIR WINDOWS_VM_MEMORY_MB WINDOWS_VM_CPUS LINUX_VM_MEMORY_MB WINDOWS_UTM_VM LAB_TART_HOME LAB_HIDDEN_MACHINES"

# KEY=value lines describing this host and the lab, for the web UI.
cmd_state() {
  local k docker_ok=no vm_tool=none
  need docker && docker info >/dev/null 2>&1 && docker_ok=yes
  if uses_vagrant; then need vagrant && need VBoxManage && vm_tool=vagrant; fi
  if uses_tart; then [ -n "$(tart_bin)" ] && vm_tool=tart; fi
  echo "profile=$(host_profile)"
  echo "label=$(host_label)"
  echo "os_version=$(os_version)"
  echo "ram_gb=$(host_ram_gb)"
  echo "docker=$docker_ok"
  echo "vm_tool=$vm_tool"
  echo "password_set=yes"
  echo "password_default=$([ -n "$(lab_password)" ] && echo no || echo yes)"
  echo "default_password=$LAB_DEFAULT_PASSWORD"
  echo "repo_root=$REPO_ROOT"
  echo "linux_containers=$LINUX_CONTAINERS"
  echo "mordor_presets=$MORDOR_PRESETS"
  for k in $CONFIG_KEYS; do eval "echo \"$k=\${$k:-}\""; done
}

# set-config KEY=value ...: change lab.conf without the interactive menu.
cmd_set_config() {
  local kv k v
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    case " $CONFIG_KEYS " in *" $k "*) ;; *) die "Unknown setting: $k" ;; esac
    case "$v" in *'"'*|*"'"*|*'$'*|*'`'*|*\\*) die "$k: quotes, \$, backticks and backslashes aren't allowed" ;; esac
    case "$k" in *_MB|*_CPUS) case "$v" in ''|*[!0-9]*) die "$k must be a number" ;; esac ;; esac
    eval "$k=\$v"
  done
  save_config
}

# set-password: read the lab password from stdin (never argv) and store it;
# an empty line goes back to the default.
cmd_set_password() {
  local p
  IFS= read -r p || die "No password on stdin"
  if [ -z "$p" ]; then delete_password; ok "Using the default lab password '$LAB_DEFAULT_PASSWORD'"; return; fi
  case "$p" in *"'"*|*'"'*|*\\*|*' '*) die "Avoid quotes, backslashes and spaces; the password is passed to remote shells" ;; esac
  local where; where="$(store_password "$p")"
  [ -n "$where" ] || die "No keyring available (install libsecret-tools for secret-tool)"
  ok "Lab password stored in $where"
}

# --------------------------------------------------------------------------- menu

usage() {
  cat <<EOF
Usage: ./lab.sh [command]

  check               Host, tools and settings report
  install             Install prerequisites for this Mac (Homebrew)
  configure           Data location, VM sizes, lab password
  linux-targets [up|stacking|down|reset|status]   Two seeded Linux containers (stacking: plus two clean Ubuntu)
  linux-vm [create|start|stop|delete|status]
  macos-vm [create|start|stop|delete|status|move <dir>]   (Apple silicon)
  windows-vm [create|start|stop|provision|gui|delete|status]
  gandalf-collect [bash|python|powershell|all] ["targets"]
  stacking-eval       Collect the Linux stacking targets, run Elrond, score stacking.csv (adds a row to README.md)
  mordor-download [test paths...]   e.g. apt29/day1 atomic/persistence
  mordor-sensor       Sysmon + Atomic Red Team in the Windows VM
  mordor-capture      Run atomics and export a dataset
  mordor-record [preset | custom <name> <T1,T2> [run]]   Record each atomic test's logs for the telemetry engine
  mordor-dataset <run>   Turn a recording into a dataset Elrond can analyse ($MORDOR_ROOT/lab/<run>)
  dernvale-env       Write the env file for run_test.py and check mounts
  agent [start|stop|status]   Host agent so the Dernvale web UI can drive the lab
  status | teardown
  quickstart          Guided first run: check, install, configure, targets, collect

Set LAB_YES=1 to accept defaults without prompting.
EOF
}

cmd_quickstart() {
  cmd_check
  confirm "Install anything missing?" y && cmd_install
  [ -f "$LAB_CONFIG" ] || cmd_configure
  confirm "Start the Linux container targets?" y && cmd_linux_targets up
  confirm "Collect from them with Gandalf (bash + python)?" y && { cmd_gandalf_collect bash ""; cmd_gandalf_collect python ""; }
  confirm "Download the Mordor datasets (APT29 day 1/2 only, to start)?" y && cmd_mordor_download apt29/day1 apt29/day2
  cmd_dernvale_env
  echo
  info "VMs (Linux, macOS, Windows) are next; use the menu when you're ready, as they're large downloads."
}

main_menu() {
  while true; do
    menu "Dernvale test lab ($(host_label), data: $LAB_DATA_DIR)" \
      "Quickstart (guided first run)" \
      "Check this Mac" \
      "Install prerequisites" \
      "Configure (data location, VM sizes, password)" \
      "Gandalf: Linux container targets" \
      "Gandalf: Linux VM" \
      "Gandalf: macOS target" \
      "Gandalf: Windows VM" \
      "Gandalf: run collections" \
      "Mordor: download OTRF datasets" \
      "Mordor: install sensor + Atomic Red Team (Windows VM)" \
      "Mordor: generate a dataset" \
      "Mordor: record telemetry (each test's logs)" \
      "Dernvale: test environment and mounts" \
      "Web UI: start/stop the lab agent" \
      "Status" \
      "Tear down"
    case "$MENU_CHOICE" in
      0) exit 0 ;;
      1) cmd_quickstart ;;   2) cmd_check ;;        3) cmd_install ;;     4) cmd_configure ;;
      5) cmd_linux_targets ;; 6) cmd_linux_vm ;;    7) cmd_macos_vm ;;    8) cmd_windows_vm ;;
      9) cmd_gandalf_collect ;; 10) cmd_mordor_download ;; 11) cmd_mordor_sensor ;; 12) cmd_mordor_capture ;;
      13) cmd_mordor_record ;; 14) cmd_dernvale_env ;;
      15) menu "Lab agent" "Start" "Stop" "Status"; case "$MENU_CHOICE" in 1) cmd_agent start ;; 2) cmd_agent stop ;; 3) cmd_agent status ;; esac ;;
      16) cmd_status ;; 17) cmd_teardown ;;
    esac
  done
}

[ "$(host_profile)" = unsupported ] && die "Unsupported host: $(uname -sm). The lab runs on macOS (Intel or Apple silicon) and Linux (x86-64 or arm64). On Windows, run it inside WSL2."

case "${1:-}" in
  "") main_menu ;;
  help|-h|--help) usage ;;
  check) cmd_check ;;
  install) cmd_install ;;
  configure) cmd_configure ;;
  linux-targets) shift; cmd_linux_targets "$@" ;;
  linux-vm) shift; cmd_linux_vm "$@" ;;
  macos-vm) shift; cmd_macos_vm "$@" ;;
  windows-vm) shift; cmd_windows_vm "$@" ;;
  gandalf-collect) shift; cmd_gandalf_collect "$@" ;;
  stacking-eval) cmd_stacking_eval ;;
  mordor-download) shift; cmd_mordor_download "$@" ;;
  mordor-sensor) cmd_mordor_sensor ;;
  mordor-capture) shift; cmd_mordor_capture "$@" ;;
  mordor-record) shift; cmd_mordor_record "$@" ;;
  mordor-dataset) shift; cmd_mordor_dataset "$@" ;;
  agent) shift; cmd_agent "$@" ;;
  dernvale-env) cmd_dernvale_env ;;
  state) cmd_state ;;
  set-config) shift; cmd_set_config "$@" ;;
  set-password) cmd_set_password ;;
  status) cmd_status ;;
  teardown) cmd_teardown ;;
  quickstart) cmd_quickstart ;;
  *) usage; exit 1 ;;
esac

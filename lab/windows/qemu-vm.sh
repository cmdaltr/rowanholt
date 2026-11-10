#!/usr/bin/env bash
# x86-64 hosts without Vagrant (the Intel Mac Mini): an unattended Windows 11 x64 VM in plain QEMU
# (HVF on macOS, KVM on Linux), its files under $LAB_VM_DIR/qemu/<vm>.
#   qemu-vm.sh create|start|stop|delete|status
#   qemu-vm.sh sensor | record <T1,T2> <run> <dest-dir> | pull-recording <run> <dest-dir>   (Atomic Red Team)
#   qemu-vm.sh capture <dest-dir>   memory and disk at one moment: the VM paused, its RAM dumped, the
#                                   disk copied as it was, then resumed; raw images and SHA256SUMS
#   qemu-vm.sh sample <dest-dir>    a Rowanholt sample: a clean VM (nothing seeded), the sensor,
#                                   Atomic Red Team with nothing cleaned up, then capture
# create builds a config ISO (autounattend.xml made x64 from the UTM one, the lab scripts, OpenSSH)
# and boots the Windows ISO with it. Windows installs itself and starts an SSH server, forwarded to
# 127.0.0.1:2232. The disk is SATA and the network card e1000e, both Windows' own drivers, so no
# virtio ISO; TPM and Secure Boot checks are bypassed (LabConfig), as in UTM.
# The screen is on VNC at 127.0.0.1:5959 (the lab password's first 8 characters, loopback only): from another machine,
# ssh -L 5959:127.0.0.1:5959 <host>, then open vnc://127.0.0.1:5959.
# The Windows 11 x64 ISO is the one manual download: put it in $LAB_DATA_DIR/isos/, or set
# WINDOWS_X64_ISO=/path/to.iso.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
load_config

action="${1:?create|start|stop|delete|status|sensor|record|pull-recording|capture|sample}"
[ "$(host_arch)" = x86_64 ] || die "x64 Windows needs an x86-64 host. On Apple silicon: ./windows/utm-vm.sh"
command -v qemu-system-x86_64 >/dev/null || die "QEMU isn't installed (brew install qemu, or apt install qemu-system-x86)"

VM="${WINDOWS_QEMU_VM:-rowan-lab-win11-x64}"
PORT=2232
COMPUTERNAME="LAB-WIN11"
QEMU_DIR="$LAB_VM_DIR/qemu/$VM"
DISK="$QEMU_DIR/disk.qcow2"
VARS="$QEMU_DIR/efivars.fd"
QMP_SOCK="$QEMU_DIR/qmp.sock"
PIDFILE="$QEMU_DIR/qemu.pid"
MEDIA="$QEMU_DIR/install-media"  # the ISOs attached until the install is done, one per line
CFG_ISO="$QEMU_DIR/labcfg.iso"
ISO_DIR="$LAB_DATA_DIR/isos"
OPENSSH_URL="https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"
SSH="$LAB_ROOT/lib/ssh.exp"
QMP="$LAB_ROOT/windows/qemu/qmp.py"
SELF="qemu-vm.sh"
STUCK="Watch its screen on vnc://127.0.0.1:5959 to see where it stopped"
DISK_GB="${WINDOWS_QEMU_DISK_GB:-48}"
# The Atomic Red Team tests a sample runs, in this order: discovery first, the log clearing last
# so it wipes only what came before it (as an intruder's would)
SAMPLE_TECHNIQUES="${SAMPLE_TECHNIQUES:-T1082,T1087.001,T1016,T1547.001,T1053.005,T1543.003,T1552.001,T1003.001,T1218.011,T1562.001,T1070.001}"

running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }
vm_status() { if running; then echo started; elif [ -f "$DISK" ]; then echo stopped; else echo "not created"; fi; }
qmp() { python3 -I "$QMP" "$QMP_SOCK" "$@"; }
. "$LAB_ROOT/windows/guest.sh"

windows_iso() {
  if [ -n "${WINDOWS_X64_ISO:-}" ]; then echo "$WINDOWS_X64_ISO"; return; fi
  ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v -i -E 'arm64|virtio|labcfg' | head -1 || true
}

# UEFI firmware from QEMU's own share folder (Homebrew's, or a distribution's OVMF)
firmware() {
  local d
  for d in "$(dirname "$(command -v qemu-system-x86_64)")/../share/qemu" /usr/share/qemu /usr/share/OVMF; do
    if [ -f "$d/edk2-x86_64-code.fd" ]; then echo "$d/edk2-x86_64-code.fd $d/edk2-i386-vars.fd"; return; fi
    if [ -f "$d/OVMF_CODE.fd" ]; then echo "$d/OVMF_CODE.fd $d/OVMF_VARS.fd"; return; fi
  done
  die "No x86-64 UEFI firmware (edk2-x86_64-code.fd or OVMF_CODE.fd) found with QEMU"
}

download() {  # download <url> <dest>
  [ -s "$2" ] && return 0
  info "Downloading $(basename "$2")"
  python3 - "$1" "$2.part" <<'PY'
import shutil, sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=60) as r, open(sys.argv[2], "wb") as f:
    shutil.copyfileobj(r, f, 1 << 20)
PY
  mv "$2.part" "$2"
}

# The UTM answer file, made x64: amd64 components, and no virtio driver paths (SATA and e1000e
# need none)
# What the answer file has to match on this ISO: its language (sources/lang.ini) and edition
# (sources/EI.CFG). An evaluation ISO is single-language (en-GB, say) and Enterprise Evaluation,
# which takes no product key; asked for another language or edition, Setup stops at its first page.
# Prints "<language> <eval:0|1>"; en-us and 0 when the ISO can't be read.
iso_facts() {
  local iso="$1" dir="" lang="" ei=""
  if is_macos; then
    dir="$(hdiutil attach -readonly -nobrowse "$iso" 2>/dev/null | tail -1 | cut -f3-)"
    if [ -n "$dir" ]; then
      lang="$(cat "$dir/sources/lang.ini" 2>/dev/null || true)"
      ei="$(cat "$dir/sources/EI.CFG" "$dir/sources/ei.cfg" 2>/dev/null || true)"
      hdiutil detach "$dir" -quiet || true
    fi
  elif command -v bsdtar >/dev/null; then
    lang="$(bsdtar -xOf "$iso" sources/lang.ini 2>/dev/null || true)"
    ei="$(bsdtar -xOf "$iso" sources/ei.cfg 2>/dev/null || bsdtar -xOf "$iso" sources/EI.CFG 2>/dev/null || true)"
  fi
  lang="$(printf '%s\n' "$lang" | tr -d '\r' | sed -n '/Available UI Languages/,/^\[/p' | grep -m1 -oE '^[a-zA-Z]{2}-[a-zA-Z]{2}' || true)"
  printf '%s %s\n' "${WINDOWS_UI_LANGUAGE:-${lang:-en-us}}" "$(printf '%s' "$ei" | grep -qi eval && echo 1 || echo 0)"
}

build_config_iso() {
  local win="$1" stage="$QEMU_DIR/labcfg" pw_xml lang eval
  read -r lang eval <<<"$(iso_facts "$win")"
  info "Windows ISO: language $lang$([ "$eval" = 1 ] && echo ", Enterprise Evaluation")"
  rm -rf "${stage:?}"
  mkdir -p "$stage/lab-scripts" "$stage/gandalf-src"
  cp "$LAB_ROOT/windows/utm/firstlogon.ps1" "$stage/"
  cp "$LAB_ROOT/windows/"*.ps1 "$stage/lab-scripts/"
  rsync -a --delete --exclude '__pycache__' "$REPO_ROOT/src/acquisition/" "$stage/gandalf-src/"
  ( umask 077; printf '%s' "$LAB_PASSWORD" > "$stage/lab-password.txt" )
  [ "${WINDOWS_QEMU_CLEAN:-0}" = 1 ] && : > "$stage/clean.txt"
  cp "$ISO_DIR/OpenSSH-Win64.zip" "$stage/"
  pw_xml="$(printf '%s' "$LAB_PASSWORD" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')"
  python3 - "$LAB_ROOT/windows/utm/autounattend.xml" "$stage/autounattend.xml" "$pw_xml" "$COMPUTERNAME" "$lang" "$eval" <<'PY'
import re, sys
src, dst, pw, name, lang, evaluation = sys.argv[1:7]
text = open(src, encoding="utf-8").read()
text = re.sub(r'\s*<!-- VirtIO disk and network drivers.*?</component>', "", text, count=1, flags=re.S)
text = text.replace('processorArchitecture="arm64"', 'processorArchitecture="amd64"')
text = re.sub(r"<(SetupUILanguage><UILanguage|UILanguage)>en-US<", lambda m: f"<{m.group(1)}>{lang}<", text)
if evaluation == "1":  # one image, no key
    text = text.replace("<Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value>", "<Key>/IMAGE/INDEX</Key><Value>1</Value>")
    text = re.sub(r"\s*<ProductKey>.*?</ProductKey>", "", text, flags=re.S)
text = text.replace("@@PASSWORD@@", pw).replace("@@COMPUTERNAME@@", name)
assert "viostor" not in text and "arm64" not in text and "en-US<" not in text
open(dst, "w", encoding="utf-8").write(text)
PY
  rm -f "$CFG_ISO"
  if is_macos; then
    hdiutil makehybrid -quiet -iso -joliet -default-volume-name LABCFG -o "$CFG_ISO" "$stage"
  else
    require xorriso
    xorriso -as mkisofs -quiet -J -V LABCFG -o "$CFG_ISO" "$stage"
  fi
  chmod 600 "$CFG_ISO"
  rm -rf "${stage:?}"
  ok "Config ISO: $CFG_ISO (holds the lab password; removed once Windows is installed)"
}

create_vm() {
  local win="$1" code vars
  read -r code vars <<<"$(firmware)"
  mkdir -p "$QEMU_DIR"
  info "Creating $VM (${WINDOWS_VM_MEMORY_MB} MB, ${WINDOWS_VM_CPUS} CPUs, ${DISK_GB} GB disk) in $QEMU_DIR"
  cp "$vars" "$VARS"
  qemu-img create -q -f qcow2 "$DISK" "${DISK_GB}G"
  printf '%s\n%s\n' "$win" "$CFG_ISO" > "$MEDIA"
}

start_vm() {
  running && return 0
  [ -f "$DISK" ] || die "$VM doesn't exist; create it first: ./windows/$SELF create"
  local code vars accel media=() i=0 iso
  read -r code vars <<<"$(firmware)"
  if is_macos; then accel=hvf; else accel=kvm; fi
  if [ -f "$MEDIA" ]; then
    while IFS= read -r iso; do
      [ -n "$iso" ] || continue
      i=$((i + 1))
      media+=(-drive "id=cd$i,file=$iso,if=none,media=cdrom,readonly=on" -device "ide-cd,drive=cd$i,bus=ahci.$i,bootindex=$((i - 1))")
    done < "$MEDIA"
  fi
  rm -f "$QMP_SOCK"
  info "Starting $VM (SSH on 127.0.0.1:$PORT, screen on vnc://127.0.0.1:5959)"
  qemu-system-x86_64 -name "$VM" -machine "q35,accel=$accel" -cpu "${WINDOWS_QEMU_CPU:-host}" \
    -smp "$WINDOWS_VM_CPUS" -m "$WINDOWS_VM_MEMORY_MB" \
    -drive "if=pflash,format=raw,readonly=on,file=$code" -drive "if=pflash,format=raw,file=$VARS" \
    -device ahci,id=ahci \
    -drive "id=disk,file=$DISK,if=none,format=qcow2,discard=unmap" -device "ide-hd,drive=disk,bus=ahci.0,bootindex=9" \
    ${media[@]+"${media[@]}"} \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$PORT-:22" -device e1000e,netdev=net0 \
    -device qemu-xhci -device usb-tablet -vga std -display none -vnc 127.0.0.1:59,password=on \
    -rtc base=utc -qmp "unix:$QMP_SOCK,server=on,wait=off" -pidfile "$PIDFILE" -daemonize \
    ${WINDOWS_QEMU_ARGS:-}  # e.g. "-action reboot=shutdown,shutdown=pause" to stop on a crash and keep its screen; resuming then needs qmp.py set-action '{"reboot":"reset"}' before system_reset and cont, since that action turns system_reset into another shutdown
  for i in $(seq 1 20); do [ -S "$QMP_SOCK" ] && break; sleep 1; done
  [ -S "$QMP_SOCK" ] || die "QEMU started but its control socket ($QMP_SOCK) didn't appear"
  # macOS Screen Sharing won't connect to a VNC server without a password. VNC keeps 8 characters.
  require_password
  qmp set_password "{\"protocol\":\"vnc\",\"password\":\"${LAB_PASSWORD:0:8}\"}" >/dev/null \
    || warn "Couldn't set the VNC password; the screen won't open until it's set"
}

stop_vm() {
  running || { ok "$VM isn't running"; return 0; }
  info "Shutting $VM down"
  qmp system_powerdown >/dev/null || true
  local _
  for _ in $(seq 1 90); do running || break; sleep 2; done
  if running; then warn "Windows didn't shut down in 3 minutes; stopping QEMU"; qmp quit >/dev/null || kill "$(cat "$PIDFILE")"; fi
  rm -f "$PIDFILE" "$QMP_SOCK"
  ok "$VM stopped"
}

# The ISO waits a few seconds for a key before it boots from CD
press_to_boot() { qmp keys spc 20 1 || true; }

# capture <dest>: memory and disk at the same moment. The VM is paused, its RAM dumped
# (dump-guest-memory, an ELF core, then made raw), the disk copied as it is (a full backup job,
# which runs while the guest is paused), and then resumed. Raw images are what Elrond reads: the
# memory for Volatility, the disk for kpartx in the worker.
capture() {
  local dest="${1:?destination folder}" elf
  running || die "$VM isn't running"
  mkdir -p "$dest"
  [ -e "$dest/memory.mem" ] || [ -e "$dest/disk.dd" ] && die "$dest already holds a capture"
  elf="$dest/memory.elf"
  info "Pausing $VM"
  qmp stop >/dev/null
  date -u +%Y-%m-%dT%H:%M:%SZ > "$dest/captured-at.txt"
  info "Dumping its memory (${WINDOWS_VM_MEMORY_MB} MB)"
  qmp dump-guest-memory "{\"paging\": false, \"protocol\": \"file:$elf\"}" >/dev/null || { qmp cont >/dev/null; die "Memory dump failed"; }
  info "Copying its disk as it is now"
  qmp backup disk "$dest/disk.qcow2" || { qmp cont >/dev/null; die "Disk copy failed"; }
  qmp cont >/dev/null
  ok "$VM resumed"
  info "Raw images"
  python3 -I "$QMP" elf2raw "$elf" "$dest/memory.mem" >/dev/null && rm -f "$elf"
  qemu-img convert -p -O raw "$dest/disk.qcow2" "$dest/disk.dd" && rm -f "$dest/disk.qcow2"
  ( cd "$dest" && shasum -a 256 memory.mem disk.dd > SHA256SUMS )
  ok "Captured: $dest (memory.mem, disk.dd, SHA256SUMS)"
}

create() {
  require_password
  local win
  win="$(windows_iso)"
  if [ -z "$win" ] || [ ! -f "$win" ]; then
    fail "No Windows 11 x64 ISO in $ISO_DIR."
    echo "  Download it from https://www.microsoft.com/software-download/windows11 (or the evaluation"
    echo "  centre), save it in $ISO_DIR and run this again. WINDOWS_X64_ISO=/path/to.iso uses one elsewhere."
    exit 1
  fi
  mkdir -p "$ISO_DIR"
  if [ -f "$DISK" ]; then
    info "$VM already exists"
    start_vm
  else
    download "$OPENSSH_URL" "$ISO_DIR/OpenSSH-Win64.zip"
    info "Windows ISO: $win"
    mkdir -p "$QEMU_DIR"
    build_config_iso "$win"
    create_vm "$win"
    start_vm
    press_to_boot
  fi
  # WINDOWS_INSTALL_WAIT: minutes to allow; a spinning disk can need hours
  wait_ready "${WINDOWS_INSTALL_WAIT:-120}"
  if [ -f "$MEDIA" ]; then
    info "Detaching the install media"
    stop_vm
    rm -f "$MEDIA" "$CFG_ISO"
    start_vm
    wait_ready "${WINDOWS_BOOT_WAIT:-30}" "boot"
  fi
}

# sample <dest>: everything a Rowanholt sample needs, then the run's expected.json beside the
# images (the tests that ran and when: the answer key)
sample() {
  local dest="${1:?destination folder}" run
  [ -e "$dest/disk.dd" ] && die "$dest already holds a sample"
  run="win11-atomics-$(date +%Y%m%d)"
  if [ "${WINDOWS_SAMPLE_RESUME:-}" = 1 ]; then
    # After the Tamper Protection stop: the same fresh install, nothing run on it since
    [ -f "$DISK" ] || die "$VM doesn't exist; run sample without WINDOWS_SAMPLE_RESUME"
    running || start_vm
    wait_ready "${WINDOWS_BOOT_WAIT:-30}" "boot"
  else
    [ -f "$DISK" ] && die "$VM already exists, and a sample starts from a fresh install: delete it first (./windows/$SELF delete)"
    WINDOWS_QEMU_CLEAN=1 create
  fi
  step "Sensor: Sysmon, PowerShell and process auditing, Atomic Red Team; Defender off"
  sensor
  ssh_vm "\$s = Get-MpComputerStatus; 'REALTIME=' + \$s.RealTimeProtectionEnabled" | tr -d '\r' | grep -q 'REALTIME=False' \
    || die "Defender's real-time protection is still on (Tamper Protection). Turn Tamper Protection off in the VM (Windows Security > Virus & threat protection > Manage settings; screen on vnc://127.0.0.1:5959), then: WINDOWS_SAMPLE_RESUME=1 ./windows/$SELF sample $dest"
  step "Atomic Red Team: $SAMPLE_TECHNIQUES"
  MORDOR_NO_CLEANUP=1 record "$SAMPLE_TECHNIQUES" "$run" "$dest/recording"
  step "Capture"
  capture "$dest"
  ( cd "$REPO_ROOT" && python3 -m src.mordor.lab.dataset --run "$run" --src "$dest/recording" --dest "$dest/dataset" ) >/dev/null \
    && cp "$dest/dataset/$run/expected.json" "$dest/expected.json" \
    || warn "Couldn't write expected.json; the recording's manifest.json has the same tests ($dest/recording/$run)"
  ok "Sample: $dest (memory.mem, disk.dd, expected.json, SHA256SUMS; the per-test logs in recording/)"
}

case "$action" in
  create) create ;;
  start) start_vm; wait_ready "${WINDOWS_BOOT_WAIT:-30}" "boot" ;;
  stop) stop_vm ;;
  delete)
    confirm "Delete $VM and its disk?" n || exit 0
    stop_vm
    rm -f "$DISK" "$VARS" "$MEDIA" "$CFG_ISO" "$PIDFILE" "$QMP_SOCK"
    rmdir "$QEMU_DIR" 2>/dev/null || true
    ok "$VM deleted" ;;
  status) echo "$VM: $(vm_status), SSH 127.0.0.1:$PORT, screen vnc://127.0.0.1:5959 ($QEMU_DIR)" ;;
  sensor) sensor ;;
  record) shift; record "$@" ;;
  pull-recording) shift; pull_recording "$@" ;;
  capture) shift; capture "$@" ;;
  sample) shift; sample "$@" ;;
  *) die "unknown action $action" ;;
esac

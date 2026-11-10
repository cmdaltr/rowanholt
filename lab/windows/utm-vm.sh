#!/usr/bin/env bash
# Apple silicon only: an unattended Windows 11 ARM VM in UTM.
#   utm-vm.sh create|adopt [bundle.utm]|start|stop|delete|status|collect|live-containers
#   utm-vm.sh sensor | record <T1,T2> <run> <dest-dir> | pull-recording <run> <dest-dir>   (Atomic Red Team telemetry)
#   utm-vm.sh raw-check [dest-dir]   (reader vs RawCopy, live and off a snapshot; report per run)
# adopt takes a Windows VM that's already installed (a .utm in $LAB_VM_DIR/utm,
# e.g. a Vagrant/Packer build with OpenSSH): it adds the SSH port forward, logs
# in with $ADOPT_USER/$ADOPT_PASSWORD (default vagrant/vagrant) and provisions it.
# create builds a config ISO (autounattend.xml, lab scripts, Gandalf, OpenSSH),
# creates the VM through UTM's AppleScript API and keeps it under
# $LAB_VM_DIR/utm. Windows installs itself, provisions the lab target on first
# logon and starts an SSH server, forwarded to 127.0.0.1:2232.
# WINDOWS_CLEAN=<n> works on clean sibling n instead (<WINDOWS_CLEAN_PREFIX><n>, rowan-lab-win11-clean<n>,
# SSH on 2232+n, nothing seeded), for stacking one seeded host among clean ones.
# The Windows 11 ARM64 ISO is the one manual download (Microsoft only hands out
# links through its web form); put it in $LAB_DATA_DIR/isos/.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
load_config

action="${1:?create|adopt|start|stop|delete|status|collect|live-containers|raw-check|sensor|record|pull-recording}"
uses_tart || die "The UTM VM is for Apple silicon. On x86-64 hosts the lab uses Vagrant: ./lab.sh windows-vm"
[ -d /Applications/UTM.app ] || die "UTM is not installed. Run: ./lab.sh install"

VM="$WINDOWS_UTM_VM"
PORT=2232
COMPUTERNAME="LAB-WIN11"
CLEAN="${WINDOWS_CLEAN:-}"
if [ -n "$CLEAN" ]; then
  case "$CLEAN" in [1-9]) ;; *) die "WINDOWS_CLEAN is a number from 1 to 9" ;; esac
  # NetBIOS names stop at 15 characters
  VM="${WINDOWS_CLEAN_PREFIX:-rowan-lab-win11-clean}$CLEAN"; PORT=$((2232 + CLEAN)); COMPUTERNAME="LAB-WINCLEAN$CLEAN"
fi
UTM_DIR="$LAB_VM_DIR/utm"
BUNDLE="$UTM_DIR/$VM.utm"
ISO_DIR="$LAB_DATA_DIR/isos"
CFG_ISO="$UTM_DIR/labcfg-$VM.iso"
VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
OPENSSH_URL="https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-ARM64.zip"
SSH="$LAB_ROOT/lib/ssh.exp"
SELF="utm-vm.sh"
STUCK="Open UTM to see where it stopped"

utm() { osascript -e "tell application \"UTM\"" -e "$1" -e "end tell"; }
vm_registered() { utm_up; utmctl list --hide 2>/dev/null | awk '{print $3}' | grep -qx "$VM"; }
vm_status() { utm_up; utmctl status --hide "$VM" 2>/dev/null || echo "not registered"; }
. "$LAB_ROOT/windows/guest.sh"

windows_iso() {
  if [ -n "${WINDOWS_ARM_ISO:-}" ]; then echo "$WINDOWS_ARM_ISO"; return; fi
  ls -t "$ISO_DIR"/*[Aa][Rr][Mm]64*.iso 2>/dev/null | grep -v -i virtio | head -1 || true
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

# The lab files every Windows target gets: scripts, Gandalf, first-logon script.
stage_lab_files() {
  local stage="$1"
  mkdir -p "$stage/lab-scripts" "$stage/gandalf-src"
  cp "$LAB_ROOT/windows/utm/firstlogon.ps1" "$stage/"
  cp "$LAB_ROOT/windows/"*.ps1 "$stage/lab-scripts/"
  rsync -a --delete --exclude '__pycache__' "$REPO_ROOT/src/acquisition/" "$stage/gandalf-src/"
  ( umask 077; printf '%s' "$LAB_PASSWORD" > "$stage/lab-password.txt" )
}

build_config_iso() {
  local stage="$UTM_DIR/labcfg"
  stage_lab_files "$stage"
  [ -z "$CLEAN" ] || : > "$stage/clean.txt"
  local pw_xml
  pw_xml="$(printf '%s' "$LAB_PASSWORD" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')"
  python3 - "$LAB_ROOT/windows/utm/autounattend.xml" "$stage/autounattend.xml" "$pw_xml" "$COMPUTERNAME" <<'PY'
import sys
src, dst, pw, name = sys.argv[1:5]
text = open(src, encoding="utf-8").read().replace("@@PASSWORD@@", pw).replace("@@COMPUTERNAME@@", name)
open(dst, "w", encoding="utf-8").write(text)
PY
  cp "$ISO_DIR/OpenSSH-ARM64.zip" "$stage/"
  rm -f "$CFG_ISO"
  hdiutil makehybrid -quiet -iso -joliet -default-volume-name LABCFG -o "$CFG_ISO" "$stage"
  chmod 600 "$CFG_ISO"
  rm -rf "${stage:?}"
  ok "Config ISO: $CFG_ISO (holds the lab password; removed with the VM)"
}

# UTM keeps removable media in its own registry, which export doesn't carry and
# scripts can't change. CD images stored in the bundle are part of config.plist,
# so hard-link the ISOs into Data/ (same volume: no copy) and point the drives at
# them. set_install_media <win.iso> <virtio.iso> <labcfg.iso>, or none to detach.
set_install_media() {
  python3 - "$BUNDLE" "$@" <<'PY'
import os, plistlib, sys
bundle, isos = sys.argv[1], sys.argv[2:]
path = os.path.join(bundle, "config.plist")
cfg = plistlib.load(open(path, "rb"))
cds = [d for d in cfg.get("Drive", []) if d.get("ImageType") == "CD"]
data = os.path.join(bundle, "Data")
for i, drive in enumerate(cds):
    old = drive.pop("ImageName", None)
    if old and old.startswith("lab-") and os.path.exists(os.path.join(data, old)):
        os.remove(os.path.join(data, old))
    if i < len(isos):
        name = "lab-" + os.path.basename(isos[i])
        dest = os.path.join(data, name)
        if os.path.exists(dest):
            os.remove(dest)
        try:
            os.link(isos[i], dest)
        except OSError:  # different volume: copy instead
            import shutil
            shutil.copy2(isos[i], dest)
        drive["ImageName"] = name
plistlib.dump(cfg, open(path, "wb"))
PY
}

# The system disk is VirtIO (driver loaded during setup from the virtio-win ISO).
# Not NVMe: QEMU's NVMe TRIM handler, nvme_dsm_cb, segfaults when Windows trims,
# and the VM just stops.
create_vm() {
  local win="$1" virtio="$ISO_DIR/virtio-win.iso"
  info "Creating $VM in UTM (${WINDOWS_VM_MEMORY_MB} MB, ${WINDOWS_VM_CPUS} CPUs, 64 GB disk)"
  utm "set vm to make new virtual machine with properties {backend:qemu, configuration:{name:\"$VM\", architecture:\"aarch64\", memory:$WINDOWS_VM_MEMORY_MB, cpu cores:$WINDOWS_VM_CPUS, hypervisor:true, uefi:true, drives:{{removable:true, interface:USB, source:POSIX file \"$win\"}, {removable:true, interface:USB, source:POSIX file \"$virtio\"}, {removable:true, interface:USB, source:POSIX file \"$CFG_ISO\"}, {interface:VirtIO, guest size:65536}}, network interfaces:{{mode:emulated}}}}" >/dev/null
  # UTM creates VMs inside its own container; move this one onto the lab drive.
  mkdir -p "$UTM_DIR"
  utm "export (virtual machine named \"$VM\") to POSIX file \"$BUNDLE\""
  [ -f "$BUNDLE/config.plist" ] || die "UTM didn't export $VM to $BUNDLE"
  utm "delete (virtual machine named \"$VM\")"
  set_install_media "$win" "$virtio" "$CFG_ISO"
  write_port_forward
  write_console || true
  register_vm
  ok "$VM: 127.0.0.1:$PORT -> guest port 22"
}

register_vm() {
  vm_registered && return 0
  [ -d "$BUNDLE" ] || die "$BUNDLE doesn't exist; create the VM first"
  utm "open POSIX file \"$BUNDLE\"" >/dev/null
  local _
  for _ in $(seq 1 10); do vm_registered && return 0; sleep 1; done
  die "UTM didn't register $BUNDLE"
}

# Forward 127.0.0.1:$PORT to the guest's SSH on the VM's emulated network card,
# adding one if it has none. UTM only changes configuration while stopped.
# Write the forward into config.plist: UTM's AppleScript rejects any
# configuration record that carries a port forward (on make and on update).
# Also make sure the VM has a display: one made through AppleScript gets none,
# and Windows then runs headless with nothing for UTM (or anyone) to show.
write_port_forward() {
  python3 - "$BUNDLE/config.plist" "$PORT" <<'PY'
import plistlib, sys
path, port = sys.argv[1], int(sys.argv[2])
with open(path, "rb") as f:
    cfg = plistlib.load(f)
if not cfg.get("Display"):
    cfg["Display"] = [{"Hardware": "virtio-ramfb", "DynamicResolution": True, "NativeResolution": False,
                       "UpscalingFilter": "Nearest", "DownscalingFilter": "Linear"}]
fwd = {"Protocol": "TCP", "HostAddress": "127.0.0.1", "HostPort": port, "GuestAddress": "", "GuestPort": 22}
nics = cfg.setdefault("Network", [])
emulated = [n for n in nics if n.get("Mode") == "Emulated"]
if emulated:
    nic = emulated[0]
else:
    nic = {"Hardware": "virtio-net-pci", "IsolateFromHost": False, "Mode": "Emulated"}
    nics.append(nic)
nic["PortForward"] = [f for f in nic.get("PortForward", []) if f.get("HostPort") != port] + [fwd]
with open(path, "wb") as f:
    plistlib.dump(cfg, f)
PY
}

# The VM's screen over VNC on 127.0.0.1:$VNC_PORT (QEMU display $VNC_DISPLAY; no password,
# loopback only), for the Console button on Aragorn > Lab and any VNC client on this host
# (open vnc://127.0.0.1:5959). Only with LAB_VM_CONSOLE=1 (or the older WINDOWS_VM_VNC=1).
# Exits 0 when config.plist changed (UTM then needs to reload it), 1 when it was already so.
VNC_DISPLAY=$((59 + ${CLEAN:-0}))
VNC_PORT=$((5900 + VNC_DISPLAY))
write_console() {
  python3 - "$BUNDLE/config.plist" "$VNC_DISPLAY" "${LAB_VM_CONSOLE:-${WINDOWS_VM_VNC:-0}}" <<'PY'
import plistlib, sys
path, display, on = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
with open(path, "rb") as f:
    cfg = plistlib.load(f)
old = cfg.setdefault("QEMU", {}).get("AdditionalArguments", [])
args, skip = [], False
for a in old:
    if skip:
        skip = False
    elif a == "-vnc":
        skip = True
    else:
        args.append(a)
args += ["-vnc", "127.0.0.1:" + display] if on else []
if args == old:
    sys.exit(1)
cfg["QEMU"]["AdditionalArguments"] = args
with open(path, "wb") as f:
    plistlib.dump(cfg, f)
PY
}

# Before a start: put the console in place on a VM made before consoles were (UTM only takes a
# configuration change while the VM is stopped)
ensure_console() {
  [ -f "$BUNDLE/config.plist" ] && [ "$(vm_status)" = stopped ] || return 0
  if write_console; then
    utm "reload configuration (virtual machine named \"$VM\")" >/dev/null 2>&1 || true
    ok "$VM: console on 127.0.0.1:$VNC_PORT"
  fi
}

add_port_forward() {
  if [ "$(vm_status)" != stopped ]; then utmctl stop --hide "$VM" >/dev/null 2>&1 || true; sleep 3; fi
  write_port_forward
  write_console || true
  utm "reload configuration (virtual machine named \"$VM\")" >/dev/null
  ok "$VM: 127.0.0.1:$PORT -> guest port 22"
}

# The VM's address on UTM's shared network, from macOS's DHCP leases (which
# drop leading zeros from each MAC octet).
shared_ip() {
  local mac
  mac="$(python3 - "$BUNDLE/config.plist" <<'PY'
import plistlib, sys
cfg = plistlib.load(open(sys.argv[1], "rb"))
for nic in cfg.get("Network", []):
    if nic.get("Mode") == "Shared" and nic.get("MacAddress"):
        print(":".join(format(int(o, 16), "x") for o in nic["MacAddress"].split(":")))
        break
PY
)"
  [ -n "$mac" ] || return 0
  awk -v mac="1,$mac" '/ip_address=/ {sub(/.*ip_address=/, ""); ip=$0} /hw_address=/ {sub(/.*hw_address=/, ""); if (tolower($0) == mac) print ip}' /var/db/dhcpd_leases 2>/dev/null | tail -1
}

# Vagrant's Windows boxes come with WinRM, not SSH: install OpenSSH Server
# through WinRM (pywinrm, in a virtualenv that belongs to the lab only).
bootstrap_ssh_over_winrm() {
  local user="$1" pass="$2" ip venv="$LAB_CONFIG_DIR/venv"
  ip="$(shared_ip)"
  [ -n "$ip" ] || return 1
  python3 -c "import socket; socket.create_connection(('$ip', 5985), timeout=5)" 2>/dev/null || return 1
  info "No SSH yet; installing OpenSSH Server over WinRM ($ip:5985, as '$user')"
  if [ ! -x "$venv/bin/python" ]; then python3 -m venv "$venv" && "$venv/bin/pip" install -q pywinrm || return 1; fi
  "$venv/bin/pip" show -q pywinrm >/dev/null 2>&1 || "$venv/bin/pip" install -q pywinrm || return 1
  OPENSSH_URL="$OPENSSH_URL" WINRM_IP="$ip" WINRM_USER="$user" WINRM_PASSWORD="$pass" "$venv/bin/python" -I - <<'PY'
import os, sys, winrm
s = winrm.Session("http://{}:5985/wsman".format(os.environ["WINRM_IP"]),
                  auth=(os.environ["WINRM_USER"], os.environ["WINRM_PASSWORD"]),
                  transport="basic", read_timeout_sec=630, operation_timeout_sec=600)
r = s.run_ps(
    # Win32-OpenSSH from GitHub rather than Add-WindowsCapability, which goes
    # through Windows Update and can stall for half an hour in a remote session.
    '$ProgressPreference = "SilentlyContinue"; '
    'if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { '
    '[Net.ServicePointManager]::SecurityProtocol = "Tls12"; '
    'Invoke-WebRequest -UseBasicParsing -Uri "' + os.environ["OPENSSH_URL"] + '" -OutFile "$env:TEMP\\OpenSSH-ARM64.zip"; '
    'Expand-Archive -Force "$env:TEMP\\OpenSSH-ARM64.zip" "C:\\Program Files"; '
    '& "C:\\Program Files\\OpenSSH-ARM64\\install-sshd.ps1" | Out-Null }; '
    'Set-Service sshd -StartupType Automatic; Start-Service sshd; '
    'if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) { '
    'New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (lab)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null }; '
    '(Get-Service sshd).Status')
out = r.std_out.decode(errors="replace").strip()
print("  sshd:", out.splitlines()[-1] if out else "?")
sys.exit(0 if "Running" in out else 1)
PY
}

adopt_vm() {
  local bundle="${1:-}"
  if [ -z "$bundle" ]; then
    bundle="$(ls -d "$UTM_DIR"/*.utm 2>/dev/null | head -1 || true)"
    [ -n "$bundle" ] || die "No .utm bundle in $UTM_DIR. Pass its path: ./lab.sh windows-vm adopt /path/to/vm.utm"
  fi
  [ -f "$bundle/config.plist" ] || die "$bundle isn't a UTM VM (no config.plist)"
  local name
  name="$(plutil -extract Information.Name raw "$bundle/config.plist")"
  [ "$(plutil -extract System.Architecture raw "$bundle/config.plist")" = aarch64 ] || die "$name isn't an ARM64 VM"
  VM="$name"; BUNDLE="$bundle"
  WINDOWS_UTM_VM="$name"; save_config >/dev/null
  info "Adopting $VM ($BUNDLE)"
  register_vm
  add_port_forward
  start_vm
  # UTM keeps its own copy of a VM that was dragged or imported into it; then
  # this bundle (and the forward just added to it) is never used.
  local i touched=""
  for i in $(seq 1 12); do
    if [ -n "$(find "$BUNDLE/Data" -type f -newer "$BUNDLE/config.plist" 2>/dev/null | head -1)" ]; then touched=1; break; fi
    sleep 5
  done
  if [ -z "$touched" ]; then
    utmctl stop --hide "$VM" >/dev/null 2>&1 || true
    die "UTM is running a different copy of $VM (one imported into UTM's own storage), not $BUNDLE. In UTM, remove $VM (right-click > Remove, which deletes UTM's copy), then run adopt again: it opens $BUNDLE in place."
  fi

  local user="${ADOPT_USER:-vagrant}" pass="${ADOPT_PASSWORD:-vagrant}"
  info "Waiting for SSH as '$user' on 127.0.0.1:$PORT"
  local bootstrapped=""
  for i in $(seq 1 20); do
    LAB_SSH_TIMEOUT=30 LAB_SSH_PASSWORD="$pass" expect "$SSH" ssh "$user" 127.0.0.1 "$PORT" "hostname" >/dev/null 2>&1 && break
    # Windows may still be booting: keep trying WinRM until it answers once.
    if [ -z "$bootstrapped" ] && [ "$i" -ge 3 ]; then
      if bootstrap_ssh_over_winrm "$user" "$pass"; then bootstrapped=1
      elif [ "$i" -eq 3 ]; then warn "No SSH or WinRM yet; Windows may still be booting"; fi
    fi
    if [ "$i" -eq 20 ]; then
      fail "No SSH login as '$user' after 10 minutes: the VM probably has no OpenSSH server."
      echo "  In the VM, in an elevated PowerShell, run:"
      echo "    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Set-Service sshd -StartupType Automatic; Start-Service sshd"
      echo "  then run adopt again. Set ADOPT_USER/ADOPT_PASSWORD if its login isn't vagrant/vagrant."
      exit 1
    fi
    sleep 10
  done

  local stage tarball
  stage="$(mktemp -d "${TMPDIR:-/tmp}/lab-adopt.XXXXXX")"
  stage_lab_files "$stage/labcfg"
  [ -s "$ISO_DIR/OpenSSH-ARM64.zip" ] && cp "$ISO_DIR/OpenSSH-ARM64.zip" "$stage/labcfg/"
  tarball="$stage/labcfg.tar"
  COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -C "$stage" -cf "$tarball" labcfg
  rm -rf "${stage:?}/labcfg"
  info "Copying the lab files in and provisioning (as '$user')"
  LAB_SSH_PASSWORD="$pass" expect "$SSH" scp "$user" 127.0.0.1 "$PORT" "$tarball" "C:/Windows/Temp/labcfg.tar" >/dev/null \
    || die "Couldn't copy the lab files into $VM"
  rm -rf "${stage:?}"
  LAB_SSH_PASSWORD="$pass" expect "$SSH" ssh "$user" 127.0.0.1 "$PORT" \
    "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Set-Location C:/Windows/Temp; tar -xf labcfg.tar; & C:/Windows/Temp/labcfg/firstlogon.ps1 -Source C:/Windows/Temp/labcfg; Remove-Item -Recurse -Force C:/Windows/Temp/labcfg, C:/Windows/Temp/labcfg.tar\"" \
    | grep -v -i password || true
  wait_ready 5 "finish provisioning"
}

start_vm() {
  register_vm
  ensure_console
  if [ "$(vm_status)" != started ]; then
    info "Starting $VM"
    utmctl start --hide "$VM" >/dev/null 2>&1 || true
    local _
    for _ in $(seq 1 30); do [ "$(vm_status)" = started ] && break; sleep 2; done
    # UTM 5.0.8's utmctl start can fail with OSStatus -10004 and start nothing, while its
    # AppleScript start works
    if [ "$(vm_status)" != started ]; then
      utm "start virtual machine named \"$VM\"" >/dev/null 2>&1 || true
      for _ in $(seq 1 30); do [ "$(vm_status)" = started ] && break; sleep 2; done
    fi
    [ "$(vm_status)" = started ] || die "UTM didn't start $VM (status: $(vm_status)). UTM may be showing a dialog: check its window, or quit and reopen UTM."
  fi
}

# The Windows ISO waits a few seconds for a key before booting from CD.
press_to_boot() {
  local _
  for _ in $(seq 1 20); do utm "input keystroke (virtual machine named \"$VM\") text \" \"" >/dev/null 2>&1 || true; sleep 1; done
}

collect() {
  require_password
  nc -z 127.0.0.1 "$PORT" 2>/dev/null || die "$VM isn't reachable on 127.0.0.1:$PORT. Start it: ./lab.sh windows-vm start"
  refresh_gandalf
  info "Running Invoke-Gandalf in $VM"
  # A full collection, file search and hashing run past ssh.exp's 15 minutes; cut off,
  # the session ends mid-archive and nothing new comes back
  LAB_SSH_TIMEOUT="${LAB_SSH_TIMEOUT:-7200}" ssh_vm "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\scripts\\Run-GandalfLocal.ps1 -GandalfSource C:\\lab\\gandalf-src -AcquisitionsRoot C:\\lab\\acquisitions${LIVE_ARGS:-}" \
    | grep -v -i password || true
  local dest="$ACQ_ROOT/powershell_collection/acquisitions" tmp host
  host="$(ssh_vm 'Write-Output "HOST=$env:COMPUTERNAME"' | tr -d '\r' | sed -n 's/^HOST=//p' | tail -1)"
  [ -n "$host" ] || die "Couldn't read $VM's computer name"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/lab-win.XXXXXX")"
  LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" pull gandalf 127.0.0.1 "$PORT" \
    "C:/lab/acquisitions/powershell_collection/acquisitions/$host" "$tmp/" >/dev/null \
    || die "Couldn't copy the acquisition out of $VM"
  [ -n "$(find "$tmp/$host" -maxdepth 1 \( -name '*.zip' -o -name '*.7z' \) -print -quit)" ] || die "Invoke-Gandalf produced no archive (see $tmp/$host)"
  mkdir -p "$dest"
  rm -rf "${dest:?}/$host"
  mv "$tmp/$host" "$dest/"
  rmdir "$tmp" 2>/dev/null || true
  # A file can go missing on the way (G36): fetch whatever the VM has that didn't arrive
  local name missing=""
  for name in $(ssh_vm "Get-ChildItem -Name -File C:\\lab\\acquisitions\\powershell_collection\\acquisitions\\$host" | tr -d '\r' | grep -E '^[A-Za-z0-9._+-]+$'); do
    [ -e "$dest/$host/$name" ] && continue
    warn "$name didn't arrive; fetching it again"
    LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" pull gandalf 127.0.0.1 "$PORT" \
      "C:/lab/acquisitions/powershell_collection/acquisitions/$host/$name" "$dest/$host/" >/dev/null || true
    [ -e "$dest/$host/$name" ] || missing="$missing $name"
  done
  [ -z "$missing" ] || warn "Still missing from $dest/$host:$missing (copy them from the VM by hand)"
  ok "Windows acquisition: $dest/$host"
}

# C:\lab\gandalf-src is a copy from when the VM was provisioned: replace it with
# the current src/acquisition (tools\disk_tools.zip included, if built) and the
# current Run-GandalfLocal.ps1, so a collection tests the code as it is now
refresh_gandalf() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/lab-gandalf.XXXXXX")"
  ( cd "$REPO_ROOT/src/acquisition" && COPYFILE_DISABLE=1 zip -qr -X "$tmp/gandalf-src.zip" . -x '*__pycache__*' '*.DS_Store' ) \
    || die "Couldn't zip src/acquisition"
  LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" scp gandalf 127.0.0.1 "$PORT" "$tmp/gandalf-src.zip" "C:/lab/gandalf-src.zip" >/dev/null \
    || die "Couldn't copy Gandalf into $VM"
  rm -f "$tmp/gandalf-src.zip"; rmdir "$tmp" 2>/dev/null || true
  ssh_vm "Remove-Item -Recurse -Force C:\\lab\\gandalf-src -ErrorAction SilentlyContinue; Expand-Archive -LiteralPath C:\\lab\\gandalf-src.zip -DestinationPath C:\\lab\\gandalf-src; Remove-Item C:\\lab\\gandalf-src.zip" >/dev/null \
    || die "Couldn't unpack Gandalf in $VM"
  push_script Run-GandalfLocal.ps1
  ok "Gandalf in $VM refreshed from src/acquisition"
}

# Gandalf's raw NTFS reader against RawCopy on locked files and metafiles (Test-RawReader.ps1)
raw_check() {
  require_password
  nc -z 127.0.0.1 "$PORT" 2>/dev/null || die "$VM isn't reachable on 127.0.0.1:$PORT. Start it: ./lab.sh windows-vm start"
  refresh_gandalf
  push_script Test-RawReader.ps1
  local dest="${1:-$LAB_DATA_DIR/raw-check}" run tmp
  run="$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dest"
  [ -e "$dest/$run" ] && die "$dest/$run already exists"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/lab-rawcheck.XXXXXX")"
  # $MFT is copied five times (reader, RawCopy, reader, then reader and RawCopy off a
  # snapshot): well over the 15 minute default on the lab VM
  LAB_SSH_TIMEOUT="${LAB_SSH_TIMEOUT:-7200}" ssh_vm "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\scripts\\Test-RawReader.ps1" \
    | grep -v -i password | tee "$tmp/console.log"
  LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" pull gandalf 127.0.0.1 "$PORT" "C:/lab/rawcheck-report" "$tmp/" >/dev/null \
    || die "Couldn't copy the report out of $VM (console output in $tmp)"
  mv "$tmp/rawcheck-report" "$dest/$run"
  mv "$tmp/console.log" "$dest/$run/"
  rmdir "$tmp" 2>/dev/null || true
  ok "Report: $dest/$run (summary.csv, blocks.csv, run.json)"
}

# live-containers: Invoke-Gandalf -LiveContainers against real containers without Docker Desktop
# (WSL2 needs nested virtualisation, which UTM on Apple silicon doesn't give a Windows guest).
# A throwaway Docker engine runs on the Mac, published on 127.0.0.1 only, which the guest reaches
# as 10.0.2.2 through UTM's emulated network; it has no authentication, so it lives only for the
# run. Two containers are seeded (one plain, one privileged with / mounted), the docker CLI is put
# in C:\lab\docker, Gandalf collects with -LiveContainers, and the engine is removed.
LIVE_ENGINE="rowan-lab-dockerd"
LIVE_PORT="${LIVE_DOCKER_PORT:-2375}"
DOCKER_CLI_URL="${DOCKER_CLI_URL:-https://download.docker.com/win/static/stable/x86_64/docker-27.3.1.zip}"

live_containers() {
  require_password
  nc -z 127.0.0.1 "$PORT" 2>/dev/null || die "$VM isn't reachable on 127.0.0.1:$PORT. Start it: ./lab.sh windows-vm start"
  command -v docker >/dev/null || die "docker isn't installed on this Mac"
  docker rm -f "$LIVE_ENGINE" >/dev/null 2>&1 || true
  trap 'docker rm -f "$LIVE_ENGINE" >/dev/null 2>&1 || true' EXIT
  info "Starting a throwaway Docker engine on 127.0.0.1:$LIVE_PORT"
  docker run -d --name "$LIVE_ENGINE" --privileged -e DOCKER_TLS_CERTDIR= -p "127.0.0.1:$LIVE_PORT:2375" \
    docker:27-dind --host=tcp://0.0.0.0:2375 >/dev/null || die "Couldn't start $LIVE_ENGINE"
  local engine="tcp://127.0.0.1:$LIVE_PORT" seeded="${TMPDIR:-/tmp}/lab-live-containers.txt" _
  for _ in $(seq 1 30); do docker -H "$engine" info >/dev/null 2>&1 && break; sleep 2; done
  docker -H "$engine" info >/dev/null 2>&1 || die "$LIVE_ENGINE didn't come up"
  docker -H "$engine" run -d --name lab-web alpine:3.20 sleep infinity >/dev/null
  docker -H "$engine" run -d --name lab-priv --privileged -v /:/host alpine:3.20 sleep infinity >/dev/null
  docker -H "$engine" ps --no-trunc --format '{{.ID}} {{.Names}}' > "$seeded"
  ok "Seeded: $(awk '{print substr($1,1,12) " " $2}' "$seeded" | tr '\n' ' ')"
  info "Docker CLI in $VM"
  ssh_vm "if (-not (Test-Path C:\\lab\\docker\\docker.exe)) { \$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -UseBasicParsing '$DOCKER_CLI_URL' -OutFile C:\\lab\\docker.zip; Expand-Archive -Force C:\\lab\\docker.zip C:\\lab; Remove-Item C:\\lab\\docker.zip }; \$env:DOCKER_HOST = 'tcp://10.0.2.2:$LIVE_PORT'; C:\\lab\\docker\\docker.exe ps --format '{{.Names}}'" \
    | tr -d '\r' | grep -cE '^lab-(web|priv)$' | grep -qx 2 \
    || die "$VM's docker CLI can't see the engine at 10.0.2.2:$LIVE_PORT"
  ok "$VM sees both containers"
  LIVE_ARGS=" -LiveContainers -DockerHost tcp://10.0.2.2:$LIVE_PORT" collect
  ok "Expected in raw/live_containers/docker/: $(awk '{print substr($1,1,12)}' "$seeded" | tr '\n' ' ')"
}

case "$action" in
  create)
    # create always builds the lab's own VM (or a clean sibling), whatever WINDOWS_UTM_VM says
    [ -n "$CLEAN" ] || { VM="rowan-lab-win11"; BUNDLE="$UTM_DIR/$VM.utm"; }
    require_password
    win="$(windows_iso)"
    if [ -z "$win" ] || [ ! -f "$win" ]; then
      fail "No Windows 11 ARM64 ISO in $ISO_DIR."
      echo "  Download it from https://www.microsoft.com/software-download/windows11arm64"
      echo "  (or with CrystalFetch: Windows 11, Arm64), save it in $ISO_DIR and run this again."
      echo "  Set WINDOWS_ARM_ISO=/path/to.iso to use one elsewhere."
      exit 1
    fi
    mkdir -p "$ISO_DIR" "$UTM_DIR"
    if vm_registered || [ -d "$BUNDLE" ]; then
      info "$VM already exists"
      start_vm
    else
      download "$VIRTIO_URL" "$ISO_DIR/virtio-win.iso"
      download "$OPENSSH_URL" "$ISO_DIR/OpenSSH-ARM64.zip"
      info "Windows ISO: $win"
      build_config_iso
      create_vm "$win"
      start_vm
      press_to_boot
    fi
    # WINDOWS_INSTALL_WAIT: minutes to allow; a spinning disk can need hours
    wait_ready "${WINDOWS_INSTALL_WAIT:-90}"
    # Detach the install media; the config ISO holds the lab password.
    if plutil -p "$BUNDLE/config.plist" | grep -q '"ImageName" => "lab-'; then
      info "Detaching the install media"
      utmctl stop --hide --request "$VM" >/dev/null 2>&1 || true  # a clean Windows shutdown
      for _ in $(seq 1 60); do [ "$(vm_status)" = stopped ] && break; sleep 2; done
      [ "$(vm_status)" = stopped ] || utmctl stop --hide --force "$VM" >/dev/null 2>&1 || true
      set_install_media
      rm -f "$CFG_ISO"
      utm "reload configuration (virtual machine named \"$VM\")" >/dev/null
      start_vm
      wait_ready "${WINDOWS_BOOT_WAIT:-30}" "boot"
    fi
    [ -n "$CLEAN" ] || { WINDOWS_UTM_VM="$VM"; save_config >/dev/null; }
    ;;
  adopt) require_password; mkdir -p "$UTM_DIR"; adopt_vm "${2:-}" ;;
  start) start_vm; wait_ready "${WINDOWS_BOOT_WAIT:-30}" "boot" ;;
  stop)
    # utmctl often reports OSStatus -10004 though the VM does stop: go by its state, not its exit
    vm_registered || { ok "$VM isn't registered with UTM"; exit 0; }
    utmctl stop --hide "$VM" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do [ "$(vm_status)" = stopped ] && break; sleep 2; done
    if [ "$(vm_status)" = stopped ]; then ok "$VM stopped"; else warn "$VM is still $(vm_status): stop it in UTM"; fi ;;
  delete)
    # Only ever delete a VM the lab built. An adopted VM is the user's own:
    # UTM's delete removes its files for good, so leave that to them.
    case "$VM" in
      rowan-lab-*) ;;
      *) warn "$VM was adopted, not built by the lab; not deleting it. Remove it in UTM yourself if you want it gone."
         WINDOWS_UTM_VM="rowan-lab-win11"; save_config >/dev/null
         exit 0 ;;
    esac
    confirm "Delete $VM and its disk?" n || exit 0
    if vm_registered; then utmctl stop --hide "$VM" 2>/dev/null || true; utm "delete (virtual machine named \"$VM\")"; fi
    rm -f "$CFG_ISO"
    ok "$VM deleted" ;;
  status)
    if vm_registered; then echo "$VM: $(vm_status), SSH 127.0.0.1:$PORT ($BUNDLE)"; else echo "$VM: not created"; fi ;;
  collect) collect ;;
  live-containers) live_containers ;;
  raw-check) shift; raw_check "$@" ;;
  sensor) sensor ;;
  record) shift; record "$@" ;;
  pull-recording) shift; pull_recording "$@" ;;
  *) die "unknown action $action" ;;
esac

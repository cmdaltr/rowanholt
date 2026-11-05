#!/usr/bin/env bash
# Apple silicon only: Linux and macOS target VMs with Tart.
#   tart-vm.sh create|start|stop|delete|status <linux|macos>
#   tart-vm.sh move <linux|macos> <dir>   move the VM to another TART_HOME (e.g. local disk while testing)
# Images are Cirrus Labs' public Tart images (default login admin/admin, which
# this script changes to the lab password once provisioned).
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
load_config

action="${1:?create|start|stop|delete|status|move}"; kind="${2:?linux|macos}"
TART="$(tart_bin)"; [ -n "$TART" ] || die "Tart is not installed. Run: ./lab.sh install"
is_arm || die "Tart VMs need Apple silicon. On an Intel Mac the lab uses Vagrant + VirtualBox."

case "$kind" in
  linux) IMAGE="${TART_LINUX_IMAGE:-ghcr.io/cirruslabs/ubuntu:latest}"; PORT=2230; MEM=2048; CPU=2 ;;
  macos) IMAGE="${TART_MACOS_IMAGE:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"; PORT=2231; MEM=4096; CPU=4 ;;
  *) die "kind must be linux or macos" ;;
esac
VM="rowan-lab-$kind"
mkdir -p "$TART_HOME"
RUN_DIR="$LAB_CONFIG_DIR/run"; mkdir -p "$RUN_DIR"
SSH="$LAB_ROOT/lib/ssh.exp"

vm_exists() { "$TART" list --quiet 2>/dev/null | grep -qx "$VM"; }
vm_ip() { "$TART" ip "$VM" 2>/dev/null || true; }
# tart ip keeps answering from the DHCP lease after a stop, so it can't say whether the VM runs
vm_running() { "$TART" list 2>/dev/null | awk -v vm="$VM" '$2 == vm {print $NF}' | grep -qx running; }

wait_ip() {
  local i ip
  # A first boot from an external drive can take several minutes.
  for i in $(seq 1 300); do ip="$(vm_ip)"; [ -n "$ip" ] && { echo "$ip"; return; }; sleep 2; done
  die "$VM did not get an IP address within 10 minutes (log: $RUN_DIR/$VM.log)"
}

start_forward() {
  local ip="$1" pidf="$RUN_DIR/forward-$PORT.pid"
  [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null || true
  nohup python3 "$LAB_ROOT/lib/forward.py" "$PORT" "$ip" 22 >"$RUN_DIR/forward-$PORT.log" 2>&1 &
  echo $! > "$pidf"
  ok "$VM SSH on 127.0.0.1:$PORT (-> $ip:22)"
}

# tart ip finds a VM's address by its MAC. A clone keeps its image's MAC, so another VM cloned
# from the same image (another project's, under the default TART_HOME) answers for this one,
# and provisioning and collection go to that machine instead. Refuse while one is running.
mac_of() { TART_HOME="$1" "$TART" get "$2" --format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["MACAddress"].lower())' 2>/dev/null || true; }

check_mac() {
  local mine home name
  mine="$(mac_of "$TART_HOME" "$VM")"
  [ -n "$mine" ] || die "Couldn't read $VM's MAC address"
  for home in "$TART_HOME" "${HOME}/.tart"; do
    [ -d "$home" ] || continue
    for name in $(TART_HOME="$home" "$TART" list --format json 2>/dev/null | python3 -c 'import json,sys; print(" ".join(v["Name"] for v in json.load(sys.stdin) if v.get("Running") and v.get("Source") == "local"))' 2>/dev/null); do
      [ "$home" = "$TART_HOME" ] && [ "$name" = "$VM" ] && continue
      if [ "$(mac_of "$home" "$name")" = "$mine" ]; then
        die "$name (in $home) is running with $VM's MAC address ($mine), so $VM's IP would be its. Give $VM its own: TART_HOME=\"$TART_HOME\" tart set $VM --random-mac"
      fi
    done
  done
}

start_vm() {
  check_mac
  if ! vm_running; then
    info "Starting $VM (headless)"
    nohup "$TART" run --no-graphics "$VM" >"$RUN_DIR/$VM.log" 2>&1 &
  fi
  local ip; ip="$(wait_ip)"
  start_forward "$ip"
  wait_ssh
}

wait_ssh() {
  # An IP comes well before sshd, on macOS especially: until the banner answers through the
  # forward, anything that connects (Gandalf's scp) is refused or cut off without saying why
  local i banner line
  info "Waiting for SSH on 127.0.0.1:$PORT"
  for i in $(seq 1 200); do
    banner="$( { exec 3<>"/dev/tcp/127.0.0.1/$PORT" && IFS= read -r -t 5 line <&3 && echo "$line"; exec 3<&-; } 2>/dev/null || true)"
    case "$banner" in SSH-*) ok "$VM SSH is up"; return ;; esac
    sleep 3
  done
  die "$VM has an IP but SSH didn't answer within 10 minutes (log: $RUN_DIR/$VM.log)"
}

provision() {
  local ip="$1" user=admin script remote
  require_password
  export LAB_SSH_PASSWORD="admin"
  # Already provisioned? The admin password will have been changed.
  if ! expect "$SSH" ssh "$user" "$ip" 22 true >/dev/null 2>&1; then
    export LAB_SSH_PASSWORD="$LAB_PASSWORD"
  fi
  info "Waiting for SSH on $ip"
  for _ in $(seq 1 60); do expect "$SSH" ssh "$user" "$ip" 22 true >/dev/null 2>&1 && break; sleep 3; done
  if [ "$kind" = "linux" ]; then
    for f in setup.sh entrypoint.sh; do expect "$SSH" scp "$user" "$ip" 22 "$LAB_ROOT/linux-targets/$f" "/tmp/$f" >/dev/null; done
    expect "$SSH" scp "$user" "$ip" 22 "$LAB_ROOT/linux-targets/seed/seed-artefacts.sh" /tmp/seed-artefacts.sh >/dev/null
    remote="echo '$LAB_SSH_PASSWORD' | sudo -S sh -c 'id gandalf >/dev/null 2>&1 || sh /tmp/setup.sh; sh /tmp/seed-artefacts.sh; echo gandalf:$LAB_PASSWORD | chpasswd; echo admin:$LAB_PASSWORD | chpasswd; systemctl restart ssh'"
  else
    expect "$SSH" scp "$user" "$ip" 22 "$LAB_ROOT/macos/seed-macos.sh" /tmp/seed-macos.sh >/dev/null
    remote="echo '$LAB_SSH_PASSWORD' | sudo -S env LAB_PASSWORD='$LAB_PASSWORD' sh /tmp/seed-macos.sh && echo '$LAB_SSH_PASSWORD' | sudo -S dscl . -passwd /Users/admin '$LAB_PASSWORD'"
  fi
  info "Provisioning $VM"
  expect "$SSH" ssh "$user" "$ip" 22 "$remote" | grep -v -i password || true
  ok "$VM provisioned: user 'gandalf', lab password; admin password changed to the lab password"
}

case "$action" in
  create)
    if ! vm_exists; then
      [ "$kind" = "macos" ] && warn "The macOS image is about 25 GB; the first pull takes a while."
      info "Pulling $IMAGE"
      "$TART" clone "$IMAGE" "$VM"
      "$TART" set "$VM" --memory "$MEM" --cpu "$CPU" --random-mac
    else
      info "$VM already exists"
    fi
    start_vm
    provision "$(vm_ip)"
    ;;
  start) vm_exists || die "$VM doesn't exist; create it first"; start_vm ;;
  stop)
    "$TART" stop "$VM" 2>/dev/null || true
    [ -f "$RUN_DIR/forward-$PORT.pid" ] && kill "$(cat "$RUN_DIR/forward-$PORT.pid")" 2>/dev/null || true
    ok "$VM stopped" ;;
  delete)
    confirm "Delete $VM and its disk?" n || exit 0
    "$TART" stop "$VM" 2>/dev/null || true; "$TART" delete "$VM"; ok "$VM deleted" ;;
  move)
    dest="${3:?move needs a directory, e.g. $LAB_VM_DIR/tart or ~/.rowanholt-lab/tart}"
    mkdir -p "$dest/vms"; dest="$(cd "$dest" && pwd)"
    old_home="$(cd "$TART_HOME" && pwd)"
    [ "$dest" != "$old_home" ] || die "$VM is already in $dest"
    vm_exists || die "$VM doesn't exist in $old_home"
    src="$old_home/vms/$VM"
    need_kb="$(du -sk "$src" | cut -f1)"
    free_kb="$(df -k "$dest" | awk 'NR==2 {print $4}')"
    [ "$free_kb" -gt $((need_kb + 5 * 1024 * 1024)) ] || die "Not enough space in $dest: $((need_kb / 1048576)) GB needed plus 5 GB spare, $((free_kb / 1048576)) GB free"
    "$TART" stop "$VM" 2>/dev/null || true
    [ -f "$RUN_DIR/forward-$PORT.pid" ] && kill "$(cat "$RUN_DIR/forward-$PORT.pid")" 2>/dev/null || true
    info "Copying $VM from $old_home to $dest ($((need_kb / 1048576)) GB in use)"
    mkdir -p "$dest/vms/$VM"
    for f in "$src"/*; do
      [ -f "$f" ] || continue  # skips control.sock, which tart recreates
      echo "  $(basename "$f")"
      python3 "$LAB_ROOT/lib/sparse_copy.py" "$f" "$dest/vms/$VM/$(basename "$f")" || die "Copy failed; $VM is still in $old_home"
    done
    TART_HOME="$dest" "$TART" list --quiet | grep -qx "$VM" || die "Tart doesn't see $VM in $dest; $VM is still in $old_home"
    LAB_TART_HOME="$dest"; save_config >/dev/null
    ok "$VM now runs from $dest (LAB_TART_HOME in $LAB_CONFIG)"
    if confirm "Remove the old copy in $old_home?" y; then
      TART_HOME="$old_home" "$TART" delete "$VM" && ok "Removed $src"
    fi ;;
  status)
    # Running without an IP is a boot still in progress (a first boot off a USB drive takes up to an hour)
    # tart ip still answers from the DHCP lease after a stop, so check the state first
    if ! vm_exists; then echo "$VM: not created"
    elif ! vm_running; then echo "$VM: stopped"
    elif [ -n "$(vm_ip)" ]; then echo "$VM: running at $(vm_ip), SSH 127.0.0.1:$PORT"
    else echo "$VM: booting (no IP yet)"; fi ;;
  *) die "unknown action $action" ;;
esac

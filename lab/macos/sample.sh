# The macOS sample case, sourced by tart-vm.sh for `tart-vm.sh sample macos-sample <dest>`
# (./lab.sh macos-vm sample [dir]); the macOS twin of windows/qemu-vm.sh sample. A fresh Sequoia
# VM of its own (rowan-lab-macos15-sample, so the lab's rowan-lab-macos is never touched), nothing
# seeded; PowerShell 7, Invoke-AtomicRedTeam and the atomics installed in it (sample-guest.sh);
# Atomic Red Team recorded with nothing cleaned up (Invoke-MordorRecord.ps1: the unified log, plist
# changes and, given Full Disk Access, Endpoint Security events per test); the VM shut down; then
# its disk as it was left: <dest>/disk.img (Tart's raw image), SHA256SUMS and expected.json.
# tart-vm.sh sets VM, PORT, IMAGE, MEM, CPU, TART, SSH and its helpers before sourcing this.

# Pinned, so a rebuild installs and runs the same: PowerShell's macOS arm64 package (v7.6.9, the
# SHA-256 GitHub and its release notes give), the module from the PowerShell Gallery, the atomics
# at one commit of redcanaryco/atomic-red-team (6 November 2026)
PWSH_VERSION=7.6.9
PWSH_SHA256=9002562086ad18dcdc4a1156f6cd6467cfb5a91b28206e56491212193b68e5e6
ART_MODULE_VERSION=2.3.0
ATOMICS_COMMIT="${ATOMICS_COMMIT:-a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6}"
SAMPLE_HOSTNAME="LAB-MACOS15"
# The Cirrus Labs image's login, left as it is: nothing on the sample is the lab's
GUEST_USER=admin
GUEST_PASSWORD=admin
GUEST_HOME="/Users/$GUEST_USER"
GUEST_LAB="$GUEST_HOME/lab"
GUEST_ATOMICS="$GUEST_HOME/AtomicRedTeam/atomics"
# Discovery first; then persistence, credential access, execution, defence evasion; the log
# clearing last, so it wipes only what came before it (as an intruder's would). Login items
# (T1547.015) aren't here: their atomic drives System Events, which an SSH session can't
# (Automation consent is a GUI prompt); startup items (T1037.005) stand in.
MACOS_SAMPLE_TECHNIQUES="${MACOS_SAMPLE_TECHNIQUES:-T1082,T1087.001,T1016,T1543.001,T1543.004,T1053.003,T1037.005,T1555.001,T1059.002,T1564.001,T1070.003,T1685.006}"

guest() { LAB_SSH_PASSWORD="$GUEST_PASSWORD" expect "$SSH" ssh "$GUEST_USER" 127.0.0.1 "$PORT" "$1"; }
guest_copy() {
  LAB_SSH_PASSWORD="$GUEST_PASSWORD" expect "$SSH" scp "$GUEST_USER" 127.0.0.1 "$PORT" "$1" "$2" >/dev/null \
    || die "Couldn't copy $(basename "$1") into $VM"
}

# The atomics need the internet. Tart's NAT goes nowhere while the Mac's IP forwarding is off
# (it has been found reset to 0, VMs reaching their gateway and no further)
no_internet() {
  if [ "$(sysctl -n net.inet.ip.forwarding 2>/dev/null)" = 0 ]; then
    die "$VM can't reach the internet: the Mac's IP forwarding is off (net.inet.ip.forwarding=0). Turn it on and run this again with MACOS_SAMPLE_RESUME=1: sudo sysctl -w net.inet.ip.forwarding=1"
  fi
  die "$VM can't reach github.com (the Mac's IP forwarding is on). Check the Mac's own connection, then run this again with MACOS_SAMPLE_RESUME=1"
}

shutdown_vm() {
  info "Shutting $VM down"
  guest "sudo -n shutdown -h now" >/dev/null 2>&1 || true
  local _
  for _ in $(seq 1 90); do vm_running || break; sleep 2; done
  if vm_running; then warn "macOS didn't shut down in 3 minutes; stopping it"; "$TART" stop "$VM" || true; fi
  [ -f "$RUN_DIR/forward-$PORT.pid" ] && kill "$(cat "$RUN_DIR/forward-$PORT.pid")" 2>/dev/null || true
  ok "$VM stopped"
}

# The disk: an APFS clone when <dest> is on the same volume as TART_HOME (instant, no space until
# either changes), else a sparse copy, checked
copy_disk() {
  local src="$TART_HOME/vms/$VM/disk.img" out="$1/disk.img" need_kb free_kb
  [ -f "$src" ] || die "No disk at $src"
  if cp -c "$src" "$out" 2>/dev/null; then
    ok "Disk cloned (same APFS volume as the VM)"
    return
  fi
  rm -f "$out"
  need_kb="$(du -sk "$src" | cut -f1)"
  free_kb="$(df -k "$1" | awk 'NR==2 {print $4}')"
  [ "$free_kb" -gt $((need_kb + 5 * 1024 * 1024)) ] || die "Not enough space in $1: $((need_kb / 1048576)) GB needed plus 5 GB spare, $((free_kb / 1048576)) GB free. The VM is kept: copy $src yourself"
  info "Copying its disk ($((need_kb / 1048576)) GB in use)"
  python3 "$LAB_ROOT/lib/sparse_copy.py" "$src" "$out" || die "Disk copy failed; the VM is kept ($src)"
}

sample() {
  local dest="${1:?destination folder}" run out tests rc log tmp
  [ -e "$dest/disk.img" ] && die "$dest already holds a sample"
  mkdir -p "$dest"
  # The run's name stays with <dest>, so a resumed build carries on the same recording
  if [ "${MACOS_SAMPLE_RESUME:-}" = 1 ] && [ -f "$dest/run.txt" ]; then run="$(cat "$dest/run.txt")"
  else run="macos15-atomics-$(date +%Y%m%d)"; echo "$run" > "$dest/run.txt"; fi
  if [ "${MACOS_SAMPLE_RESUME:-}" = 1 ]; then
    vm_exists || die "$VM doesn't exist; run sample without MACOS_SAMPLE_RESUME"
  else
    vm_exists && die "$VM already exists, and a sample starts from a fresh clone: delete it first (./macos/tart-vm.sh delete macos-sample), or carry on with MACOS_SAMPLE_RESUME=1"
    step "A fresh macOS 15 VM: $VM from $IMAGE"
    "$TART" clone "$IMAGE" "$VM"
    "$TART" set "$VM" --memory "$MEM" --cpu "$CPU" --random-mac
  fi
  start_vm

  step "PowerShell $PWSH_VERSION, Invoke-AtomicRedTeam $ART_MODULE_VERSION, the atomics at ${ATOMICS_COMMIT:0:12}"
  # The image's admin has passwordless sudo; if not, this gives it, so nothing below waits on a prompt
  guest "sudo -n true" >/dev/null 2>&1 \
    || guest "echo '$GUEST_PASSWORD' | sudo -S -p '' sh -c 'echo \"$GUEST_USER ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/rowanholt-sample && chmod 0440 /etc/sudoers.d/rowanholt-sample'" >/dev/null \
    || die "Couldn't get sudo for $GUEST_USER in $VM"
  guest "mkdir -p $GUEST_LAB" >/dev/null || die "$VM doesn't answer over SSH as $GUEST_USER"
  guest_copy "$LAB_ROOT/macos/sample-guest.sh" "$GUEST_LAB/sample-guest.sh"
  guest_copy "$LAB_ROOT/windows/Invoke-MordorRecord.ps1" "$GUEST_LAB/Invoke-MordorRecord.ps1"
  rc=0 log="$RUN_DIR/$VM-prepare.log"
  LAB_SSH_TIMEOUT=3600 guest "sudo -n sh $GUEST_LAB/sample-guest.sh prepare $SAMPLE_HOSTNAME $PWSH_VERSION $PWSH_SHA256 $ART_MODULE_VERSION $ATOMICS_COMMIT $GUEST_ATOMICS $MACOS_SAMPLE_TECHNIQUES" \
    | tee "$log" | grep --line-buffered -v -E '^(spawn |ES=|TESTS )' || rc=$?
  out="$(tr -d '\r' < "$log")"
  case "$out" in *NO-INTERNET*) no_internet ;; esac
  case "$out" in *NO-MACOS-TESTS*) die "Some techniques have no macOS atomics at ${ATOMICS_COMMIT:0:12} (above); set MACOS_SAMPLE_TECHNIQUES without them" ;; esac
  [ "$rc" = 0 ] || die "Setting $VM up failed (exit $rc, above)"
  tests="$(printf '%s\n' "$out" | sed -n 's/^TESTS //p')"
  if printf '%s\n' "$out" | grep -qx 'ES=denied'; then
    warn "eslogger can't start in $VM: Endpoint Security needs Full Disk Access, which an SSH session doesn't have and which can't be granted without turning SIP off. Carrying on without it: each test's unified log and plist changes are still recorded, its es.ndjson stays empty."
  fi

  step "Atomic Red Team: $MACOS_SAMPLE_TECHNIQUES (${tests:-?} tests, nothing cleaned up)"
  info "Each test takes about a minute with its ${MORDOR_SETTLE:-20}s settle and unified log export"
  # -Command, not -File: -File passes "T1,T2" as one string, not a list. HOME stays the admin's, so
  # the atomics' ~ (the login keychain, shell history) is the user's, not root's
  LAB_SSH_TIMEOUT="${LAB_SSH_TIMEOUT:-14400}" guest "sudo -n env HOME=$GUEST_HOME /usr/local/bin/pwsh -NoProfile -Command \"& $GUEST_LAB/Invoke-MordorRecord.ps1 -Techniques $MACOS_SAMPLE_TECHNIQUES -Run $run -Out $GUEST_LAB/mordor/telemetry -AtomicsPath $GUEST_ATOMICS -Settle ${MORDOR_SETTLE:-20} -NoCleanup\"" \
    | grep --line-buffered -v -i password || true
  guest "sudo -n chown -R $GUEST_USER $GUEST_LAB/mordor" >/dev/null || true

  tmp="$(mktemp -d "${TMPDIR:-/tmp}/lab-rec.XXXXXX")"
  LAB_SSH_TIMEOUT=3600 LAB_SSH_PASSWORD="$GUEST_PASSWORD" expect "$SSH" pull "$GUEST_USER" 127.0.0.1 "$PORT" "$GUEST_LAB/mordor/telemetry/$run" "$tmp/" \
    | grep -v -i password || true
  [ -f "$tmp/$run/manifest.json" ] || die "Nothing was recorded, or it couldn't be copied out (in $VM: $GUEST_LAB/mordor/telemetry/$run). Run this again with MACOS_SAMPLE_RESUME=1: it carries on from the recorded tests"
  mkdir -p "$dest/recording"
  rm -rf "${dest:?}/recording/$run"
  mv "$tmp/$run" "$dest/recording/"
  rmdir "$tmp" 2>/dev/null || true
  ok "Recorded: $dest/recording/$run"

  step "Disk"
  shutdown_vm
  date -u +%Y-%m-%dT%H:%M:%SZ > "$dest/captured-at.txt"
  copy_disk "$dest"
  info "SHA-256 of the disk"
  ( cd "$dest" && shasum -a 256 disk.img > SHA256SUMS )
  ( cd "$REPO_ROOT" && python3 -m src.mordor.lab.dataset --run "$run" --src "$dest/recording" --dest "$dest/dataset" ) >/dev/null \
    && cp "$dest/dataset/$run/expected.json" "$dest/expected.json" \
    || warn "Couldn't write expected.json; the recording's manifest.json has the same tests ($dest/recording/$run)"
  rm -f "$dest/run.txt"
  ok "Sample: $dest (disk.img, expected.json, SHA256SUMS; the per-test logs in recording/)"
  info "$VM is kept, stopped; once the sample is checked, ./macos/tart-vm.sh delete macos-sample frees its space"
}

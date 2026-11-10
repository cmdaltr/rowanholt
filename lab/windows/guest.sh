# What the lab does inside its Windows VM over SSH, whichever hypervisor runs it: sourced by
# utm-vm.sh (Apple silicon) and qemu-vm.sh (x86-64). Each sets VM, PORT, SSH, SELF (its own
# name, for messages), STUCK (where to look when the VM doesn't come up) and vm_status.

ssh_vm() { LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" ssh gandalf 127.0.0.1 "$PORT" "$1"; }

wait_ready() {
  local limit="${1:-90}" what="${2:-install and provision itself}" i
  # ssh_vm needs it; without it every check fails and the wait runs to its limit.
  require_password
  info "Waiting for Windows to $what (up to $limit minutes)"
  for i in $(seq 1 $((limit * 2))); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null && LAB_SSH_TIMEOUT=30 ssh_vm "if (Test-Path C:\\lab\\ready.txt) { 'READY' }" 2>/dev/null | grep -q READY; then
      ok "$VM is ready: ssh -p $PORT gandalf@127.0.0.1 (lab password)"
      return 0
    fi
    [ $((i % 10)) -eq 0 ] && info "  still waiting ($((i / 2)) min, $(vm_status))"
    sleep 30
  done
  die "$VM wasn't ready after $limit minutes. $STUCK; on a slow disk, run create again (it resumes waiting) with WINDOWS_INSTALL_WAIT=240."
}

reachable() {
  nc -z 127.0.0.1 "$PORT" 2>/dev/null || die "$VM isn't reachable on 127.0.0.1:$PORT. Start it: ./lab.sh windows-vm start"
}

# The VM's C:\lab\scripts is from when it was provisioned: copy the current one in
push_script() {
  LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" scp gandalf 127.0.0.1 "$PORT" "$LAB_ROOT/windows/$1" "C:/lab/scripts/$1" >/dev/null \
    || die "Couldn't copy $1 into $VM"
}

sensor() {
  require_password
  reachable
  push_script Install-MordorSensor.ps1
  ssh_vm "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\scripts\\Install-MordorSensor.ps1"
}

# Atomic Red Team tests, each test's logs recorded (Invoke-MordorRecord.ps1), copied to <dest>/<run>
record() {
  local techniques="${1:?techniques}" run="${2:?run name}" dest="${3:?destination}"
  require_password
  reachable
  push_script Invoke-MordorRecord.ps1
  # MORDOR_NO_CLEANUP=1: leave what each test made (a sample image is analysed for it afterwards)
  local keep=""; [ "${MORDOR_NO_CLEANUP:-0}" = 1 ] && keep=" -NoCleanup"
  info "Recording $techniques in $VM (each test, then a ${MORDOR_SETTLE:-20}s settle${keep:+, no cleanup})"
  # -Command, not -File: -File passes "T1,T2" as one string, not a list. Each test takes about two
  # minutes with its settle and log export, and a sample's 11 techniques are ~150 tests, so allow
  # eight hours rather than ssh.exp's 15 minutes: when it runs out, Windows ends the run mid-list
  LAB_SSH_TIMEOUT="${LAB_SSH_TIMEOUT:-28800}" ssh_vm "powershell -NoProfile -ExecutionPolicy Bypass -Command \"& C:\\lab\\scripts\\Invoke-MordorRecord.ps1 -Techniques $techniques -Run $run -Out C:\\lab\\mordor\\telemetry -Settle ${MORDOR_SETTLE:-20}$keep\"" \
    | grep --line-buffered -v -i password || true
  pull_recording "$run" "$dest"
}

# pull-recording <run> <dest-dir>: a recording's folder out of the VM into <dest>/<run>, on its own
# when a run recorded but its copy failed (the captures make it large: allow an hour, not ssh.exp's 15 minutes)
pull_recording() {
  local run="${1:?run name}" dest="${2:?destination}" tmp
  case "$run" in *[!A-Za-z0-9_.-]*) die "Run names may only use letters, digits, _ . -" ;; esac
  require_password
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/lab-rec.XXXXXX")"
  LAB_SSH_TIMEOUT="${LAB_SSH_TIMEOUT:-3600}" LAB_SSH_PASSWORD="$LAB_PASSWORD" expect "$SSH" pull gandalf 127.0.0.1 "$PORT" "C:/lab/mordor/telemetry/$run" "$tmp/" \
    | grep -v -i password || true
  [ -d "$tmp/$run" ] || die "Couldn't copy the recording out of $VM (it's in C:\\lab\\mordor\\telemetry\\$run; try again: ./windows/$SELF pull-recording $run <dest>)"
  [ -f "$tmp/$run/manifest.json" ] || die "Nothing was recorded (see $tmp/$run)"
  mkdir -p "$dest"
  [ -e "$dest/$run" ] && die "$dest/$run already exists (left in $tmp/$run)"
  mv "$tmp/$run" "$dest/"
  rmdir "$tmp" 2>/dev/null || true
  ok "Recorded: $dest/$run"
}

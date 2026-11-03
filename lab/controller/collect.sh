#!/usr/bin/env bash
# Run inside lab-controller: collect.sh <bash|python> <host> [host ...] [--workarounds]
#
# Writes archives to /acquisitions/<collector>_collection/acquisitions/<host>/,
# the layout Elrond's --Gandalf mode requires, plus a per-run log and the
# target's ground-truth expected.json.
set -uo pipefail

collector="${1:?collector (bash|python)}"; shift
workarounds=0
hosts=()
for a in "$@"; do
  if [ "$a" = "--workarounds" ]; then workarounds=1; else hosts+=("$a"); fi
done
[ "${#hosts[@]}" -gt 0 ] || { echo "No hosts given" >&2; exit 2; }
: "${LAB_PASSWORD:?LAB_PASSWORD not set}"
export SSHPASS="$LAB_PASSWORD"

# VM targets live outside Docker. lab.sh forwards their SSH to fixed loopback
# ports on the Mac; relay each alias to host.docker.internal:<port> on port 22
# here, because gandalf.py (paramiko) always connects to port 22.
relay() {
  local alias="$1" port="$2" ip="$3"
  echo "$ip $alias" >> /etc/hosts
  socat "TCP-LISTEN:22,bind=$ip,fork,reuseaddr" "TCP:host.docker.internal:$port" &
}
n=2
for h in "${hosts[@]}"; do
  case "$h" in
    lab-linuxvm) relay "$h" 2230 "127.0.0.$n"; n=$((n + 1)) ;;
    lab-macos)   relay "$h" 2231 "127.0.0.$n"; n=$((n + 1)) ;;
    lab-machost) relay "$h" 22   "127.0.0.$n"; n=$((n + 1)) ;;
  esac
done
sleep 1

out_root="/acquisitions/${collector}_collection/acquisitions"
mkdir -p "$out_root"
work="$(mktemp -d)"
cp -R /gandalf-src/. "$work/"
status=0

fetch_truth() {  # copy the target's ground truth next to its archive
  local host="$1" dest="$2"
  mkdir -p "$dest"
  PATH="/opt/lab-bin:$PATH" scp "gandalf@${host}:/etc/rivendell-lab/expected.json" "$dest/expected.json" >/dev/null 2>&1 || true
}

run_bash() {
  local host="$1"
  local dest="$out_root/$host"
  mkdir -p "$dest"
  local enc="${GANDALF_ENCRYPTION:-None}"  # None or Key (Password needs a terminal)
  # gandalf.sh only says "Failed to copy script", and sshpass prints nothing when the password is
  # refused, so say why first
  local probe
  PATH="/opt/lab-bin:$PATH" ssh -o ConnectTimeout=20 "gandalf@${host}" true 2>&1 | sed 's/^/    ssh: /'
  probe=${PIPESTATUS[0]}
  case "$probe" in
    0) echo "[+] $host: SSH as gandalf works" ;;
    5) echo "[x] $host: the lab password was refused for gandalf (sshpass 5)" ;;
    6) echo "[x] $host: unknown host key (sshpass 6)" ;;
    *) echo "[x] $host: SSH failed (exit $probe)" ;;
  esac
  echo "[*] gandalf.sh $enc Remote -h $host -u gandalf"
  # Only this run's archives count: an earlier run's are still in $dest.
  local since; since="$(mktemp)"
  ( cd "$work/bash" && PATH="/opt/lab-bin:$PATH" bash ./gandalf.sh "$enc" Remote -h "$host" -u gandalf -o "$dest" ) 2>&1 | tee "$dest/collector.log"
  local rc=${PIPESTATUS[0]}
  fetch_truth "$host" "$dest"
  local fresh; fresh="$(find "$dest" -maxdepth 1 -name '*.tar.gz*' -newer "$since")"; rm -f "$since"
  if [ "$rc" = "0" ] && [ -n "$fresh" ]; then
    echo "[+] $host: $(echo "$fresh" | grep -c 'tar.gz') archive(s)"
    if [ "$workarounds" = "1" ]; then
      # Known gap: Elrond's --Gandalf mode reads .zip/.7z only, gandalf.sh writes .tar.gz.
      for t in $(echo "$fresh" | grep '\.tar\.gz$'); do
        local x; x="$(mktemp -d)"; tar -xzf "$t" -C "$x" && (cd "$x" && zip -qr "$dest/$(basename "$t" .tar.gz).zip" .); rm -rf "$x"
        echo "[!] Workaround: repacked $(basename "$t") as zip for Elrond"
      done
    fi
  else
    echo "[x] $host: no archive produced (exit $rc)"; status=1
  fi
}

run_python() {
  local dest
  # gandalf.py reads lists/hosts.list relative to its working directory and asks
  # for each host's IP, user and password interactively; expect answers them.
  printf '%s\n' "${hosts[@]}" > "$work/lists/hosts.list"
  if [ "$workarounds" = "1" ] && [ ! -e "$work/shire" ]; then
    # Known gap: gandalf.py copies shire/collect_artefacts-py, which lives in python/.
    ln -s python "$work/shire"; echo "[!] Workaround: linked shire -> python"
  fi
  echo "[*] gandalf.py None Remote (hosts: ${hosts[*]})"
  ( cd "$work" && expect /lab/gandalf_python.exp "${hosts[@]}" ) 2>&1 | tee "$out_root/collector-python.log"
  for host in "${hosts[@]}"; do
    dest="$out_root/$host"; mkdir -p "$dest"
    # Remote archives are fetched into the working directory.
    # Only this run's archive counts: an earlier run's is still in $dest.
    local got=0; mv "$work"/"$host".zip* "$dest"/ 2>/dev/null && got=1
    fetch_truth "$host" "$dest"
    if [ "$got" = "1" ]; then echo "[+] $host: $(ls "$dest" | grep -c zip) archive(s)"; else echo "[x] $host: no archive produced"; status=1; fi
  done
}

case "$collector" in
  bash) for h in "${hosts[@]}"; do run_bash "$h"; done ;;
  python) run_python ;;
  *) echo "Unknown collector $collector" >&2; exit 2 ;;
esac
rm -rf "$work"
exit $status

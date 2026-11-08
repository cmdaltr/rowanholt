#!/usr/bin/env bash
# FR-02's Windows Server 2022 VM, in VMware Fusion on the Mac Mini, reached from this Mac through the
# Mini (ProxyJump): the VM stays on Fusion's NAT, nothing is published and it doesn't join the tailnet.
# Run on the MacBook, after Enable-LabSsh.ps1 has run in the VM:
#   lab/winserver/connect-winserver.sh
# It checks the Mini and the VM (running, nested virtualisation on, its address, SSH open), makes a key
# of its own (~/.ssh/rowan_winsrv_ed25519), writes "Host rowan-winsrv" in ~/.ssh/config and installs
# the key in the VM: the VM's Administrator password is asked for once, by ssh, in this terminal.
# Afterwards: ssh rowan-winsrv
#   MINI=user@host     the jump host (default: MacMini.local, as homelab; MINI=macmini over the tailnet)
#   WINSRV_VMX=<path>  the VM's .vmx on the Mini, when no running VM has "winsrv" or "server" in its path
#   WINSRV_IP=<ip>     the VM's address, when VMware Tools isn't installed in it
#   WINSRV_USER=<name> the VM account (default: Administrator)
set -euo pipefail
MINI="${MINI:-MacMini.local}"
VM_USER="${WINSRV_USER:-Administrator}"
ALIAS=rowan-winsrv
KEY="$HOME/.ssh/rowan_winsrv_ed25519"
CONFIG="$HOME/.ssh/config"
VMRUN='/Applications/VMware Fusion.app/Contents/Library/vmrun'

step() { printf '\n== %s\n' "$*"; }
ok() { printf '   OK: %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
on_mini() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$MINI" "$(printf '%q ' "$@")"; }
# PowerShell in the VM, base64 UTF-16LE, so no quoting survives three shells
encoded() { printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'; }

step "1. The Mac Mini ($MINI)"
on_mini true 2>/dev/null || die "can't ssh to $MINI without a password. Check:
  - the Mini is on this network (or MINI=macmini with Tailscale connected on both Macs)
  - Remote Login is on on the Mini:             System Settings > General > Sharing > Remote Login
  - this Mac's key is on the Mini:              ssh-copy-id $MINI"
ok "ssh $MINI works"
on_mini test -x "$VMRUN" || die "VMware Fusion isn't installed on the Mini ($VMRUN)"
ok "VMware Fusion installed"

step "2. The VM"
vmx="${WINSRV_VMX:-}"
if [ -z "$vmx" ]; then
  running=$(on_mini "$VMRUN" -T fusion list)
  vmx=$(printf '%s\n' "$running" | grep -i '\.vmx$' | grep -i -m1 -E 'winsrv|server' || true)
  [ -n "$vmx" ] || die "no running Fusion VM with 'winsrv' or 'server' in its path. Running:
$running
Start the VM, or give its path: WINSRV_VMX=/path/to/rowan-winsrv.vmx $0"
fi
ok "$vmx"
if on_mini grep -qi '^vhv.enable *= *"TRUE"' "$vmx"; then
  ok "nested virtualisation is on (vhv.enable)"
else
  die "nested virtualisation is off, and WSL 2 needs it. Shut the VM down, then in Fusion:
  Settings > Processors & Memory > Advanced options > Enable hypervisor applications in this virtual machine
and start it again"
fi
ip="${WINSRV_IP:-}"
if [ -z "$ip" ]; then
  ip=$(on_mini "$VMRUN" -T fusion getGuestIPAddress "$vmx" -wait 2>/dev/null | tr -d '\r' || true)
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Fusion can't see the VM's address (VMware Tools not installed?).
Install them (Virtual Machine > Install VMware Tools), or give the address Enable-LabSsh.ps1 printed:
  WINSRV_IP=192.168.x.y $0"
fi
ok "address $ip"
on_mini nc -z -G 5 "$ip" 22 || die "the Mini can't reach $ip:22. Run Enable-LabSsh.ps1 in the VM as Administrator"
ok "SSH is open on the VM"

step "3. Key and ~/.ssh/config"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
if [ -f "$KEY" ]; then
  ok "$KEY exists"
else
  ssh-keygen -q -t ed25519 -N '' -C "rowanholt-fr02-$(hostname -s)" -f "$KEY"
  ok "made $KEY"
fi
touch "$CONFIG"
if grep -q "^Host $ALIAS\$" "$CONFIG"; then
  cp "$CONFIG" "$CONFIG.bak-winsrv"
  # Only the address changes (Fusion's DHCP can hand out another)
  awk -v alias="$ALIAS" -v ip="$ip" '
    $1 == "Host" { inblock = ($2 == alias) }
    inblock && $1 == "HostName" { print "  HostName " ip; next }
    { print }' "$CONFIG.bak-winsrv" > "$CONFIG"
  ok "updated Host $ALIAS (old config in $CONFIG.bak-winsrv)"
else
  cat >> "$CONFIG" <<EOF

# FR-02's Windows Server VM in Fusion on the Mac Mini (lab/winserver/connect-winserver.sh)
Host $ALIAS
  HostName $ip
  User $VM_USER
  ProxyJump $MINI
  IdentityFile $KEY
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  ServerAliveInterval 30
EOF
  ok "added Host $ALIAS"
fi
chmod 600 "$CONFIG"

step "4. The key in the VM"
if ssh -o BatchMode=yes -o ConnectTimeout=15 "$ALIAS" exit 2>/dev/null; then
  ok "key login already works"
else
  echo "   ssh will ask for the VM's $VM_USER password once:"
  pub=$(cat "$KEY.pub")
  # An administrator's keys live in administrators_authorized_keys, readable by Administrators and SYSTEM only
  install='$f = Join-Path $env:ProgramData "ssh\administrators_authorized_keys"
$key = "'"$pub"'"
if (-not (Test-Path $f) -or -not (Select-String -Path $f -SimpleMatch $key -Quiet)) { Add-Content -Path $f -Value $key }
icacls $f /inheritance:r /grant "*S-1-5-32-544:F" /grant "SYSTEM:F" | Out-Null
"installed"'
  ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive "$ALIAS" \
    "powershell -NoProfile -EncodedCommand $(encoded "$install")"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$ALIAS" exit || die "the key was installed but key login still fails: check C:\\ProgramData\\ssh\\administrators_authorized_keys in the VM"
  ok "key login works"
fi

step "5. What the VM is"
report='$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
"Windows:   $($os.Caption) $($os.Version)"
"Memory:    $([math]::Round($os.TotalVisibleMemorySize / 1MB, 1)) GB"
"CPUs:      $((Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors)"
"VT-x/SLAT: $($cpu.VirtualizationFirmwareEnabled) / $($cpu.SecondLevelAddressTranslationExtensions)"
"Volumes:   $((Get-Volume | Where-Object DriveLetter | ForEach-Object { "$($_.DriveLetter): $([math]::Round($_.SizeRemaining / 1GB))/$([math]::Round($_.Size / 1GB)) GB free" }) -join ", ")"'
ssh "$ALIAS" "powershell -NoProfile -EncodedCommand $(encoded "$report")"

printf '\nDone: ssh %s\n' "$ALIAS"

<#
.SYNOPSIS
  First logon of the lab's Windows 11 ARM VM (UTM): drivers, the lab target
  provisioning, and an SSH server so the Mac can drive Gandalf and fetch the
  archive. Runs from the LABCFG config ISO via autounattend.xml, or with
  -Source <folder> when utm-vm.sh adopts an installed VM over SSH.
#>
param([string]$Source)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\lab | Out-Null
Start-Transcript -Path C:\lab\firstlogon.log -Append | Out-Null

$cfg = if ($Source) { $Source } else { (Get-Volume -FileSystemLabel LABCFG).DriveLetter + ":" }

# virtio drivers (network, serial, balloon...) from the virtio-win ISO
$virtio = Get-Volume | Where-Object { $_.DriveLetter -and (Test-Path "$($_.DriveLetter):\NetKVM") } | Select-Object -First 1
if ($Source) {
    Write-Host "Installed VM: leaving its drivers as they are"
} elseif ($virtio) {
    Get-ChildItem "$($virtio.DriveLetter):\" -Recurse -Filter *.inf -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\w11\\ARM64\\' } |
        ForEach-Object { pnputil.exe /add-driver $_.FullName /install | Out-Null }
    Write-Host "virtio drivers installed"
} else {
    Write-Warning "virtio-win ISO not attached: no network driver"
}

# Defender (AMSI) blocks Provision-GandalfTarget.ps1 outright, because it seeds
# inert IEX and mimikatz strings, and would quarantine the seeded artefacts too
Add-MpPreference -ExclusionPath C:\lab, C:\ProgramData\RivendellLab, C:\TEMP, C:\Users\Public\Documents

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue C:\lab\scripts, C:\lab\gandalf-src
Copy-Item -Recurse -Force "$cfg\lab-scripts" C:\lab\scripts
Copy-Item -Recurse -Force "$cfg\gandalf-src" C:\lab\gandalf-src
# Files off a CD keep their read-only attribute, and utm-vm.sh collect then can't copy the current scripts over them
Get-ChildItem -Recurse -File C:\lab\scripts, C:\lab\gandalf-src | ForEach-Object { $_.IsReadOnly = $false }

# Lab target: user, WinRM, seeded artefacts (same script as the x64 Vagrant VM)
$env:LAB_PASSWORD = (Get-Content -Raw "$cfg\lab-password.txt").Trim()
& C:\lab\scripts\Provision-GandalfTarget.ps1 -Clean:(Test-Path "$cfg\clean.txt")
Remove-Item Env:\LAB_PASSWORD
Remove-Item -Force -ErrorAction SilentlyContinue "$cfg\lab-password.txt"

# OpenSSH server from the Win32-OpenSSH ARM64 release (works offline)
$ssh = "C:\Program Files\OpenSSH-ARM64"
if (-not (Get-Service sshd -ErrorAction SilentlyContinue) -and (Test-Path "$cfg\OpenSSH-ARM64.zip")) {
    Expand-Archive -Force "$cfg\OpenSSH-ARM64.zip" "C:\Program Files"
    & "$ssh\install-sshd.ps1"
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (lab)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

# Don't leave the answer file (it holds the lab password) on the disk
Remove-Item -Force -ErrorAction SilentlyContinue C:\Windows\Panther\unattend.xml, C:\Windows\Panther\Unattend\unattend.xml

Set-Content C:\lab\ready.txt (Get-Date -Format o)
Write-Host "Rivendell lab Windows target ready"
Stop-Transcript | Out-Null

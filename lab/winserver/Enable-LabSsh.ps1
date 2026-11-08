# FR-02's Windows Server 2022 VM (VMware Fusion on the Mac Mini): OpenSSH Server, so the MacBook
# can reach it through the Mini (lab/winserver/connect-winserver.sh), and no sleep.
# Run once in the VM, in PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File Enable-LabSsh.ps1
# or paste the lines below into an elevated PowerShell window.

Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (lab)' -Enabled True -Direction Inbound `
        -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
# PowerShell, not cmd.exe, for what the MacBook runs over SSH
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -PropertyType String -Force `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | Out-Null
# A sleeping VM looks like a dead one from the MacBook
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0

"sshd: $((Get-Service sshd).Status)"
"Nested virtualisation (needed by WSL 2): $((Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled)"
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -notlike 'Loopback*' |
    Format-Table InterfaceAlias, IPAddress -AutoSize

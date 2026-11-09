# FR-02's Windows Server 2022 VM (VMware Fusion on the Mac Mini): OpenSSH Server, so the MacBook
# can reach it through the Mini (lab/winserver/connect-winserver.sh), and no sleep.
# Run once in the VM, in PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File Enable-LabSsh.ps1
# or paste the lines below into an elevated PowerShell window.

# Microsoft's OpenSSH MSI, not Add-WindowsCapability: that comes through Windows Update, and on
# an unpatched Server 2022 it fails (0x80010108)
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    $ProgressPreference = 'SilentlyContinue'
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases' -UseBasicParsing |
        Where-Object { $_.assets.name -like 'OpenSSH-Win64-v*.msi' } | Select-Object -First 1
    $asset = $release.assets | Where-Object name -like 'OpenSSH-Win64-v*.msi' | Select-Object -First 1
    $msi = Join-Path $env:TEMP $asset.name
    Start-BitsTransfer -Source $asset.browser_download_url -Destination $msi
    if ($asset.digest -match '^sha256:([0-9a-f]{64})$' -and (Get-FileHash $msi -Algorithm SHA256).Hash -ne $Matches[1].ToUpper()) {
        Remove-Item $msi; throw 'The OpenSSH MSI failed its SHA-256 check.'
    }
    $install = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart'
    Remove-Item $msi
    if ($install.ExitCode -notin 0, 3010) { throw "Installing OpenSSH failed (msiexec $($install.ExitCode))." }
}
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

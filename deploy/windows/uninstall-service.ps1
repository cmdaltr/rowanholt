<#
.SYNOPSIS
    Remove the Rowanholt team server that deploy\windows\install-service.ps1 set up. Keeps data by default.
.DESCRIPTION
    Elevated PowerShell:
        .\deploy\windows\uninstall-service.ps1 [-Purge [-Yes]]

    Runs deploy/linux/uninstall.sh inside the Rowanholt distribution, which stops the stack, then
    removes the boot task, the port forwarding and the firewall rule, and install-service.ps1's
    files in %ProgramData%\Rowanholt. -Purge also removes the stack's volumes (every job, finding
    and note), .env and the backend's data folder, after asking unless -Yes is given.

    Always left in place: the distribution itself and its virtual disk (under -WslPath, which
    holds the code and any case output written inside it), Docker in it, and WSL. To remove those
    too: wsl --unregister Rowanholt, which deletes the disk and everything on it.
.PARAMETER Distribution
    The WSL distribution Rowanholt runs in (default: the one install-service.ps1 recorded, else Rowanholt).
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $Distribution = '',
    [switch] $Purge,
    [switch] $Yes
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Fail([string] $Text) { [Console]::Error.WriteLine("uninstall-service.ps1: $Text"); exit 1 }

if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { Fail 'This is for Windows. On Linux run deploy/linux/uninstall.sh.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'Run this in an elevated PowerShell (Run as administrator).'
}

$State = Join-Path $env:ProgramData 'Rowanholt'
$StateFile = Join-Path $State 'server.json'
$saved = $null
if (Test-Path $StateFile) { $saved = Get-Content -Raw $StateFile | ConvertFrom-Json }
if (-not $Distribution) { $Distribution = if ($saved) { $saved.Distribution } else { 'Rowanholt' } }
$Root = if ($saved -and $saved.Root) { $saved.Root } else { '/opt/rowanholt' }
$wslExe = Join-Path $env:ProgramFiles 'WSL\wsl.exe'  # WSL's MSI, as install-service.ps1 uses
if (-not (Test-Path $wslExe)) { $wslExe = 'wsl.exe' }

# The Linux side first, so a purge that's declined leaves everything as it was. The uninstaller
# beside this script, so the two match even when the server tree predates deploy/linux/uninstall.sh
$env:WSL_UTF8 = '1'
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$linux = (Resolve-Path (Join-Path $PSScriptRoot '..\linux\uninstall.sh')).Path
$wslPath = (((& $wslExe -d $Distribution -- wslpath -a $linux 2>&1) | ForEach-Object { "$_" }) -join '').Trim()
$reached = ($LASTEXITCODE -eq 0 -and $wslPath.StartsWith('/'))
$ErrorActionPreference = $previous
if ($reached) {
    $arguments = @('--dir', $Root)
    if ($Purge) { $arguments += '--purge' }
    if ($Yes) { $arguments += '--yes' }
    # Not captured, so --purge can ask on the console
    & $wslExe -d $Distribution -u root -- bash $wslPath @arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Warning "Couldn't reach $Distribution, so the stack wasn't stopped: run deploy/linux/uninstall.sh inside it later."
}

Write-Host "==> removing the Rowanholt scheduled task"
Stop-ScheduledTask -TaskName Rowanholt -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName Rowanholt -Confirm:$false -ErrorAction SilentlyContinue

Write-Host '==> removing the port forwarding and the firewall rule'
$ports = if ($saved -and $saved.Ports) { @($saved.Ports) } else { @(80, 443, 7755, 5601, 5602) }
foreach ($port in $ports) {
    & netsh.exe interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 2>$null | Out-Null
}
Get-NetFirewallRule -Group Rowanholt -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# install-service.ps1's own files only: the distribution's disk may be under the same folder (-WslPath)
foreach ($name in 'server.json', 'Start-RowanholtServer.ps1', 'step.sh') {
    Remove-Item -Force (Join-Path $State $name) -ErrorAction SilentlyContinue
}
Write-Host "    left the $Distribution distribution, Docker in it and the code in $Root (wsl --unregister $Distribution removes them)."

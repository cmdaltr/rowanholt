<#
.SYNOPSIS
  Prepares the lab Windows VM to generate Mordor-style datasets: Sysmon with a
  community config, verbose PowerShell logging, and Atomic Red Team.

.DESCRIPTION
  Run elevated, inside the lab VM only. Atomic Red Team executes real attack
  techniques, so this script adds Defender exclusions for its folders and turns
  off real-time protection. Never run it on a machine you care about.

  Downloads (all over HTTPS from their publishers):
    Sysmon         https://download.sysinternals.com/files/Sysmon.zip
    sysmon-modular https://github.com/olafhartong/sysmon-modular (sysmonconfig.xml, a release asset since
                   July 2026; pinned to a release, as its README advises)
    Atomic Red Team https://github.com/redcanaryco/invoke-atomicredteam
#>
[CmdletBinding()]
param(
    [string]$SysmonConfigUrl = "https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig.xml",
    [string]$AtomicRoot = "C:\AtomicRedTeam"
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Write-Step($m) { Write-Host "`n== $m ==" -ForegroundColor Cyan }

Write-Step "Defender (lab VM only)"
Add-MpPreference -ExclusionPath $AtomicRoot, "C:\lab" -ErrorAction SilentlyContinue
try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Host "  Real-time protection off."
} catch {
    Write-Host "  Couldn't turn off real-time protection (Tamper Protection?). Turn it off in Windows Security > Virus & threat protection, then re-run." -ForegroundColor Yellow
}

Write-Step "Sysmon"
$tmp = Join-Path $env:TEMP "sysmon"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$tmp\Sysmon.zip" -UseBasicParsing
Expand-Archive "$tmp\Sysmon.zip" -DestinationPath $tmp -Force
Invoke-WebRequest $SysmonConfigUrl -OutFile "$tmp\sysmonconfig.xml" -UseBasicParsing
$exe = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "Sysmon64a.exe" } else { "Sysmon64.exe" }
if (Get-Service -Name Sysmon64, Sysmon64a -ErrorAction SilentlyContinue) {
    & "$tmp\$exe" -c "$tmp\sysmonconfig.xml" | Out-Null
} else {
    & "$tmp\$exe" -accepteula -i "$tmp\sysmonconfig.xml" | Out-Null
}
Write-Host "  $exe installed with sysmon-modular."

Write-Step "PowerShell logging"
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path "$ps\ScriptBlockLogging", "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
Set-ItemProperty "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1
Set-ItemProperty "$ps\ModuleLogging\ModuleNames" -Name "*" -Value "*"
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "  Script block, module and command-line process auditing on."

Write-Step "Atomic Red Team"
if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Invoke-Expression (Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing).Content
    Install-AtomicRedTeam -getAtomics -InstallPath $AtomicRoot -Force
}
Write-Host "  Atomic Red Team in $AtomicRoot." -ForegroundColor Green
Write-Host "`nNext: .\Invoke-MordorCapture.ps1 -Name lab_persistence -Techniques T1547.001,T1053.005"

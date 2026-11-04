<#
.SYNOPSIS
Runs Atomic Red Team tests on this machine and saves each test's logs for Rowanholt's recorded
telemetry (src/mordor/telemetry/lab.py). Ported from Archer's record-atomics.ps1.

.DESCRIPTION
Run it on a disposable test machine, never on one you care about: the tests change the system.
Elevated, with Invoke-AtomicRedTeam and the atomics installed. In the lab's Windows VM,
./lab.sh mordor-sensor installs them (with Sysmon) and ./lab.sh mordor-record runs this script and
copies the run out. Windows PowerShell 5.1 works there; Linux and macOS need PowerShell 7
(sudo pwsh), with the module installed as below:

    Install-Module invoke-atomicredteam -Scope CurrentUser
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics

For each test it records, between the test's start and end:
  Windows  events.xml      Security, System, PowerShell, Sysmon (if installed), Task Scheduler, WMI, Defender, BITS
  Linux    audit.log       auditd (/var/log/audit; auditd with ATT&CK rules, e.g. Neo23x0's)
           journal.log     the systemd journal, syslog format
  macOS    es.ndjson       Endpoint Security events (eslogger; give the terminal Full Disk Access)
           unified.ndjson  the unified log
           plists.ndjson   launch agents, launch daemons and login hooks added, changed or removed

Copy the run's folder to src/mordor/data/telemetry/lab/ and run
python -m src.mordor.telemetry --build --source lab (./lab.sh mordor-record does both).

.EXAMPLE
sudo pwsh ./record-atomics.ps1 -Techniques T1053.003,T1543.001,T1059.004
#>
param(
    [Parameter(Mandatory)][string[]]$Techniques,
    [string]$Run = "$([Environment]::MachineName.ToLower())-$(Get-Date -Format yyyyMMdd-HHmm)",
    [string]$Out = (Join-Path $PWD 'mordor-telemetry'),
    [int]$Settle = 20,
    [int]$Timeout = 120,
    [string]$AtomicsPath = '',
    [switch]$NoCleanup
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 has no $IsWindows; there it can only be Windows
if ($PSVersionTable.PSEdition -eq 'Desktop') { $IsWindows = $true; $IsLinux = $false; $IsMacOS = $false }
# Install-MordorSensor.ps1 installs the module under C:\AtomicRedTeam, outside PSModulePath
$artModule = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
if ($IsWindows -and -not (Get-Module -ListAvailable invoke-atomicredteam) -and (Test-Path $artModule)) { Import-Module $artModule -Force } else { Import-Module invoke-atomicredteam }
# Defaulted here, not in param(): 5.1 only knows $IsWindows from the line above
if (-not $AtomicsPath) { $AtomicsPath = if ($IsWindows) { 'C:\AtomicRedTeam\atomics' } else { "$HOME/AtomicRedTeam/atomics" } }

$platform = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
$hostName = ([Environment]::MachineName).ToLower()
$runDir = Join-Path $Out $Run
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$manifest = [ordered]@{ run = $Run; host = $hostName; platform = $platform; started = (Get-Date).ToUniversalTime().ToString('o'); tests = @() }
# A file of IDs, or a list
if ($Techniques.Count -eq 1 -and (Test-Path $Techniques[0])) { $Techniques = Get-Content $Techniques[0] | Where-Object { $_ -match '^T\d{4}' } }

$windowsLogs = 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
$esEvents = 'exec', 'fork', 'create', 'rename', 'unlink', 'write', 'btm_launch_item_add', 'btm_launch_item_remove',
    'login_login', 'authentication', 'sudo', 'su', 'xp_malware_detected', 'tcc_modify', 'profile_add', 'od_create_user',
    'od_group_add', 'screensharing_attach', 'openssh_login', 'mount', 'kextload', 'setowner', 'setmode', 'signal'
if ($IsMacOS) {
    $supported = (& /usr/bin/eslogger --list-events) -split "`n" | ForEach-Object { $_.Trim() }
    $esEvents = $esEvents | Where-Object { $supported -contains $_ }
}

function Get-PlistState {
    $paths = @('/Library/LaunchAgents', '/Library/LaunchDaemons', '/Library/Preferences/com.apple.loginwindow.plist') +
        (Get-ChildItem /Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Library/LaunchAgents' })
    $state = @{}
    foreach ($p in $paths) {
        Get-ChildItem -Path $p -Filter *.plist -File -ErrorAction SilentlyContinue | ForEach-Object {
            $state[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
    }
    $state
}

function Write-PlistChanges($before, $after, $file) {
    $lines = foreach ($path in (@($before.Keys) + @($after.Keys) | Sort-Object -Unique)) {
        $change = if (-not $before.ContainsKey($path)) { 'added' } elseif (-not $after.ContainsKey($path)) { 'removed' }
                  elseif ($before[$path] -ne $after[$path]) { 'changed' } else { $null }
        if (-not $change) { continue }
        $entry = [ordered]@{ plist = $change; path = $path }
        if ($change -ne 'removed') {
            try {
                $doc = & /usr/bin/plutil -convert json -o - $path 2>$null | ConvertFrom-Json
                $entry.Label = $doc.Label
                $entry.ProgramArguments = ($doc.ProgramArguments -join ' ')
                $entry.Program = $doc.Program
            } catch { }
        }
        $entry | ConvertTo-Json -Compress
    }
    if ($lines) { $lines | Set-Content -Path $file }
}

foreach ($t in $Techniques) {
    $yaml = Join-Path $AtomicsPath "$t/$t.yaml"
    if (-not (Test-Path $yaml)) { Write-Warning "$t has no atomics here"; continue }
    $tests = (Get-AtomicTechnique -Path $yaml).atomic_tests
    for ($i = 1; $i -le $tests.Count; $i++) {
        $test = $tests[$i - 1]
        if ($test.supported_platforms -notcontains $platform -or $test.executor.name -eq 'manual') { continue }
        $folder = "$t-$i"
        $dir = Join-Path $runDir $folder
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "==> $t test ${i}: $($test.name)"
        try { Invoke-AtomicTest $t -TestNumbers $i -GetPrereqs -PathToAtomicsFolder $AtomicsPath | Out-Null } catch { Write-Warning "prerequisites: $_" }

        $es = $null
        if ($IsMacOS) {
            $plistsBefore = Get-PlistState
            $es = Start-Process -FilePath /usr/bin/eslogger -ArgumentList $esEvents -RedirectStandardOutput (Join-Path $dir 'es.ndjson') -PassThru -NoNewWindow
            Start-Sleep -Seconds 2
        }
        $start = Get-Date
        try { Invoke-AtomicTest $t -TestNumbers $i -PathToAtomicsFolder $AtomicsPath -TimeoutSeconds $Timeout } catch { Write-Warning "test: $_" }
        Start-Sleep -Seconds $Settle
        $end = Get-Date

        if ($IsWindows) {
            $present = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LogName
            $xml = foreach ($log in $windowsLogs | Where-Object { $present -contains $_ }) {
                Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start; EndTime = $end } -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }
            }
            if ($xml) { $xml | Set-Content -Path (Join-Path $dir 'events.xml') -Encoding utf8 }
        } elseif ($IsLinux) {
            # By each record's own epoch (msg=audit(1729100000.123:42)): ausearch's dates follow the locale
            $from = [DateTimeOffset]$start.ToUniversalTime(); $to = [DateTimeOffset]$end.ToUniversalTime()
            $logs = Get-ChildItem /var/log/audit -Filter 'audit.log*' -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ne '.gz' }
            if ($logs) {
                $logs | Get-Content | Where-Object {
                    $_ -match 'msg=audit\((\d+)\.' -and [long]$Matches[1] -ge $from.ToUnixTimeSeconds() -and [long]$Matches[1] -le $to.ToUnixTimeSeconds()
                } | Set-Content (Join-Path $dir 'audit.log')
            } else { Write-Warning 'auditd not installed or not logging: no audit.log' }
            & journalctl --since $start.ToString('yyyy-MM-dd HH:mm:ss') --until $end.ToString('yyyy-MM-dd HH:mm:ss') -o short --no-pager 2>$null | Set-Content (Join-Path $dir 'journal.log')
        } else {
            Stop-Process -Id $es.Id -ErrorAction SilentlyContinue
            & /usr/bin/log show --start $start.ToString('yyyy-MM-dd HH:mm:ss') --end $end.ToString('yyyy-MM-dd HH:mm:ss') --style ndjson 2>$null | Set-Content (Join-Path $dir 'unified.ndjson')
            Write-PlistChanges $plistsBefore (Get-PlistState) (Join-Path $dir 'plists.ndjson')
        }

        if (-not $NoCleanup) { try { Invoke-AtomicTest $t -TestNumbers $i -Cleanup -PathToAtomicsFolder $AtomicsPath | Out-Null } catch { } }
        $manifest.tests += [ordered]@{ technique = $t; test = $i; name = $test.name; folder = $folder
                                       start = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); end = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        # Saved after every test, so a run that stops part-way is still usable
        $manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $runDir 'manifest.json')
    }
}
Write-Host "Recorded $($manifest.tests.Count) tests in $runDir"

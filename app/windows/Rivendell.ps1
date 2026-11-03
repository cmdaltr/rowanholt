<#
.SYNOPSIS
    What the Rivendell shortcut runs: start the Docker stack if the web UI isn't
    answering, then open the UI in its own Edge (or Chrome) app window. With a team
    server (RIVENDELL_SERVER, or .rivendell-server from the installer) it just opens
    the server: nothing runs here.
.NOTES
    The bash launcher doesn't run on Windows, so this does what 'rivendell start'
    does there: make sure Docker Desktop is up, then 'docker compose up -d' in the repo,
    with docker-compose.local.yml (the installer's evidence folders) when it exists.
    A copy the installer put down (.rivendell-version) gets a .env with its own
    SECRET_KEY on first start and an image rebuild after each upgrade.

    While the stack starts, the console shows the road to Rivendell: the phase, where
    Gandalf has got to, and an ETA from this PC's earlier starts (the same history
    format and estimate as src/common/startup_progress.py on macOS and Linux).
#>
[CmdletBinding()]
param(
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Url = 'http://localhost:5687'
$ServerFile = Join-Path $Root '.rivendell-server'
$Server = if ($env:RIVENDELL_SERVER) { $env:RIVENDELL_SERVER }
          elseif (Test-Path $ServerFile) { (Get-Content $ServerFile -Raw).Trim() }
          else { '' }
if ($Server) { $Url = $Server }
$State = Join-Path $env:LOCALAPPDATA 'Rivendell'
$BrowserProfile = Join-Path $State 'browser'
New-Item -ItemType Directory -Force -Path $BrowserProfile | Out-Null
$Host.UI.RawUI.WindowTitle = 'Rivendell'

function Test-Frontend {
    try {
        Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec 2 -UseBasicParsing | Out-Null
        return $true
    } catch {
        # Any HTTP answer, even an error status, means the frontend is listening
        return $null -ne $_.Exception.Response
    }
}

function Test-Docker {
    # Windows PowerShell turns a native command's redirected stderr into a terminating
    # error under 'Stop', so the probe runs under 'Continue'
    $ErrorActionPreference = 'Continue'
    docker info *> $null
    return $LASTEXITCODE -eq 0
}

function Wait-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'The docker command isn''t on PATH. Install Docker Desktop and retry.'
    }
    if (Test-Docker) { return }
    $desktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (-not (Test-Path $desktop)) {
        throw "Docker isn't running and Docker Desktop isn't installed at $desktop. Start Docker and retry."
    }
    Write-Host 'Starting Docker Desktop...'
    # Its own CLI starts the engine without the dashboard; older versions don't have it
    $ErrorActionPreference = 'Continue'
    docker desktop start --detach *> $null
    if ($LASTEXITCODE -ne 0) { Start-Process $desktop -WindowStyle Hidden }
    $ErrorActionPreference = 'Stop'
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Seconds 2
        if ($script:Journey) { Show-Journey $script:Journey }
        if (Test-Docker) { Write-Host 'Docker started.'; return }
    }
    throw 'Docker did not start in time. Start it manually and retry.'
}

function Get-ComposeFiles {
    $files = @('-f', 'docker-compose.yml')
    if (Test-Path (Join-Path $Root 'docker-compose.local.yml')) { $files += @('-f', 'docker-compose.local.yml') }
    return $files
}

function Invoke-Compose {
    param([string[]]$Arguments)
    $files = Get-ComposeFiles
    Push-Location $Root
    try {
        docker compose @files @Arguments
        if ($LASTEXITCODE -ne 0) { throw "docker compose $($Arguments -join ' ') exited with status $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

function Initialize-AppCopy {
    # Returns the extra 'up' arguments: --build once after the installer upgraded the copy
    $versionFile = Join-Path $Root '.rivendell-version'
    if (-not (Test-Path $versionFile)) { return @() }
    $envFile = Join-Path $Root '.env'
    $example = Join-Path $Root '.env.example'
    if (-not (Test-Path $envFile) -and (Test-Path $example)) {
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $key = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
        (Get-Content $example) -replace '^SECRET_KEY=.*', "SECRET_KEY=$key" | Set-Content -Path $envFile -Encoding ASCII
        Write-Host 'Created .env with a new SECRET_KEY.'
    }
    $built = Join-Path $Root '.rivendell-built'
    $version = (Get-Content $versionFile -Raw).Trim()
    if ((Test-Path $built) -and (Get-Content $built -Raw).Trim() -eq $version) { return @() }
    Write-Host 'New Rivendell version: rebuilding the images (this takes a while)...'
    return @('--build')
}

# ── The road to Rivendell ─────────────────────────────────────────────────────
$Phases = @('docker', 'images', 'containers', 'ui')
# Seconds, until this PC has history of its own
$Defaults = @{
    warm = @{ docker = 20; images = 4; containers = 12; ui = 45 }
    cold = @{ docker = 20; images = 900; containers = 25; ui = 90 }
}
$Messages = @{ docker = 'Waking Docker'; images = 'Forging the images'; containers = 'Raising the halls'; ui = 'Opening the doors' }
$Places = @(@(0.0, 'the Shire'), @(0.18, 'Bree'), @(0.38, 'Weathertop'), @(0.55, 'the Last Bridge'),
            @(0.7, 'the Trollshaws'), @(0.86, 'the Ford of Bruinen'))
$HistoryFile = Join-Path $State 'start-history.jsonl'
# BuildKit's step lines with --progress plain: '#12 [worker 5/31] RUN ...' (startup_progress.py's STEP)
$StepLine = '^#\d+ \[([\w.-]+)(?:\s+[\w.-]+)?\s+(\d+)/(\d+)\]'
$script:Journey = $null

function Get-Median([double[]]$Values) {
    $sorted = @($Values | Sort-Object)
    $mid = [int][math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2) { return $sorted[$mid] }
    return ($sorted[$mid - 1] + $sorted[$mid]) / 2
}

function New-Journey([string]$Kind) {
    $base = if ($Kind -like 'cold*') { $Defaults.cold } else { $Defaults.warm }
    $history = @()
    if (Test-Path $HistoryFile) {
        $history = @(Get-Content $HistoryFile | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
                     Where-Object { $_ -and $_.kind -eq $Kind } | Select-Object -Last 20)
    }
    $expected = @{}
    foreach ($phase in $Phases) {
        $seen = @($history | ForEach-Object { $_.phases.$phase } | Where-Object { $null -ne $_ })
        $expected[$phase] = if ($seen.Count) { Get-Median $seen } else { [double]$base[$phase] }
    }
    $now = Get-Date
    return [pscustomobject]@{ Kind = $Kind; Learning = ($history.Count -eq 0); Expected = $expected
                              Started = $now; Phase = 'docker'; PhaseStarted = $now; Done = @{}
                              BuildFraction = 0.0; Detail = '' }
}

function Enter-Phase($J, [string]$Phase) {
    $now = Get-Date
    $J.Done[$J.Phase] = ($now - $J.PhaseStarted).TotalSeconds
    $J.Phase = $Phase
    $J.PhaseStarted = $now
    $J.Detail = ''
}

function Show-Journey($J) {
    $inPhase = ((Get-Date) - $J.PhaseStarted).TotalSeconds
    $expected = $J.Expected[$J.Phase]
    if ($J.Phase -eq 'images' -and $J.BuildFraction -gt 0.05 -and $inPhase -gt 20) {
        # The build's own pace beats history once it's under way
        $expected = $inPhase / $J.BuildFraction
    }
    $current = if ($inPhase -lt $expected) { $expected - $inPhase } else { [math]::Max(3, $expected * 0.1) }
    $index = [array]::IndexOf($Phases, $J.Phase)
    $later = 0
    for ($i = $index + 1; $i -lt $Phases.Count; $i++) { $later += $J.Expected[$Phases[$i]] }
    $remaining = $current + $later
    $elapsed = ((Get-Date) - $J.Started).TotalSeconds
    $fraction = [math]::Min(0.99, $elapsed / [math]::Max(1, $elapsed + $remaining))
    $place = ($Places | Where-Object { $fraction -ge $_[0] } | Select-Object -Last 1)[1]
    $where = if ($place -eq 'the Shire') { 'Gandalf sets out from the Shire' } else { "Gandalf has passed $place" }
    $eta = if ($remaining -lt 45) { 'less than a minute' } elseif ($remaining -lt 90) { 'about a minute' } else { "about $([math]::Round($remaining / 60)) minutes" }
    $guess = if ($J.Learning) { ' (a first guess: no timings on this PC yet)' } else { '' }
    Write-Progress -Activity 'The road to Rivendell' -Status "$where - $eta to Rivendell$guess" `
        -CurrentOperation ($Messages[$J.Phase] + $(if ($J.Detail) { " ($($J.Detail))" } else { '' })) -PercentComplete ([int]($fraction * 100))
}

function Complete-Journey($J) {
    Enter-Phase $J 'arrived'
    # Not $phases: PowerShell names are case-insensitive, and that would hide $Phases
    $times = [ordered]@{}
    foreach ($phase in $Phases) { $times[$phase] = [math]::Round([double]$J.Done[$phase], 1) }
    $record = [ordered]@{ kind = $J.Kind; at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); phases = $times
                          total = [math]::Round(((Get-Date) - $J.Started).TotalSeconds, 1) }
    New-Item -ItemType Directory -Force -Path (Split-Path $HistoryFile) | Out-Null
    Add-Content -Path $HistoryFile -Value ($record | ConvertTo-Json -Compress)
    Write-Progress -Activity 'The road to Rivendell' -Completed
}

function Get-MissingImages {
    # Images the stack needs that aren't here yet: a cold start
    $ErrorActionPreference = 'Continue'
    $files = Get-ComposeFiles
    Push-Location $Root
    try { $images = docker compose @files config --images 2>$null } finally { Pop-Location }
    return @($images | Where-Object { $_ } | Sort-Object -Unique | Where-Object {
        docker image inspect $_ *> $null
        $LASTEXITCODE -ne 0
    })
}

function Invoke-ComposeUp($J, [string[]]$Extra, [int]$Builds) {
    # Native output through the pipeline: 'Continue', or Windows PowerShell stops on stderr
    $ErrorActionPreference = 'Continue'
    $files = Get-ComposeFiles
    $steps = @{}
    Push-Location $Root
    try {
        # --progress plain: BuildKit's step counts, to pace a build by
        docker compose --progress plain @files up -d @Extra 2>&1 | ForEach-Object {
            $line = "$_"
            if ($line -match $StepLine -and [int]$Matches[3] -gt 0) {
                $service = $Matches[1]; $n = [int]$Matches[2]; $m = [int]$Matches[3]
                $before = if ($steps.ContainsKey($service)) { $steps[$service][0] } else { 0 }
                $steps[$service] = @([math]::Max($n, $before), $m)
                $done = 0.0
                foreach ($s in $steps.Values) { $done += $s[0] / $s[1] }
                $of = [math]::Max(1, [math]::Max($Builds, $steps.Count))
                $J.BuildFraction = [math]::Min(1.0, $done / $of)
                $J.Detail = "$($steps.Count) of $of images under way"
            }
            if ($line.StartsWith('#')) { Show-Journey $J; return }  # BuildKit chatter stays out of the console
            if ($J.Phase -eq 'images' -and $line -match '\b(Creating|Created|Starting|Started|Recreate|Running)\b') {
                Enter-Phase $J 'containers'
            }
            Write-Host $line
            Show-Journey $J
        }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($code -ne 0) { throw "docker compose up exited with status $code" }
}

function Open-Window {
    # Edge ships with Windows 10 and 11; Chrome is the fallback, then the default browser
    $browsers = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    $browser = $browsers | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($browser) {
        Start-Process $browser -ArgumentList "--app=$Url", "--user-data-dir=`"$BrowserProfile`"", '--no-first-run'
    } else {
        Start-Process $Url
    }
}

try {
    if ($Server) {
        if ($Stop) {
            Write-Host "Rivendell runs on $Server; its admins start and stop it."
            Start-Sleep -Seconds 4
            exit 0
        }
        Open-Window
        exit 0
    }

    if ($Stop) {
        Wait-Docker
        Write-Host 'Stopping Rivendell...'
        Invoke-Compose @('down', '--remove-orphans')
        Write-Host 'Stopped.'
        Start-Sleep -Seconds 2
        exit 0
    }

    if (-not (Test-Frontend)) {
        $script:Journey = New-Journey 'warm'
        Show-Journey $script:Journey
        Wait-Docker
        $extra = @(Initialize-AppCopy)
        $missing = @(Get-MissingImages)
        $kind = if ($missing.Count -or ($extra -contains '--build')) { 'cold' } else { 'warm' }
        if ($kind -ne $script:Journey.Kind) {
            $fresh = New-Journey $kind
            $fresh.Started = $script:Journey.Started
            $fresh.PhaseStarted = $script:Journey.PhaseStarted
            $script:Journey = $fresh
        }
        if ($missing.Count) { Write-Host "$($missing.Count) image(s) to fetch or build: the first start takes a while." }
        Write-Host 'Starting Rivendell...'
        Enter-Phase $script:Journey 'images'
        Invoke-ComposeUp $script:Journey $extra $missing.Count
        if ($script:Journey.Phase -eq 'images') { Enter-Phase $script:Journey 'containers' }
        if ($extra -contains '--build') {
            Copy-Item (Join-Path $Root '.rivendell-version') (Join-Path $Root '.rivendell-built') -Force
        }
        Enter-Phase $script:Journey 'ui'
        $deadline = (Get-Date).AddMinutes(15)
        while (-not (Test-Frontend)) {
            if ((Get-Date) -gt $deadline) {
                throw "The stack started but nothing answered on $Url. Try 'docker compose ps' in $Root."
            }
            Show-Journey $script:Journey
            Start-Sleep -Seconds 2
        }
        Complete-Journey $script:Journey
    }
    Open-Window
} catch {
    Write-Host ''
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}

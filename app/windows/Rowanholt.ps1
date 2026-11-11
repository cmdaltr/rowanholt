<#
.SYNOPSIS
    What the Rowanholt shortcut runs: start the Docker stack if the web UI isn't
    answering, then open the UI in its own Edge (or Chrome) app window. With a team
    server (ROWANHOLT_SERVER, or the one setup saved) it just opens the server: nothing
    runs here.
.DESCRIPTION
    From a checkout (app\windows\ in a clone) it runs that checkout. Installed from the MSI
    (%LOCALAPPDATA%\Programs\cmdaltr\Rowanholt, beside rowanholt-src.tar.gz), its first run is
    setup, as the Linux packages' is: either a team server's address, or a check for Docker
    Desktop, Rowanholt's files unpacked into a folder you choose (or a copy you already have)
    and evidence folders mounted. -Setup (the Set Up Rowanholt shortcut) runs it again. When
    a newer MSI is installed, the next start offers to update the files in place.
.NOTES
    The bash launcher doesn't run on Windows, so this does what 'rowanholt start' does
    there: make sure Docker Desktop is up, then 'docker compose up -d' in the copy, with
    docker-compose.local.yml (setup's evidence folders) when it exists. A copy setup
    unpacked (.rowanholt-version) gets a .env with its own SECRET_KEY on first start and
    an image rebuild after each upgrade.

    While the stack starts, the console shows the road to Rowanholt: the phase, where
    Gandalf has got to, and an ETA from this PC's earlier starts (the same history
    format and estimate as src/common/startup_progress.py on macOS and Linux).
#>
[CmdletBinding()]
param(
    [switch]$Stop,
    [switch]$Setup
)

$ErrorActionPreference = 'Stop'
# The install folder, or a checkout's root
$AppDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Bundled = Join-Path $AppDir 'rowanholt-src.tar.gz'
$Packaged = Test-Path $Bundled
$Url = 'http://localhost:5687'
$State = Join-Path $env:LOCALAPPDATA 'Rowanholt'
$ServerFile = Join-Path $State 'server'
$RootFile = Join-Path $State 'root'
$BrowserProfile = Join-Path $State 'browser'
New-Item -ItemType Directory -Force -Path $BrowserProfile | Out-Null
$Host.UI.RawUI.WindowTitle = 'Rowanholt'
$Root = $null

# ── Setup (the MSI's app) ─────────────────────────────────────────────────────
# What the Inno Setup installer's pages asked, asked on the first run instead: an MSI has no
# room for questions, and the Linux packages already work this way
$LocalHeader = "# Written by Rowanholt's desktop setup"
# Copies the Inno Setup installer set up carry its header; they're setup's to rewrite too
$OldLocalHeader = "# Written by Rowanholt's Windows installer"

function Get-AppVersion {
    $file = Join-Path $AppDir 'VERSION'
    if (Test-Path $file) { return (Get-Content $file -Raw).Trim() }
    return '0'
}

function Get-SavedServer {
    if ($env:ROWANHOLT_SERVER) { return $env:ROWANHOLT_SERVER }
    if (Test-Path $ServerFile) { return (Get-Content $ServerFile -Raw).Trim() }
    return ''
}

function Show-Message([string]$Text, [string]$Buttons = 'OK', [string]$Icon = 'Information') {
    Add-Type -AssemblyName System.Windows.Forms
    return [string][System.Windows.Forms.MessageBox]::Show($Text, 'Rowanholt', $Buttons, $Icon)
}

function Test-Copy([string]$Dir) {
    return $Dir -and (Test-Path (Join-Path $Dir 'docker-compose.yml')) -and (Test-Path (Join-Path $Dir 'rowanholt'))
}

# A typed address as https://host[:port]; '' if it isn't one (http for localhost only)
function ConvertTo-ServerUrl([string]$Text) {
    $Text = ($Text -replace '\s', '')
    if ($Text -notmatch '://') { $Text = "https://$Text" }
    if ($Text -notmatch '^(?<scheme>[A-Za-z]+)://(?<host>[^/]+)') { return '' }
    $scheme = $Matches.scheme.ToLower(); $hostPort = $Matches.host
    if ($hostPort -notmatch '^[A-Za-z0-9.-]+(:\d+)?$') { return '' }
    if ($scheme -eq 'https') { return "https://$hostPort" }
    if ($scheme -eq 'http' -and ($hostPort -split ':')[0] -in 'localhost', '127.0.0.1') { return "http://$hostPort" }
    return ''
}

function Select-Mode {
    # Where Rowanholt runs: 0 here (unpacked), 1 a copy already here, 2 a team server; $null cancelled
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Set up Rowanholt'
    $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
    $form.StartPosition = 'CenterScreen'; $form.ClientSize = New-Object System.Drawing.Size(520, 230)
    $iconFile = Join-Path $AppDir 'app\icons\rowanholt.ico'
    if (Test-Path $iconFile) { $form.Icon = New-Object System.Drawing.Icon($iconFile) }
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Where does Rowanholt run?`n`nA server needs nothing here but a window onto it: no Docker, no evidence, no 70 MB of files."
    $label.SetBounds(16, 12, 490, 60)
    $form.Controls.Add($label)
    $options = @("Install Rowanholt $(Get-AppVersion) on this PC (needs Docker Desktop)",
                 'Use a copy I already have (a git clone, for instance)',
                 "Connect to my team's Rowanholt server")
    $radios = for ($i = 0; $i -lt $options.Count; $i++) {
        $radio = New-Object System.Windows.Forms.RadioButton
        $radio.Text = $options[$i]; $radio.SetBounds(24, 78 + 28 * $i, 480, 24); $radio.Checked = ($i -eq 0)
        $form.Controls.Add($radio); $radio
    }
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Next'; $ok.DialogResult = 'OK'; $ok.SetBounds(330, 190, 85, 28)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.SetBounds(421, 190, 85, 28)
    $form.Controls.AddRange(@($ok, $cancel)); $form.AcceptButton = $ok; $form.CancelButton = $cancel
    if ($form.ShowDialog() -ne 'OK') { return $null }
    for ($i = 0; $i -lt $radios.Count; $i++) { if ($radios[$i].Checked) { return $i } }
    return 0
}

function Select-Folder([string]$Description, [string]$Start) {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    if ($Start -and (Test-Path $Start)) { $dialog.SelectedPath = $Start }
    if ($dialog.ShowDialog() -ne 'OK') { return $null }
    return $dialog.SelectedPath
}

function Set-Server {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $typed = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Your team's Rowanholt server.`n`nIts address, e.g. rowanholt.example.org. If Edge warns about its certificate, ask the server's admin for its root certificate.",
        'Set up Rowanholt', (Get-SavedServer))
    if (-not $typed) { exit 1 }
    $server = ConvertTo-ServerUrl $typed
    if (-not $server) {
        Show-Message "'$typed' isn't a server address, e.g. rowanholt.example.org (https only)." 'OK' 'Error' | Out-Null
        exit 1
    }
    Set-Content -Path $ServerFile -Value $server -Encoding ASCII
}

function Test-DockerInstalled {
    return (Test-Path (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')) -or
           [bool](Get-Command docker -ErrorAction SilentlyContinue)
}

function Assert-DockerInstalled {
    if (Test-DockerInstalled) { return }
    $answer = Show-Message ("Rowanholt runs as a set of Docker containers, and Docker Desktop isn't installed.`n`n" +
        "Install Docker Desktop (it needs WSL 2), start it once, then open Rowanholt from the Start menu.`n`n" +
        "Docker Desktop is free for personal use and small businesses; larger organisations need a paid subscription.`n`n" +
        'Open the Docker Desktop download page?') 'YesNo' 'Warning'
    if ($answer -eq 'Yes') { Start-Process 'https://www.docker.com/products/docker-desktop/' }
    exit 1
}

function Expand-Bundle([string]$Target) {
    New-Item -ItemType Directory -Force -Path $Target | Out-Null
    Write-Host "Copying Rowanholt $(Get-AppVersion) into $Target..."
    # Windows 10 and 11 ship bsdtar; .env, docker-compose.local.yml and cases aren't in the tarball, so they're kept
    & (Join-Path $env:SystemRoot 'System32\tar.exe') -xzf $Bundled -C $Target --strip-components 1
    if ($LASTEXITCODE -ne 0) { throw "Couldn't unpack Rowanholt into $Target (tar exited with status $LASTEXITCODE)" }
    Set-Content -Path (Join-Path $Target '.rowanholt-version') -Value (Get-AppVersion) -Encoding ASCII -NoNewline
}

function ConvertTo-ContainerPath([string]$Dir) {
    # D:\Cases is /mnt/d/Cases inside the containers (Docker Desktop's WSL 2 paths)
    $rest = $Dir.Substring(2).Replace('\', '/').TrimEnd('/')
    return '/mnt/' + $Dir.Substring(0, 1).ToLower() + $rest
}

function Write-Evidence([string]$Dir, [string[]]$Folders) {
    $file = Join-Path $Dir 'docker-compose.local.yml'
    if (Test-Path $file) {
        $first = Get-Content $file -TotalCount 1
        if (-not ($first.StartsWith($LocalHeader) -or $first.StartsWith($OldLocalHeader))) {
            Show-Message "$file was written by hand, so setup left its mounts alone." 'OK' 'Warning' | Out-Null
            return
        }
    }
    if (-not $Folders) { Remove-Item $file -ErrorAction SilentlyContinue; return }
    $lines = @("${LocalHeader}: evidence folders, read-only in the backend.", 'services:')
    foreach ($service in 'backend', 'celery-worker') {
        $lines += "  ${service}:", '    volumes:'
        foreach ($folder in $Folders) {
            $lines += '      - type: bind', "        source: `"$($folder.Replace('\', '/'))`"",
                      "        target: `"$(ConvertTo-ContainerPath $folder)`""
            if ($service -eq 'backend') { $lines += '        read_only: true' }
        }
    }
    # LF and no BOM: compose reads either, but the file matches the other platforms'
    [IO.File]::WriteAllText($file, ($lines -join "`n") + "`n")
}

function Select-Evidence {
    $folders = @()
    $question = ("Mount a folder of evidence (disk images, memory dumps, Gandalf archives) into Rowanholt?`n`n" +
        "Rowanholt sees it inside its containers under /mnt/<drive>/..., so D:\Cases becomes /mnt/d/Cases. " +
        "External drives aren't visible otherwise. Optional: run Set Up Rowanholt again to change it.")
    while ((Show-Message $question 'YesNo' 'Question') -eq 'Yes') {
        $folder = Select-Folder 'Evidence folder' ''
        if ($folder) {
            if ($folder -notmatch '^[A-Za-z]:\\') {
                Show-Message 'Choose a folder on a lettered drive (C:\..., D:\...).' 'OK' 'Error' | Out-Null
            } elseif ($folders -notcontains $folder) {
                $folders += $folder
            }
        }
        $question = "Evidence so far:`n  $($folders -join "`n  ")`n`nAdd another folder?"
    }
    return $folders
}

function Invoke-Setup {
    # Returns the copy to run, or $null when it's a server now
    $mode = Select-Mode
    if ($null -eq $mode) { exit 1 }
    if ($mode -eq 2) { Set-Server; return $null }
    Remove-Item $ServerFile -ErrorAction SilentlyContinue
    Assert-DockerInstalled
    if ($mode -eq 1) {
        $dir = Select-Folder 'Choose your Rowanholt folder' $env:USERPROFILE
        if (-not $dir) { exit 1 }
        if (-not (Test-Copy $dir)) {
            Show-Message "$dir doesn't look like Rowanholt: there's no rowanholt launcher and docker-compose.yml in it." 'OK' 'Error' | Out-Null
            exit 1
        }
    } else {
        $parent = Select-Folder 'Choose where to put the Rowanholt folder' $env:USERPROFILE
        if (-not $parent) { exit 1 }
        $dir = Join-Path $parent 'Rowanholt'
    }
    # Unpack into a new folder, or over a copy setup unpacked before (never a git clone)
    $unpacked = (Test-Copy $dir) -and (Test-Path (Join-Path $dir '.rowanholt-version')) -and -not (Test-Path (Join-Path $dir '.git'))
    if (-not (Test-Path $dir) -or $unpacked) {
        Expand-Bundle $dir
    } elseif (-not (Test-Copy $dir)) {
        Show-Message "$dir already exists and isn't Rowanholt. Choose another folder." 'OK' 'Error' | Out-Null
        exit 1
    }
    Write-Evidence $dir @(Select-Evidence)
    Set-Content -Path $RootFile -Value $dir -Encoding UTF8
    return $dir
}

function Resolve-Root([switch]$NoSetup) {
    if ($env:ROWANHOLT_ROOT -and (Test-Copy $env:ROWANHOLT_ROOT)) { return $env:ROWANHOLT_ROOT }
    # A checkout's own app\windows: run that checkout
    if (-not $Packaged) { return $AppDir }
    if (Test-Path $RootFile) {
        $saved = (Get-Content $RootFile -Raw).Trim()
        if (Test-Copy $saved) { return $saved }
    }
    if ($NoSetup) { return $null }
    return Invoke-Setup
}

function Update-Copy {
    # A newer MSI than the copy setup unpacked: offer to bring the copy up to it
    $versionFile = Join-Path $Root '.rowanholt-version'
    if (-not $Packaged -or -not (Test-Path $versionFile) -or (Test-Path (Join-Path $Root '.git'))) { return }
    if ((Get-Content $versionFile -Raw).Trim() -eq (Get-AppVersion)) { return }
    $answer = Show-Message ("Update Rowanholt in $Root to $(Get-AppVersion)?`n`n" +
        'Your .env, evidence folders and cases are kept. The images are rebuilt on this start, which takes a while.') 'YesNo' 'Question'
    if ($answer -eq 'Yes') { Expand-Bundle $Root }
}

# ── Running it ────────────────────────────────────────────────────────────────
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
    $versionFile = Join-Path $Root '.rowanholt-version'
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
    $built = Join-Path $Root '.rowanholt-built'
    $version = (Get-Content $versionFile -Raw).Trim()
    if ((Test-Path $built) -and (Get-Content $built -Raw).Trim() -eq $version) { return @() }
    Write-Host 'New Rowanholt version: rebuilding the images (this takes a while)...'
    return @('--build')
}

# ── The road to Rowanholt ─────────────────────────────────────────────────────
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
    Write-Progress -Activity 'The road to Rowanholt' -Status "$where - $eta to Rowanholt$guess" `
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
    Write-Progress -Activity 'The road to Rowanholt' -Completed
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
    if ($Setup) {
        if (-not $Packaged) {
            Show-Message "This is a checkout's launcher: it always runs $AppDir." | Out-Null
            exit 0
        }
        Invoke-Setup | Out-Null
        # A server opens now; a copy here starts from the Rowanholt shortcut
        if (-not (Get-SavedServer)) { exit 0 }
    }

    $Server = Get-SavedServer
    if ($Server) {
        if ($Stop) {
            Write-Host "Rowanholt runs on $Server; its admins start and stop it."
            Start-Sleep -Seconds 4
            exit 0
        }
        $Url = $Server
        Open-Window
        exit 0
    }

    if ($Stop) {
        $Root = Resolve-Root -NoSetup
        if (-not $Root) {
            Write-Host "Rowanholt isn't set up on this PC yet: nothing to stop."
            Start-Sleep -Seconds 4
            exit 0
        }
        Wait-Docker
        Write-Host 'Stopping Rowanholt...'
        Invoke-Compose @('down', '--remove-orphans')
        Write-Host 'Stopped.'
        Start-Sleep -Seconds 2
        exit 0
    }

    $Root = Resolve-Root
    # Setup may just have chosen a server
    $Server = Get-SavedServer
    if (-not $Root -or $Server) {
        if ($Server) { $Url = $Server; Open-Window }
        exit 0
    }
    Update-Copy

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
        Write-Host 'Starting Rowanholt...'
        Enter-Phase $script:Journey 'images'
        Invoke-ComposeUp $script:Journey $extra $missing.Count
        if ($script:Journey.Phase -eq 'images') { Enter-Phase $script:Journey 'containers' }
        if ($extra -contains '--build') {
            Copy-Item (Join-Path $Root '.rowanholt-version') (Join-Path $Root '.rowanholt-built') -Force
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

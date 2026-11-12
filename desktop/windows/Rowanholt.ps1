<#
.SYNOPSIS
    What the Rowanholt shortcut runs: start the Docker stack if the web UI isn't
    answering, then open the UI in its own Edge (or Chrome) app window. With a team
    server (ROWANHOLT_SERVER, or the one setup saved) it just opens the server: nothing
    runs here.
.DESCRIPTION
    From a checkout (desktop\windows\ in a clone) it runs that checkout. Installed from the MSI
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
    [switch]$Setup,
    # -Update installs the newest release now (desktop\install.ps1, which the MSI carries in
    # seed\); -Update -Check only says whether there is one
    [switch]$Update,
    [switch]$Check
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

# The server IT has set (Group Policy or Intune): it wins, and setup can't change it
$PolicyKey = 'SOFTWARE\Policies\cmdaltr\Rowanholt'
$script:ServerManaged = $false

function Get-ManagedServer {
    foreach ($hive in 'HKLM:', 'HKCU:') {
        try {
            $value = (Get-ItemProperty -Path "$hive\$PolicyKey" -Name ServerURL -ErrorAction Stop).ServerURL
            if ("$value".Trim()) { return "$value".Trim() }
        } catch { }
    }
    return ''
}

# IT's server, then ROWANHOLT_SERVER (a URL, or 'local' to run here whatever setup saved), then setup's
function Get-SavedServer {
    $managed = Get-ManagedServer
    if ($managed) {
        $url = ConvertTo-ServerUrl $managed -AllowHttp
        if (-not $url) { throw "The server address IT set ($managed, in $PolicyKey) isn't a web address." }
        $script:ServerManaged = $true
        return $url
    }
    if ($env:ROWANHOLT_SERVER) {
        if ($env:ROWANHOLT_SERVER.Trim() -eq 'local') { return '' }
        $url = ConvertTo-ServerUrl $env:ROWANHOLT_SERVER -AllowHttp
        if (-not $url) { throw "ROWANHOLT_SERVER ($env:ROWANHOLT_SERVER) isn't a web address." }
        return $url
    }
    if (Test-Path $ServerFile) { return (Get-Content $ServerFile -Raw).Trim() }
    return ''
}

# ── Windows' own look ─────────────────────────────────────────────────────────
# Without visual styles WinForms draws Windows 95's buttons, and without DPI awareness Windows
# stretches the dialogs into blurred text on a scaled display. The console is hidden while
# setup's dialogs are up: it has nothing to show until the stack starts or files are copied
Add-Type -Namespace Rowanholt -Name Native -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
'@
$script:GuiReady = $false

function Initialize-Gui {
    if ($script:GuiReady) { return }
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [Rowanholt.Native]::SetProcessDPIAware() | Out-Null
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:GuiReady = $true
}

function Hide-Console {
    # Only a console of its own (the shortcut's): run from someone's terminal, that terminal stays
    if ([Rowanholt.Native]::GetConsoleProcessList((New-Object UInt32[] 4), 4) -ne 1) { return }
    [Rowanholt.Native]::ShowWindow([Rowanholt.Native]::GetConsoleWindow(), 0) | Out-Null
}
function Show-Console { [Rowanholt.Native]::ShowWindow([Rowanholt.Native]::GetConsoleWindow(), 5) | Out-Null }

function Show-Message([string]$Text, [string]$Buttons = 'OK', [string]$Icon = 'Information') {
    Initialize-Gui
    return [string][System.Windows.Forms.MessageBox]::Show($Text, 'Rowanholt', $Buttons, $Icon)
}

function New-SetupForm([string]$Heading, [string]$Subheading, [int]$BodyHeight) {
    # A wizard page as the MSI's are: white header with the icon, the body, Next and Cancel.
    # Laid out at 96 DPI; AutoScaleMode Dpi scales it to the display's
    Initialize-Gui
    $form = New-Object System.Windows.Forms.Form
    $form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.Text = 'Set up Rowanholt'
    $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
    $form.StartPosition = 'CenterScreen'; $form.ShowInTaskbar = $true
    $form.ClientSize = New-Object System.Drawing.Size(520, (64 + 1 + $BodyHeight + 1 + 52))
    $form.Add_Shown({ $this.Activate() })
    $iconFile = Join-Path $AppDir 'desktop\icons\rowanholt.ico'

    $header = New-Object System.Windows.Forms.Panel
    $header.SetBounds(0, 0, 520, 64); $header.BackColor = [System.Drawing.Color]::White
    $title = New-Object System.Windows.Forms.Label
    $title.Text = $Heading; $title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
    $title.SetBounds(20, 12, 420, 22)
    $sub = New-Object System.Windows.Forms.Label
    $sub.Text = $Subheading; $sub.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $sub.SetBounds(20, 36, 420, 20)
    $header.Controls.AddRange(@($title, $sub))
    if (Test-Path $iconFile) {
        $form.Icon = New-Object System.Drawing.Icon($iconFile)
        $picture = New-Object System.Windows.Forms.PictureBox
        $picture.Image = (New-Object System.Drawing.Icon($iconFile, 48, 48)).ToBitmap()
        $picture.SizeMode = 'Zoom'; $picture.SetBounds(460, 10, 44, 44)
        $header.Controls.Add($picture)
    }
    $form.Controls.Add($header)
    foreach ($y in 64, (65 + $BodyHeight)) {
        $line = New-Object System.Windows.Forms.Panel
        $line.SetBounds(0, $y, 520, 1); $line.BackColor = [System.Drawing.Color]::FromArgb(218, 218, 218)
        $form.Controls.Add($line)
    }

    $buttonsY = 66 + $BodyHeight + 13
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Next'; $ok.DialogResult = 'OK'; $ok.SetBounds(316, $buttonsY, 92, 28)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.SetBounds(416, $buttonsY, 92, 28)
    $form.Controls.AddRange(@($ok, $cancel)); $form.AcceptButton = $ok; $form.CancelButton = $cancel
    return $form
}

function Add-FormText($Form, [string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height, [switch]$Muted) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text; $label.SetBounds($X, $Y, $Width, $Height)
    if ($Muted) { $label.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96) }
    $Form.Controls.Add($label)
}

function Test-Copy([string]$Dir) {
    return $Dir -and (Test-Path (Join-Path $Dir 'docker-compose.yml')) -and (Test-Path (Join-Path $Dir 'rowanholt'))
}

# A typed address as https://host[:port]; '' if it isn't one. http only for localhost, unless IT
# or ROWANHOLT_SERVER set it (-AllowHttp), for a server on a network they trust
function ConvertTo-ServerUrl([string]$Text, [switch]$AllowHttp) {
    $Text = ($Text -replace '\s', '')
    if ($Text -notmatch '://') { $Text = "https://$Text" }
    if ($Text -notmatch '^(?<scheme>[A-Za-z]+)://(?<host>[^/]+)') { return '' }
    $scheme = $Matches.scheme.ToLower(); $hostPort = $Matches.host
    if ($hostPort -notmatch '^[A-Za-z0-9.-]+(:\d+)?$') { return '' }
    if ($scheme -eq 'https') { return "https://$hostPort" }
    if ($scheme -eq 'http' -and ($AllowHttp -or ($hostPort -split ':')[0] -in 'localhost', '127.0.0.1')) { return "http://$hostPort" }
    return ''
}

function Select-Mode {
    # Where Rowanholt runs: 0 here (unpacked), 1 a copy already here, 2 a team server; $null cancelled
    $form = New-SetupForm 'Where should Rowanholt run?' 'You can change this later with Set Up Rowanholt in the Start menu.' 210
    $options = @(
        @('On this PC', "Rowanholt $(Get-AppVersion) runs here in Docker Desktop, and your evidence stays on this PC."),
        @('From a copy I already have', 'A Rowanholt folder that is already on this PC, such as a git clone.'),
        @("On my team's server", "Opens your team's Rowanholt in a window. Nothing else is installed or run here.")
    )
    $bold = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
    $radios = for ($i = 0; $i -lt $options.Count; $i++) {
        $y = 82 + 64 * $i
        $radio = New-Object System.Windows.Forms.RadioButton
        $radio.Text = $options[$i][0]; $radio.Font = $bold
        $radio.SetBounds(28, $y, 460, 24); $radio.Checked = ($i -eq 0)
        $form.Controls.Add($radio)
        Add-FormText $form $options[$i][1] 46 ($y + 24) 450 34 -Muted
        $radio
    }
    if ($form.ShowDialog() -ne 'OK') { return $null }
    for ($i = 0; $i -lt $radios.Count; $i++) { if ($radios[$i].Checked) { return $i } }
    return 0
}

function Select-Folder([string]$Description, [string]$Start) {
    Initialize-Gui
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    if ($Start -and (Test-Path $Start)) { $dialog.SelectedPath = $Start }
    if ($dialog.ShowDialog() -ne 'OK') { return $null }
    return $dialog.SelectedPath
}

function Set-Server {
    $form = New-SetupForm "Your team's Rowanholt server" 'Rowanholt opens it in its own window.' 150
    Add-FormText $form 'Server address:' 28 84 460 20
    $box = New-Object System.Windows.Forms.TextBox
    $box.SetBounds(28, 106, 464, 24); $box.Text = (Get-SavedServer)
    $form.Controls.Add($box)
    Add-FormText $form ("For example rowanholt.example.org. If Edge warns about the server's certificate, " +
        "ask its admin for the root certificate.") 28 142 464 40 -Muted
    $form.Add_Shown({ $box.Focus() })
    if ($form.ShowDialog() -ne 'OK') { exit 1 }
    $typed = $box.Text
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
    Show-Console
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
    # A checkout's own desktop\windows: run that checkout
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
    Show-Console
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

# ── Updates (the MSI's app) ───────────────────────────────────────────────────
# Once a day, ask GitHub for the latest published release (drafts and prereleases aren't
# 'latest'); offer it once the window is open. Nothing but the request is sent. Off with
# ROWANHOLT_UPDATE_CHECK=0, or "check": false in update.json
$UpdateFile = Join-Path $State 'update.json'
$Repo = 'cmdaltr/rowanholt'

function ConvertTo-VersionParts([string]$Text) {
    # 'v2.1.0' as 2,1,0; anything after the numbers (-dev.4, -rc1) is ignored, as Shikari does
    if ("$Text".Trim() -notmatch '^v?(\d+(\.\d+)*)') { return @() }
    return @($Matches[1].Split('.') | ForEach-Object { [int]$_ })
}

function Test-Newer([string]$Latest, [string]$Current) {
    $a = @(ConvertTo-VersionParts $Latest); $b = @(ConvertTo-VersionParts $Current)
    if (-not $a.Count) { return $false }
    for ($i = 0; $i -lt [math]::Max($a.Count, $b.Count); $i++) {
        $x = if ($i -lt $a.Count) { $a[$i] } else { 0 }
        $y = if ($i -lt $b.Count) { $b[$i] } else { 0 }
        if ($x -ne $y) { return $x -gt $y }
    }
    return $false
}

function Read-UpdateState {
    try { return (Get-Content $UpdateFile -Raw | ConvertFrom-Json) } catch { return [pscustomobject]@{} }
}

function Write-UpdateState($UpdateState) {
    try { $UpdateState | ConvertTo-Json -Depth 4 | Set-Content -Path $UpdateFile -Encoding UTF8 } catch { }
}

function Get-LatestRelease {
    # The repository is public; a token only lifts GitHub's rate limit
    $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'rowanholt-update' }
    $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { '' }
    if ($token) { $headers.Authorization = "Bearer $token" }
    $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -TimeoutSec 10
    return [pscustomobject]@{ tag = "$($r.tag_name)"; version = "$($r.tag_name)".TrimStart('v'); url = "$($r.html_url)" }
}

function Test-UpdateChecks {
    if ("$env:ROWANHOLT_UPDATE_CHECK".Trim().ToLower() -in '0', 'false', 'no', 'off') { return $false }
    return (Read-UpdateState).check -ne $false
}

function Get-DailyUpdate {
    # The newer release, or $null; GitHub at most once a day, and a failed check is just $null
    if (-not (Test-UpdateChecks)) { return $null }
    $st = Read-UpdateState
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (-not $st.checked_at -or ($now - [double]$st.checked_at) -ge 86400) {
        $latest = $null
        try { $latest = Get-LatestRelease } catch { }
        $st | Add-Member -Force -NotePropertyName latest -NotePropertyValue $latest
        $st | Add-Member -Force -NotePropertyName checked_at -NotePropertyValue $now
        Write-UpdateState $st
    }
    if ($st.latest -and (Test-Newer $st.latest.version (Get-AppVersion)) -and $st.latest.version -ne $st.skipped) { return $st.latest }
    return $null
}

function Start-AppUpdate([string]$Tag, [switch]$Foreground) {
    $script = Join-Path $AppDir 'seed\install.ps1'
    if (-not (Test-Path $script)) { throw "No installer beside the app ($script): reinstall Rowanholt." }
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"", '-Version', $Tag)
    if ($Foreground) { & powershell @arguments; return }
    Start-Process powershell -ArgumentList ($arguments + '-Launch')
}

function Show-UpdateNotice($Latest) {
    # Update, Later (until the next start) or Skip this version (until a newer one)
    Initialize-Gui
    $form = New-Object System.Windows.Forms.Form
    $form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96); $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.Text = 'Rowanholt'; $form.ClientSize = New-Object System.Drawing.Size(440, 132); $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.TopMost = $true
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Rowanholt $($Latest.version) is available (you have $(Get-AppVersion)).`n`nUpdate downloads it, checks it against the release's SHA256SUMS and installs it."
    $label.SetBounds(12, 10, 410, 70)
    $form.Controls.Add($label)
    foreach ($b in @(@('Update', 'now', 150), @('Later', 'later', 240), @('Skip this version', 'skip', 330))) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $b[0]; $button.Tag = $b[1]; $button.SetBounds($b[2] - 70, 88, 90, 28)
        $button.Add_Click({ $script:UpdateAnswer = $this.Tag; $this.FindForm().Close() })
        $form.Controls.Add($button)
    }
    $script:UpdateAnswer = 'later'  # closing the window is Later
    [void]$form.ShowDialog()
    switch ($script:UpdateAnswer) {
        'now' { Start-AppUpdate $Latest.tag }
        'skip' {
            $st = Read-UpdateState
            $st | Add-Member -Force -NotePropertyName skipped -NotePropertyValue $Latest.version
            Write-UpdateState $st
        }
    }
}

function Invoke-UpdateCheck {
    # After the window opens, for the MSI's app only: a checkout updates with git
    if (-not $Packaged) { return }
    $latest = Get-DailyUpdate
    if ($latest) { Show-UpdateNotice $latest }
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
    # -Stop and -Update only write to the console; everything else starts with setup's dialogs or nothing
    if (-not ($Stop -or $Update)) { Hide-Console }
    if ($Update) {
        if (-not $Packaged) { Write-Host "This is a checkout's launcher: update it with git pull."; exit 0 }
        $latest = Get-LatestRelease
        if (-not (Test-Newer $latest.version (Get-AppVersion))) { Write-Host "Rowanholt $(Get-AppVersion) is the latest."; exit 0 }
        Write-Host "Rowanholt $($latest.version) is available (you have $(Get-AppVersion)): $($latest.url)"
        if (-not $Check) { Start-AppUpdate $latest.tag -Foreground }
        exit 0
    }
    if ($Setup) {
        if ((Get-SavedServer) -and $script:ServerManaged) {
            Show-Message "Your organisation has set Rowanholt to open $(Get-SavedServer), so there's nothing to set up." | Out-Null
            exit 0
        }
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
        Invoke-UpdateCheck
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
        if ($Server) { $Url = $Server; Open-Window; Invoke-UpdateCheck }
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
    Invoke-UpdateCheck
} catch {
    Show-Console
    Write-Host ''
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}

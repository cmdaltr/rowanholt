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
    # The PNG, not the .ico: Icon.ToBitmap garbles an .ico's PNG-compressed sizes into noise
    $pngFile = Join-Path $AppDir 'desktop\icons\rowanholt.png'

    $header = New-Object System.Windows.Forms.Panel
    $header.SetBounds(0, 0, 520, 64); $header.BackColor = [System.Drawing.Color]::White
    $title = New-Object System.Windows.Forms.Label
    $title.Text = $Heading; $title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
    $title.SetBounds(20, 12, 420, 22)
    $sub = New-Object System.Windows.Forms.Label
    $sub.Text = $Subheading; $sub.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $sub.SetBounds(20, 36, 420, 20)
    $header.Controls.AddRange(@($title, $sub))
    if (Test-Path $iconFile) { $form.Icon = New-Object System.Drawing.Icon($iconFile) }
    if (Test-Path $pngFile) {
        $picture = New-Object System.Windows.Forms.PictureBox
        $picture.Image = [System.Drawing.Image]::FromFile($pngFile)
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

function Get-DockerDesktop {
    # Per-user (Docker's default since 4.83, no administrator needed) or all-users
    foreach ($exe in $DockerUserExe, $DockerMachineExe) { if (Test-Path $exe) { return $exe } }
    return $null
}

function Add-DockerToPath {
    # A Docker Desktop installed since this process started isn't on its PATH yet
    if (Get-Command docker -ErrorAction SilentlyContinue) { return }
    $desktop = Get-DockerDesktop
    if ($desktop) { $env:Path = (Join-Path (Split-Path $desktop) 'resources\bin') + ";$env:Path" }
}

function Test-DockerInstalled {
    return [bool](Get-DockerDesktop) -or [bool](Get-Command docker -ErrorAction SilentlyContinue)
}

function Assert-DockerInstalled {
    if (Test-DockerInstalled) { Add-DockerToPath; return }
    $answer = Show-Message ("Rowanholt runs as a set of Docker containers, and Docker Desktop isn't installed.`n`n" +
        "Install it now? Rowanholt downloads it from docker.com, checks it's signed by Docker and installs it " +
        "for you alone (no administrator rights; turning on WSL 2, if it's off, asks for them).`n`n" +
        "Installing it accepts Docker's Subscription Service Agreement: free for personal use, education and " +
        'small businesses; larger organisations need a paid subscription.') 'YesNo' 'Question'
    if ($answer -ne 'Yes') { exit 1 }
    $result = Install-Dependencies @('docker')
    if ($result.Restart -or -not (Test-DockerInstalled)) { exit 1 }
    Add-DockerToPath
}

# ── What Rowanholt needs, and what it can use ─────────────────────────────────
# Docker Desktop (with WSL 2) runs the stack; Ollama and a model give Smith its AI answers, and
# without them Smith answers from the case files. The MSI's options page records what was ticked
# under HKCU\Software\cmdaltr\Rowanholt (InstallDocker, InstallOllama, InstallModel) and the next
# start installs it, so unticking Launch on the Finish page only puts it off. Downloads come from
# Docker and Ollama themselves and must carry their Authenticode signature: "latest" has no fixed hash
$AppKey = 'HKCU:\Software\cmdaltr\Rowanholt'
$DockerUserExe = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'
$DockerMachineExe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
$OllamaExe = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
$OllamaUrl = 'http://127.0.0.1:11434'
# The backend's default (ROWANHOLT_MODEL_NAME in docker-compose.yml)
$SmithModel = 'llama3.2:3b'
$Dependencies = [ordered]@{
    docker = @{ Value = 'InstallDocker'; Name = 'Docker Desktop' }
    ollama = @{ Value = 'InstallOllama'; Name = 'Ollama' }
    model  = @{ Value = 'InstallModel'; Name = "Smith's model ($SmithModel)" }
}

# Something to read while the downloads run, from the web app's own guide (src/web/frontend/src/guide)
$GuideCards = @(
    @('Rowanholt', 'Acquisition, analysis and an analyst to ask, in one place: Gandalf collects, Elrond analyses, and Smith answers questions about a case from its files.'),
    @('Gandalf: acquisition', 'Collects artefacts from live hosts, locally, over SSH or over PowerShell Remoting, in order of volatility, and logs the SHA-256 of every file it takes. Elrond checks each one against that log before using it.'),
    @('Elrond: analysis', 'Turns disk images, memory images, Gandalf archives, network evidence and datasets into timelines, CSVs and ATT&CK mappings. Brisk for triage; Exhaustive when the case matters more than the clock.'),
    @('Several hosts, one case', 'Analyse hosts together and Elrond stacks them: with three or more hosts of one OS, what is rare across them stands out, persistence first.'),
    @('The case browser', "Every host's artefacts, read-only and filterable. Flag a row as a finding, assign hosts to analysts and keep case notes; the report puts confirmed findings first."),
    @('Smith', 'Ask about a case in plain English. Answers cite the rows they rest on, and each cited row can be flagged as a lead. Without a model, Smith still answers fixed questions: hosts, techniques, persistence, logins, IOCs.'),
    @('Pippin: threat intelligence', 'Indicators from STIX/TAXII feeds, MITRESaw and your own imports. Elrond matches cases against them, and expired indicators drop out of matching.'),
    @('Mordor Recordings', 'Recorded attack telemetry: which logs record each ATT&CK technique, from public labs and your own. Look here before writing a detection.'),
    @('Your evidence stays put', "Evidence folders are mounted read-only for the web app: D:\Cases appears inside Rowanholt as /mnt/d/Cases. Set Up Rowanholt in the Start menu changes them later.")
)

function Show-GuideCard($Ui, [int]$Index) {
    $Ui.Card = ($Index + $GuideCards.Count) % $GuideCards.Count
    $Ui.CardTitle.Text = $GuideCards[$Ui.Card][0]
    $Ui.CardText.Text = $GuideCards[$Ui.Card][1]
    $Ui.CardCount.Text = "$($Ui.Card + 1) of $($GuideCards.Count)"
}

function Get-PendingDependencies {
    $values = Get-ItemProperty -Path $AppKey -ErrorAction SilentlyContinue
    if (-not $values) { return @() }
    return @($Dependencies.Keys | Where-Object { $values.($Dependencies[$_].Value) -eq 1 })
}

function Clear-PendingDependencies([string[]]$Items) {
    foreach ($item in $Items) {
        Remove-ItemProperty -Path $AppKey -Name $Dependencies[$item].Value -ErrorAction SilentlyContinue
    }
}

function Test-WslFeatures {
    # Win32_OptionalFeature answers without administrator rights; Get-WindowsOptionalFeature doesn't
    $on = @(Get-CimInstance Win32_OptionalFeature -Filter "InstallState = 1" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform' })
    return $on.Count -eq 2
}

function Test-Virtualisation {
    # With Windows' own hypervisor running (WSL on), the processor reports its virtualisation as off
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($cpu.VirtualizationFirmwareEnabled) { return $true }
    return (Test-WslFeatures) -and (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
}

function Test-Ollama {
    try { Invoke-RestMethod -Uri "$OllamaUrl/api/version" -TimeoutSec 2 | Out-Null; return $true } catch { return $false }
}

function Step-Gui { [System.Windows.Forms.Application]::DoEvents() }

function Assert-NotCancelled { if ($script:DependenciesCancelled) { throw 'Cancelled' } }

function Write-ComponentLog([string]$Line) {
    # What happened, for after the window has gone: %LOCALAPPDATA%\Rowanholt\components.log
    Add-Content -Path (Join-Path $State 'components.log') -Value "$((Get-Date).ToString('s')) $Line" -ErrorAction SilentlyContinue
}

function Set-Status($Ui, [string]$Item, [string]$Text, [double]$Fraction = -1) {
    # Kept beside the label: the summary is written after the window, and its labels, have closed
    if ($Ui.Status[$Item] -ne $Text -and $Text -notlike 'Downloading *') { Write-ComponentLog "$Item`: $Text" }
    $Ui.Status[$Item] = $Text
    $Ui.Rows[$Item].Text = $Text
    $Ui.Detail.Text = "$($Dependencies[$Item].Name): $Text"
    if ($Fraction -lt 0) { $Ui.Bar.Style = 'Marquee' } else {
        $Ui.Bar.Style = 'Continuous'; $Ui.Bar.Value = [int][math]::Min(1000, 1000 * $Fraction)
    }
    Step-Gui
}

function Save-Download($Ui, [string]$Item, [string]$Url, [string]$Path) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $response = [Net.WebRequest]::Create($Url).GetResponse()
    try {
        $total = $response.ContentLength
        $in = $response.GetResponseStream(); $out = [IO.File]::Create($Path)
        try {
            $buffer = New-Object byte[] 262144; $done = 0L; $shown = [DateTime]::MinValue
            while (($n = $in.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $out.Write($buffer, 0, $n); $done += $n
                if (((Get-Date) - $shown).TotalMilliseconds -ge 250) {
                    $shown = Get-Date
                    $text = if ($total -gt 0) { 'Downloading {0:N0} of {1:N0} MB' -f ($done / 1MB), ($total / 1MB) } else { 'Downloading {0:N0} MB' -f ($done / 1MB) }
                    Set-Status $Ui $Item $text $(if ($total -gt 0) { $done / $total } else { -1 })
                    Assert-NotCancelled
                }
            }
        } finally { $out.Dispose(); $in.Dispose() }
    } finally { $response.Dispose() }
}

function Assert-Signed([string]$Path, [string]$Publisher) {
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch "O=`"?$([regex]::Escape($Publisher))") {
        Remove-Item $Path -Force -ErrorAction SilentlyContinue
        throw "the download isn't signed by $Publisher ($($signature.Status)), so it wasn't run"
    }
}

function Wait-Exit($Process) {
    $null = $Process.Handle  # without it, ExitCode stays empty once the process has gone
    while (-not $Process.HasExited) { Start-Sleep -Milliseconds 200; Step-Gui }
    return $Process.ExitCode
}

function Install-Wsl($Ui) {
    Set-Status $Ui 'docker' 'Turning on WSL 2 (Windows asks for administrator rights)'
    $command = 'foreach ($f in ''Microsoft-Windows-Subsystem-Linux'', ''VirtualMachinePlatform'') { ' +
        '& dism.exe /online /enable-feature /featurename:$f /all /norestart /quiet; if ($LASTEXITCODE -notin 0, 3010) { exit $LASTEXITCODE } }'
    try {
        $p = Start-Process (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Hidden -PassThru `
            -ArgumentList '-NoProfile', '-Command', $command
    } catch {
        throw 'WSL 2 needs administrator rights to turn on, and Windows was told no'
    }
    $code = Wait-Exit $p
    if ($code -ne 0 -or -not (Test-WslFeatures)) { throw "turning on WSL 2 failed (DISM exit $code)" }
}

function Install-Docker($Ui, $Result) {
    if (Get-DockerDesktop) { Set-Status $Ui 'docker' 'Already installed' 1; return }
    if (-not (Test-Virtualisation)) {
        throw ("this PC's processor virtualisation is off, and WSL 2 needs it: turn on VT-x / AMD-V (SVM) in the " +
               "firmware settings, or for a virtual machine, nested virtualisation in its hypervisor")
    }
    if (-not (Test-WslFeatures)) { Install-Wsl $Ui; $Result.Restart = $true }
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $installer = Join-Path $env:TEMP 'Docker Desktop Installer.exe'
    Save-Download $Ui 'docker' "https://desktop.docker.com/win/main/$arch/Docker%20Desktop%20Installer.exe" $installer
    Set-Status $Ui 'docker' 'Checking the signature'
    Assert-Signed $installer 'Docker Inc'
    Set-Status $Ui 'docker' 'Installing (a few minutes)'
    $code = Wait-Exit (Start-Process $installer -PassThru -ArgumentList 'install', '--user', '--quiet', '--accept-license')
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
    # Judged by what's there: Process.ExitCode can come back empty for a process that has gone
    if (-not (Get-DockerDesktop)) { throw "Docker's installer failed (exit $code)" }
    Set-Status $Ui 'docker' $(if ($Result.Restart) { 'Installed: restart Windows to finish' } else { 'Installed' }) 1
}

function Start-Ollama($Ui, [string]$Item) {
    if (Test-Ollama) { return }
    Set-Status $Ui $Item 'Starting Ollama'
    # Its installer starts the app itself: give that a chance before starting another copy
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Ollama) { return }
        if (Get-Process -Name 'ollama app', 'ollama' -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 500; Step-Gui } else { break }
    }
    $app = Join-Path (Split-Path $OllamaExe) 'ollama app.exe'
    if (Test-Path $app) { Start-Process $app } else { Start-Process $OllamaExe -ArgumentList 'serve' -WindowStyle Hidden }
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-Ollama) { return }
        Start-Sleep -Milliseconds 500; Step-Gui
    }
    throw "Ollama didn't start ($OllamaUrl isn't answering)"
}

function Install-Ollama($Ui) {
    if (Test-Path $OllamaExe) { Set-Status $Ui 'ollama' 'Already installed' 1; return }
    $installer = Join-Path $env:TEMP 'OllamaSetup.exe'
    Save-Download $Ui 'ollama' 'https://ollama.com/download/OllamaSetup.exe' $installer
    Set-Status $Ui 'ollama' 'Checking the signature'
    Assert-Signed $installer 'Ollama'
    Set-Status $Ui 'ollama' 'Installing'
    $code = Wait-Exit (Start-Process $installer -PassThru -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-')
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $OllamaExe)) { throw "Ollama's installer failed (exit $code)" }
    Start-Ollama $Ui 'ollama'
    Set-Status $Ui 'ollama' 'Installed' 1
}

function Install-Model($Ui) {
    if (-not (Test-Path $OllamaExe) -and -not (Test-Ollama)) { throw "Ollama isn't installed, and the model needs it" }
    Start-Ollama $Ui 'model'
    # Ollama's own API streams the pull's progress as JSON lines
    $request = [Net.WebRequest]::Create("$OllamaUrl/api/pull")
    $request.Method = 'POST'; $request.ContentType = 'application/json'
    $body = [Text.Encoding]::UTF8.GetBytes((@{ model = $SmithModel; name = $SmithModel; stream = $true } | ConvertTo-Json -Compress))
    $stream = $request.GetRequestStream(); $stream.Write($body, 0, $body.Length); $stream.Close()
    $response = $request.GetResponse()
    try {
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        while ($null -ne ($line = $reader.ReadLine())) {
            $progress = $line | ConvertFrom-Json
            if ($progress.error) { throw "Ollama couldn't pull $SmithModel ($($progress.error))" }
            if ($progress.total) {
                Set-Status $Ui 'model' ('Downloading {0:N0} of {1:N0} MB' -f ($progress.completed / 1MB), ($progress.total / 1MB)) ($progress.completed / $progress.total)
            } else {
                Set-Status $Ui 'model' $progress.status
            }
            Assert-NotCancelled
        }
    } finally { $response.Dispose() }
    Set-Status $Ui 'model' 'Ready' 1
}

function Install-Dependencies([string[]]$Items) {
    # One window for all of them, in order; one failing doesn't stop the rest. Returns
    # @{ Failed; Restart }, Restart when WSL 2 was just turned on
    $result = @{ Failed = @(); Restart = $false }
    $height = 40 + 30 * $Items.Count + 70 + 150
    $form = New-SetupForm 'Finishing the install' 'Installing what you chose in the installer, straight from Docker and Ollama.' $height
    $form.AcceptButton.Visible = $false
    $script:DependenciesCancelled = $false
    $form.CancelButton.DialogResult = 'None'
    $form.CancelButton.Add_Click({ $script:DependenciesCancelled = $true })
    $form.Add_FormClosing({ param($s, $e) if (-not $script:DependenciesDone) { $script:DependenciesCancelled = $true; $e.Cancel = $true } })
    $script:DependenciesDone = $false
    $ui = @{ Rows = @{}; Status = @{}; Problems = @() }
    Write-ComponentLog "Installing: $($Items -join ', ')"
    $y = 84
    foreach ($item in $Items) {
        $name = New-Object System.Windows.Forms.Label
        $name.Text = $Dependencies[$item].Name; $name.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
        $name.SetBounds(28, $y, 190, 22); $form.Controls.Add($name)
        $status = New-Object System.Windows.Forms.Label
        $status.Text = 'Waiting'; $status.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
        $status.SetBounds(220, $y, 280, 22); $form.Controls.Add($status)
        $ui.Rows[$item] = $status
        $y += 30
    }
    $ui.Bar = New-Object System.Windows.Forms.ProgressBar
    $ui.Bar.SetBounds(28, $y + 12, 464, 18); $ui.Bar.Maximum = 1000; $ui.Bar.MarqueeAnimationSpeed = 30
    $ui.Detail = New-Object System.Windows.Forms.Label
    $ui.Detail.SetBounds(28, $y + 36, 464, 36); $ui.Detail.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
    $form.Controls.AddRange(@($ui.Bar, $ui.Detail))

    # The guide: ‹ › to flick through, and it moves on by itself every 12 seconds
    $card = New-Object System.Windows.Forms.Panel
    $card.SetBounds(28, $y + 84, 464, 136); $card.BackColor = [System.Drawing.Color]::White
    $card.BorderStyle = 'FixedSingle'
    $ui.CardTitle = New-Object System.Windows.Forms.Label
    $ui.CardTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10); $ui.CardTitle.SetBounds(14, 10, 430, 22)
    $ui.CardText = New-Object System.Windows.Forms.Label
    $ui.CardText.SetBounds(14, 36, 434, 64)
    $ui.CardCount = New-Object System.Windows.Forms.Label
    $ui.CardCount.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96); $ui.CardCount.SetBounds(14, 106, 200, 20)
    $back = New-Object System.Windows.Forms.Button
    $back.Text = [string][char]0x2039; $back.SetBounds(372, 102, 34, 26)
    $next = New-Object System.Windows.Forms.Button
    $next.Text = [string][char]0x203A; $next.SetBounds(412, 102, 34, 26)
    $card.Controls.AddRange(@($ui.CardTitle, $ui.CardText, $ui.CardCount, $back, $next))
    $form.Controls.Add($card)
    $script:GuideUi = $ui
    $script:GuideTimer = New-Object System.Windows.Forms.Timer
    $script:GuideTimer.Interval = 12000
    $script:GuideTimer.Add_Tick({ Show-GuideCard $script:GuideUi ($script:GuideUi.Card + 1) })
    # A click restarts the 12 seconds, so a card being read isn't swapped out under the reader
    $back.Add_Click({ Show-GuideCard $script:GuideUi ($script:GuideUi.Card - 1); $script:GuideTimer.Stop(); $script:GuideTimer.Start() })
    $next.Add_Click({ Show-GuideCard $script:GuideUi ($script:GuideUi.Card + 1); $script:GuideTimer.Stop(); $script:GuideTimer.Start() })
    Show-GuideCard $ui 0
    $script:GuideTimer.Start()
    $form.Show(); Step-Gui

    foreach ($item in $Items) {
        if ($script:DependenciesCancelled) { $ui.Status[$item] = 'Cancelled'; $ui.Rows[$item].Text = 'Cancelled'; $result.Failed += $item; continue }
        try {
            switch ($item) {
                'docker' { Install-Docker $ui $result }
                'ollama' { Install-Ollama $ui }
                'model'  { Install-Model $ui }
            }
        } catch {
            $result.Failed += $item
            $ui.Status[$item] = 'Not installed'
            $ui.Rows[$item].Text = 'Not installed'
            $ui.Detail.Text = "$($Dependencies[$item].Name): $($_.Exception.Message)"
            if ($_.Exception.Message -ne 'Cancelled') { $ui.Problems += "$($Dependencies[$item].Name): $($_.Exception.Message)" }
            Write-ComponentLog "$item`: not installed: $($_.Exception.Message)"
            $ui.Bar.Style = 'Continuous'; $ui.Bar.Value = 0
            Step-Gui
            if ($_.Exception.Message -ne 'Cancelled') { Start-Sleep -Seconds 3 }
        }
    }
    Clear-PendingDependencies $Items
    $script:GuideTimer.Stop()
    $script:DependenciesDone = $true
    $form.Close()

    $lines = @()
    foreach ($item in $Items) { $lines += "$($Dependencies[$item].Name): $($ui.Status[$item])" }
    if ($ui.Problems) { $lines += '', 'What went wrong:'; $lines += $ui.Problems }
    if ($result.Failed -contains 'docker') { $lines += '', 'Set Up Rowanholt in the Start menu offers Docker Desktop again.' }
    if ($result.Restart) { $lines += '', 'Restart Windows to finish turning on WSL 2, then open Rowanholt from the Start menu.' }
    $icon = if ($result.Failed) { 'Warning' } else { 'Information' }
    Show-Message ($lines -join "`n") 'OK' $icon | Out-Null
    return $result
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
    Add-DockerToPath
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'The docker command isn''t on PATH. Install Docker Desktop and retry.'
    }
    if (Test-Docker) { return }
    $desktop = Get-DockerDesktop
    if (-not $desktop) {
        throw "Docker isn't running and Docker Desktop isn't installed in $(Split-Path $DockerUserExe) or $(Split-Path $DockerMachineExe). Start Docker and retry."
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
    # What the MSI's options page ticked, before setup asks anything
    $pending = @(Get-PendingDependencies)
    if ($pending.Count) {
        $installed = Install-Dependencies $pending
        if ($installed.Restart) { exit 0 }
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

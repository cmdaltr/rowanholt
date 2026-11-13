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
# stretches the dialogs into blurred text on a scaled display. The console stays hidden: setup,
# installing components and starting the stack all happen in the Rowanholt window below
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

function Show-Message([string]$Text, [string]$Buttons = 'OK', [string]$Icon = 'Information') {
    Initialize-Gui
    return [string][System.Windows.Forms.MessageBox]::Show($Text, 'Rowanholt', $Buttons, $Icon)
}

# ── The Rowanholt window ──────────────────────────────────────────────────────
# Everything the launcher asks or shows happens in one window, as an installer's pages do: a
# white header with the icon, the page, then Back, Next and Cancel along the bottom. It's shown
# without blocking (Show, not ShowDialog), and the launcher pumps its messages (Step-Gui) while it
# waits for a click or works, so one window carries setup, downloads and the road to Rowanholt.
# Laid out at 96 DPI; AutoScaleMode Dpi scales it to the display's
$script:Wizard = $null

function Get-Wizard {
    if ($script:Wizard) { return $script:Wizard }
    Initialize-Gui
    $form = New-Object System.Windows.Forms.Form
    $form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.Text = 'Rowanholt'
    $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false
    $form.StartPosition = 'CenterScreen'
    $form.ClientSize = New-Object System.Drawing.Size(560, 460)
    $iconFile = Join-Path $AppDir 'desktop\icons\rowanholt.ico'
    # The PNG, not the .ico: Icon.ToBitmap garbles an .ico's PNG-compressed sizes into noise
    $pngFile = Join-Path $AppDir 'desktop\icons\rowanholt.png'
    if (Test-Path $iconFile) { $form.Icon = New-Object System.Drawing.Icon($iconFile) }

    $header = New-Object System.Windows.Forms.Panel
    $header.SetBounds(0, 0, 560, 64); $header.BackColor = [System.Drawing.Color]::White
    $title = New-Object System.Windows.Forms.Label
    $title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11); $title.SetBounds(20, 12, 470, 22)
    $sub = New-Object System.Windows.Forms.Label
    $sub.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90); $sub.SetBounds(20, 36, 470, 22)
    $header.Controls.AddRange(@($title, $sub))
    if (Test-Path $pngFile) {
        $picture = New-Object System.Windows.Forms.PictureBox
        $picture.Image = [System.Drawing.Image]::FromFile($pngFile)
        $picture.SizeMode = 'Zoom'; $picture.SetBounds(502, 10, 44, 44)
        $header.Controls.Add($picture)
    }
    $body = New-Object System.Windows.Forms.Panel
    $body.SetBounds(0, 65, 560, 340)
    $form.Controls.AddRange(@($header, $body))
    foreach ($y in 64, 405) {
        $line = New-Object System.Windows.Forms.Panel
        $line.SetBounds(0, $y, 560, 1); $line.BackColor = [System.Drawing.Color]::FromArgb(218, 218, 218)
        $form.Controls.Add($line)
    }
    $back = New-Object System.Windows.Forms.Button; $back.SetBounds(268, 418, 88, 28)
    $next = New-Object System.Windows.Forms.Button; $next.SetBounds(364, 418, 88, 28)
    $cancel = New-Object System.Windows.Forms.Button; $cancel.SetBounds(460, 418, 88, 28)
    $form.Controls.AddRange(@($back, $next, $cancel)); $form.AcceptButton = $next

    $script:Wizard = [pscustomobject]@{ Form = $form; Title = $title; Sub = $sub; Body = $body
                                        Back = $back; Next = $next; Cancel = $cancel; Action = $null; Closing = $false }
    $back.Add_Click({ $script:Wizard.Action = 'back' })
    $next.Add_Click({ $script:Wizard.Action = 'next' })
    $cancel.Add_Click({ $script:Wizard.Action = 'cancel' })
    # The window's own close button is Cancel; only Close-Wizard really closes it
    $form.Add_FormClosing({ param($s, $e) if (-not $script:Wizard.Closing) { $e.Cancel = $true; $script:Wizard.Action = 'cancel' } })
    $form.Add_Shown({ $this.Activate() })
    $form.Show(); Step-Gui
    return $script:Wizard
}

function Show-Page([string]$Title, [string]$Subtitle, [string]$Next = 'Next', [string]$Back = '', [string]$Cancel = 'Cancel') {
    # A fresh page: the header's text, the buttons it has ('' hides one), an empty body to fill
    $w = Get-Wizard
    if ($script:GuideTimer) { $script:GuideTimer.Stop() }
    $w.Body.Controls.Clear()
    $w.Title.Text = $Title; $w.Sub.Text = $Subtitle
    foreach ($b in @(@($w.Next, $Next), @($w.Back, $Back), @($w.Cancel, $Cancel))) {
        $b[0].Text = $b[1]; $b[0].Visible = [bool]$b[1]; $b[0].Enabled = $true
    }
    $w.Action = $null
    Step-Gui
    return $w.Body
}

function Wait-Page {
    # 'next', 'back' or 'cancel', once one is clicked
    $w = Get-Wizard
    $w.Action = $null
    while (-not $w.Action) { Start-Sleep -Milliseconds 40; Step-Gui }
    $action = $w.Action
    $w.Action = $null
    return $action
}

function Close-Wizard {
    if (-not $script:Wizard) { return }
    if ($script:GuideTimer) { $script:GuideTimer.Stop() }
    $script:Wizard.Closing = $true
    $script:Wizard.Form.Close()
    $script:Wizard = $null
    Step-Gui
}

function Add-Text($Body, [string]$Text, [int]$Y, [int]$Height = 20, [int]$X = 24, [int]$Width = 512, [switch]$Muted, [switch]$Bold) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text; $label.SetBounds($X, $Y, $Width, $Height)
    if ($Muted) { $label.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96) }
    if ($Bold) { $label.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9) }
    $Body.Controls.Add($label)
}

function New-ErrorLabel($Body, [int]$Y, [int]$Height = 36) {
    $label = New-Object System.Windows.Forms.Label
    $label.ForeColor = [System.Drawing.Color]::FromArgb(176, 32, 32); $label.SetBounds(24, $Y, 512, $Height)
    $Body.Controls.Add($label)
    return $label
}

function Show-Problem([string]$Title, [string]$Text) {
    # The end of the road, said in the window; the text can be selected and copied
    $body = Show-Page $Title 'Rowanholt stopped here.' -Next 'Close' -Cancel ''
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.BorderStyle = 'None'; $box.ScrollBars = 'Vertical'
    $box.BackColor = $script:Wizard.Form.BackColor; $box.SetBounds(24, 20, 512, 290); $box.Text = $Text
    $body.Controls.Add($box)
    Wait-Page | Out-Null
    Close-Wizard
}

function Show-ProgressPage([string]$Title, [string]$Subtitle, $Rows) {
    # Rows: an ordered key => name for each thing being installed, or none. Then a progress bar,
    # what's happening now, and the guide to read meanwhile. Cancel stays
    $body = Show-Page $Title $Subtitle -Next '' -Cancel 'Cancel'
    $ui = @{ Rows = @{}; Status = @{}; Problems = @() }
    $y = 18
    if ($Rows) {
        foreach ($key in $Rows.Keys) {
            Add-Text $body $Rows[$key] $y -Width 200 -Bold
            $status = New-Object System.Windows.Forms.Label
            $status.Text = 'Waiting'; $status.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
            $status.SetBounds(230, $y, 306, 20); $body.Controls.Add($status)
            $ui.Rows[$key] = $status
            $y += 26
        }
        $y += 6
    }
    $ui.Bar = New-Object System.Windows.Forms.ProgressBar
    $ui.Bar.SetBounds(24, $y, 512, 18); $ui.Bar.Maximum = 1000; $ui.Bar.MarqueeAnimationSpeed = 30; $ui.Bar.Style = 'Marquee'
    $ui.Detail = New-Object System.Windows.Forms.Label
    $ui.Detail.SetBounds(24, $y + 24, 512, 36); $ui.Detail.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
    $body.Controls.AddRange(@($ui.Bar, $ui.Detail))
    Add-GuideCard $body ($y + 68)
    Step-Gui
    return $ui
}

function Set-Progress($Ui, [string]$Text, [double]$Fraction = -1) {
    $Ui.Detail.Text = $Text
    if ($Fraction -lt 0) { $Ui.Bar.Style = 'Marquee' } else {
        $Ui.Bar.Style = 'Continuous'; $Ui.Bar.Value = [int][math]::Min(1000, 1000 * $Fraction)
    }
    Step-Gui
    Assert-NotCancelled
}

function Write-Step([string]$Text) {
    # A line of what's happening: in the window when it's open, else the console (-Stop)
    if ($script:Progress) { $script:Progress.Detail.Text = $Text; Step-Gui } else { Write-Host $Text }
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

# Where "On this PC" unpacks Rowanholt: always here, not a choice. The containers write into it
# (symbols\, the source's caches), so a folder OneDrive syncs (Desktop, Documents) or a network drive
# would fight them, and the launcher and uninstall.ps1 find it by the path setup saved, so a copy
# moved later is set up afresh and the old one left behind. %USERPROFILE% itself isn't synced.
# The databases are Docker volumes named after the compose project, wherever this folder is
$AppCopy = Join-Path $env:USERPROFILE 'Rowanholt'

function Select-Mode([int]$Current = 0) {
    # Where Rowanholt runs: 0 here (unpacked), 1 a copy already here, 2 a team server; $null cancelled
    $body = Show-Page 'Where should Rowanholt run?' 'You can change this later with Set Up Rowanholt in the Start menu.'
    $options = @(
        @('On this PC', "Rowanholt $(Get-AppVersion) runs here in Docker Desktop. Its files go in $AppCopy; your evidence stays where it is."),
        @('From a copy I already have', 'A Rowanholt folder that is already on this PC, such as a git clone. It runs as it is and is never overwritten.'),
        @("On my team's server", "Opens your team's Rowanholt in a window. Nothing else is installed or run on this PC.")
    )
    $bold = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
    $radios = @()
    for ($i = 0; $i -lt $options.Count; $i++) {
        $y = 22 + 76 * $i
        $radio = New-Object System.Windows.Forms.RadioButton
        $radio.Text = $options[$i][0]; $radio.Font = $bold
        $radio.SetBounds(24, $y, 500, 24); $radio.Checked = ($i -eq $Current)
        $body.Controls.Add($radio)
        Add-Text $body $options[$i][1] ($y + 24) -X 44 -Width 492 -Height 40 -Muted
        $radios += $radio
    }
    if ((Wait-Page) -ne 'next') { return $null }
    for ($i = 0; $i -lt $radios.Count; $i++) { if ($radios[$i].Checked) { return $i } }
    return 0
}

function Select-Folder([string]$Description, [string]$Start) {
    # Explorer's own picker, through OpenFileDialog: .NET Framework's FolderBrowserDialog is
    # Windows XP's tree. The file name is a placeholder; the folder it's in is the answer
    Initialize-Gui
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Description
    $dialog.ValidateNames = $false; $dialog.CheckFileExists = $false; $dialog.CheckPathExists = $true
    $dialog.Filter = 'Folders|*.folder'
    $dialog.FileName = 'Select this folder'
    if ($Start -and (Test-Path $Start)) { $dialog.InitialDirectory = $Start }
    $owner = if ($script:Wizard) { $script:Wizard.Form } else { $null }
    if ($dialog.ShowDialog($owner) -ne 'OK') { return $null }
    return Split-Path $dialog.FileName
}

function Set-Server {
    # 'done' once the address is saved, 'back' for the previous page
    $body = Show-Page "Your team's Rowanholt server" 'Rowanholt opens it in its own window.' -Back 'Back'
    Add-Text $body 'Server address' 20 -Bold
    $box = New-Object System.Windows.Forms.TextBox
    $box.SetBounds(24, 44, 512, 24); $box.Text = (Get-SavedServer)
    $body.Controls.Add($box)
    Add-Text $body ("For example rowanholt.example.org; https is assumed. If Edge warns about the server's " +
        "certificate, ask its admin for the root certificate.") 80 -Height 40 -Muted
    $problem = New-ErrorLabel $body 128
    $box.Focus() | Out-Null
    while ($true) {
        $action = Wait-Page
        if ($action -eq 'back') { return 'back' }
        if ($action -ne 'next') { exit 1 }
        $server = ConvertTo-ServerUrl $box.Text
        if ($server) {
            Set-Content -Path $ServerFile -Value $server -Encoding ASCII
            return 'done'
        }
        $problem.Text = "'$($box.Text)' isn't a server address: for example rowanholt.example.org (https only)."
    }
}

function Select-ExistingCopy([string]$Start) {
    # The folder of a copy already here, or $null for the previous page
    $body = Show-Page 'Your Rowanholt folder' 'A copy of Rowanholt already on this PC, such as a git clone.' -Back 'Back'
    Add-Text $body 'Folder' 20 -Bold
    $script:CopyBox = New-Object System.Windows.Forms.TextBox
    $script:CopyBox.SetBounds(24, 44, 420, 24); $script:CopyBox.Text = $Start
    $browse = New-Object System.Windows.Forms.Button
    $browse.Text = 'Browse...'; $browse.SetBounds(452, 42, 84, 28)
    $browse.Add_Click({
        $folder = Select-Folder 'Choose your Rowanholt folder' $(if ($script:CopyBox.Text) { $script:CopyBox.Text } else { $env:USERPROFILE })
        if ($folder) { $script:CopyBox.Text = $folder }
    })
    $body.Controls.AddRange(@($script:CopyBox, $browse))
    Add-Text $body ("Rowanholt runs that folder as it is and never overwrites it, so a git clone stays yours to " +
        'update with git pull.') 80 -Height 40 -Muted
    $problem = New-ErrorLabel $body 128
    while ($true) {
        $action = Wait-Page
        if ($action -eq 'back') { return $null }
        if ($action -ne 'next') { exit 1 }
        $dir = $script:CopyBox.Text.Trim()
        if (Test-Copy $dir) { return $dir }
        $problem.Text = "That folder doesn't look like Rowanholt: there's no rowanholt launcher and docker-compose.yml in it."
    }
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
    # Docker Desktop and the WSL 2 it runs on: a page offering whatever's missing. A Docker that's
    # already answering is enough, whatever it runs on
    Add-DockerToPath
    if ((Get-Command docker -ErrorAction SilentlyContinue) -and (Test-Docker)) { return }
    $missing = @()
    if (-not (Test-WslReady)) { $missing += 'wsl' }
    if (-not (Test-DockerInstalled)) { $missing += 'docker' }
    if (-not $missing) { return }
    $names = ($missing | ForEach-Object { $Dependencies[$_].Name }) -join ' and '
    $verb = if ($missing.Count -gt 1) { 'are' } else { 'is' }
    $body = Show-Page "$names $verb needed" 'Rowanholt runs as a set of containers in Docker Desktop, on WSL 2.' -Next 'Install'
    $text = @()
    if ($missing -contains 'wsl') {
        $text += ("WSL 2 isn't installed. Rowanholt can install it: Microsoft's latest release from GitHub, checked " +
                  "against Microsoft's signature. It needs administrator rights, and a restart if Windows' WSL features were off.")
    }
    if ($missing -contains 'docker') {
        $text += ("Docker Desktop isn't installed. Rowanholt can install it: downloaded from docker.com, checked against " +
                  "Docker's signature and installed for you alone, without administrator rights.")
    }
    Add-Text $body ($text -join "`n`n") 20 -Height 120
    if ($missing -contains 'docker') {
        Add-Text $body ("Installing Docker Desktop accepts Docker's Subscription Service Agreement: free for personal use, " +
            'education and small businesses; larger organisations need a paid subscription.') 150 -Height 44 -Muted
    }
    if ((Wait-Page) -ne 'next') { Close-Wizard; exit 1 }
    $result = Install-Dependencies $missing
    if ($result.Restart -or $result.Failed) { Close-Wizard; exit 1 }
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
# In the order they run: a clean reinstall removes first, then WSL 2 before the Docker Desktop that
# needs it. Value is the HKCU value msiexec's properties queue each under (INSTALLDOCKER=1 queues
# WSL 2 with Docker Desktop; CleanFirst both removals); setup's What Rowanholt needs page picks them too
$Dependencies = [ordered]@{
    cleandocker = @{ Value = 'CleanFirst'; Name = 'Removing Docker Desktop and WSL' }
    cleanai     = @{ Value = 'CleanFirst'; Name = 'Removing Ollama and its models' }
    wsl         = @{ Value = 'InstallDocker'; Name = 'WSL 2' }
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

function Add-GuideCard($Body, [int]$Y) {
    # ‹ › to flick through, and it moves on by itself every 12 seconds; a click restarts the 12
    # seconds, so a card being read isn't swapped out under the reader
    $ui = @{}
    $card = New-Object System.Windows.Forms.Panel
    $card.SetBounds(24, $Y, 512, [math]::Min(136, 330 - $Y)); $card.BackColor = [System.Drawing.Color]::White
    $card.BorderStyle = 'FixedSingle'
    $ui.CardTitle = New-Object System.Windows.Forms.Label
    $ui.CardTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10); $ui.CardTitle.SetBounds(14, 10, 480, 22)
    $ui.CardText = New-Object System.Windows.Forms.Label
    $ui.CardText.SetBounds(14, 36, 482, 62)
    $ui.CardCount = New-Object System.Windows.Forms.Label
    $ui.CardCount.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96); $ui.CardCount.SetBounds(14, 104, 200, 20)
    $back = New-Object System.Windows.Forms.Button
    $back.Text = [string][char]0x2039; $back.SetBounds(420, 100, 34, 26)
    $next = New-Object System.Windows.Forms.Button
    $next.Text = [string][char]0x203A; $next.SetBounds(460, 100, 34, 26)
    $card.Controls.AddRange(@($ui.CardTitle, $ui.CardText, $ui.CardCount, $back, $next))
    $Body.Controls.Add($card)
    $script:GuideUi = $ui
    if (-not $script:GuideTimer) {
        $script:GuideTimer = New-Object System.Windows.Forms.Timer
        $script:GuideTimer.Interval = 12000
        $script:GuideTimer.Add_Tick({ Show-GuideCard $script:GuideUi ($script:GuideUi.Card + 1) })
    }
    $back.Add_Click({ Show-GuideCard $script:GuideUi ($script:GuideUi.Card - 1); $script:GuideTimer.Stop(); $script:GuideTimer.Start() })
    $next.Add_Click({ Show-GuideCard $script:GuideUi ($script:GuideUi.Card + 1); $script:GuideTimer.Stop(); $script:GuideTimer.Start() })
    Show-GuideCard $ui (Get-Random -Maximum $GuideCards.Count)
    $script:GuideTimer.Stop(); $script:GuideTimer.Start()
}

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

function Test-WslPackage {
    # Since WSL 2.0 Windows' own wsl.exe is a stub: the kernel and the service are a package of their
    # own (Microsoft's MSI, or the Store's), installed into Program Files\WSL
    return Test-Path (Join-Path $env:ProgramFiles 'WSL\wsl.exe')
}

function Test-WslReady { return (Test-WslFeatures) -and (Test-WslPackage) }

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

function Assert-NotCancelled { if ($script:Wizard -and $script:Wizard.Action -eq 'cancel') { throw 'Cancelled' } }

function Write-ComponentLog([string]$Line) {
    # What happened, for after the window has gone: %LOCALAPPDATA%\Rowanholt\components.log
    Add-Content -Path (Join-Path $State 'components.log') -Value "$((Get-Date).ToString('s')) $Line" -ErrorAction SilentlyContinue
}

function Set-Status($Ui, [string]$Item, [string]$Text, [double]$Fraction = -1) {
    # Kept beside the label, for the summary page and the log
    if ($Ui.Status[$Item] -ne $Text -and $Text -notlike 'Downloading *') { Write-ComponentLog "$Item`: $Text" }
    $Ui.Status[$Item] = $Text
    $Ui.Rows[$Item].Text = $Text
    Set-Progress $Ui "$($Dependencies[$Item].Name): $Text" $Fraction
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

function Invoke-Elevated([string[]]$Lines, [string]$What) {
    # Lines of PowerShell run as administrator under one UAC prompt, from a script removed after.
    # Returns its exit code; a UAC prompt answered no is an error
    $elevated = Join-Path $env:TEMP 'rowanholt-elevated.ps1'
    Set-Content -Path $elevated -Value ($Lines -join "`r`n") -Encoding ASCII
    try {
        $p = Start-Process (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Hidden -PassThru `
            -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$elevated`""
    } catch {
        Remove-Item $elevated -ErrorAction SilentlyContinue
        throw "$What needs administrator rights, and Windows was told no"
    }
    $code = Wait-Exit $p
    Remove-Item $elevated -ErrorAction SilentlyContinue
    return $code
}

function Get-WslProductCode {
    # The WSL package's MSI product code, from its Settings > Apps entry
    $key = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq 'Windows Subsystem for Linux' } |
        Select-Object -First 1
    if ($key) { return $key.PSChildName }
    return $null
}

function Remove-Docker($Ui) {
    # Docker Desktop with every container, image and volume it holds, and the WSL package with
    # Docker's distributions. Windows' WSL features stay on: off and on again is two restarts for nothing
    Set-Status $Ui 'cleandocker' 'Stopping Docker Desktop'
    Get-Process -Name 'Docker Desktop', 'com.docker.backend', 'com.docker.build' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-WslPackage) {
        Set-Status $Ui 'cleandocker' "Removing Docker Desktop's WSL distributions"
        foreach ($distro in 'docker-desktop', 'docker-desktop-data') {
            & (Join-Path $env:ProgramFiles 'WSL\wsl.exe') --unregister $distro 2>&1 | Out-Null
        }
    }
    $userInstaller = Join-Path (Split-Path $DockerUserExe) 'Docker Desktop Installer.exe'
    if (Test-Path $userInstaller) {
        Set-Status $Ui 'cleandocker' 'Removing Docker Desktop'
        Wait-Exit (Start-Process $userInstaller -PassThru -ArgumentList 'uninstall', '--quiet') | Out-Null
    }
    $lines = @()
    $machineInstaller = Join-Path (Split-Path $DockerMachineExe) 'Docker Desktop Installer.exe'
    if (Test-Path $machineInstaller) { $lines += "Start-Process '$machineInstaller' -ArgumentList 'uninstall', '--quiet' -Wait" }
    $wsl = Get-WslProductCode
    if ($wsl) { $lines += "Start-Process msiexec.exe -ArgumentList '/x', '$wsl', '/quiet', '/norestart' -Wait" }
    if ($lines) {
        Set-Status $Ui 'cleandocker' 'Removing WSL (Windows asks for administrator rights)'
        Invoke-Elevated $lines 'Removing WSL' | Out-Null
    }
    $left = @()
    if (Get-DockerDesktop) { $left += 'Docker Desktop' }
    if (Test-WslPackage) { $left += 'WSL' }
    if ($left) { throw "$($left -join ' and ') couldn't be removed; remove it from Settings > Apps and open Rowanholt again" }
    Set-Status $Ui 'cleandocker' 'Removed' 1
}

function Remove-Ollama($Ui) {
    Set-Status $Ui 'cleanai' 'Stopping Ollama'
    Get-Process -Name 'ollama app', 'ollama' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $uninstaller = Get-ChildItem (Split-Path $OllamaExe) -Filter 'unins*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($uninstaller) {
        Set-Status $Ui 'cleanai' 'Removing Ollama'
        Wait-Exit (Start-Process $uninstaller.FullName -PassThru -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') | Out-Null
    }
    Remove-Item -Recurse -Force (Join-Path $env:USERPROFILE '.ollama'), (Join-Path $env:LOCALAPPDATA 'Ollama') -ErrorAction SilentlyContinue
    if (Test-Path $OllamaExe) { throw "Ollama couldn't be removed; remove it from Settings > Apps and open Rowanholt again" }
    Set-Status $Ui 'cleanai' 'Removed' 1
}

function Get-InstalledVersion([string]$Root, [string]$DisplayName) {
    # A Settings > Apps entry's version, or '' when it isn't installed
    $key = Get-ChildItem $Root -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -eq $DisplayName } | Select-Object -First 1
    if ($key) { return [string]$key.DisplayVersion }
    return ''
}

function Get-ComponentState {
    # What's on this PC now, for the What Rowanholt needs page
    $uninstall = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $docker = Get-InstalledVersion "HKCU:\$uninstall" 'Docker Desktop'
    if (-not $docker) { $docker = Get-InstalledVersion "HKLM:\$uninstall" 'Docker Desktop' }
    $model = Join-Path $env:USERPROFILE ('.ollama\models\manifests\registry.ollama.ai\library\' + ($SmithModel -replace ':', '\'))
    return @{
        Docker = [bool](Get-DockerDesktop); DockerVersion = $docker
        Wsl = (Test-WslReady); WslVersion = (Get-InstalledVersion "HKLM:\$uninstall" 'Windows Subsystem for Linux')
        Ollama = (Test-Path $OllamaExe)
        OllamaVersion = $(if (Test-Path $OllamaExe) { (Get-Item $OllamaExe).VersionInfo.ProductVersion } else { '' })
        Model = (Test-Path $model)
    }
}

function Select-Components {
    # What Rowanholt needs: what's here and what to do with each. Returns the items to run, in order,
    # or 'back'. A clean reinstall removes first, then installs afresh
    $state = Get-ComponentState
    $body = Show-Page 'What Rowanholt needs' "What's on this PC, and what to do with it." -Back 'Back'
    $green = [System.Drawing.Color]::FromArgb(24, 120, 60)

    # Docker Desktop and WSL 2
    Add-Text $body 'Docker Desktop and WSL 2' 14 -Width 230 -Bold
    $parts = @()
    $parts += $(if ($state.Docker) { "Docker Desktop $($state.DockerVersion)".Trim() } else { 'Docker Desktop missing' })
    $parts += $(if ($state.Wsl) { "WSL $($state.WslVersion)".Trim() } else { 'WSL missing' })
    $dockerStatus = New-Object System.Windows.Forms.Label
    $dockerStatus.Text = $parts -join ', '; $dockerStatus.TextAlign = 'TopRight'; $dockerStatus.SetBounds(256, 14, 280, 20)
    if ($state.Docker -and $state.Wsl) { $dockerStatus.ForeColor = $green }
    $body.Controls.Add($dockerStatus)
    Add-Text $body "Runs Rowanholt's containers: needed to run it on this PC." 36 -Muted
    $dockerGroup = New-Object System.Windows.Forms.Panel
    $dockerGroup.SetBounds(24, 58, 512, 28)
    $dockerKeep = New-Object System.Windows.Forms.RadioButton
    $dockerKeep.Text = $(if ($state.Docker -and $state.Wsl) { 'Keep it' } elseif ($state.Docker -or $state.Wsl) { "Install what's missing" } else { 'Install' })
    $dockerKeep.SetBounds(0, 2, 200, 24); $dockerKeep.Checked = $true
    $dockerClean = New-Object System.Windows.Forms.RadioButton
    $dockerClean.Text = 'Reinstall clean'; $dockerClean.SetBounds(220, 2, 200, 24)
    $dockerGroup.Controls.Add($dockerKeep)
    if ($state.Docker -or $state.Wsl) { $dockerGroup.Controls.Add($dockerClean) }
    $body.Controls.Add($dockerGroup)

    # Smith's AI answers
    Add-Text $body "Smith's AI answers (optional)" 100 -Width 230 -Bold
    $aiStatus = New-Object System.Windows.Forms.Label
    $aiStatus.Text = $(if ($state.Ollama -and $state.Model) { "Ollama $($state.OllamaVersion), Smith's model".Trim() } elseif ($state.Ollama) { "Ollama $($state.OllamaVersion); model missing" } else { 'Not installed' })
    $aiStatus.TextAlign = 'TopRight'; $aiStatus.SetBounds(256, 100, 280, 20)
    if ($state.Ollama -and $state.Model) { $aiStatus.ForeColor = $green }
    $body.Controls.Add($aiStatus)
    Add-Text $body ("Ollama runs Smith's model, Meta's Llama 3.2 (3B), on this PC, so nothing leaves it: about 3 GB. " +
        'Without them, Smith answers fixed questions from the case files.') 122 -Height 36 -Muted
    $aiGroup = New-Object System.Windows.Forms.Panel
    $aiGroup.SetBounds(24, 160, 512, 28)
    $aiKeep = New-Object System.Windows.Forms.RadioButton
    $aiKeep.SetBounds(0, 2, 200, 24); $aiKeep.Checked = $true
    $aiClean = New-Object System.Windows.Forms.RadioButton
    $aiClean.Text = 'Reinstall clean'; $aiClean.SetBounds(220, 2, 150, 24)
    $aiSkip = New-Object System.Windows.Forms.RadioButton
    $aiSkip.SetBounds(380, 2, 130, 24)
    if ($state.Ollama -and $state.Model) {
        $aiKeep.Text = 'Keep it'; $aiGroup.Controls.AddRange(@($aiKeep, $aiClean))
    } elseif ($state.Ollama) {
        $aiKeep.Text = "Install the model"; $aiSkip.Text = 'Leave it'; $aiGroup.Controls.AddRange(@($aiKeep, $aiClean, $aiSkip))
    } else {
        $aiKeep.Text = 'Install'; $aiSkip.Text = 'Not now'; $aiKeep.Checked = $false; $aiSkip.Checked = $true
        $aiSkip.SetBounds(220, 2, 150, 24); $aiGroup.Controls.AddRange(@($aiKeep, $aiSkip))
    }
    $body.Controls.Add($aiGroup)

    Add-Text $body ('Reinstall clean removes the installation and everything it holds, then installs it afresh. For ' +
        "Docker Desktop that's every container, image and volume on this PC, for every app, Rowanholt's databases " +
        "and cases among them; for Ollama, its models. Evidence folders and Rowanholt's own folder are left alone.") 202 -Height 66
    Add-Text $body ("Installing Docker Desktop accepts Docker's Subscription Service Agreement: free for personal use, " +
        'education and small businesses; larger organisations need a paid subscription.') 274 -Height 40 -Muted

    $action = Wait-Page
    if ($action -eq 'back') { return 'back' }
    if ($action -ne 'next') { Close-Wizard; exit 1 }
    $items = @()
    if ($dockerClean.Checked) { $items += 'cleandocker' }
    if ($aiClean.Checked) { $items += 'cleanai' }
    if ($dockerClean.Checked -or -not $state.Wsl) { $items += 'wsl' }
    if ($dockerClean.Checked -or -not $state.Docker) { $items += 'docker' }
    if ($aiClean.Checked -or ($aiKeep.Checked -and -not $state.Ollama)) { $items += 'ollama' }
    if ($aiClean.Checked -or ($aiKeep.Checked -and -not $state.Model)) { $items += 'model' }
    return ,$items
}

function Register-Resume {
    # The next sign-in carries on where this one stopped: RunOnce runs it once, then forgets it
    $command = "`"$(Join-Path $PSHOME 'powershell.exe')`" -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Rowanholt' -Value $command
}

function Install-Wsl($Ui, $Result) {
    if (Test-WslReady) { Set-Status $Ui 'wsl' 'Already installed' 1; return }
    if (-not (Test-Virtualisation)) {
        throw ("this PC's processor virtualisation is off, and WSL 2 needs it: turn on VT-x / AMD-V (SVM) in the " +
               "firmware settings, or for a virtual machine, nested virtualisation in its hypervisor")
    }
    $features = -not (Test-WslFeatures)
    $msi = $null
    if (-not (Test-WslPackage)) {
        Set-Status $Ui 'wsl' 'Finding the latest WSL release'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/WSL/releases/latest' -Headers @{ 'User-Agent' = 'Rowanholt' } -TimeoutSec 20
        $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
        $asset = @($release.assets | Where-Object { $_.name -match "^wsl\..+\.$arch\.msi$" })[0]
        if (-not $asset) { throw "WSL's release $($release.tag_name) has no $arch installer" }
        $msi = Join-Path $env:TEMP $asset.name
        Save-Download $Ui 'wsl' $asset.browser_download_url $msi
        Set-Status $Ui 'wsl' 'Checking the signature'
        Assert-Signed $msi 'Microsoft Corporation'
    }
    # The features and the package under one UAC prompt: a script run elevated, then removed
    Set-Status $Ui 'wsl' 'Installing (Windows asks for administrator rights)'
    $lines = @()
    if ($features) {
        $lines += 'foreach ($f in ''Microsoft-Windows-Subsystem-Linux'', ''VirtualMachinePlatform'') { & dism.exe /online /enable-feature /featurename:$f /all /norestart /quiet; if ($LASTEXITCODE -notin 0, 3010) { exit $LASTEXITCODE } }'
    }
    if ($msi) {
        $lines += "`$p = Start-Process msiexec.exe -ArgumentList '/i', '`"$msi`"', '/quiet', '/norestart' -Wait -PassThru; if (`$p.ExitCode -notin 0, 3010) { exit `$p.ExitCode }"
    }
    try { $code = Invoke-Elevated $lines 'Installing WSL 2' }
    finally { if ($msi) { Remove-Item $msi -ErrorAction SilentlyContinue } }
    if (-not (Test-WslReady)) { throw "installing WSL 2 failed (exit $code)" }
    if ($features) { $Result.Restart = $true }
    Set-Status $Ui 'wsl' $(if ($features) { 'Installed: restart Windows to finish' } else { 'Installed' }) 1
}

function Install-Docker($Ui, $Result) {
    if (Get-DockerDesktop) { Set-Status $Ui 'docker' 'Already installed' 1; return }
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
    Set-Status $Ui 'docker' 'Installed' 1
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
    # On one page, in order; one failing doesn't stop the rest. Then a summary page. Returns
    # @{ Failed; Restart }, Restart when WSL 2 was just turned on
    $result = @{ Failed = @(); Restart = $false }
    $rows = [ordered]@{}
    foreach ($item in $Items) { $rows[$item] = $Dependencies[$item].Name }
    $ui = Show-ProgressPage 'Finishing the install' 'Installing what you chose, straight from Docker and Ollama.' $rows
    Write-ComponentLog "Installing: $($Items -join ', ')"
    $cancelled = $false
    foreach ($item in $Items) {
        if ($cancelled) { $ui.Status[$item] = 'Cancelled'; $ui.Rows[$item].Text = 'Cancelled'; $result.Failed += $item; continue }
        try {
            switch ($item) {
                'cleandocker' { Remove-Docker $ui }
                'cleanai'     { Remove-Ollama $ui }
                'wsl'    { Install-Wsl $ui $result }
                'docker' { Install-Docker $ui $result }
                'ollama' { Install-Ollama $ui }
                'model'  { Install-Model $ui }
            }
        } catch {
            $result.Failed += $item
            $message = $_.Exception.Message
            $cancelled = $message -eq 'Cancelled'
            $ui.Status[$item] = if ($cancelled) { 'Cancelled' } else { 'Not installed' }
            $ui.Rows[$item].Text = $ui.Status[$item]
            if (-not $cancelled) { $ui.Problems += "$($Dependencies[$item].Name): $message" }
            Write-ComponentLog "$item`: not installed: $message"
            $script:Wizard.Action = $null
        }
    }
    Clear-PendingDependencies $Items

    $title = if ($result.Failed) { 'Not everything was installed' } else { 'Installed' }
    $subtitle = if ($result.Restart) { 'Windows needs a restart to finish turning on WSL 2.' } else { 'Rowanholt carries on from here.' }
    if ($result.Restart) {
        Register-Resume
        $body = Show-Page $title $subtitle -Next 'Restart now' -Back 'Later' -Cancel ''
    } else {
        $body = Show-Page $title $subtitle -Next 'Continue' -Cancel ''
    }
    $y = 20
    foreach ($item in $Items) {
        Add-Text $body $Dependencies[$item].Name $y -Width 200 -Bold
        Add-Text $body $ui.Status[$item] $y -X 230 -Width 306
        $y += 26
    }
    $notes = @()
    if ($ui.Problems) { $notes += 'What went wrong:'; $notes += $ui.Problems; $notes += '' }
    if ($result.Failed -contains 'docker') { $notes += 'Set Up Rowanholt in the Start menu offers Docker Desktop again.' }
    if ($result.Restart) { $notes += 'Rowanholt carries on by itself when you next sign in after the restart.' }
    $notes += "A record of what happened is in $(Join-Path $State 'components.log')."
    Add-Text $body ($notes -join "`n") ($y + 12) -Height (300 - $y) -Muted
    $action = Wait-Page
    if ($result.Restart) {
        Close-Wizard
        if ($action -eq 'next') { & shutdown.exe /r /t 5 /c 'Restarting to finish installing WSL 2 for Rowanholt' }
    }
    return $result
}

function Expand-Bundle([string]$Target) {
    New-Item -ItemType Directory -Force -Path $Target | Out-Null
    $script:Progress = Show-ProgressPage 'Setting up Rowanholt' "Copying Rowanholt $(Get-AppVersion) into $Target." $null
    Set-Progress $script:Progress 'Unpacking the files'
    # Windows 10 and 11 ship bsdtar; .env, docker-compose.local.yml and cases aren't in the tarball, so they're kept
    $tar = Start-Process (Join-Path $env:SystemRoot 'System32\tar.exe') -WindowStyle Hidden -PassThru `
        -ArgumentList '-xzf', "`"$Bundled`"", '-C', "`"$Target`"", '--strip-components', '1'
    $code = Wait-Exit $tar
    if (-not (Test-Copy $Target)) { throw "Couldn't unpack Rowanholt into $Target (tar exited with status $code)" }
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

function Read-Evidence([string]$Dir) {
    # The folders setup mounted last time, to start the list from
    $file = Join-Path $Dir 'docker-compose.local.yml'
    if (-not (Test-Path $file)) { return @() }
    return @(Get-Content $file | Where-Object { $_ -match '^\s+source: "(.+)"$' } | ForEach-Object { $Matches[1].Replace('/', '\') } | Select-Object -Unique)
}

function Add-EvidenceRow([string]$Folder) {
    # Name (the key) is the Windows folder; the second column is the containers' path for it
    $row = New-Object System.Windows.Forms.ListViewItem($Folder)
    $row.Name = $Folder
    [void]$row.SubItems.Add((ConvertTo-ContainerPath $Folder))
    [void]$script:EvidenceList.Items.Add($row)
}

function Select-Evidence([string[]]$Current) {
    # @{ Action = 'next' or 'back'; Folders }
    $body = Show-Page 'Evidence folders' 'Optional: folders of disk images, memory dumps and Gandalf archives.' -Back 'Back'
    Add-Text $body ("Choose folders on this PC that hold evidence. Rowanholt's containers run in WSL 2, the small " +
        'Linux virtual machine inside Docker Desktop, and can see only the folders listed here. Inside Rowanholt ' +
        "each has a Linux path, shown beside it: that's the path to give Elrond. The web app can only read them; " +
        "Elrond's worker can also write there.") 14 -Height 64
    # Two columns: the Windows folder you chose, and where the containers see it
    $script:EvidenceList = New-Object System.Windows.Forms.ListView
    $script:EvidenceList.View = 'Details'; $script:EvidenceList.FullRowSelect = $true
    $script:EvidenceList.HeaderStyle = 'Nonclickable'; $script:EvidenceList.MultiSelect = $false
    $script:EvidenceList.SetBounds(24, 86, 420, 140)
    [void]$script:EvidenceList.Columns.Add('Folder on this PC', 200)
    [void]$script:EvidenceList.Columns.Add('In Rowanholt', 196)
    foreach ($folder in $Current) { Add-EvidenceRow $folder }
    $add = New-Object System.Windows.Forms.Button
    $add.Text = 'Add...'; $add.SetBounds(452, 86, 84, 28)
    $remove = New-Object System.Windows.Forms.Button
    $remove.Text = 'Remove'; $remove.SetBounds(452, 120, 84, 28)
    $body.Controls.AddRange(@($script:EvidenceList, $add, $remove))
    $script:EvidenceProblem = New-ErrorLabel $body 286 40
    $add.Add_Click({
        $folder = Select-Folder 'Choose a folder of evidence' ''
        if (-not $folder) { return }
        if ($folder -notmatch '^[A-Za-z]:\\') {
            $script:EvidenceProblem.Text = 'Choose a folder on a lettered drive (C:\..., D:\...): Docker Desktop shares drives, not network paths.'
        } elseif (-not $script:EvidenceList.Items.ContainsKey($folder)) {
            Add-EvidenceRow $folder; $script:EvidenceProblem.Text = ''
        }
    })
    $remove.Add_Click({ foreach ($row in @($script:EvidenceList.SelectedItems)) { $script:EvidenceList.Items.Remove($row) } })
    Add-Text $body ('Anything not listed, other drives and external disks included, is invisible to Rowanholt. ' +
        'Change the list any time with Set Up Rowanholt in the Start menu.') 236 -Height 40 -Muted
    $action = Wait-Page
    if ($action -ne 'next' -and $action -ne 'back') { exit 1 }
    return @{ Action = $action; Folders = @($script:EvidenceList.Items | ForEach-Object { $_.Name }) }
}

function Invoke-Setup {
    # Returns the copy to run, or $null when it's a server now. Back goes to the previous page
    $saved = if (Test-Path $RootFile) { (Get-Content $RootFile -Raw).Trim() } else { '' }
    $current = if (Get-SavedServer) { 2 } elseif ($saved -and $saved -ne $AppCopy) { 1 } else { 0 }
    while ($true) {
        $mode = Select-Mode $current
        if ($null -eq $mode) { exit 1 }
        $current = $mode
        if ($mode -eq 2) {
            if ((Set-Server) -eq 'back') { continue }
            return $null
        }
        if ($mode -eq 1) {
            $dir = Select-ExistingCopy $(if ($saved -ne $AppCopy) { $saved } else { '' })
            if (-not $dir) { continue }
        } else {
            $dir = $AppCopy
            if ((Test-Path $dir) -and -not (Test-Copy $dir)) {
                Show-Problem "Rowanholt can't use its folder" "$dir already exists and isn't Rowanholt. Rename or move that folder, then open Rowanholt again."
                exit 1
            }
        }
        $items = Select-Components
        if ($items -eq 'back') { continue }
        if ($items.Count) {
            $result = Install-Dependencies $items
            if ($result.Restart) { exit 0 }
            if (-not (Test-DockerInstalled) -or -not (Test-WslReady)) { Close-Wizard; exit 1 }
        }
        Add-DockerToPath
        $evidence = Select-Evidence (Read-Evidence $dir)
        if ($evidence.Action -eq 'back') { continue }
        Remove-Item $ServerFile -ErrorAction SilentlyContinue
        # Unpack into a new folder, or over a copy setup unpacked before (never a git clone)
        $unpacked = (Test-Copy $dir) -and (Test-Path (Join-Path $dir '.rowanholt-version')) -and -not (Test-Path (Join-Path $dir '.git'))
        if ($mode -eq 0 -and (-not (Test-Path $dir) -or $unpacked)) { Expand-Bundle $dir }
        Write-Evidence $dir $evidence.Folders
        Set-Content -Path $RootFile -Value $dir -Encoding UTF8
        return $dir
    }
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
    $old = (Get-Content $versionFile -Raw).Trim()
    if ($old -eq (Get-AppVersion)) { return }
    $body = Show-Page 'Update Rowanholt' "Rowanholt $(Get-AppVersion) is installed; the copy in $Root is $old." -Next 'Update' -Back 'Not now' -Cancel ''
    Add-Text $body ("Updating replaces Rowanholt's files in that folder. Your .env, evidence folders and cases are " +
        'kept. The images are rebuilt on this start, which takes a while.') 20 -Height 44
    if ((Wait-Page) -eq 'next') { Expand-Bundle $Root }
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
    Write-Step 'Starting Docker Desktop'
    # Its own CLI starts the engine without the dashboard; older versions don't have it
    $ErrorActionPreference = 'Continue'
    docker desktop start --detach *> $null
    if ($LASTEXITCODE -ne 0) { Start-Process $desktop -WindowStyle Hidden }
    $ErrorActionPreference = 'Stop'
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Seconds 2
        if ($script:Journey) { Show-Journey $script:Journey }
        if (Test-Docker) { Write-Step 'Docker started'; return }
    }
    if (-not (Test-WslReady)) {
        throw "Docker Desktop didn't start: WSL 2, which it runs on, isn't fully installed. Open Rowanholt again and it offers to install it."
    }
    throw "Docker Desktop didn't start within 4 minutes. Open Docker Desktop from the Start menu to see what it says, then open Rowanholt again."

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
        Write-Step 'Created .env with a new SECRET_KEY'
    }
    $built = Join-Path $Root '.rowanholt-built'
    $version = (Get-Content $versionFile -Raw).Trim()
    if ((Test-Path $built) -and (Get-Content $built -Raw).Trim() -eq $version) { return @() }
    Write-Step 'A new Rowanholt version: rebuilding the images, which takes a while'
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
    # The road is drawn in the window (Show-Journey); a second call (warm found to be cold) keeps the page
    if (-not $script:Progress -or $script:ProgressKind -ne 'journey') {
        $script:Progress = Show-ProgressPage 'Starting Rowanholt' 'Working out how long it will take' $null
        $script:ProgressKind = 'journey'
    }
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
    # Just the time left in the header: where Gandalf has got to is the macOS app's picture, not this one's.
    # A step well past its estimate (a slow disk, a busy machine) says so: a time left that never moves
    # reads as a hang
    $overrun = $inPhase -gt [math]::Max(60, $expected * 1.5)
    $script:Wizard.Sub.Text = if ($overrun) { "Taking longer than expected; still working ($([math]::Round($inPhase / 60)) min on this step)" } elseif ($remaining -lt 45) { 'Less than a minute left' } elseif ($remaining -lt 90) { 'About a minute left' } else { "About $([math]::Round($remaining / 60)) minutes left" }
    $script:Progress.Bar.Style = 'Continuous'; $script:Progress.Bar.Value = [int](1000 * $fraction)
    if ($J.Phase -ne $script:ShownPhase -or $J.Detail) {
        $script:ShownPhase = $J.Phase
        $script:Progress.Detail.Text = $Messages[$J.Phase] + $(if ($J.Detail) { " ($($J.Detail))" } else { '' })
    }
    Step-Gui
    Assert-NotCancelled
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
            if ($line.StartsWith('#')) { Show-Journey $J; return }  # BuildKit's chatter isn't shown
            if ($J.Phase -eq 'images' -and $line -match '\b(Creating|Created|Starting|Started|Recreate|Running)\b') {
                Enter-Phase $J 'containers'
            }
            Write-Step $line.Trim()
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
    # -Stop and -Update only write to the console; everything else happens in the Rowanholt window
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
        # A server opens now; a copy here takes the settings when it next starts
        if (-not (Get-SavedServer)) {
            $body = Show-Page 'Rowanholt is set up' 'Your choices are saved.' -Next 'Close' -Cancel ''
            Add-Text $body ("Rowanholt uses them the next time it starts. If it's running now, stop it with Stop " +
                'Rowanholt in the Start menu, then open Rowanholt.') 20 -Height 44
            Wait-Page | Out-Null
            Close-Wizard
            exit 0
        }
    }

    $Server = Get-SavedServer
    if ($Server) {
        if ($Stop) {
            Write-Host "Rowanholt runs on $Server; its admins start and stop it."
            Start-Sleep -Seconds 4
            exit 0
        }
        $Url = $Server
        Close-Wizard
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
        if ($Server) { $Url = $Server; Close-Wizard; Open-Window; Invoke-UpdateCheck }
        exit 0
    }
    Update-Copy

    if (-not (Test-Frontend)) {
        Assert-DockerInstalled
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
        if ($missing.Count) { Write-Step "$($missing.Count) images to fetch or build: the first start takes a while" }
        else { Write-Step 'Starting the containers' }
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
            for ($i = 0; $i -lt 10; $i++) { Show-Journey $script:Journey; Start-Sleep -Milliseconds 200 }
        }
        Complete-Journey $script:Journey
    }
    Close-Wizard
    Open-Window
    Invoke-UpdateCheck
} catch {
    $message = $_.Exception.Message
    if ($message -eq 'Cancelled') { Close-Wizard; exit 1 }
    if ($Stop -or $Update) {
        Write-Host ''
        Write-Host "Error: $message" -ForegroundColor Red
        Read-Host 'Press Enter to close'
    } else {
        Show-Problem "Rowanholt couldn't start" $message
    }
    exit 1
}

<#
Remove the Rowanholt desktop app from Windows (app/README.md).

    powershell -ExecutionPolicy Bypass -File desktop\uninstall.ps1             remove the app, then ask before deleting its data
    powershell -ExecutionPolicy Bypass -File desktop\uninstall.ps1 -KeepData   remove the app only: the data stays for a reinstall
    powershell -ExecutionPolicy Bypass -File desktop\uninstall.ps1 -Yes        don't ask: delete the data too

Rowanholt's data is the folder setup unpacked it into (%USERPROFILE%\Rowanholt unless you chose
another: .env, docker-compose.local.yml, the stack's files), its Docker volumes (the database of
users, jobs and findings, case output, Splunk and Elastic), and %LOCALAPPDATA%\Rowanholt (setup's
choices, the window's Edge profile, start timings). A git clone is never deleted, nor are evidence
folders, which are only mounted. Without a console to ask on, the data is kept unless -Yes says
otherwise. The program itself is removed by Windows Installer, as Settings > Apps would. Works in
Windows PowerShell 5.1 and pwsh.
#>
param(
    [switch]$KeepData,
    [switch]$Yes
)
$ErrorActionPreference = "Stop"

$script:step = 0
$script:steps = 3
function Step($text) {
    $script:step++
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $script:step, $script:steps, $text) -ForegroundColor Cyan
}
function Done($text) { Write-Host "      OK  $text" -ForegroundColor Green }
function Note($text) { Write-Host "      $text" -ForegroundColor DarkGray }

$state = Join-Path $env:LOCALAPPDATA "Rowanholt"
$rootFile = Join-Path $state "root"
$root = if (Test-Path $rootFile) { (Get-Content $rootFile -Raw).Trim() } else { $null }
# Only a copy setup unpacked is Rowanholt's to delete; a clone is the user's
$ours = $root -and (Test-Path (Join-Path $root ".rowanholt-version")) -and -not (Test-Path (Join-Path $root ".git"))

function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $false }
    # Windows PowerShell turns a native command's redirected stderr into a terminating error under 'Stop'
    $ErrorActionPreference = "Continue"
    docker info *> $null
    return $LASTEXITCODE -eq 0
}

Write-Host ""
Write-Host "  Rowanholt: desktop app uninstaller"

Step "Stopping Rowanholt"
# The stack runs from the folder that may be deleted below; stopped first, whatever is kept
$docker = Test-Docker
if (-not $docker) {
    Done "Docker isn't running: nothing to stop"
} else {
    $ErrorActionPreference = "Continue"
    $running = @(docker ps -q --filter "label=com.docker.compose.project=rowanholt" 2>$null)
    if ($running.Count) {
        docker stop $running *> $null
        docker rm $running *> $null
        Done "Stopped $($running.Count) container(s)"
    } else {
        Done "Not running"
    }
    $ErrorActionPreference = "Stop"
}

Step "Removing the app"
# Asked of Windows Installer by the MSI's UpgradeCode (app/windows/rowanholt.wxs): a per-user MSI
# has no key under HKCU's Uninstall, which only lists non-MSI per-user installs
$upgradeCode = "{2960092C-3402-4618-A64F-289055BDD7C2}"
$installer = New-Object -ComObject WindowsInstaller.Installer
$entries = @(foreach ($code in @($installer.RelatedProducts($upgradeCode))) {
    [pscustomobject]@{ PSChildName = $code; DisplayVersion = $installer.ProductInfo($code, "VersionString") }
})
if (-not $entries) {
    Done "Rowanholt isn't installed"
} else {
    foreach ($e in $entries) {
        $log = Join-Path $env:TEMP "rowanholt-uninstall.log"
        Note "Windows shows its own progress window while it removes Rowanholt $($e.DisplayVersion)"
        $p = Start-Process msiexec.exe -ArgumentList "/x", $e.PSChildName, "/passive", "/l*v", "`"$log`"" -Wait -PassThru
        # 1605: already gone; 3010: removed, a restart is pending for something else
        if ($p.ExitCode -notin 0, 1605, 3010) {
            Get-Content $log -Tail 40
            throw "msiexec failed with $($p.ExitCode)"
        }
        Done "Removed Rowanholt $($e.DisplayVersion)"
    }
}

Step "The data"
$volumes = @()
if ($docker) {
    $ErrorActionPreference = "Continue"
    $volumes = @(docker volume ls -q --filter "label=com.docker.compose.project=rowanholt" 2>$null | Where-Object { $_ })
    $ErrorActionPreference = "Stop"
}
$folders = @(@($(if ($ours) { $root }), $state) | Where-Object { $_ -and (Test-Path $_) })
if (-not $folders -and -not $volumes) {
    Done "None found"
} else {
    $bytes = ($folders | ForEach-Object { Get-ChildItem $_ -Recurse -Force -File -ErrorAction SilentlyContinue } |
        Measure-Object Length -Sum).Sum
    $size = "{0:N0} MB" -f ($bytes / 1MB)
    $what = @($folders) + $(if ($volumes) { "$($volumes.Count) Docker volume(s): the database of users, jobs and findings, and case output" })
    foreach ($w in $what) { Note $w }
    if ($root -and -not $ours) { Note "$root is a git clone or a copy you chose: it's kept" }
    if (-not $docker) { Note "Docker isn't running, so Rowanholt's Docker volumes (if any) aren't checked or deleted" }
    $delete = [bool]$Yes
    if (-not $Yes -and -not $KeepData -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        $answer = Read-Host "      Delete all of the above ($size of files, plus the volumes)? It can't be undone. [y/N]"
        $delete = $answer -match '^[yY]'
    }
    if ($delete) {
        foreach ($f in $folders) { Remove-Item -Recurse -Force $f }
        if ($volumes) {
            $ErrorActionPreference = "Continue"
            docker volume rm $volumes *> $null
            $ErrorActionPreference = "Stop"
        }
        Done "Deleted ($size, $($volumes.Count) volume(s)). Evidence folders were only mounted: they're untouched"
        # Not removed here: an image prune would take other projects' images with Rowanholt's
        Note "Rowanholt's images (rowanholt-*) stay in Docker until you remove them with docker rmi"
    } else {
        Done "Kept: reinstall to carry on, or delete them to start again"
    }
}

Write-Host ""
Write-Host "  Rowanholt is uninstalled." -ForegroundColor Green

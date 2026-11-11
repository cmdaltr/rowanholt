<#
Install or upgrade the Rowanholt desktop app on Windows from a GitHub release (app/README.md).

    powershell -ExecutionPolicy Bypass -File desktop\install.ps1                      the latest release
    powershell -ExecutionPolicy Bypass -File desktop\install.ps1 -Version v1.4.0      a given release
    powershell -ExecutionPolicy Bypass -File desktop\install.ps1 -File Rowanholt.msi  an installer already downloaded
    powershell -ExecutionPolicy Bypass -File desktop\install.ps1 -Launch              open Rowanholt when it's installed
    powershell -ExecutionPolicy Bypass -File desktop\install.ps1 -Clean               a clean install: once the new installer is
                                                                              downloaded and checked, remove the current app and
                                                                              its data (desktop\uninstall.ps1 -Yes) first

The installer is checked against the release's SHA256SUMS before use. The repository is public, so
no token is needed; GH_TOKEN (or GITHUB_TOKEN, or a logged-in gh) is used when there is one, for
GitHub's higher rate limit. It installs for the current user, so it needs no administrator rights.
One MSI serves x64 and Arm64. Works in Windows PowerShell 5.1 and pwsh.
#>
param(
    [string]$Version = "latest",
    [string]$File,
    [switch]$Launch,
    [switch]$Clean
)
$ErrorActionPreference = "Stop"
# Windows PowerShell's progress bar slows downloads by an order of magnitude
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = if ($env:ROWANHOLT_REPO) { $env:ROWANHOLT_REPO } else { "cmdaltr/rowanholt" }
$suffix = "-windows-universal.msi"
# Numbered steps, so it's clear how far through the install is
$script:step = 0
$script:steps = 0
$started = Get-Date
function Step($text) {
    $script:step++
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $script:step, $script:steps, $text) -ForegroundColor Cyan
}
function Done($text) { Write-Host "      OK  $text" -ForegroundColor Green }
function Note($text) { Write-Host "      $text" -ForegroundColor DarkGray }

# Invoke-WebRequest's own progress bar is what makes it slow in Windows PowerShell: read the stream
# here instead, and print the percentage on one line
function Get-Download($url, $headers, $out) {
    $req = [Net.HttpWebRequest]::Create($url)
    foreach ($k in $headers.Keys) {
        if ($k -eq "Accept") { $req.Accept = $headers[$k] } else { $req.Headers[$k] = $headers[$k] }
    }
    $req.UserAgent = "rowanholt-install"
    $resp = $req.GetResponse()
    $total = $resp.ContentLength
    $in = $resp.GetResponseStream()
    $fs = [IO.File]::Create($out)
    try {
        $buf = New-Object byte[] (1MB)
        $done = 0
        $shown = -1
        while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
            $fs.Write($buf, 0, $n)
            $done += $n
            if ($total -gt 0) {
                $pct = [int](100 * $done / $total)
                if ($pct -ne $shown) {
                    Write-Host -NoNewline ("`r      {0,3}%  {1:N1} of {2:N1} MB" -f $pct, ($done / 1MB), ($total / 1MB))
                    $shown = $pct
                }
            }
        }
        Write-Host ""
    }
    finally {
        $fs.Close(); $in.Close(); $resp.Close()
    }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("rowanholt-" + [Guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
# -Clean runs the uninstaller beside this script (the repository's app\, or the installed app's
# seed\). Copied out first: it deletes the app this script may be running from
if ($Clean) {
    $uninstaller = Join-Path $PSScriptRoot "uninstall.ps1"
    if (-not (Test-Path $uninstaller)) {
        Remove-Item -Recurse -Force $tmp
        throw "-Clean needs uninstall.ps1 beside install.ps1 (the app's seed folder, or the repository's app folder)"
    }
    Copy-Item $uninstaller (Join-Path $tmp "uninstall.ps1")
}

Write-Host ""
Write-Host "  Rowanholt: desktop app installer" -ForegroundColor White
Write-Host "  rowan + Old English holt, a wood: the rowan wood" -ForegroundColor DarkGray
# Find (and download and check) the installer when there's no -File, install it, then find what was installed
$script:steps = $(if ($File) { 2 } else { 5 }) + $(if ($Clean) { 1 } else { 0 })

try {
    if (-not $File) {
        Step "Finding the $Version release of $repo"
        $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $null }
        if (-not $token -and (Get-Command gh -ErrorAction SilentlyContinue)) { $token = (gh auth token 2>$null) }
        $auth = if ($token) { @{ Authorization = "Bearer $token" } } else { @{} }

        $path = if ($Version -eq "latest") { "releases/latest" } else { "releases/tags/$Version" }
        $release = Invoke-RestMethod -Headers ($auth + @{ Accept = "application/vnd.github+json" }) "https://api.github.com/repos/$repo/$path"
        $asset = $release.assets | Where-Object { $_.name.EndsWith($suffix) } | Select-Object -First 1
        $sums = $release.assets | Where-Object { $_.name -eq "SHA256SUMS" } | Select-Object -First 1
        if (-not $asset) { throw "The $Version release has no Windows installer (*$suffix)" }
        if (-not $sums) { throw "The $Version release has no SHA256SUMS" }
        Done "$($release.tag_name): $($asset.name)"

        Step "Downloading $($asset.name)"
        $File = Join-Path $tmp $asset.name
        $raw = $auth + @{ Accept = "application/octet-stream" }
        Get-Download $asset.url $raw $File
        Invoke-WebRequest -UseBasicParsing -Headers $raw -OutFile (Join-Path $tmp "SHA256SUMS") $sums.url
        Done "Downloaded"

        Step "Checking it against the release's SHA256SUMS"
        $expected = Get-Content (Join-Path $tmp "SHA256SUMS") | ForEach-Object {
            $hash, $name = $_ -split '\s+\*?', 2
            if ($name -eq $asset.name) { $hash }
        } | Select-Object -First 1
        $actual = (Get-FileHash -Algorithm SHA256 $File).Hash
        if (-not $expected -or $actual -ne $expected) { throw "$($asset.name) doesn't match SHA256SUMS: not installing it" }
        Done "SHA-256 matches"
    }
    $File = (Resolve-Path $File).Path

    if ($Clean) {
        Step "Removing the current install and its data"
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tmp "uninstall.ps1") -Yes |
            Where-Object { $_ -match '^      ' } | ForEach-Object { Write-Host $_ }
    }

    Step "Installing $(Split-Path $File -Leaf)"
    Note "Windows shows its own progress window while it installs"
    $log = Join-Path $tmp "install.log"
    # /passive: Windows' progress window, no questions
    $p = Start-Process msiexec.exe -ArgumentList "/i", "`"$File`"", "/passive", "/l*v", "`"$log`"" -Wait -PassThru
    # 3010: installed, a restart is pending for something else
    if ($p.ExitCode -notin 0, 3010) {
        Get-Content $log -Tail 40
        throw "msiexec failed with $($p.ExitCode)"
    }
    Done "Installed$(if ($p.ExitCode -eq 3010) { ' (Windows wants a restart for something else)' })"

    Step "Finding the installed app"
    # A per-user install, always here (app\windows\rowanholt.wxs)
    $launcher = Join-Path $env:LOCALAPPDATA "Programs\cmdaltr\Rowanholt\app\windows\Rowanholt.ps1"
    if (Test-Path $launcher) { Done $launcher } else { $launcher = $null; Write-Warning "The launcher isn't where the MSI puts it" }
    $took = (Get-Date) - $started
    Write-Host ""
    Write-Host ("  Rowanholt is installed ({0}m {1}s). Open it from the Start menu." -f [math]::Floor($took.TotalMinutes), $took.Seconds) -ForegroundColor Green
    Write-Host "  The first start asks where Rowanholt runs, then builds its images: a while the first time; after that, a minute." -ForegroundColor DarkGray
    if ($Launch -and $launcher) {
        Start-Process (Join-Path $PSHOME "powershell.exe") -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$launcher`""
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

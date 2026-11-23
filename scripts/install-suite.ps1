<#
Install or upgrade the suite on Windows: Ostraka (incident record), Rowanholt (evidence and analysis)
and Shikari (detection and hunting), each from its latest GitHub release.

The same file is in all three repositories (scripts/install-suite.ps1), the twin of install-suite.sh;
change them together. It doesn't install anything itself: for each product it finds the latest
release, fetches that release's own desktop/install.ps1 (from the release's tag, so the installer
matches the packages), and runs it with -Version <tag>. Each product's installer picks the package and
checks it against the release's SHA256SUMS, as when it's run alone.

    Invoke-WebRequest https://raw.githubusercontent.com/cmdaltr/ostraka/main/scripts/install-suite.ps1 -OutFile install-suite.ps1
    powershell -ExecutionPolicy Bypass -File install-suite.ps1                     all three
    powershell -ExecutionPolicy Bypass -File install-suite.ps1 -Only ostraka,shikari
    powershell -ExecutionPolicy Bypass -File install-suite.ps1 -Skip rowanholt
    powershell -ExecutionPolicy Bypass -File install-suite.ps1 -Launch            open each once installed
    powershell -ExecutionPolicy Bypass -File install-suite.ps1 -DryRun            say what would be installed

All three repositories are public, so no token is needed; GH_TOKEN or GITHUB_TOKEN is used when set,
for GitHub's higher rate limit.
#>
param(
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [switch]$Launch,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
# Windows PowerShell's progress bar slows downloads by an order of magnitude
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$All = @("ostraka", "rowanholt", "shikari")
$Names = @{ ostraka = "Ostraka"; rowanholt = "Rowanholt"; shikari = "Shikari" }
$Owner = if ($env:SUITE_OWNER) { $env:SUITE_OWNER } else { "cmdaltr" }
# Only the tests point these elsewhere
$Api = if ($env:SUITE_GITHUB_API) { $env:SUITE_GITHUB_API } else { "https://api.github.com" }
$Raw = if ($env:SUITE_GITHUB_RAW) { $env:SUITE_GITHUB_RAW } else { "https://raw.githubusercontent.com" }

function Split-List([string[]]$List) { @($List | ForEach-Object { $_ -split "[,\s]+" } | Where-Object { $_ }) }
$Only = Split-List $Only
$Skip = Split-List $Skip
foreach ($item in $Only + $Skip) {
    if ($All -notcontains $item) {
        throw "There's no $item in the suite: choose from ostraka, rowanholt, shikari."
    }
}
$Chosen = @($All | Where-Object { (-not $Only.Count -or $Only -contains $_) -and $Skip -notcontains $_ })
if (-not $Chosen.Count) { throw "Nothing left to install." }

$token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { "" }
$headers = @{ "User-Agent" = "install-suite"; "Accept" = "application/vnd.github+json" }
if ($token -and $Api -eq "https://api.github.com") { $headers["Authorization"] = "Bearer $token" }

# file:// is for the tests' fake trees; Invoke-WebRequest only speaks http(s)
function Get-Json([string]$Uri) {
    if ($Uri.StartsWith("file:")) { return Get-Content -Raw -LiteralPath ([Uri]$Uri).LocalPath | ConvertFrom-Json }
    Invoke-RestMethod -Uri $Uri -Headers $headers
}
function Save-Url([string]$Uri, [string]$OutFile) {
    if ($Uri.StartsWith("file:")) { return Copy-Item -LiteralPath ([Uri]$Uri).LocalPath -Destination $OutFile }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -Headers @{ "User-Agent" = "install-suite" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("install-suite-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$installed = @()
$failed = @()
try {
    foreach ($product in $Chosen) {
        $name = $Names[$product]
        $repo = "$Owner/$product"
        Write-Host $name -ForegroundColor Cyan
        try {
            $tag = (Get-Json "$Api/repos/$repo/releases/latest").tag_name
        } catch {
            Write-Host "  couldn't find a release of $repo" -ForegroundColor Red
            $failed += $name
            continue
        }
        if ($tag -notmatch '^v[0-9]') { throw "$repo's latest release has an unexpected tag: $tag" }
        Write-Host "  latest release $tag" -ForegroundColor DarkGray
        $source = "$Raw/$repo/$tag/desktop/install.ps1"
        if ($DryRun) {
            Write-Host "  would run $source -Version $tag$(if ($Launch) { ' -Launch' })" -ForegroundColor DarkGray
            continue
        }
        $installer = Join-Path $work "$product-install.ps1"
        try {
            Save-Url $source $installer
        } catch {
            Write-Host "  couldn't fetch $name's installer for $tag" -ForegroundColor Red
            $failed += $name
            continue
        }
        $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $installer, "-Version", $tag)
        if ($Launch) { $arguments += "-Launch" }
        $shell = (Get-Process -Id $PID).Path
        & $shell @arguments
        if ($LASTEXITCODE -eq 0) { $installed += $name } else { $failed += $name }
        Write-Host ""
    }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($DryRun) { exit 0 }
if ($installed.Count) { Write-Host ("Installed: " + ($installed -join ", ")) -ForegroundColor Green }
if ($failed.Count) {
    Write-Host ("Not installed: " + ($failed -join ", ")) -ForegroundColor Red
    exit 1
}

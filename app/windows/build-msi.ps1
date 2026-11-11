<#
.SYNOPSIS
    Build Rowanholt-<version>-windows-universal.msi from rowanholt.wxs with the WiX Toolset 5.
.DESCRIPTION
    The release workflow runs it; it also runs on any Windows PC with the .NET SDK:
        dotnet tool install --global wix --version 5.0.2
        wix extension add --global WixToolset.UI.wixext/5.0.2
        powershell -File app\windows\build-msi.ps1 -Version 1.4.0 -Tarball rowanholt-src.tar.gz -OutDir dist
    The tarball is app/source-tarball.sh's (the source tree the launcher unpacks); the launcher,
    icon, LICENSE and the install scripts come from this checkout, which is the same commit in CI.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$Tarball,
    [string]$OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Tarball = (Resolve-Path $Tarball).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# An MSI version is numbers only (major.minor.build, each part capped): 1.4.0-rc1 is 1.4.0 to
# Windows Installer, and 1.4.0-dev.57 is 1.4.0.57; the file name keeps the full version
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') {
    throw "'$Version' doesn't start with major.minor.patch"
}
$msiVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
if ($Version -match '-dev\.(\d+)$') { $msiVersion += ".$($Matches[1])" }

$work = Join-Path ([IO.Path]::GetTempPath()) ('rowanholt-msi-' + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $versionFile = Join-Path $work 'VERSION'
    [IO.File]::WriteAllText($versionFile, "$Version`n")

    # WixUI shows the licence as RTF: the plain text, escaped, a paragraph break per line
    $text = [IO.File]::ReadAllText((Join-Path $Root 'LICENSE'))
    $escaped = $text.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}') -replace "`r?`n", "\par`r`n"
    $rtf = Join-Path $work 'LICENSE.rtf'
    [IO.File]::WriteAllText($rtf, "{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\f0\fs18 $escaped}", [Text.Encoding]::ASCII)

    $msi = Join-Path $OutDir "Rowanholt-$Version-windows-universal.msi"
    wix build (Join-Path $PSScriptRoot 'rowanholt.wxs') -arch x86 -ext WixToolset.UI.wixext `
        -d "ProductVersion=$msiVersion" -d "Root=$Root" -d "Tarball=$Tarball" `
        -d "VersionFile=$versionFile" -d "LicenceRtf=$rtf" -o $msi
    if ($LASTEXITCODE -ne 0) { throw "wix build exited with status $LASTEXITCODE" }
    Write-Host "Built $msi (MSI version $msiVersion)"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

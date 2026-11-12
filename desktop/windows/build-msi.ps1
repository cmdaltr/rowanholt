<#
.SYNOPSIS
    Build Rowanholt-<version>-windows-universal.msi from rowanholt.wxs with the WiX Toolset 5.
.DESCRIPTION
    The release workflow runs it; it also runs on any Windows PC with the .NET SDK:
        dotnet tool install --global wix --version 5.0.2
        wix extension add --global WixToolset.UI.wixext/5.0.2
        powershell -File desktop\windows\build-msi.ps1 -Version 1.4.0 -Tarball rowanholt-src.tar.gz -OutDir dist
    The tarball is desktop/source-tarball.sh's (the source tree the launcher unpacks); the launcher,
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

    # The wizard's art, drawn from the icon in its own colours: the banner along the top of the
    # inner pages (493x58) and the panel down the left of Welcome and Finish (493x312, text drawn
    # by Windows Installer on the white right-hand part). Sizes are WixUI's
    Add-Type -AssemblyName System.Drawing
    $icon = [System.Drawing.Image]::FromFile((Join-Path $Root 'desktop\icons\rowanholt.png'))
    $dark = [System.Drawing.Color]::FromArgb(16, 27, 23)
    $gold = [System.Drawing.Color]::FromArgb(201, 164, 76)
    function New-Art([int]$Width, [int]$Height, [scriptblock]$Draw, [string]$Path) {
        $bmp = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'; $g.InterpolationMode = 'HighQualityBicubic'; $g.TextRenderingHint = 'AntiAliasGridFit'
        $g.Clear([System.Drawing.Color]::White)
        & $Draw $g
        $g.Dispose(); $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp); $bmp.Dispose()
    }
    $bannerBmp = Join-Path $work 'banner.bmp'
    New-Art 493 58 { param($g) $g.DrawImage($icon, 441, 5, 48, 48) } $bannerBmp
    $dialogBmp = Join-Path $work 'dialog.bmp'
    New-Art 493 312 {
        param($g)
        $g.FillRectangle((New-Object System.Drawing.SolidBrush($dark)), 0, 0, 164, 312)
        $g.DrawImage($icon, 22, 52, 120, 120)
        $centre = New-Object System.Drawing.StringFormat; $centre.Alignment = 'Center'
        $g.DrawString('Rowanholt', (New-Object System.Drawing.Font('Segoe UI Semibold', 15, [System.Drawing.GraphicsUnit]::Pixel)),
            [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF(0, 186, 164, 24)), $centre)
        $g.FillRectangle((New-Object System.Drawing.SolidBrush($gold)), 62, 214, 40, 2)
        $g.DrawString('DFIR platform', (New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.GraphicsUnit]::Pixel)),
            (New-Object System.Drawing.SolidBrush($gold)), (New-Object System.Drawing.RectangleF(0, 222, 164, 18)), $centre)
    } $dialogBmp
    $icon.Dispose()

    $msi = Join-Path $OutDir "Rowanholt-$Version-windows-universal.msi"
    wix build (Join-Path $PSScriptRoot 'rowanholt.wxs') -arch x86 -ext WixToolset.UI.wixext `
        -d "ProductVersion=$msiVersion" -d "Root=$Root" -d "Tarball=$Tarball" `
        -d "VersionFile=$versionFile" -d "LicenceRtf=$rtf" -d "BannerBmp=$bannerBmp" -d "DialogBmp=$dialogBmp" -o $msi
    if ($LASTEXITCODE -ne 0) { throw "wix build exited with status $LASTEXITCODE" }
    Write-Host "Built $msi (MSI version $msiVersion)"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS
    Install (or -Uninstall) Rowanholt's Start menu and desktop shortcuts for the current user.
.DESCRIPTION
    The shortcuts run Rowanholt.ps1 with the Rowanholt icon. Windows doesn't let a script
    pin to the taskbar: right-click the Start menu entry and choose Pin to taskbar.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File app\windows\install.ps1
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NoDesktop
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Programs = [Environment]::GetFolderPath('Programs')
$Desktop = [Environment]::GetFolderPath('Desktop')
$Shortcuts = @{
    (Join-Path $Programs 'Rowanholt.lnk')      = ''
    (Join-Path $Programs 'Stop Rowanholt.lnk') = '-Stop'
}
if (-not $NoDesktop) { $Shortcuts[(Join-Path $Desktop 'Rowanholt.lnk')] = '' }

if ($Uninstall) {
    foreach ($link in @($Shortcuts.Keys) + (Join-Path $Desktop 'Rowanholt.lnk')) {
        if (Test-Path $link) { Remove-Item $link; Write-Host "Removed $link" }
    }
    exit 0
}

$Launcher = Join-Path $PSScriptRoot 'Rowanholt.ps1'
$Icon = Join-Path $Root 'app\icons\rowanholt.ico'
$Shell = New-Object -ComObject WScript.Shell
foreach ($link in $Shortcuts.Keys) {
    $shortcut = $Shell.CreateShortcut($link)
    $shortcut.TargetPath = Join-Path $PSHOME 'powershell.exe'
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Launcher`" $($Shortcuts[$link])".TrimEnd()
    $shortcut.WorkingDirectory = $Root
    $shortcut.IconLocation = "$Icon,0"
    # The console shows the road to Rowanholt while the stack starts, then closes
    $shortcut.WindowStyle = if ($Shortcuts[$link]) { 7 } else { 1 }
    $shortcut.Description = 'Rowanholt DFIR platform'
    $shortcut.Save()
    Write-Host "Created $link"
}
Write-Host 'Pin it: right-click Rowanholt in the Start menu > Pin to taskbar.'

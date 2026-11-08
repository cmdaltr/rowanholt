<#
.SYNOPSIS
    What the Rowanholt scheduled task runs at boot (Install-RowanholtServer.ps1 copies it to
    %ProgramData%\Rowanholt): start the stack in WSL, forward the proxy's ports to it, and hold
    the distribution open.
.DESCRIPTION
    WSL 2 gives the distribution a new address on each boot, so the port forwarding (netsh
    portproxy, on every Windows address) is rebuilt here each time. WSL stops a distribution
    nothing is attached to, so the task ends by attaching to it and staying: stopping the task
    stops Rowanholt's way in, not its containers.
#>
$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'
$State = Join-Path $env:ProgramData 'Rowanholt'
$Log = Join-Path $State 'start.log'
$config = Get-Content (Join-Path $State 'server.json') -Raw | ConvertFrom-Json
$Distro = $config.Distribution

function Write-Log([string]$Text) { Add-Content -Path $Log -Value "[$(Get-Date -Format s)] $Text" }

Write-Log 'Starting Rowanholt'
# WSL's MSI (Install-RowanholtServer.ps1), not System32's wsl.exe, which on Server 2022 predates it
$wslExe = Join-Path $env:ProgramFiles 'WSL\wsl.exe'
if (Test-Path $wslExe) { Set-Alias -Name wsl.exe -Value $wslExe -Scope Script }
& wsl.exe -d $Distro -u root -- "$($config.Root)/rowanholt" start *>> $Log
if ($LASTEXITCODE -ne 0) { Write-Log "rowanholt start failed ($LASTEXITCODE)"; exit 1 }

$address = ((& wsl.exe -d $Distro -u root -- hostname -I) -split '\s+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
if (-not $address) { Write-Log 'No address for the distribution'; exit 1 }
foreach ($port in $config.Ports) {
    & netsh.exe interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 *> $null
    & netsh.exe interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$address | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Log "portproxy for $port failed"; exit 1 }
}
Write-Log "Forwarding $($config.Ports -join ', ') to $address"

& wsl.exe -d $Distro -u root -- sleep infinity

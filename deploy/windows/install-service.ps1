<#
.SYNOPSIS
    Set Windows Server 2022 or 2025 up as a Rowanholt team server, through WSL 2
    (deploy\windows\install-service.ps1, as Shikari's and Ostraka's; deploy\windows\uninstall-service.ps1 removes it).
.DESCRIPTION
    Rowanholt's images are Linux containers, and Docker Desktop isn't supported or licensed on
    Windows Server, so the server is Linux: a WSL 2 distribution of its own (Ubuntu 24.04, named
    Rowanholt) running Docker Engine, with Rowanholt cloned into /opt/rowanholt and set up by the
    same `rowanholt server init` as any Linux server (docs/SERVER.md). This script:

      1. turns WSL 2 on (wsl --install --no-distribution; the first run may ask for a reboot,
         then run it again);
      2. imports Ubuntu's WSL root filesystem as the Rowanholt distribution, under -WslPath;
      3. installs Docker Engine from Docker's own repository, with systemd;
      4. clones Rowanholt and runs `rowanholt server init`, with the certificate from the
         Windows certificate store when -CertificateThumbprint is given;
      5. mounts -EvidencePath folders (D:\Evidence is /mnt/d/Evidence inside);
      6. opens the proxy's ports in Windows Firewall and registers the Rowanholt scheduled task,
         which starts the stack at boot with nobody signed in and forwards those ports into WSL.

    Run it again to change the hostname, certificate or evidence folders; it keeps what exists.
.EXAMPLE
    .\deploy\windows\install-service.ps1 -Hostname rowanholt.dfir.example.org -CertificateThumbprint 3F2A... -EvidencePath D:\Evidence
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.-]+$')][string]$Hostname,
    # internal (Caddy's own CA) or an email address for Let's Encrypt; ignored with -CertificateThumbprint
    [string]$Tls = 'internal',
    # A certificate in Cert:\LocalMachine\My, with an exportable private key: served as --tls files
    [string]$CertificateThumbprint,
    [ValidateRange(1, 65535)][int]$HttpsPort = 443,
    [string[]]$EvidencePath = @(),
    # Where the distribution's virtual disk lives: cases are written inside it, so a data drive
    [string]$WslPath = (Join-Path $env:ProgramData 'Rowanholt\wsl'),
    [string]$Repository = 'https://github.com/cmdaltr/rowanholt.git',
    [string]$Branch = 'main',
    # The account the scheduled task runs as: this one (WSL distributions belong to a user)
    [pscredential]$Credential
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'  # wsl.exe writes UTF-16 otherwise
$Distro = 'Rowanholt'
$Root = '/opt/rowanholt'
$State = Join-Path $env:ProgramData 'Rowanholt'
$RootFs = 'https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz'

function ConvertTo-WslPath([string]$Path) {
    '/mnt/' + $Path.Substring(0, 1).ToLower() + ($Path.Substring(2) -replace '\\', '/').TrimEnd('/')
}

function Invoke-Wsl {
    # Invoke-Wsl <bash script>: run as root in the Rowanholt distribution, failing on error. Through
    # a file: Windows PowerShell passes a native argument's double quotes to wsl.exe unescaped
    param([Parameter(Mandatory)][string]$Script)
    $file = Join-Path $State 'step.sh'
    [IO.File]::WriteAllText($file, ($Script -replace "`r", ''), (New-Object Text.UTF8Encoding $false))
    try {
        & wsl.exe -d $Distro -u root -- bash -euo pipefail (ConvertTo-WslPath $file)
        if ($LASTEXITCODE -ne 0) { throw "In WSL ($LASTEXITCODE): $($Script.Trim().Split("`n")[0])..." }
    } finally {
        Remove-Item $file -ErrorAction SilentlyContinue
    }
}

function Quote-Bash([string]$Text) { "'" + ($Text -replace "'", "'\''") + "'" }

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an administrator PowerShell.'
}
$build = [Environment]::OSVersion.Version.Build
if ($build -lt 20348) { throw "Windows Server 2022 (build 20348) or later is needed; this is build $build." }
if ($CertificateThumbprint -and -not (Test-Path "Cert:\LocalMachine\My\$CertificateThumbprint")) {
    throw "No certificate $CertificateThumbprint in Cert:\LocalMachine\My."
}
foreach ($folder in $EvidencePath) {
    if ($folder -notmatch '^[A-Za-z]:\\') { throw "-EvidencePath takes folders on a drive (D:\Evidence), not '$folder'." }
    if (-not (Test-Path $folder -PathType Container)) { throw "No folder $folder." }
}
if (-not $Credential) {
    $Credential = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" `
        -Message 'The scheduled task starts Rowanholt at boot as this account (its password is needed to run without anyone signed in)'
}
if ($Credential.UserName -notmatch "(^|\\)$([regex]::Escape($env:USERNAME))$") {
    throw 'The task must run as the account running this script: the Rowanholt distribution is registered to it.'
}
# Checked now, not at Register-ScheduledTask after everything else has been done
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$context = if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { 'Domain' } else { 'Machine' }
$principal = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $context, $env:USERDOMAIN
if (-not $principal.ValidateCredentials($env:USERNAME, $Credential.GetNetworkCredential().Password)) {
    throw "That isn't $env:USERDOMAIN\$env:USERNAME's password: run the script again."
}
New-Item -ItemType Directory -Force -Path $State, $WslPath | Out-Null

# 1. WSL 2. Windows Server 2022's own wsl.exe predates --install --no-distribution and --status
# (it prints its usage, so the check below never passed and the script asked for a reboot forever):
# the two features are turned on here and WSL itself is Microsoft's MSI, in Program Files
$reboot = $false
foreach ($feature in 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform') {
    if ((Get-WindowsOptionalFeature -Online -FeatureName $feature).State -ne 'Enabled') {
        Write-Host "Turning $feature on..."
        if ((Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart).RestartNeeded) { $reboot = $true }
    }
}
$wslExe = Join-Path $env:ProgramFiles 'WSL\wsl.exe'
if (-not (Test-Path $wslExe)) {
    Write-Host 'Installing WSL from its latest release...'
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/WSL/releases/latest' -UseBasicParsing
    $asset = $release.assets | Where-Object name -like '*.x64.msi' | Select-Object -First 1
    if (-not $asset) { throw "No x64 MSI in WSL's release $($release.tag_name)." }
    $msi = Join-Path $State $asset.name
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi -UseBasicParsing
    # GitHub gives each asset's SHA-256
    if ($asset.digest -match '^sha256:([0-9a-f]{64})$' -and (Get-FileHash $msi -Algorithm SHA256).Hash -ne $Matches[1].ToUpper()) {
        Remove-Item $msi; throw 'The WSL MSI failed its SHA-256 check.'
    }
    $install = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart'
    Remove-Item $msi
    if ($install.ExitCode -eq 3010) { $reboot = $true }
    elseif ($install.ExitCode -ne 0) { throw "Installing WSL failed (msiexec $($install.ExitCode))." }
}
if ($reboot) {
    Write-Host 'WSL needs a reboot to finish. Restart Windows, then run this script again.'
    exit 3010
}
# Every wsl.exe below is this one, not System32's
Set-Alias -Name wsl.exe -Value $wslExe -Scope Script
# 'Continue' while stderr is captured: under 'Stop' its first line would be thrown instead
$ErrorActionPreference = 'Continue'
$status = & wsl.exe --status 2>&1 | Out-String
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($code -ne 0) {
    # An unpatched Server 2022 (20348.587, the release media) is refused by the MSI's WSL
    if ($status -match 'WSL_E_OS_NOT_SUPPORTED') {
        throw "This Windows build ($([Environment]::OSVersion.Version)) is too old for WSL: install Windows Update's cumulative updates, reboot, then run this script again.`n$status"
    }
    throw "WSL is installed but doesn't start ($wslExe --status). Is nested virtualisation on in the VM?`n$status"
}
& wsl.exe --update | Out-Null

# The proxy is reached through Windows' own addresses (portproxy, below), not WSL's localhost
# relay, which would hold the same ports on 127.0.0.1
$wslConfig = Join-Path $env:USERPROFILE '.wslconfig'
$config = if (Test-Path $wslConfig) { Get-Content $wslConfig -Raw } else { '' }
if ($config -notmatch '(?m)^\s*localhostForwarding\s*=') {
    if ($config -notmatch '(?m)^\[wsl2\]') { $config = "[wsl2]`r`n" + $config }
    $config = $config -replace '(?m)^\[wsl2\]\r?$', "[wsl2]`r`nlocalhostForwarding=false"
    Set-Content -Path $wslConfig -Value $config -Encoding ascii
    & wsl.exe --shutdown
}

# 2. The distribution
$registered = (& wsl.exe --list --quiet) -split "`r?`n" | ForEach-Object { $_.Trim() }
if ($registered -notcontains $Distro) {
    $tarball = Join-Path $State 'ubuntu-noble-wsl-amd64.rootfs.tar.gz'
    Write-Host 'Downloading Ubuntu 24.04 for WSL...'
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $RootFs -OutFile $tarball -UseBasicParsing
    $sums = (Invoke-WebRequest -Uri ($RootFs -replace '[^/]+$', 'SHA256SUMS') -UseBasicParsing).Content
    if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
    $expected = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape(($RootFs -split '/')[-1]) }) -replace '\s.*$', ''
    $actual = (Get-FileHash $tarball -Algorithm SHA256).Hash
    if (-not $expected -or $actual -ne $expected.Trim().ToUpper()) { Remove-Item $tarball; throw 'The Ubuntu image failed its SHA-256 check.' }
    & wsl.exe --import $Distro $WslPath $tarball --version 2
    if ($LASTEXITCODE -ne 0) { throw 'wsl --import failed.' }
    Remove-Item $tarball
}

# 3. Docker Engine, under systemd (WSL starts it with the distribution)
Invoke-Wsl @'
if ! grep -q '^systemd=true' /etc/wsl.conf 2>/dev/null; then
    printf '[boot]\nsystemd=true\n' > /etc/wsl.conf
    touch /run/rowanholt-restart-wsl
fi
'@
& wsl.exe -d $Distro -u root -- test -e /run/rowanholt-restart-wsl
if ($LASTEXITCODE -eq 0) { & wsl.exe --terminate $Distro | Out-Null }
Write-Host 'Installing Docker Engine in WSL...'
Invoke-Wsl @'
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl git openssl >/dev/null
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    . /etc/os-release
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null
docker info >/dev/null
'@

# 4. Rowanholt
Write-Host "Fetching Rowanholt ($Branch)..."
Invoke-Wsl @"
if [ -d $Root/.git ]; then git -C $Root pull --ff-only -q; else git clone -q --branch $(Quote-Bash $Branch) $(Quote-Bash $Repository) $Root; fi
"@
$initArgs = @((Quote-Bash $Hostname))
if ($HttpsPort -ne 443) { $initArgs += "--https-port $HttpsPort" }
if ($CertificateThumbprint) {
    # Exported once with a throwaway password, converted inside WSL and deleted
    $pfx = Join-Path $State 'rowanholt.pfx'
    $password = [Convert]::ToBase64String((1..24 | ForEach-Object { [byte](Get-Random -Maximum 256) }))
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$CertificateThumbprint" -FilePath $pfx -Password $secure `
        -ChainOption BuildChain | Out-Null
    $wslPfx = ConvertTo-WslPath $pfx
    try {
        Invoke-Wsl @"
certs=$Root/deploy/server/certs
umask 077
openssl pkcs12 -in $(Quote-Bash $wslPfx) -passin pass:$(Quote-Bash $password) -nokeys -out `$certs/rowanholt.crt
openssl pkcs12 -in $(Quote-Bash $wslPfx) -passin pass:$(Quote-Bash $password) -nocerts -nodes -out `$certs/rowanholt.key
chmod 644 `$certs/rowanholt.crt
"@
    } finally {
        Remove-Item $pfx -ErrorAction SilentlyContinue
    }
    $initArgs += '--tls files'
} else {
    $initArgs += "--tls $(Quote-Bash $Tls)"
}
Invoke-Wsl "cd $Root && ./rowanholt server init $($initArgs -join ' ')"

# 5. Evidence folders: D:\Evidence is /mnt/d/Evidence, read-only in the backend
$mounts = @($EvidencePath | ForEach-Object { ConvertTo-WslPath $_ })
if ($mounts.Count -gt 0) {
    $yaml = @('# Written by deploy\windows\install-service.ps1: -EvidencePath folders', 'services:')
    foreach ($service in 'backend', 'celery-worker') {
        $yaml += "  ${service}:", '    volumes:'
        foreach ($mount in $mounts) {
            $yaml += '      - type: bind', "        source: `"$mount`"", "        target: `"$mount`""
            if ($service -eq 'backend') { $yaml += '        read_only: true' }
        }
    }
    $local = $yaml -join "`n"
    Invoke-Wsl @"
printf '%s\n' $(Quote-Bash $local) > $Root/docker-compose.local.yml
grep -v '^ROWANHOLT_EVIDENCE_PATHS=' $Root/.env > $Root/.env.new || true
echo $(Quote-Bash ("ROWANHOLT_EVIDENCE_PATHS=" + ($mounts -join ','))) >> $Root/.env.new
cat $Root/.env.new > $Root/.env && rm $Root/.env.new
"@
}

# 6. Firewall, the boot task and its port forwarding
$httpPublish = (& wsl.exe -d $Distro -u root -- sed -n 's/^ROWANHOLT_HTTP_PUBLISH=//p' "$Root/.env" | Select-Object -Last 1)
$ports = @($HttpsPort, 7755, 5601, 5602)
if ("$httpPublish".Trim() -eq '80') { $ports = @(80) + $ports }
Get-NetFirewallRule -Group Rowanholt -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'Rowanholt (proxy)' -Group Rowanholt -Direction Inbound -Protocol TCP `
    -LocalPort $ports -Action Allow | Out-Null
@{ Distribution = $Distro; Root = $Root; Ports = $ports } | ConvertTo-Json | Set-Content (Join-Path $State 'server.json')
$starter = Join-Path $State 'Start-RowanholtServer.ps1'
# deploy\windows\start-service.ps1, copied under its old name so a task registered before the move still finds it
Copy-Item (Join-Path $PSScriptRoot 'start-service.ps1') $starter -Force

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$starter`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName Rowanholt -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest `
    -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -Force -ErrorAction Stop | Out-Null

Write-Host 'Starting Rowanholt (the first start builds the images, which takes a while)...'
Start-ScheduledTask -TaskName Rowanholt -ErrorAction Stop
Write-Host ''
Write-Host "Rowanholt runs at boot as $($Credential.UserName), forwarding $($ports -join ', ') into WSL."
Write-Host "Follow the first start with: wsl -d $Distro -u root -- $Root/rowanholt status"
Write-Host "The rowanholt command inside: wsl -d $Distro -u root -- $Root/rowanholt <command>"

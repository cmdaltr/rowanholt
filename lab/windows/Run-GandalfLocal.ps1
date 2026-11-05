<#
.SYNOPSIS
  Runs Invoke-Gandalf.ps1 in Local mode with no prompts and copies the archive to
  the layout Elrond's --Gandalf mode reads:
    <AcquisitionsRoot>\powershell_collection\acquisitions\<COMPUTERNAME>\

.DESCRIPTION
  Invoke-Gandalf asks several Read-Host questions and has no switch to suppress
  them (it checks $NoPrompt, which is not a declared parameter). A function named
  Read-Host takes precedence over the cmdlet, so this wrapper answers them from a
  table and logs every question it answered. Remote mode is not driven here: it
  uses $host.UI.PromptForCredential, which can't be answered this way.
#>
[CmdletBinding()]
param(
    [string]$GandalfSource = "C:\lab\gandalf-src",
    [string]$AcquisitionsRoot = "C:\lab\acquisitions",
    [switch]$Memory,
    # Seeded files outside Gandalf's artefact set (expected.json's IOCs live in them),
    # collected with -CollectFiles; an empty list skips file collection
    [string[]]$Files = @("sync.ps1", "notes.txt"),
    # -LiveContainers asks the docker CLI for its running containers; -DockerHost points that CLI
    # at an engine elsewhere (the lab's throwaway one on the Mac, utm-vm.sh live-containers)
    [switch]$LiveContainers,
    [string]$DockerHost = ""
)
$ErrorActionPreference = "Stop"

$script:Answered = New-Object System.Collections.Generic.List[string]
function global:Read-Host {
    param([Parameter(Position = 0)]$Prompt, [switch]$AsSecureString, [switch]$MaskInput)
    $answer = switch -Regex ([string]$Prompt) {
        "no encryption"                  { "y"; break }
        "overwrite"                      { "Y"; break }
        "continue without|continue\?"    { "y"; break }
        "Collected"                      { ""; break }
        default                          { "" }
    }
    $script:Answered.Add("Q: $Prompt -> A: '$answer'")
    Write-Host "$Prompt $answer" -ForegroundColor DarkGray
    if ($AsSecureString) { return (ConvertTo-SecureString "lab-unused" -AsPlainText -Force) }
    return $answer
}

$entry = Join-Path $GandalfSource "windows\Invoke-Gandalf.ps1"
if (-not (Test-Path $entry)) { throw "Invoke-Gandalf.ps1 not found at $entry (is the repo shared into the VM?)" }

# Invoke-Gandalf runs from wherever it's installed; C:\TEMP\gandalf\gandalf keeps the lab's
# runs alike (and out of the seeded files Get-Files searches C:\ for).
$work = "C:\TEMP\gandalf\gandalf"
Remove-Item -Recurse -Force "C:\TEMP\gandalf" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Split-Path $work) | Out-Null
Copy-Item -Recurse $GandalfSource $work
# The copy's files.list, not the repo's: Get-Files reads it from the install path
if ($Files) { Set-Content -Path (Join-Path $work "lists\files.list") -Value $Files }
$entry = Join-Path $work "windows\Invoke-Gandalf.ps1"
$started = Get-Date

Push-Location (Join-Path $work "windows")
try {
    $gandalfArgs = @{ EncryptionObject = "None"; Acquisition = "Local"; OutputDirectory = "acquisitions" }
    if ($Memory) { $gandalfArgs.Memory = $true }
    if ($Files) { $gandalfArgs.CollectFiles = $true }
    if ($LiveContainers) {
        $gandalfArgs.LiveContainers = $true
        if (Test-Path "C:\lab\docker\docker.exe") { $env:PATH = "C:\lab\docker;$env:PATH" }
        if ($DockerHost) { $env:DOCKER_HOST = $DockerHost }
        Write-Host "docker: $((Get-Command docker -ErrorAction SilentlyContinue).Source) -> $env:DOCKER_HOST"
    }
    # Newer Invoke-Gandalf declares -NoPrompt; the Read-Host shim covers older copies.
    if ((Get-Command $entry).Parameters.ContainsKey("NoPrompt")) { $gandalfArgs.NoPrompt = $true }
    # Gandalf expects PowerShell's default "Continue": under "Stop" one artefact's
    # error ends the whole acquisition
    $ErrorActionPreference = "Continue"
    & $entry @gandalfArgs
    $ErrorActionPreference = "Stop"
} finally {
    Pop-Location
}

$dest = Join-Path $AcquisitionsRoot "powershell_collection\acquisitions\$env:COMPUTERNAME"
# Only this run's output: an earlier run's archive left here would be copied out as new
Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$found = Get-ChildItem -Recurse -File -Path "C:\TEMP\gandalf" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $started -and $_.Extension -in ".zip", ".7z", ".log", ".audit" }
$found | ForEach-Object { Copy-Item $_.FullName $dest -Force }
Copy-Item "C:\ProgramData\RivendellLab\expected.json" $dest -ErrorAction SilentlyContinue
$script:Answered | Set-Content (Join-Path $dest "prompts-answered.txt")

$archives = @($found | Where-Object Extension -in ".zip", ".7z")
if ($archives.Count -eq 0) {
    Write-Host "[x] Invoke-Gandalf produced no archive. Prompts answered:" -ForegroundColor Red
    $script:Answered | ForEach-Object { Write-Host "    $_" }
    exit 1
}
Write-Host "[+] $($archives.Count) archive(s) copied to $dest" -ForegroundColor Green

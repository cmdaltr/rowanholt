<#
 .Synopsis
 Collects forensic artefacts on Windows hosts; compatible with Ledger
 Version: 1.0
 Author : cmdaltr
 License: MIT
 .Description
 Collects digital forensic artefacts from Windows hosts. Output is compatible
  with Ledger, Rowanholt's analysis (https://github.com/cmdaltr/rowanholt)
 .Parameter EncryptionObject
 Method of encryption used for archive file - Key, Password or None
 .Parameter Acquisition
 Method of acquisition - either Remote or Local
 .Parameter OutputDirectory
 Destination directory of where the collected will be stored
 .Parameter Memory
 Collect a live memory dump
 .Parameter ShowProgress
 Print progress of individual artefact acquisition to screen
 .Parameter CollectFiles
 Collect files containing string (provided in files.list) in file name
 .Parameter LiveContainers
 Ask Docker about its running containers (inspect, processes, filesystem export); opt-in, as it
 touches the live host; every command is audited
 .Example
 The following example invokes all of the parameters with the default arguments;
   -EncryptionObject None -Acquisition Local -OutputDirectory C:\TEMP\gandalf\gandalf
  PS C:\> .\Invoke-Gandalf.ps1
 .Example
 The following example invokes all of the parameters with the default arguments;
  explicitly stated:
  PS C:\> .\Invoke-Gandalf.ps1 -EncryptionObject Key -Acquisition Local -OutputDirectory C:\TEMP\gandalf\gandalf
 .Example
 The following example invokes all of the parameters with non-default arguments;
  deployment against a remote host, specified by IP or Hostnames, a (less secure) 
  password-protected package, and outputted to the root directory on the D: drive.
  PS C:\> .\Invoke-Gandalf.ps1 -EncryptionObject Password -Acquisition <REMOTE_HOST> -OutputDirectory D: -Memory -ShowProgress
#>

Param(
    [Parameter(Mandatory = $True, Position = 0)][string]$EncryptionObject,
    [Parameter(Position = 1)][string]$Acquisition,
    [Parameter(Position = 2)][string]$OutputDirectory,
    [Parameter(Position = 3)][switch]$Memory,
    [Parameter(Position = 4)][switch]$ShowProgress,
    [Parameter(Position = 5)][switch]$CollectFiles,
    # Accept the defaults for every question (no encryption confirmation,
    # overwrite the output directory).
    [Parameter(Position = 6)][switch]$NoPrompt,
    [Parameter(Position = 7)][switch]$LiveContainers
)

function Format-Art {
    # A copy of QUIPS in src/common/quips.py, the source: this script runs on its own, so the
    # copy must match it
    $quotes = @(
        "Hash it before you trust it.",
        "Volatile first. The disk will wait; the RAM won't.",
        "If it isn't in the timeline, it didn't happen. If it is, prove it.",
        "Every artefact is innocent until correlated.",
        "The attacker cleared the logs. The logs about the logs are still here.",
        "Absence of evidence is a finding. Write it down.",
        "Time zones: the oldest adversary.",
        "Never analyse the original. Not even once. Especially not once.",
        "Prefetch remembers what the user would rather forget.",
        "The registry keeps secrets badly and grudges well.",
        "A clean system is either clean or very well cleaned.",
        "Your hypothesis is not your conclusion. Yet.",
        "Write the report as if the defence will read it. They will.",
        "Chain of custody: boring until the day it isn't.",
        "Correlation is a lead. Causation needs a second source.",
        "Timestamps lie. Four of them lie less.",
        "The first alert is rarely the first event.",
        "Living off the land still leaves footprints in the mud.",
        "Assume the clock is wrong until it proves otherwise.",
        "Scope creep is also an incident.",
        "Read the ShimCache, then distrust it accordingly.",
        "If the binary is signed, ask who signed it and why.",
        "Every persistence mechanism was somebody's convenience feature.",
        "The quietest host is worth a second look.",
        "Collect broadly. Conclude narrowly.",
        "No IOC survives contact with a competent adversary.",
        "Lateral movement leaves logons. Logons leave 4624s.",
        "Deleted is a state of mind. The MFT disagrees.",
        "Document now. Your memory is not evidence.",
        "The answer is in the data. The question is usually the problem."
    )
    Write-Host "
    `n`n`n`n`n
                             __             .___.__
        ____  __ __  _______/  |_  ____   __| _/|__|____    ____
      _/ ___\|  |  \/  ___/\   __\/  _ \ / __ | |  \__  \  /    \
      \  \___|  |  /\___ \  |  | (  <_> ) /_/ | |  |/ __ \|   |  \
       \___  >____//____  > |__|  \____/\____ | |__(____  /___|  /
           \/           \/                   \/         \/     \/
    "  -Foreground Magenta
    $quote = Get-Random -InputObject $quotes
    Write-Host "     $quote`n" -Foreground Gray
}

function Format-Time {
    Param ($TimeDifference)

    $Seconds = [math]::round($TimeDifference % 60)
    $Minutes = [math]::round($TimeDifference / 60 % 60)
    $Hours = [math]::round($TimeDifference / 60 / 60)

    if ($Hours -gt 1 -Or $Hours -eq 1) {
        if ($Hours -gt 1 -And $Minutes -gt 1 -And $Seconds -gt 1) {
            $ElapsedTime = "$Hours hours, $Minutes minutes and $Seconds seconds."
        }
        elseif ($Hours -gt 1 -And $Minutes -gt 1 -And $Seconds -eq 1) {
            $ElapsedTime = "$Hours hours, $Minutes minutes and $Seconds second."
        }
        elseif ($Hours -gt 1 -And $Minutes -eq 1 -And $Seconds -gt 1) {
            $ElapsedTime = "$Hours hours, $Minutes minute and $Seconds seconds."
        }
        elseif ($Hours -eq 1 -And $Minutes -gt 1 -And $Seconds -gt 1) {
            $ElapsedTime = "$Hours hour, $Minutes minutes and $Seconds seconds."
        }
        elseif ($Hours -gt 1 -And $Minutes -eq 1 -And $Seconds -eq 1) {
            $ElapsedTime = "$Hours hours, $Minutes minute and $Seconds second."
        }
        elseif ($Hours -eq 1 -And $Minutes -gt 1 -And $Seconds -eq 1) {
            $ElapsedTime = "$Hours hour, $Minutes minutes and $Seconds second."
        }
        elseif ($Hours -eq 1 -And $Minutes -eq 1 -And $Seconds -gt 1) {
            $ElapsedTime = "$Hours hour, $Minutes minute and $Seconds seconds."
        }
        elseif ($Hours -gt 1 -And $Minutes -gt 1 -And $Seconds -eq 0) {
            $ElapsedTime = "$Hours hours and $Minutes minutes."
        }
        elseif ($Hours -gt 1 -And $Minutes -eq 0 -And $Seconds -gt 0) {
            $ElapsedTime = "$Hours hours and $Seconds seconds."
        }
        elseif ($Hours -eq 1 -And $Minutes -gt 1 -And $Seconds -eq 0) {
            $ElapsedTime = "$Hours hour and $Minutes minutes."
        }
        elseif ($Hours -eq 1 -And $Minutes -eq 0 -And $Seconds -gt 0) {
            $ElapsedTime = "$Hours hour and $Seconds second."
        }
        elseif ($Hours -gt 1 -And $Minutes -eq 0 -And $Seconds -eq 0) {
            $ElapsedTime = "$Hours hours."
        }
        else {
            $ElapsedTime = "$Hours hour."
        }
    }
    elseif ($Minutes -gt 1 -Or $Minutes -eq 1) {
        if ($Minutes -gt 1 -And $Seconds -gt 1) {
            $ElapsedTime = "$Minutes minutes and $Seconds seconds."
        }
        elseif ($Minutes -eq 1 -And $Seconds -gt 1) {
            $ElapsedTime = "$Minutes minute and $Seconds seconds."
        }
        elseif ($Minutes -gt 1 -And $Seconds -eq 1) {
            $ElapsedTime = "$Minutes minute and $Seconds seconds."
        }
        elseif ($Minutes -eq 1 -And $Seconds -eq 1) {
            $ElapsedTime = "$Minutes minute and $Seconds second."
        }
        else {
            $ElapsedTime = "$Minutes minutes."
        }
    }
    else {
        if ($Seconds -gt 1) {
            $ElapsedTime = "$Seconds seconds."
        }
        else {
            $ElapsedTime = "$Seconds second."
        }
    }

    return $ElapsedTime
}

function Reset-Modules {
    Param ($EncryptionObject, $Session)

    if ($EncryptionObject -eq "Key" -Or $EncryptionObject -eq "Password") {
        try {
            Invoke-Command -Session $Session -ScriptBlock { Uninstall-Module -Name 7Zip4PowerShell -Force -ErrorAction SilentlyContinue }
            Remove-PSSession -Session $Session
        }
        catch {
            Write-Host "`n     Additional modules could not be removed"
        }
    }
    else {
        try {
            Uninstall-Module -Name 7Zip4PowerShell -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "`n     Additional modules could not be removed"
        }
    }
}

function Set-Defaults {
    Param ($EncryptionObject, $Acquisition, $OutputDirectory, $NoPrompt)

    if ($null -eq $Acquisition -Or $Acquisition -eq "" -Or $Acquisition -eq "Local") {
        $Acquisition = "Local"
    }
    else {
        $Acquisition = "Remote"
    }

    if ($EncryptionObject -eq "Key" -Or $EncryptionObject -eq "Password") {
        if ($EncryptionObject -eq "Key") {
            Write-Host "     You have chosen to use Key-based encryption but unfortunately this is not yet supported. Please try again`n`n"
            Exit
        }
        $ConfirmEncryption = Read-Host "     You have chosen to use encryption when archiving the artefacts. Although this is recommended, you will need an Internet connection on each endpoint, to download the additional modules.`n      Do you wish to proceed? Y/n [Y] "
        if ($ConfirmEncryption -eq "n") {
            Write-Host "      Please try again with the " -NoNewLine; Write-Host "-EncryptionObject" -NoNewLine -Foreground Magenta; Write-Host " parameter set to 'None'`n`n"
            Exit
        }
        Write-Host `r
    }
    elseif ($EncryptionObject -eq "None" -And $Acquisition -eq "Remote") {
        if (-Not ($NoPrompt)) {
            $ConfirmNoEncryption = Read-Host "     You have chosen to use no encryption when archiving the artefacts. This is not recommended.`n      Are you sure you want to proceed? y/N [N] "
            if ($ConfirmNoEncryption -ne "y") {
                Write-Host "      Please try again with the " -NoNewLine; Write-Host "-EncryptionObject" -NoNewLine -Foreground Magenta; Write-Host " parameter set to 'Key' or 'Password'`n`n"
                Exit
            }
        }
        else {
            $ConfirmNoEncryption = "y"
        }
    }
    elseif ($EncryptionObject -ne "None") {
        Write-Host "    '$EncryptionObject' is not a valid option for the -EncryptionObject parameter. You can choose from 'Key' (Most Secure), 'Password' or 'None' (Least Secure)`n`n"
        Exit
    }

    if ($null -eq $OutputDirectory -Or $OutputDirectory -eq "") {
        $OutputDirectory = "C:\TEMP\gandalf\acquisitions"
    }

    if (Test-Path -LiteralPath $OutputDirectory) {
        if (-Not($OutputDirectory.Startswith(".\"))) {
            $OutputDirectory = [IO.Path]::Combine(".\", $OutputDirectory)
        }
        if (-Not ($NoPrompt)) {
            $OverwriteDestination = Read-Host "    The destination of '$OutputDirectory' already exists. Do you wish to overwrite it? Y/n [Y]"
        }
        else {
            $OverwriteDestination = "y"
        }
        if ($OverwriteDestination -ne "n") {
            Remove-Item -Path $OutputDirectory -Recurse > $null
            New-Item -Path $OutputDirectory -ItemType Directory > $null
        }
        Write-Host `n
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory > $null
    }

    if ($Acquisition -eq "Local") {
        if (-not (Test-Path -LiteralPath $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -ErrorAction Stop | Out-Null
        }
    }

    return $EncryptionObject, $Acquisition, $OutputDirectory
}

function Set-ArtefactParams {
    # $TargetHome: where tools\ and lists\ are on the machine the collection runs on
    Param ($EncryptionObject, $OutputDirectory, $ShowProgress, $Memory, $CollectFiles, $Hostnames, $ArchiveObject, $GandalfHome, $TargetHome)

    $InvokeArtefactAcquisition = [IO.Path]::Combine($GandalfHome, "tools", "Invoke-ArtefactAcquisition.ps1"); $SetArtefactCollection = Join-Path $PSScriptRoot "Set-ArtefactCollection"
    $ArtefactParams = "Param(`$EncryptionObject = '$EncryptionObject', `$OutputDirectory = '$OutputDirectory', `$ShowProgress = '$ShowProgress', `$Memory = '$Memory', `$CollectFiles = '$CollectFiles', `$Hostnames = '$Hostnames', `$ArchiveObject = '$ArchiveObject', `$GandalfHome = '$TargetHome', `$LiveContainers = '$LiveContainers')"
    $ArtefactCollection = Get-Content -Path $SetArtefactCollection

    Add-Content -Path $InvokeArtefactAcquisition -Value $ArtefactParams
    Add-Content -Path $InvokeArtefactAcquisition -Value $ArtefactCollection
}

function Invoke-RemoteArtefactCollection {
    Param ($EncryptionObject, $OutputDirectory, $ShowProgress, $Memory, $CollectFiles, $DriveLetter, $Hostnames, $Session, $ArchiveObject, $GandalfHome)

    Set-ArtefactParams $EncryptionObject $OutputDirectory $ShowProgress $Memory $CollectFiles $Hostnames $ArchiveObject $GandalfHome "C:\TEMP\gandalf\gandalf"

    $ToolsPath = [IO.Path]::Combine($GandalfHome, "tools"); $DiskTools = [IO.Path]::Combine($ToolsPath, "disk_tools.zip"); $DumpIt = [IO.Path]::Combine($ToolsPath, "memory", "DumpIt.exe"); $DumpItx86 = [IO.Path]::Combine($ToolsPath, "memory", "DumpItx86.exe"); $InvokeArtefactAcquisition = [IO.Path]::Combine($ToolsPath, "Invoke-ArtefactAcquisition.ps1")

    Invoke-Command -Session $Session -ScriptBlock { if (Test-Path -LiteralPath "C:\TEMP\gandalf") { Remove-Item "C:\TEMP\gandalf" -Recurse -Force } }
    Invoke-Command -Session $Session -ScriptBlock { New-Item -Path "C:\TEMP\gandalf" -ItemType Directory > $null }; Invoke-Command -Session $Session -ScriptBlock { New-Item -Path "C:\TEMP\gandalf\gandalf" -ItemType Directory > $null }; Invoke-Command -Session $Session -ScriptBlock { New-Item -Path "C:\TEMP\gandalf\acquisitions" -ItemType Directory > $null }; Invoke-Command -Session $Session -ScriptBlock { New-Item -Path "C:\TEMP\gandalf\gandalf\tools" -ItemType Directory > $null }; Invoke-Command -Session $Session -ScriptBlock { New-Item -Path "C:\TEMP\gandalf\gandalf\tools\memory" -ItemType Directory > $null }; Invoke-Command -Session $Session -ScriptBlock { New-Item -Path "C:\TEMP\gandalf\gandalf\lists" -ItemType Directory > $null }
    if (Test-Path -LiteralPath $DiskTools) { Copy-Item -ToSession $Session -Path $DiskTools -Destination "C:\TEMP\gandalf\gandalf\tools\disk_tools.zip" -Force }; Copy-Item -ToSession $Session -Path $InvokeArtefactAcquisition -Destination "C:\TEMP\gandalf\gandalf\tools\Invoke-ArtefactAcquisition.ps1" -Force

    if ($Memory -And $Memory -ne "False") {
        Copy-Item -ToSession $Session -Path $DumpIt -Destination "C:\TEMP\gandalf\gandalf\tools\memory\DumpIt.exe" -Force; Copy-Item -ToSession $Session -Path $DumpItx86 -Destination "C:\TEMP\gandalf\gandalf\tools\memory\DumpItx86.exe" -Force
    }

    if ($CollectFiles -And $CollectFiles -ne "False") {
        Copy-Item -ToSession $Session -Path ([IO.Path]::Combine($GandalfHome, "lists", "files.list")) -Destination "C:\TEMP\gandalf\gandalf\lists\files.list" -Force
    }

    # -FilePath is read here and sent: the copy generated in this install
    Invoke-Command -Session $Session -FilePath ([IO.Path]::Combine($GandalfHome, "tools", "Invoke-ArtefactAcquisition.ps1"))
    Remove-PSSession -Session $Session
    Invoke-RemoteArchiveCollection $OutputDirectory $Hostnames $ArchiveObject $GandalfHome
}

function Invoke-RemoteArchiveCollection {
    Param ($OutputDirectory, $Hostnames, $ArchiveObject, $GandalfHome)

    $FilePath = [IO.Path]::Combine($GandalfHome, $OutputDirectory, $Hostnames)
    $Session = New-PSSession -ComputerName $Hostnames -Credential $RemoteCredentials

    Write-Progress "Collecting acquired artefacts from '$Hostnames'..."
    $RemoteComputer = Invoke-Command -Session $Session -ScriptBlock { $env:COMPUTERNAME }
    New-Item -Path $OutputDirectory\$RemoteComputer -ItemType Directory > $null

    $LogSource = [IO.Path]::Combine($OutputDirectory, $RemoteComputer, "log.audit"); $LogDestination = [IO.Path]::Combine($FilePath, "log.audit"); $MetaSource = [IO.Path]::Combine($OutputDirectory, $RemoteComputer, "artefacts", "log.meta"); $MetaDestination = [IO.Path]::Combine($FilePath, "log.meta"); $ZipSource = [IO.Path]::Combine($OutputDirectory, $RemoteComputer, "$RemoteComputer.zip"); $ZipDestination = [IO.Path]::Combine($FilePath, "$RemoteComputer.zip"); $7ZSource = [IO.Path]::Combine($OutputDirectory, $RemoteComputer, "$RemoteComputer.7z"); $7ZDestination = [IO.Path]::Combine($FilePath, "$RemoteComputer.7z")
    Copy-Item -FromSession $Session -Path $LogSource -Destination $LogDestination -Force > $null 2>&1
    Copy-Item -FromSession $Session -Path $MetaSource -Destination $MetaDestination -Force > $null 2>&1
    Copy-Item -FromSession $Session -Path $ZipSource -Destination $ZipDestination -Force > $null 2>&1
    Copy-Item -FromSession $Session -Path $7zSource -Destination $7zDestination -Force > $null 2>&1

    Write-Host "`n   -> Collected acquired artefacts from '$Hostnames'"
    Write-Progress "Cleaning up '$Hostnames'..."

    Invoke-Command -Session $Session -ScriptBlock { Remove-Item -Path "C:\TEMP\gandalf" -Recurse }
    Remove-PSSession -Session $Session
    $Session = New-PSSession -ComputerName $Hostnames -Credential $RemoteCredentials

    Reset-Modules $EncryptionObject $Session

    Write-Progress -Activity "_" -Completed
}

# Gathering Date/Time information
$DateTime = "{0}" -f (Get-Date)
$StartTime = Get-Date -Date $DateTime -UFormat %s
$StartTime = [convert]::ToInt32($StartTime)
$global:ProgressPreference = "Continue"
$Environment = Get-ChildItem -Path Env:

# Checking if ps1 file is running on Windows or *nix
if (($Environment -like "*XPC_*" -Or $Environment -like "*com.apple.Terminal*" -Or $Environment -like "*/bin/zsh*" -Or $Environment -like "*com.apple.launchd.*") -Or ($Environment -like "*XDG_*" -Or $Environment -like "*/Terminal/*" -Or $Environment -like "*/bin/bash*" -Or $Environment -like "*/home/*")) {
    $GandalfRoot = [IO.Path]::Combine("/tmp", "gandalf")
}
else {
    $GandalfRoot = [IO.Path]::Combine("C:\", "TEMP", "gandalf")
}
# The install: tools\, lists\ and windows\ (this script) side by side. It used to have
# to be C:\TEMP\gandalf\gandalf (G13); that is now only the staging folder on remote targets.
$GandalfHome = Split-Path -Parent $PSScriptRoot
$DiskToolsPath = [IO.Path]::Combine($GandalfHome, "tools", "disk_tools.zip")

# disk_tools.zip (RawCopy, third-party, not shipped) is only a fallback: locked files are read off
# the raw volume first, then from a temporary shadow copy, so nothing is lost without it
if (-Not (Test-Path -LiteralPath $DiskToolsPath)) {
    Write-Host "      '$DiskToolsPath' isn't there: locked files are read off the raw volume, with a shadow copy as the fallback (docs/CLI.md)." -Foreground White
}

# Removing files which if exist during second attempt will cause failures
$ArtefactAquisitionPath = [IO.Path]::Combine($GandalfHome, "tools", "Invoke-ArtefactAcquisition.ps1")
$RemnantFiles = @("$GandalfHome\tools\RawCopy.exe", "$GandalfHome\tools\RawCopy64.exe", "$GandalfHome\tools\sleuthkit-4.12.1-win32", "$GandalfHome\tools\sleuthkit-4.12.1-win32.zip", "$GandalfHome\tools\icat", "$GandalfHome\tools\tsk", $ArtefactAquisitionPath)
ForEach ($RemnantFile in $RemnantFiles) {
    if (Test-Path -LiteralPath $RemnantFile) {
        Remove-Item $RemnantFile -Recurse -Force
    }
}

Clear-Host
Format-Art

if (-Not ($NoPrompt)) {
    Write-Host `r
}

# Exiting if running .ps1 file locally on *nix
if ($GandalfRoot -eq "/tmp/gandalf" -And $Acquisition -eq "Local") {
    Write-Host "      Invoke-Gandalf.ps1 is not designed to run Locally on Linux/macOS devices."; Write-Host "       Please use gandalf.py instead.`n`n"
    Exit
}

# Setting default parameters
$EncryptionObject, $Acquisition, $OutputDirectory = Set-Defaults $EncryptionObject $Acquisition $OutputDirectory $NoPrompt

if ($EncryptionObject -eq "Key") {
    $ArchiveObject = Read-Host "     Provide path to PGP Public Key for archive encryption"
}
elseif ($EncryptionObject -eq "Password") {
    $ArchiveObject = Read-Host "     Enter Password for archive encryption" -AsSecureString
    $ArchiveObject = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchiveObject)
    $ArchiveObject = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ArchiveObject)
}
else {
    $ArchiveObject = "None"
}

Write-Host `r

if ($Acquisition -eq "Local") {
    $Hostnames = $env:COMPUTERNAME
    Set-ArtefactParams $EncryptionObject $OutputDirectory $ShowProgress $Memory $CollectFiles $Hostnames $ArchiveObject $GandalfHome $GandalfHome
    & $ArtefactAquisitionPath
}
else {
    $RemoteCredentials = $host.ui.PromptForCredential("Local Admin authentication required", "Please enter credentials for PowerShell remoting", "", "")
    $HostListPath = [IO.Path]::Combine("lists", "hosts.list")
    $Hostnames = Get-Content $HostListPath
    $Session = New-PSSession -ComputerName $Hostnames -Credential $RemoteCredentials -ErrorAction SilentlyContinue -ErrorVariable SessionError
    if ($SessionError) {
        if ((Select-String -InputObject $SessionError -Pattern "server name cannot be resolved") -Or (Select-String -InputObject $SessionError -Pattern "Access is denied")) { 
            if (Select-String -InputObject $SessionError -Pattern "server name cannot be resolved") { 
                Write-Host "      FAILURE: Server name '$Hostnames' could not be resolved." -Foreground Red; Write-Host "       Perhaps the host is offline or there is a networking issue?" -Foreground White
                $ContinueAcquisition = Read-Host "      Do you wish to continue? Y/n [Y] "
                if ($ContinueAcquisition -eq "n") {
                    Write-Host "`r      Please try again.`n`n"
                    Exit
                }
            }
            elseif (Select-String -InputObject $SessionError -Pattern "Access is denied") { 
                Write-Host "      FAILURE: Invalid credentials provided to access '$Hostnames'." -Foreground Red; Write-Host "       Ensure you are using an account which is a member of the necessary Administrators Group" -Foreground White
                $ContinueAcquisition = Read-Host "      Do you wish to continue? Y/n [Y] "
                if ($ContinueAcquisition -eq "n") {
                    Write-Host "`r      Please try again.`n`n"
                    Exit
                }
            }
        }
    }
    else {
        Write-Host "      Session(s) opened for '$Hostnames'" -ForegroundColor Green
        Invoke-RemoteArtefactCollection $EncryptionObject $OutputDirectory $ShowProgress $Memory $CollectFiles $DriveLetter $Hostnames $Session $ArchiveObject $GandalfHome
    }
}

# Removing files only needed during acquisition
ForEach ($RemnantFile in $RemnantFiles) {
    if (Test-Path -LiteralPath $RemnantFile) {
        Remove-Item $RemnantFile -Recurse -Force
    }
}

# Gathering Date/Time information
$DateTime = "{0}" -f (Get-Date)
$EndTime = Get-Date -Date $DateTime -UFormat %s
$EndTime = [convert]::ToInt32($EndTime)
$TimeDifference = $EndTime - $StartTime
$ElapsedTime = Format-Time $TimeDifference

# Finishing
Write-Host "`n`n  -> Finished. Total elapsed time: $ElapsedTime`n    ----------------------------------------" -Foreground Gray
Write-Host "      Custodian completed for:"

ForEach ($EachHost in $Hostnames.split("`n")) {
    Write-Host "       - $EachHost"
}

Write-Host `n`n

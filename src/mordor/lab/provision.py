"""
Turn a fresh machine into one a recording can run on, in one click per step, run inside the
machine itself (docker exec / tart exec / utmctl exec). Ported from Shikari. The lab's own Windows
VM is set up by ./lab.sh mordor-sensor instead (Sysmon too), which the lab agent runs. The steps:

  logging   the OS's native audit logging the detections rely on (auditd rules on Linux;
            Endpoint Security / unified log on macOS; Security, PowerShell and audit on Windows)
  powershell  PowerShell 7, which Atomic Red Team runs under
  atomics   Invoke-AtomicRedTeam and the atomics folder

Each step is a script for the machine's OS. A step that finishes is remembered
(registry) so the page can show it's done. These change the machine — they're meant
for a disposable VM you've snapshotted, which the page says before running them.
"""

from typing import Dict, List

from . import registry
from .engines import engine_for
from .runner import LabError, safe_name

# Per OS: the interpreter inside the guest, and each step's script
_SHELL = ["bash", "-lc"]
# Windows PowerShell 5.1: every Windows install has it; PowerShell 7 is an extra
_POWERSHELL = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

STEPS = {
    "linux": {
        "interp": _SHELL,
        "logging": (
            "set -e; "
            "if command -v apt-get >/dev/null; then sudo apt-get update -y && sudo apt-get install -y auditd; fi; "
            "curl -sL https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules "
            "| sudo tee /etc/audit/rules.d/attack.rules >/dev/null; "
            "sudo augenrules --load 2>/dev/null || true; "
            "(sudo systemctl restart auditd 2>/dev/null || sudo service auditd restart 2>/dev/null || true); "
            "echo 'auditd rules loaded'"),
        "powershell": (
            "set -e; "
            "if ! command -v pwsh >/dev/null; then "
            "  curl -sL https://aka.ms/install-powershell.sh | sudo bash || "
            "  (sudo apt-get update -y && sudo apt-get install -y powershell); fi; "
            "pwsh --version"),
        "atomics": (
            "set -e; pwsh -NoProfile -Command "
            "\"Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force; "
            "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); "
            "Install-AtomicRedTeam -getAtomics -Force\""),
    },
    "macos": {
        "interp": _SHELL,
        "logging": (
            "echo 'macOS records through Endpoint Security (eslogger) and the unified log, "
            "both built in. eslogger needs Full Disk Access for the terminal running it, "
            "which is granted in System Settings and cannot be set from here.'; "
            "log stats --status 2>/dev/null || true"),
        "powershell": (
            "set -e; if ! command -v pwsh >/dev/null; then brew install --quiet powershell/tap/powershell || "
            "brew install --quiet powershell; fi; pwsh --version"),
        "atomics": (
            "set -e; pwsh -NoProfile -Command "
            "\"Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force; "
            "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); "
            "Install-AtomicRedTeam -getAtomics -Force\""),
    },
    "windows": {
        "interp": _POWERSHELL,
        "logging": (
            "auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable; "
            "reg add 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' "
            "/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f; "
            "reg add 'HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
            "/v EnableScriptBlockLogging /t REG_DWORD /d 1 /f; "
            "auditpol /set /category:'Logon/Logoff','Account Management','Object Access',"
            "'Policy Change','Privilege Use','DS Access' /success:enable /failure:enable; "
            "Write-Output 'Windows audit policy set'"),
        "powershell": "$PSVersionTable.PSVersion.ToString()",  # Windows images ship PowerShell
        "atomics": (
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null; "
            "Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force; "
            "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); "
            "Install-AtomicRedTeam -getAtomics -Force"),
    },
}
ORDER = ["logging", "powershell", "atomics"]
LABELS = {"logging": "Turn on audit logging", "powershell": "Install PowerShell 7",
          "atomics": "Install Atomic Red Team"}


def steps_for(os_name: str) -> List[Dict]:
    """The provisioning steps for a machine's OS, in order, with their labels."""
    if os_name not in STEPS:
        return []
    return [{"step": s, "label": LABELS[s]} for s in ORDER]


def run_step(engine_key: str, name: str, os_name: str, step: str, timeout: int = 1200) -> str:
    """Run one provisioning step inside the machine and remember it if it finishes."""
    name = safe_name(name)
    spec = STEPS.get(os_name)
    if not spec:
        raise LabError("No provisioning for this OS", os_name)
    script = spec.get(step)
    if not script:
        raise LabError("Unknown step", step)
    engine = engine_for(engine_key)
    try:
        out = engine.exec(name, [*spec["interp"], script], timeout=timeout)
    except LabError as e:
        # tart exec needs the guest agent; say so rather than a bare failure
        if engine_key == "tart":
            raise LabError("Couldn't run it in the VM",
                           "Tart runs commands through its guest agent. The Cirrus Labs base "
                           "images include it; a custom image may not. " + (e.detail or ""))
        raise
    registry.mark_provisioned(engine_key, name, step)
    return out

#!/usr/bin/env python3 -tt
"""
Misplaced Binaries Detection (MITRE ATT&CK T1036.005)

Detects Windows system binaries found in unexpected locations, which may indicate
masquerading attacks where adversaries rename/copy legitimate binaries to evade detection.

Reference: https://attack.mitre.org/techniques/T1036/005/
"""

import os
import csv
from datetime import datetime

# Windows system binaries and their expected locations
# Format: binary_name -> list of expected paths (case-insensitive)
WINDOWS_SYSTEM_BINARIES = {
    # Core system binaries (System32)
    "cmd.exe": ["windows/system32"],
    "powershell.exe": ["windows/system32/windowspowershell/v1.0", "windows/syswow64/windowspowershell/v1.0"],
    "pwsh.exe": ["program files/powershell"],
    "svchost.exe": ["windows/system32"],
    "csrss.exe": ["windows/system32"],
    "smss.exe": ["windows/system32"],
    "wininit.exe": ["windows/system32"],
    "winlogon.exe": ["windows/system32"],
    "services.exe": ["windows/system32"],
    "lsass.exe": ["windows/system32"],
    "lsaiso.exe": ["windows/system32"],
    "taskhost.exe": ["windows/system32"],
    "taskhostw.exe": ["windows/system32"],
    "dwm.exe": ["windows/system32"],
    "conhost.exe": ["windows/system32"],
    "explorer.exe": ["windows"],
    "rundll32.exe": ["windows/system32", "windows/syswow64"],
    "regsvr32.exe": ["windows/system32", "windows/syswow64"],
    "msiexec.exe": ["windows/system32", "windows/syswow64"],
    "mshta.exe": ["windows/system32", "windows/syswow64"],
    "cscript.exe": ["windows/system32", "windows/syswow64"],
    "wscript.exe": ["windows/system32", "windows/syswow64"],
    "certutil.exe": ["windows/system32"],
    "bitsadmin.exe": ["windows/system32"],
    "net.exe": ["windows/system32"],
    "net1.exe": ["windows/system32"],
    "netsh.exe": ["windows/system32"],
    "sc.exe": ["windows/system32"],
    "schtasks.exe": ["windows/system32"],
    "at.exe": ["windows/system32"],
    "reg.exe": ["windows/system32"],
    "regedit.exe": ["windows"],
    "tasklist.exe": ["windows/system32"],
    "taskkill.exe": ["windows/system32"],
    "wmic.exe": ["windows/system32/wbem"],
    "mmc.exe": ["windows/system32"],
    "control.exe": ["windows/system32"],
    "notepad.exe": ["windows/system32", "windows"],
    "calc.exe": ["windows/system32"],
    "write.exe": ["windows/system32", "windows"],
    "wordpad.exe": ["program files/windows nt/accessories"],

    # Potentially abused utilities
    "attrib.exe": ["windows/system32"],
    "cacls.exe": ["windows/system32"],
    "icacls.exe": ["windows/system32"],
    "takeown.exe": ["windows/system32"],
    "xcopy.exe": ["windows/system32"],
    "robocopy.exe": ["windows/system32"],
    "compact.exe": ["windows/system32"],
    "expand.exe": ["windows/system32"],
    "makecab.exe": ["windows/system32"],
    "extrac32.exe": ["windows/system32"],
    "esentutl.exe": ["windows/system32"],
    "replace.exe": ["windows/system32"],
    "print.exe": ["windows/system32"],
    "ftp.exe": ["windows/system32"],
    "finger.exe": ["windows/system32"],
    "bash.exe": ["windows/system32"],
    "wsl.exe": ["windows/system32"],

    # Diagnostic/debug tools often abused
    "cmstp.exe": ["windows/system32"],
    "msconfig.exe": ["windows/system32"],
    "msbuild.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],
    "installutil.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],
    "regasm.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],
    "regsvcs.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],
    "vbc.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],
    "csc.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],
    "jsc.exe": ["windows/microsoft.net/framework", "windows/microsoft.net/framework64"],

    # Network utilities
    "ping.exe": ["windows/system32"],
    "tracert.exe": ["windows/system32"],
    "nslookup.exe": ["windows/system32"],
    "ipconfig.exe": ["windows/system32"],
    "arp.exe": ["windows/system32"],
    "route.exe": ["windows/system32"],
    "netstat.exe": ["windows/system32"],
    "hostname.exe": ["windows/system32"],
    "whoami.exe": ["windows/system32"],
    "systeminfo.exe": ["windows/system32"],
    "quser.exe": ["windows/system32"],
    "qwinsta.exe": ["windows/system32"],
    "query.exe": ["windows/system32"],

    # PowerShell-related
    "powershell_ise.exe": ["windows/system32/windowspowershell/v1.0"],

    # Remote access
    "mstsc.exe": ["windows/system32"],
    "msra.exe": ["windows/system32"],
    "shutdown.exe": ["windows/system32"],

    # Security-related
    "bcdedit.exe": ["windows/system32"],
    "vssadmin.exe": ["windows/system32"],
    "wbadmin.exe": ["windows/system32"],
    "diskshadow.exe": ["windows/system32"],

    # Windows Defender
    "mpcmdrun.exe": ["program files/windows defender", "programdata/microsoft/windows defender/platform"],
}


def detect_misplaced_binaries(mnt, output_directory, verbosity, img, vssimage):
    """
    Scan mounted disk image for Windows system binaries in unexpected locations.

    Args:
        mnt: Mount point path
        output_directory: Output directory for results
        verbosity: Verbosity level
        img: Image identifier
        vssimage: VSS image name

    Returns:
        List of findings (dicts with path, expected_location, etc.)
    """
    findings = []

    print(f"\n       \033[1;33mScanning for misplaced system binaries in {vssimage}...\033[1;m")

    # Walk the mounted filesystem
    for root, dirs, files in os.walk(mnt):
        for filename in files:
            filename_lower = filename.lower()

            # Check if this is a known system binary
            if filename_lower in WINDOWS_SYSTEM_BINARIES:
                full_path = os.path.join(root, filename)
                relative_path = root.replace(mnt, "").lower().lstrip("/\\")

                # Normalize path separators
                relative_path = relative_path.replace("\\", "/")

                # Check if it's in an expected location
                expected_locations = WINDOWS_SYSTEM_BINARIES[filename_lower]
                is_expected = False

                for expected in expected_locations:
                    # Check if the relative path starts with or contains the expected location
                    if expected in relative_path:
                        is_expected = True
                        break

                if not is_expected:
                    # This is a misplaced binary - potential masquerading
                    finding = {
                        "timestamp": datetime.now().isoformat(),
                        "hostname": vssimage.replace("'", ""),
                        "binary_name": filename,
                        "found_path": full_path.replace(mnt, ""),
                        "expected_locations": ", ".join(expected_locations),
                        "mitre_technique": "T1036.005",
                        "description": "Masquerading: Match Legitimate Name or Location"
                    }
                    findings.append(finding)

                    if verbosity:
                        print(f"        [!] Misplaced binary: {filename} found in {relative_path}")
                        print(f"            Expected in: {', '.join(expected_locations)}")

    # Write findings to CSV
    if findings:
        csv_path = os.path.join(output_directory, img.split("::")[0], "analysis", "misplaced_binaries.csv")
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        fieldnames = ["timestamp", "hostname", "binary_name", "found_path", "expected_locations", "mitre_technique", "description"]

        file_exists = os.path.exists(csv_path)
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerows(findings)

        print(f"\n       \033[1;32mFound {len(findings)} misplaced binaries - results written to misplaced_binaries.csv\033[1;m")
    else:
        print(f"\n       \033[1;32mNo misplaced binaries detected in {vssimage}\033[1;m")

    return findings

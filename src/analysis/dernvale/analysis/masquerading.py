#!/usr/bin/env python3 -tt
"""
Masquerading Detection (MITRE ATT&CK T1036)

Detects various masquerading techniques used by adversaries to evade detection:
- T1036.002: Right-to-Left Override (RLO) characters in filenames
- T1036.003: Renamed system utilities (executables with wrong names)
- T1036.004: Masquerade Task or Service (suspicious scheduled task names)
- T1036.006: Space after Filename (trailing spaces)
- T1036.007: Double File Extension (e.g., document.pdf.exe)

Reference: https://attack.mitre.org/techniques/T1036/
"""

import os
import csv
import re
import hashlib
from datetime import datetime

# Unicode Right-to-Left Override characters
RLO_CHARACTERS = [
    '\u202E',  # RIGHT-TO-LEFT OVERRIDE
    '\u202D',  # LEFT-TO-RIGHT OVERRIDE
    '\u202C',  # POP DIRECTIONAL FORMATTING
    '\u200E',  # LEFT-TO-RIGHT MARK
    '\u200F',  # RIGHT-TO-LEFT MARK
    '\u2066',  # LEFT-TO-RIGHT ISOLATE
    '\u2067',  # RIGHT-TO-LEFT ISOLATE
    '\u2068',  # FIRST STRONG ISOLATE
    '\u2069',  # POP DIRECTIONAL ISOLATE
]

# Executable extensions (case-insensitive)
EXECUTABLE_EXTENSIONS = {
    'exe', 'dll', 'sys', 'drv', 'ocx', 'scr', 'cpl', 'msi',
    'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse',
    'ws', 'wsf', 'wsc', 'wsh', 'ps1', 'psm1', 'psd1',
    'msc', 'hta', 'jar', 'reg'
}

# Document/media extensions commonly used for double extension attacks
DOCUMENT_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'txt', 'rtf', 'odt', 'ods', 'odp',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'ico',
    'mp3', 'mp4', 'avi', 'mov', 'wmv', 'wav', 'flac',
    'zip', 'rar', '7z', 'tar', 'gz'
}

# Known Windows system binary hashes (SHA256) mapped to their legitimate names
# This is a small sample - in production you'd want a larger database
KNOWN_BINARY_HASHES = {
    # These would be populated with actual hashes of known Windows binaries
    # For demonstration, this shows the structure
}

# Suspicious patterns in scheduled task/service names
SUSPICIOUS_TASK_PATTERNS = [
    r'^[a-f0-9]{32}$',  # MD5-like names
    r'^[a-f0-9]{64}$',  # SHA256-like names
    r'^\d+$',  # Numeric only
    r'^[a-zA-Z]{1,3}$',  # Very short names (1-3 chars)
    r'update.*service',  # Fake update services
    r'windows.*update',
    r'microsoft.*update',
    r'system.*service',
    r'svc.*host',
    r'chrome.*update',
    r'adobe.*update',
    r'java.*update',
]


def detect_rlo_characters(filename):
    """
    Detect Right-to-Left Override characters in filename (T1036.002).

    Example: "document[RLO]cod.exe" displays as "documentexe.doc"
    """
    findings = []
    for char in RLO_CHARACTERS:
        if char in filename:
            findings.append({
                "technique": "T1036.002",
                "technique_name": "Right-to-Left Override",
                "detail": f"RLO character U+{ord(char):04X} found in filename"
            })
    return findings


def detect_double_extension(filename):
    """
    Detect double file extensions (T1036.007).

    Example: "invoice.pdf.exe" appears as PDF but is executable
    """
    findings = []

    # Split filename by dots
    parts = filename.lower().split('.')

    if len(parts) >= 3:  # Need at least name.ext1.ext2
        # Get last two extensions
        last_ext = parts[-1]
        second_last_ext = parts[-2]

        # Check if last extension is executable and second-to-last is document/media
        if last_ext in EXECUTABLE_EXTENSIONS and second_last_ext in DOCUMENT_EXTENSIONS:
            findings.append({
                "technique": "T1036.007",
                "technique_name": "Double File Extension",
                "detail": f"Executable extension '.{last_ext}' hidden after '.{second_last_ext}'"
            })

        # Also check for patterns like "file.exe.txt" (hiding exe)
        if second_last_ext in EXECUTABLE_EXTENSIONS and last_ext in DOCUMENT_EXTENSIONS:
            findings.append({
                "technique": "T1036.007",
                "technique_name": "Double File Extension",
                "detail": f"Possible hidden executable '.{second_last_ext}' with '.{last_ext}' suffix"
            })

    return findings


def detect_trailing_space(filename):
    """
    Detect space after filename (T1036.006).

    Example: "legitimate.exe " (with trailing space) to evade detection
    """
    findings = []

    if filename.endswith(' ') or filename.endswith('\t'):
        findings.append({
            "technique": "T1036.006",
            "technique_name": "Space after Filename",
            "detail": "Filename has trailing whitespace"
        })

    # Also check for spaces before the extension
    parts = filename.rsplit('.', 1)
    if len(parts) == 2:
        name, ext = parts
        if name.endswith(' ') or name.endswith('\t'):
            findings.append({
                "technique": "T1036.006",
                "technique_name": "Space after Filename",
                "detail": "Whitespace before file extension"
            })

    return findings


def detect_suspicious_task_names(filename, filepath):
    """
    Detect masqueraded task or service names (T1036.004).

    Checks for suspicious patterns in scheduled task XML files.
    """
    findings = []

    # Check if this is a scheduled task file
    if 'tasks' in filepath.lower() and filename.lower().endswith('.xml'):
        task_name = filename.rsplit('.', 1)[0]

        for pattern in SUSPICIOUS_TASK_PATTERNS:
            if re.match(pattern, task_name, re.IGNORECASE):
                findings.append({
                    "technique": "T1036.004",
                    "technique_name": "Masquerade Task or Service",
                    "detail": f"Suspicious task name pattern: '{task_name}'"
                })
                break

    return findings


def detect_executable_in_wrong_location(filename, filepath):
    """
    Detect renamed legitimate utilities (T1036.003).

    Finds executables with system-like names in non-system locations.
    """
    findings = []

    # Common system utilities that shouldn't be in user directories
    system_binaries = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe', 'svchost.exe',
        'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wscript.exe',
        'cscript.exe', 'certutil.exe', 'bitsadmin.exe', 'net.exe',
        'netsh.exe', 'sc.exe', 'tasklist.exe', 'taskkill.exe',
        'wmic.exe', 'msiexec.exe', 'reg.exe', 'regedit.exe'
    }

    filename_lower = filename.lower()
    filepath_lower = filepath.lower()

    # Check if filename matches a system binary name
    if filename_lower in system_binaries:
        # Check if it's in a suspicious location (not System32, SysWOW64, Windows)
        suspicious_locations = ['users', 'temp', 'tmp', 'appdata', 'programdata', 'downloads', 'desktop']

        for loc in suspicious_locations:
            if loc in filepath_lower:
                findings.append({
                    "technique": "T1036.003",
                    "technique_name": "Rename System Utilities",
                    "detail": f"System binary '{filename}' found in non-system location"
                })
                break

    # Check for typosquatting (similar names to system binaries)
    typosquat_patterns = [
        (r'svch0st\.exe', 'svchost.exe'),  # Zero instead of 'o'
        (r'svhost\.exe', 'svchost.exe'),   # Missing 'c'
        (r'scvhost\.exe', 'svchost.exe'),  # Swapped letters
        (r'lssas\.exe', 'lsass.exe'),      # Extra 's'
        (r'csrs\.exe', 'csrss.exe'),       # Missing 's'
        (r'cssrs\.exe', 'csrss.exe'),      # Extra 's'
        (r'explore\.exe', 'explorer.exe'), # Missing 'r'
        (r'explor\.exe', 'explorer.exe'),  # Missing 'er'
        (r'iexplore\.exe', 'iexplore.exe'),# Legitimate but often spoofed
        (r'chorme\.exe', 'chrome.exe'),    # Typo
        (r'chrorne\.exe', 'chrome.exe'),   # Using 'rn' to look like 'm'
        (r'firef0x\.exe', 'firefox.exe'),  # Zero instead of 'o'
    ]

    for pattern, legit_name in typosquat_patterns:
        if re.match(pattern, filename_lower):
            findings.append({
                "technique": "T1036.003",
                "technique_name": "Rename System Utilities",
                "detail": f"Possible typosquatted name '{filename}' (similar to '{legit_name}')"
            })

    return findings


def detect_unicode_lookalikes(filename):
    """
    Detect Unicode characters that look like ASCII but aren't.

    Example: Using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
    """
    findings = []

    # Common Unicode lookalike substitutions
    lookalikes = {
        'а': 'a',  # Cyrillic
        'е': 'e',  # Cyrillic
        'о': 'o',  # Cyrillic
        'р': 'p',  # Cyrillic
        'с': 'c',  # Cyrillic
        'х': 'x',  # Cyrillic
        'і': 'i',  # Ukrainian
        'ј': 'j',  # Serbian
        'ѕ': 's',  # Macedonian
        'ᴀ': 'a',  # Small caps
        'ᴇ': 'e',  # Small caps
        'ꜱ': 's',  # Modifier letter
    }

    for char in filename:
        if char in lookalikes:
            findings.append({
                "technique": "T1036.003",
                "technique_name": "Rename System Utilities",
                "detail": f"Unicode lookalike character '{char}' (U+{ord(char):04X}) found, looks like '{lookalikes[char]}'"
            })

    return findings


def detect_masquerading(mnt, output_directory, verbosity, img, vssimage):
    """
    Scan mounted disk image for masquerading techniques.

    Args:
        mnt: Mount point path
        output_directory: Output directory for results
        verbosity: Verbosity level
        img: Image identifier
        vssimage: VSS image name

    Returns:
        List of findings (dicts with technique details)
    """
    all_findings = []

    print(f"\n       \033[1;33mScanning for masquerading techniques in {vssimage}...\033[1;m")

    checks = [
        ("Right-to-Left Override (T1036.002)", detect_rlo_characters, "filename"),
        ("Double File Extension (T1036.007)", detect_double_extension, "filename"),
        ("Trailing Space (T1036.006)", detect_trailing_space, "filename"),
        ("Unicode Lookalikes", detect_unicode_lookalikes, "filename"),
        ("Suspicious Task Names (T1036.004)", detect_suspicious_task_names, "both"),
        ("Renamed Utilities (T1036.003)", detect_executable_in_wrong_location, "both"),
    ]

    file_count = 0

    # Walk the mounted filesystem
    for root, dirs, files in os.walk(mnt):
        for filename in files:
            file_count += 1
            full_path = os.path.join(root, filename)
            relative_path = root.replace(mnt, "").lstrip("/\\")

            for check_name, check_func, check_type in checks:
                try:
                    if check_type == "filename":
                        findings = check_func(filename)
                    else:  # "both"
                        findings = check_func(filename, relative_path)

                    for finding in findings:
                        result = {
                            "timestamp": datetime.now().isoformat(),
                            "hostname": vssimage.replace("'", ""),
                            "filename": filename,
                            "path": full_path.replace(mnt, ""),
                            "technique_id": finding["technique"],
                            "technique_name": finding["technique_name"],
                            "detail": finding["detail"],
                        }
                        all_findings.append(result)

                        if verbosity:
                            print(f"        [!] {finding['technique']}: {filename}")
                            print(f"            {finding['detail']}")
                            print(f"            Path: {relative_path}")

                except Exception as e:
                    if verbosity:
                        print(f"        Warning: Error checking {filename}: {str(e)}")

    # Write findings to CSV
    if all_findings:
        csv_path = os.path.join(output_directory, img.split("::")[0], "analysis", "masquerading.csv")
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        fieldnames = ["timestamp", "hostname", "filename", "path", "technique_id", "technique_name", "detail"]

        file_exists = os.path.exists(csv_path)
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerows(all_findings)

        # Group findings by technique for summary
        technique_counts = {}
        for f in all_findings:
            tid = f["technique_id"]
            technique_counts[tid] = technique_counts.get(tid, 0) + 1

        print(f"\n       \033[1;32mFound {len(all_findings)} masquerading indicators:\033[1;m")
        for tid, count in sorted(technique_counts.items()):
            print(f"         - {tid}: {count} finding(s)")
        print(f"       Results written to masquerading.csv")
    else:
        print(f"\n       \033[1;32mNo masquerading techniques detected in {vssimage} ({file_count} files scanned)\033[1;m")

    return all_findings

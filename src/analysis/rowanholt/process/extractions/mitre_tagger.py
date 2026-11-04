#!/usr/bin/env python3
"""
MITRE ATT&CK Technique Tagger for Forensic Artifacts

This module provides cross-platform MITRE technique tagging for macOS and Linux
artifacts, complementing the Windows-specific tagging in artemis.py.

Usage:
    from rowanholt.process.extractions.mitre_tagger import tag_mitre_technique
    tag_mitre_technique(output_directory, img, "plist", "T1543.001")
"""

import os
from typing import List, Optional


# Artefact type to MITRE technique mappings for macOS and Linux
# These complement the Windows mappings in artemis.py
ARTEFACT_MITRE_MAPPING = {
    # macOS artifacts
    "plist": {
        "technique_ids": ["T1543.001", "T1543.004", "T1547.015"],  # Launch Agent/Daemon/Login Items
        "technique_names": ["Launch Agent", "Launch Daemon", "Login Items"],
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "launchagent": {
        "technique_ids": ["T1543.001"],
        "technique_names": ["Launch Agent"],
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "launchdaemon": {
        "technique_ids": ["T1543.004"],
        "technique_names": ["Launch Daemon"],
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "loginitems": {
        "technique_ids": ["T1547.015"],
        "technique_names": ["Login Items"],
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "unified_log": {
        "technique_ids": ["T1070.002"],
        "technique_names": ["Clear Linux or Mac System Logs"],
        "tactics": ["Defense Evasion"],
    },
    "fsevent": {
        "technique_ids": ["T1083", "T1070.004"],
        "technique_names": ["File and Directory Discovery", "File Deletion"],
        "tactics": ["Discovery", "Defense Evasion"],
    },
    "quarantine": {
        "technique_ids": ["T1105", "T1566"],
        "technique_names": ["Ingress Tool Transfer", "Phishing"],
        "tactics": ["Command and Control", "Initial Access"],
    },
    "tcc": {
        "technique_ids": ["T1123", "T1125", "T1005"],
        "technique_names": ["Audio Capture", "Video Capture", "Data from Local System"],
        "tactics": ["Collection"],
    },
    "coreduet": {
        "technique_ids": ["T1083", "T1087", "T1105"],
        "technique_names": ["File and Directory Discovery", "Account Discovery", "Ingress Tool Transfer"],
        "tactics": ["Discovery", "Command and Control"],
    },
    "spotlight": {
        "technique_ids": ["T1083"],
        "technique_names": ["File and Directory Discovery"],
        "tactics": ["Discovery"],
    },
    "keychain": {
        "technique_ids": ["T1555.001"],
        "technique_names": ["Keychain"],
        "tactics": ["Credential Access"],
    },

    # Linux artifacts
    "journal": {
        "technique_ids": ["T1070.002"],
        "technique_names": ["Clear Linux or Mac System Logs"],
        "tactics": ["Defense Evasion"],
    },
    "journalctl": {
        "technique_ids": ["T1070.002"],
        "technique_names": ["Clear Linux or Mac System Logs"],
        "tactics": ["Defense Evasion"],
    },
    "audit": {
        "technique_ids": ["T1059", "T1059.004", "T1136", "T1087", "T1078", "T1110"],
        "technique_names": ["Command and Scripting Interpreter", "Unix Shell", "Create Account", "Account Discovery", "Valid Accounts", "Brute Force"],
        "tactics": ["Execution", "Persistence", "Discovery", "Initial Access", "Credential Access"],
    },
    "syslog": {
        "technique_ids": ["T1070.002"],
        "technique_names": ["Clear Linux or Mac System Logs"],
        "tactics": ["Defense Evasion"],
    },
    "auth_log": {
        "technique_ids": ["T1078", "T1110", "T1021.004"],
        "technique_names": ["Valid Accounts", "Brute Force", "SSH"],
        "tactics": ["Initial Access", "Persistence", "Credential Access", "Lateral Movement"],
    },
    "secure_log": {
        "technique_ids": ["T1078", "T1110"],
        "technique_names": ["Valid Accounts", "Brute Force"],
        "tactics": ["Initial Access", "Persistence", "Credential Access"],
    },
    "cron": {
        "technique_ids": ["T1053.003"],
        "technique_names": ["Cron"],
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
    },
    "crontab": {
        "technique_ids": ["T1053.003"],
        "technique_names": ["Cron"],
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
    },
    "systemd": {
        "technique_ids": ["T1543.002"],
        "technique_names": ["Systemd Service"],
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "service": {
        "technique_ids": ["T1543.002"],
        "technique_names": ["Systemd Service"],
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "docker": {
        "technique_ids": ["T1610", "T1613", "T1611"],
        "technique_names": ["Deploy Container", "Container and Resource Discovery", "Escape to Host"],
        "tactics": ["Defense Evasion", "Execution", "Discovery", "Privilege Escalation"],
    },

    # Cross-platform Unix artifacts
    "bash_history": {
        "technique_ids": ["T1059.004", "T1070.003"],
        "technique_names": ["Unix Shell", "Clear Command History"],
        "tactics": ["Execution", "Defense Evasion"],
    },
    "zsh_history": {
        "technique_ids": ["T1059.004", "T1070.003"],
        "technique_names": ["Unix Shell", "Clear Command History"],
        "tactics": ["Execution", "Defense Evasion"],
    },
    "group": {
        "technique_ids": ["T1087.001", "T1069"],
        "technique_names": ["Local Account", "Permission Groups Discovery"],
        "tactics": ["Discovery"],
    },
    "passwd": {
        "technique_ids": ["T1087.001", "T1003.008"],
        "technique_names": ["Local Account", "/etc/passwd and /etc/shadow"],
        "tactics": ["Discovery", "Credential Access"],
    },
    "shadow": {
        "technique_ids": ["T1003.008"],
        "technique_names": ["/etc/passwd and /etc/shadow"],
        "tactics": ["Credential Access"],
    },
    "hosts": {
        "technique_ids": ["T1565.001"],
        "technique_names": ["Stored Data Manipulation"],
        "tactics": ["Impact"],
    },
    "mail": {
        "technique_ids": ["T1114"],
        "technique_names": ["Email Collection"],
        "tactics": ["Collection"],
    },
    "email": {
        "technique_ids": ["T1114"],
        "technique_names": ["Email Collection"],
        "tactics": ["Collection"],
    },

    # Browser artifacts (cross-platform)
    "browser": {
        "technique_ids": ["T1217", "T1539", "T1185"],
        "technique_names": ["Browser Bookmark Discovery", "Steal Web Session Cookie", "Browser Session Hijacking"],
        "tactics": ["Discovery", "Credential Access", "Collection"],
    },
    "history": {
        "technique_ids": ["T1217"],
        "technique_names": ["Browser Bookmark Discovery"],
        "tactics": ["Discovery"],
    },
    "cookies": {
        "technique_ids": ["T1539"],
        "technique_names": ["Steal Web Session Cookie"],
        "tactics": ["Credential Access"],
    },

    # Generic log types
    "log": {
        "technique_ids": ["T1070.002"],
        "technique_names": ["Clear Linux or Mac System Logs"],
        "tactics": ["Defense Evasion"],
    },
    "logs": {
        "technique_ids": ["T1070.002"],
        "technique_names": ["Clear Linux or Mac System Logs"],
        "tactics": ["Defense Evasion"],
    },
}


def get_mitre_techniques(artefact_type: str) -> List[str]:
    """
    Get MITRE ATT&CK technique IDs for an artefact type.

    Args:
        artefact_type: Type of artefact (e.g., "plist", "journal", "bash_history")

    Returns:
        List of MITRE technique IDs
    """
    artefact_lower = artefact_type.lower()
    mapping = ARTEFACT_MITRE_MAPPING.get(artefact_lower, {})
    return mapping.get("technique_ids", [])


def tag_mitre_technique(
    output_directory: str,
    img: str,
    artefact_type: str,
    specific_technique: Optional[str] = None,
) -> bool:
    """
    Tag an artefact with MITRE ATT&CK technique(s) by writing to mitre_techniques.txt.

    This writes technique IDs to the mitre_techniques.txt file at the CASE level
    (alongside rowanholt_audit.log) for use by the MITRE Navigator layer generator.

    Args:
        output_directory: Base output directory for the case
        img: Image identifier (e.g., "image.E01::macOS")
        artefact_type: Type of artefact being processed (e.g., "plist", "journal")
        specific_technique: Optional specific technique ID to add (overrides mapping)

    Returns:
        True if techniques were written, False otherwise
    """
    try:
        # Path to mitre_techniques.txt at CASE level (same directory as rowanholt_audit.log)
        # This consolidates techniques from ALL images into a single file
        techniques_file = os.path.join(
            output_directory,
            "mitre_techniques.txt"
        )

        # Ensure directory exists
        os.makedirs(os.path.dirname(techniques_file), exist_ok=True)

        # Gather techniques to write
        techniques_to_write = set()

        if specific_technique:
            techniques_to_write.add(specific_technique)
        else:
            techniques = get_mitre_techniques(artefact_type)
            techniques_to_write.update(techniques)

        if not techniques_to_write:
            return False

        # Read existing techniques to avoid duplicates
        existing_techniques = set()
        if os.path.exists(techniques_file):
            with open(techniques_file, 'r') as f:
                existing_techniques = set(line.strip() for line in f if line.strip())

        # Write only new techniques
        new_techniques = techniques_to_write - existing_techniques
        if new_techniques:
            with open(techniques_file, 'a') as f:
                for tech_id in sorted(new_techniques):
                    f.write(f"{tech_id}\n")

        return True

    except Exception as e:
        print(f" -> WARNING: Failed to write MITRE techniques: {e}")
        return False


def tag_mitre_for_platform(
    output_directory: str,
    img: str,
    platform: str,
) -> bool:
    """
    Tag an image with all MITRE techniques relevant to its platform.

    This is called once per image during processing to ensure that at minimum
    the platform-specific base techniques are recorded.

    Args:
        output_directory: Base output directory for the case
        img: Image identifier (e.g., "image.E01::macOS")
        platform: Platform type ("macOS", "Linux", or "Windows")

    Returns:
        True if techniques were written, False otherwise
    """
    platform_techniques = {
        "macOS": [
            "T1543.001",  # Launch Agent
            "T1543.004",  # Launch Daemon
            "T1547.015",  # Login Items
            "T1059.002",  # AppleScript
            "T1059.004",  # Unix Shell
            "T1070.002",  # Clear macOS Logs
        ],
        "Linux": [
            "T1543.002",  # Systemd Service
            "T1053.003",  # Cron
            "T1059.004",  # Unix Shell
            "T1070.002",  # Clear Linux Logs
        ],
        "Windows": [],  # Windows is handled by artemis.py
    }

    techniques = platform_techniques.get(platform, [])
    if not techniques:
        return False

    success = True
    for tech in techniques:
        if not tag_mitre_technique(output_directory, img, "", tech):
            success = False

    return success

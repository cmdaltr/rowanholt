#!/usr/bin/env python3 -tt
"""
MITRE ATT&CK Enterprise Data

Comprehensive ATT&CK technique metadata including:
- Technique ID and Name
- Tactics
- CTI (Threat Groups/Software known to use the technique)
- Procedure Examples

This data is used to enrich JSON artefacts with full ATT&CK context,
independent of any SIEM platform.

Groups, software and procedures: curated, from MITRE ATT&CK Enterprise v14.
Names, tactics and domains: the pinned release (attack_lookup.py), Enterprise and Mobile.
Author: Rowanholt DF Acceleration Suite
Version: 1.0.0
"""

from typing import Dict, List, Optional

from rowanholt.post.mitre import attack_lookup


# Complete ATT&CK technique metadata
# Format: technique_id -> {name, tactics, description, groups, software, procedure_examples}
ATTACK_TECHNIQUES: Dict[str, Dict] = {
    # ==================== RECONNAISSANCE ====================
    "T1595": {
        "name": "Active Scanning",
        "tactics": ["Reconnaissance"],
        "description": "Adversaries may execute active reconnaissance scans to gather information.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Sandworm Team"],
        "software": ["Nmap", "Masscan"],
        "procedure_examples": ["APT28 has performed large-scale scans to identify vulnerable systems."]
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactics": ["Reconnaissance"],
        "description": "Adversaries may gather information about the victim's hosts.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has gathered host information via watering hole attacks."]
    },

    # ==================== INITIAL ACCESS ====================
    "T1189": {
        "name": "Drive-by Compromise",
        "tactics": ["Initial Access"],
        "description": "Adversaries may gain access through a user visiting a website.",
        "groups": ["APT28", "APT29", "Turla", "Lazarus Group", "APT32", "Darkhotel"],
        "software": ["CHOPSTICK", "Cobalt Strike"],
        "procedure_examples": ["APT28 has compromised websites to deliver malware to visitors.", "Turla has used watering holes to deliver malware."]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing systems.",
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group", "Sandworm Team", "HAFNIUM"],
        "software": ["China Chopper", "Cobalt Strike"],
        "procedure_examples": ["APT29 exploited vulnerabilities in VPN appliances.", "HAFNIUM exploited Exchange Server vulnerabilities."]
    },
    "T1133": {
        "name": "External Remote Services",
        "tactics": ["Initial Access", "Persistence"],
        "description": "Adversaries may leverage external-facing remote services to gain access.",
        "groups": ["APT28", "APT29", "FIN7", "Wizard Spider", "Sandworm Team"],
        "software": ["Cobalt Strike", "Metasploit"],
        "procedure_examples": ["APT29 has used compromised VPN credentials for initial access."]
    },
    "T1566": {
        "name": "Phishing",
        "tactics": ["Initial Access"],
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "groups": ["APT28", "APT29", "APT32", "Kimsuky", "Lazarus Group", "FIN7", "Wizard Spider", "TA505"],
        "software": ["Emotet", "TrickBot", "Cobalt Strike"],
        "procedure_examples": ["APT28 has sent spearphishing emails with malicious attachments.", "Lazarus Group has used LinkedIn messages for spearphishing."]
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "Adversaries may send spearphishing emails with malicious attachments.",
        "groups": ["APT28", "APT29", "APT32", "Kimsuky", "Lazarus Group", "FIN7", "Gamaredon Group", "MuddyWater"],
        "software": ["Emotet", "TrickBot", "Agent Tesla"],
        "procedure_examples": ["APT28 sent Word documents with malicious macros.", "Kimsuky has sent malicious HWP files to Korean targets."]
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactics": ["Initial Access"],
        "description": "Adversaries may send spearphishing emails with malicious links.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Kimsuky", "OilRig", "TA505"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT29 has sent emails with links to credential harvesting sites."]
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "groups": ["APT28", "APT29", "APT41", "FIN7", "Wizard Spider", "Sandworm Team"],
        "software": ["Mimikatz", "Cobalt Strike"],
        "procedure_examples": ["APT29 has used compromised credentials for lateral movement.", "FIN7 obtained credentials through phishing."]
    },
    "T1091": {
        "name": "Replication Through Removable Media",
        "tactics": ["Initial Access", "Lateral Movement"],
        "description": "Adversaries may move onto systems by copying malware to removable media.",
        "groups": ["APT28", "Turla", "Equation Group"],
        "software": ["USBStealer", "Agent.BTZ"],
        "procedure_examples": ["Turla has used USB drives to spread malware in air-gapped networks."]
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactics": ["Initial Access"],
        "description": "Adversaries may manipulate products or delivery mechanisms prior to receipt.",
        "groups": ["APT29", "APT41", "Lazarus Group", "Sandworm Team"],
        "software": ["SUNBURST", "CCleaner Backdoor"],
        "procedure_examples": ["APT29 compromised SolarWinds Orion updates to deliver SUNBURST."]
    },

    # ==================== EXECUTION ====================
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group", "FIN7", "Wizard Spider", "Turla"],
        "software": ["Cobalt Strike", "Empire", "Metasploit"],
        "procedure_examples": ["APT28 has used PowerShell for execution.", "Lazarus Group uses cmd.exe for command execution."]
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "groups": ["APT28", "APT29", "APT41", "FIN7", "Wizard Spider", "Turla", "Cobalt Group", "MuddyWater"],
        "software": ["Cobalt Strike", "Empire", "PowerSploit"],
        "procedure_examples": ["APT29 has used PowerShell to download and execute payloads.", "FIN7 heavily uses PowerShell in their operations."]
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse the Windows command shell for execution.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["Cobalt Strike", "Metasploit"],
        "procedure_examples": ["Lazarus Group executes batch scripts via cmd.exe."]
    },
    "T1059.005": {
        "name": "Visual Basic",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse VBScript for execution.",
        "groups": ["APT28", "APT32", "Gamaredon Group", "MuddyWater", "TA505"],
        "software": ["Emotet", "TrickBot"],
        "procedure_examples": ["Gamaredon Group uses VBScript in malicious documents."]
    },
    "T1059.006": {
        "name": "Python",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse Python for execution.",
        "groups": ["APT28", "Turla", "Lazarus Group"],
        "software": ["Pupy", "Empire"],
        "procedure_examples": ["Turla has used Python-based backdoors."]
    },
    "T1059.007": {
        "name": "JavaScript",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse JavaScript for execution.",
        "groups": ["APT28", "Lazarus Group", "FIN7", "TA505"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["FIN7 has used JavaScript in spearphishing attachments."]
    },
    "T1059.002": {
        "name": "AppleScript",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse AppleScript for execution on macOS.",
        "groups": ["Lazarus Group", "APT32"],
        "software": [],
        "procedure_examples": ["Lazarus Group has used AppleScript to execute malware on macOS."]
    },
    "T1106": {
        "name": "Native API",
        "tactics": ["Execution"],
        "description": "Adversaries may interact with the native OS API to execute behaviors.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "APT41"],
        "software": ["Cobalt Strike", "Metasploit", "Mimikatz"],
        "procedure_examples": ["APT28 uses Windows API calls for process injection.", "Turla malware makes extensive use of Windows APIs."]
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse task scheduling functionality to facilitate execution.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider", "APT41"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT29 has used scheduled tasks for persistence."]
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse Windows Task Scheduler to perform execution.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider", "APT41", "Sandworm Team"],
        "software": ["Cobalt Strike", "Empire", "TrickBot"],
        "procedure_examples": ["APT29 created scheduled tasks for persistence.", "FIN7 uses scheduled tasks to execute their backdoor."]
    },
    "T1053.002": {
        "name": "At",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse the at utility to perform execution.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has used at.exe for execution."]
    },
    "T1053.006": {
        "name": "Systemd Timers",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse systemd timers to perform execution.",
        "groups": ["TeamTNT"],
        "software": [],
        "procedure_examples": ["TeamTNT has used systemd timers for persistence on Linux."]
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse WMI to execute commands.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider", "APT41"],
        "software": ["Cobalt Strike", "Empire", "Impacket"],
        "procedure_examples": ["APT29 has used WMI for lateral movement.", "FIN7 uses WMI for execution on remote systems."]
    },
    "T1204": {
        "name": "User Execution",
        "tactics": ["Execution"],
        "description": "Adversaries may rely upon user actions to gain execution.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "TA505", "Kimsuky"],
        "software": ["Emotet", "TrickBot"],
        "procedure_examples": ["FIN7 relies on users opening malicious documents."]
    },
    "T1204.001": {
        "name": "Malicious Link",
        "tactics": ["Execution"],
        "description": "Adversaries may rely upon a user clicking a malicious link.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Kimsuky", "OilRig"],
        "software": [],
        "procedure_examples": ["APT28 has sent spearphishing emails with malicious links."]
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactics": ["Execution"],
        "description": "Adversaries may rely upon a user opening a malicious file.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "TA505", "Kimsuky", "Gamaredon Group"],
        "software": ["Emotet", "TrickBot", "Agent Tesla"],
        "procedure_examples": ["FIN7 sends Word documents with malicious macros.", "Lazarus Group uses malicious HWP files."]
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactics": ["Execution"],
        "description": "Adversaries may exploit software vulnerabilities in client applications.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT32", "Darkhotel"],
        "software": [],
        "procedure_examples": ["APT28 has exploited Microsoft Office vulnerabilities."]
    },

    # ==================== PERSISTENCE ====================
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may configure system settings to automatically execute a program.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT28 has added registry run keys for persistence."]
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may add programs to registry run keys or startup folder.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7", "APT41", "Wizard Spider"],
        "software": ["Cobalt Strike", "Empire", "TrickBot", "Emotet"],
        "procedure_examples": ["APT28 adds entries to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.", "TrickBot persists via registry run keys."]
    },
    "T1547.004": {
        "name": "Winlogon Helper DLL",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse Winlogon helper DLL for persistence.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has used Winlogon helper DLLs for persistence."]
    },
    "T1547.009": {
        "name": "Shortcut Modification",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may create or modify shortcuts to execute malware.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla"],
        "software": [],
        "procedure_examples": ["APT29 has modified shortcuts for persistence."]
    },
    "T1547.012": {
        "name": "Print Processors",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse print processors to establish persistence.",
        "groups": ["APT28"],
        "software": [],
        "procedure_examples": ["APT28 has used print processor persistence."]
    },
    "T1547.015": {
        "name": "Login Items",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may add login items to execute upon user login on macOS.",
        "groups": ["Lazarus Group", "APT32"],
        "software": [],
        "procedure_examples": ["Lazarus Group has added login items on macOS systems."]
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may create or modify system processes to repeatedly execute.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 has created malicious Windows services."]
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may create or modify Windows services to repeatedly execute.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7", "Wizard Spider"],
        "software": ["Cobalt Strike", "Metasploit", "TrickBot"],
        "procedure_examples": ["APT28 has created services for persistence.", "TrickBot installs itself as a service."]
    },
    "T1543.001": {
        "name": "Launch Agent",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may create or modify launch agents to repeatedly execute on macOS.",
        "groups": ["Lazarus Group", "APT32"],
        "software": [],
        "procedure_examples": ["Lazarus Group has used launch agents for persistence on macOS."]
    },
    "T1543.004": {
        "name": "Launch Daemon",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may create or modify launch daemons to execute at startup.",
        "groups": ["APT32"],
        "software": [],
        "procedure_examples": ["APT32 has created launch daemons on macOS."]
    },
    "T1546": {
        "name": "Event Triggered Execution",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may establish persistence by modifying event triggers.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has used event-triggered execution mechanisms."]
    },
    "T1546.003": {
        "name": "Windows Management Instrumentation Event Subscription",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may establish persistence via WMI event subscriptions.",
        "groups": ["APT28", "APT29", "Turla", "Leviathan"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT29 has used WMI event subscriptions for persistence."]
    },
    "T1546.004": {
        "name": "Unix Shell Configuration Modification",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may modify shell configuration files for persistence.",
        "groups": ["TeamTNT", "Rocke"],
        "software": [],
        "procedure_examples": ["TeamTNT has modified .bashrc for persistence."]
    },
    "T1546.008": {
        "name": "Accessibility Features",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may establish persistence by executing malicious content via accessibility features.",
        "groups": ["APT28", "APT29", "Lazarus Group"],
        "software": [],
        "procedure_examples": ["APT28 has replaced sethc.exe with cmd.exe for backdoor access."]
    },
    "T1037": {
        "name": "Boot or Logon Initialization Scripts",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may use scripts automatically executed at boot or logon.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has used logon scripts for persistence."]
    },
    "T1037.001": {
        "name": "Logon Script (Windows)",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may use Windows logon scripts for persistence.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has used logon scripts for persistence."]
    },
    "T1037.004": {
        "name": "RC Scripts",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may establish persistence by modifying RC scripts.",
        "groups": ["TeamTNT", "Rocke"],
        "software": [],
        "procedure_examples": ["TeamTNT has modified rc.local for persistence."]
    },
    "T1136": {
        "name": "Create Account",
        "tactics": ["Persistence"],
        "description": "Adversaries may create accounts to maintain access to victim systems.",
        "groups": ["APT28", "APT29", "APT41", "FIN7"],
        "software": [],
        "procedure_examples": ["APT29 has created local accounts for persistence."]
    },
    "T1136.001": {
        "name": "Local Account",
        "tactics": ["Persistence"],
        "description": "Adversaries may create a local account to maintain access.",
        "groups": ["APT28", "APT29", "APT41", "FIN7", "Wizard Spider"],
        "software": [],
        "procedure_examples": ["APT29 has created local administrator accounts."]
    },
    "T1136.002": {
        "name": "Domain Account",
        "tactics": ["Persistence"],
        "description": "Adversaries may create a domain account to maintain access.",
        "groups": ["APT28", "APT29", "APT41"],
        "software": [],
        "procedure_examples": ["APT29 has created domain accounts for persistence."]
    },
    "T1197": {
        "name": "BITS Jobs",
        "tactics": ["Defense Evasion", "Persistence"],
        "description": "Adversaries may abuse BITS jobs to download, execute, and clean up.",
        "groups": ["APT41", "Leviathan", "Turla"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT41 has used BITS jobs for file transfers.", "Leviathan uses BITS for downloads."]
    },
    "T1505": {
        "name": "Server Software Component",
        "tactics": ["Persistence"],
        "description": "Adversaries may abuse server software components to establish persistence.",
        "groups": ["APT28", "APT29", "APT41", "HAFNIUM"],
        "software": ["China Chopper"],
        "procedure_examples": ["APT28 has deployed web shells for persistence."]
    },
    "T1505.003": {
        "name": "Web Shell",
        "tactics": ["Persistence"],
        "description": "Adversaries may backdoor web servers with web shells.",
        "groups": ["APT28", "APT29", "APT41", "HAFNIUM", "Lazarus Group", "OilRig"],
        "software": ["China Chopper", "ASPXSpy"],
        "procedure_examples": ["HAFNIUM deployed web shells on Exchange servers.", "APT41 uses web shells for persistence."]
    },

    # ==================== PRIVILEGE ESCALATION ====================
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
        "groups": ["APT28", "APT29", "Lazarus Group"],
        "software": [],
        "procedure_examples": ["APT28 has bypassed UAC."]
    },
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may bypass UAC mechanisms to elevate privileges.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT41", "FIN7"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT28 uses eventvwr.exe for UAC bypass.", "FIN7 has bypassed UAC."]
    },
    "T1548.003": {
        "name": "Sudo and Sudo Caching",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may abuse sudo or sudo caching to elevate privileges.",
        "groups": ["TeamTNT", "Rocke"],
        "software": [],
        "procedure_examples": ["TeamTNT attempts to use sudo for privilege escalation."]
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactics": ["Privilege Escalation"],
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group", "Sandworm Team"],
        "software": [],
        "procedure_examples": ["APT28 has exploited local privilege escalation vulnerabilities."]
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "description": "Adversaries may modify access tokens to operate under different security contexts.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": ["Cobalt Strike", "Mimikatz"],
        "procedure_examples": ["APT28 has used token manipulation for privilege escalation."]
    },
    "T1134.001": {
        "name": "Token Impersonation/Theft",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "description": "Adversaries may duplicate then impersonate access tokens.",
        "groups": ["APT28", "APT29", "FIN7", "Wizard Spider"],
        "software": ["Cobalt Strike", "Mimikatz"],
        "procedure_examples": ["APT28 has used incognito to impersonate tokens."]
    },

    # ==================== DEFENSE EVASION ====================
    "T1070": {
        "name": "Indicator Removal",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may delete or modify artifacts generated to remove evidence.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT41", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has deleted logs to cover tracks."]
    },
    "T1685.005": {
        "name": "Clear Windows Event Logs",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may clear Windows Event Logs to hide activity.",
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has cleared event logs.", "Lazarus Group clears logs after operations."]
    },
    "T1685.006": {
        "name": "Clear Linux or Mac System Logs",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may clear system logs to hide activity.",
        "groups": ["TeamTNT", "Rocke"],
        "software": [],
        "procedure_examples": ["TeamTNT clears bash history and system logs."]
    },
    "T1070.003": {
        "name": "Clear Command History",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may clear command history to conceal commands.",
        "groups": ["APT28", "APT29", "TeamTNT"],
        "software": [],
        "procedure_examples": ["TeamTNT clears bash history after execution."]
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may delete files to remove indicators of intrusion.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 deletes malware after execution.", "Lazarus Group removes tools after use."]
    },
    "T1070.005": {
        "name": "Network Share Connection Removal",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may remove share connections after operations.",
        "groups": ["APT28", "APT29"],
        "software": [],
        "procedure_examples": ["APT29 has removed network share connections."]
    },
    "T1070.006": {
        "name": "Timestomp",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may modify file timestamps to hide activity.",
        "groups": ["APT28", "APT29", "APT41", "Lazarus Group", "Turla"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 has timestomped files to match legitimate files."]
    },
    "T1112": {
        "name": "Modify Registry",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may modify the Windows Registry for defense evasion.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7", "APT41"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT28 modifies registry for persistence and evasion."]
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may deobfuscate files or information to execute.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 decodes base64-encoded payloads.", "FIN7 decrypts payloads at runtime."]
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may obfuscate payloads to make analysis difficult.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT28 uses encoding and encryption.", "FIN7 obfuscates scripts."]
    },
    "T1027.004": {
        "name": "Compile After Delivery",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may compile payloads after delivery to evade detection.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has compiled malware on victim systems."]
    },
    "T1036": {
        "name": "Masquerading",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may masquerade as legitimate files or processes.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has named malware to appear legitimate."]
    },
    "T1036.003": {
        "name": "Rename System Utilities",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may rename system utilities to evade detection.",
        "groups": ["APT28", "APT29", "Lazarus Group"],
        "software": [],
        "procedure_examples": ["APT28 has renamed cmd.exe to evade detection."]
    },
    "T1036.004": {
        "name": "Masquerade Task or Service",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may masquerade malicious tasks or services as legitimate.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 names services to appear legitimate."]
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may match legitimate names or locations.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": [],
        "procedure_examples": ["APT28 places malware in System32 directory."]
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "description": "Adversaries may inject code into processes to evade defenses.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["Cobalt Strike", "Metasploit", "Empire"],
        "procedure_examples": ["APT28 uses process injection techniques.", "Cobalt Strike injects into processes."]
    },
    "T1055.001": {
        "name": "Dynamic-link Library Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "description": "Adversaries may inject DLLs into processes.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla"],
        "software": ["Cobalt Strike", "Metasploit"],
        "procedure_examples": ["APT28 has used DLL injection."]
    },
    "T1055.012": {
        "name": "Process Hollowing",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "description": "Adversaries may inject malicious code into suspended processes.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["Lazarus Group has used process hollowing."]
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may bypass process and signature-based defenses.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": [],
        "procedure_examples": ["APT28 has used system binaries for execution."]
    },
    "T1218.001": {
        "name": "Compiled HTML File",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may abuse CHM files to conceal malicious code.",
        "groups": ["APT28", "Lazarus Group", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has used CHM files for delivery."]
    },
    "T1218.005": {
        "name": "Mshta",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may abuse mshta.exe to execute malicious code.",
        "groups": ["APT28", "Lazarus Group", "FIN7", "MuddyWater"],
        "software": [],
        "procedure_examples": ["FIN7 has used mshta.exe to execute payloads."]
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may abuse rundll32.exe to execute malicious code.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 has used rundll32 for execution."]
    },
    "T1564": {
        "name": "Hide Artifacts",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may hide artifacts to evade detection.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has hidden files using attrib."]
    },
    "T1564.001": {
        "name": "Hidden Files and Directories",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may set files to hidden to evade detection.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "TeamTNT"],
        "software": [],
        "procedure_examples": ["APT28 uses attrib +h to hide files."]
    },
    "T1564.003": {
        "name": "Hidden Window",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may run processes in hidden windows.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["FIN7 runs PowerShell in hidden windows."]
    },
    "T1564.004": {
        "name": "NTFS File Attributes",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may abuse NTFS file attributes to hide activities.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has hidden data in alternate data streams."]
    },
    "T1553": {
        "name": "Subvert Trust Controls",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may undermine security controls that rely on trust.",
        "groups": ["APT28", "APT29", "Lazarus Group"],
        "software": [],
        "procedure_examples": ["APT28 has signed malware with stolen certificates."]
    },
    "T1553.001": {
        "name": "Gatekeeper Bypass",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may modify file attributes to bypass Gatekeeper.",
        "groups": ["Lazarus Group", "APT32"],
        "software": [],
        "procedure_examples": ["Lazarus Group has bypassed Gatekeeper on macOS."]
    },
    "T1553.004": {
        "name": "Install Root Certificate",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may install root certificates to intercept traffic.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has installed root certificates."]
    },
    "T1553.006": {
        "name": "Code Signing Policy Modification",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may modify code signing policies to enable execution.",
        "groups": ["Lazarus Group"],
        "software": [],
        "procedure_examples": ["Lazarus Group has modified code signing policies."]
    },
    "T1220": {
        "name": "XSL Script Processing",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may use XSL files to bypass application control.",
        "groups": ["APT28", "Lazarus Group", "MuddyWater"],
        "software": [],
        "procedure_examples": ["MuddyWater has used XSL for execution."]
    },
    "T1221": {
        "name": "Template Injection",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries may exploit Office templates for execution.",
        "groups": ["APT28", "Gamaredon Group", "MuddyWater"],
        "software": [],
        "procedure_examples": ["Gamaredon Group uses template injection extensively."]
    },

    # ==================== CREDENTIAL ACCESS ====================
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "description": "Adversaries may dump credentials to obtain account login information.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Wizard Spider"],
        "software": ["Mimikatz", "Cobalt Strike", "gsecdump"],
        "procedure_examples": ["APT28 uses Mimikatz for credential dumping.", "FIN7 dumps credentials with Mimikatz."]
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactics": ["Credential Access"],
        "description": "Adversaries may dump LSASS memory to obtain credentials.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Wizard Spider"],
        "software": ["Mimikatz", "Cobalt Strike", "procdump"],
        "procedure_examples": ["APT28 dumps LSASS with Mimikatz.", "Wizard Spider uses procdump for LSASS."]
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactics": ["Credential Access"],
        "description": "Adversaries may attempt to extract credential material from the SAM.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": ["Mimikatz", "Cobalt Strike", "gsecdump", "pwdumpx"],
        "procedure_examples": ["APT28 has dumped the SAM database."]
    },
    "T1003.003": {
        "name": "NTDS",
        "tactics": ["Credential Access"],
        "description": "Adversaries may access NTDS.dit for credential material.",
        "groups": ["APT28", "APT29", "APT41", "Wizard Spider"],
        "software": ["Mimikatz", "secretsdump", "ntdsutil"],
        "procedure_examples": ["APT29 has dumped NTDS.dit for credentials."]
    },
    "T1003.004": {
        "name": "LSA Secrets",
        "tactics": ["Credential Access"],
        "description": "Adversaries may access LSA secrets for credential material.",
        "groups": ["APT28", "APT29", "Lazarus Group"],
        "software": ["Mimikatz", "Cobalt Strike"],
        "procedure_examples": ["APT28 has extracted LSA secrets."]
    },
    "T1003.008": {
        "name": "/etc/passwd and /etc/shadow",
        "tactics": ["Credential Access"],
        "description": "Adversaries may dump /etc/passwd and /etc/shadow for credentials.",
        "groups": ["TeamTNT", "Rocke"],
        "software": [],
        "procedure_examples": ["TeamTNT has accessed /etc/shadow for password hashes."]
    },
    "T1110": {
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "description": "Adversaries may use brute force techniques to gain access.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Sandworm Team"],
        "software": ["Hydra", "Medusa"],
        "procedure_examples": ["APT28 has used password spraying attacks."]
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactics": ["Credential Access"],
        "description": "Adversaries may guess passwords to attempt authentication.",
        "groups": ["APT28", "APT29", "Sandworm Team"],
        "software": [],
        "procedure_examples": ["Sandworm Team has used password guessing."]
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactics": ["Credential Access"],
        "description": "Adversaries may use a single password against many accounts.",
        "groups": ["APT28", "APT29", "APT33", "Sandworm Team"],
        "software": [],
        "procedure_examples": ["APT28 has conducted password spraying campaigns."]
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactics": ["Credential Access"],
        "description": "Adversaries may search for common password storage locations.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": ["Mimikatz", "Cobalt Strike"],
        "procedure_examples": ["FIN7 extracts credentials from browsers."]
    },
    "T1555.001": {
        "name": "Keychain",
        "tactics": ["Credential Access"],
        "description": "Adversaries may collect credentials from macOS Keychain.",
        "groups": ["Lazarus Group", "APT32"],
        "software": [],
        "procedure_examples": ["Lazarus Group has accessed the macOS Keychain."]
    },
    "T1555.003": {
        "name": "Credentials from Web Browsers",
        "tactics": ["Credential Access"],
        "description": "Adversaries may acquire credentials from web browsers.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["FIN7 has stolen browser credentials."]
    },
    "T1555.004": {
        "name": "Windows Credential Manager",
        "tactics": ["Credential Access"],
        "description": "Adversaries may acquire credentials from Windows Credential Manager.",
        "groups": ["APT28", "APT29", "FIN7"],
        "software": ["Mimikatz"],
        "procedure_examples": ["APT28 has extracted credentials from Credential Manager."]
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactics": ["Credential Access"],
        "description": "Adversaries may search for unsecured credentials.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": [],
        "procedure_examples": ["APT28 has searched for credentials in files."]
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactics": ["Credential Access"],
        "description": "Adversaries may search for credentials stored in files.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has searched for password files."]
    },
    "T1552.003": {
        "name": "Bash History",
        "tactics": ["Credential Access"],
        "description": "Adversaries may search bash history for credentials.",
        "groups": ["TeamTNT", "Rocke"],
        "software": [],
        "procedure_examples": ["TeamTNT has searched bash history for credentials."]
    },
    "T1552.004": {
        "name": "Private Keys",
        "tactics": ["Credential Access"],
        "description": "Adversaries may search for private key certificate files.",
        "groups": ["APT28", "APT29", "Lazarus Group", "TeamTNT"],
        "software": [],
        "procedure_examples": ["TeamTNT has stolen SSH keys."]
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactics": ["Credential Access"],
        "description": "Adversaries may steal or forge Kerberos tickets.",
        "groups": ["APT28", "APT29", "FIN7", "Wizard Spider"],
        "software": ["Mimikatz", "Rubeus"],
        "procedure_examples": ["APT28 has used Kerberoasting."]
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactics": ["Credential Access"],
        "description": "Adversaries may abuse Kerberos to obtain service ticket hashes.",
        "groups": ["APT28", "APT29", "FIN7", "Wizard Spider"],
        "software": ["Rubeus", "Mimikatz"],
        "procedure_examples": ["APT28 has used Kerberoasting to obtain credentials."]
    },
    "T1056": {
        "name": "Input Capture",
        "tactics": ["Collection", "Credential Access"],
        "description": "Adversaries may capture user input to obtain credentials.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7"],
        "software": [],
        "procedure_examples": ["Turla has used keyloggers."]
    },
    "T1056.001": {
        "name": "Keylogging",
        "tactics": ["Collection", "Credential Access"],
        "description": "Adversaries may log keystrokes to intercept credentials.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has used keyloggers to capture credentials."]
    },

    # ==================== DISCOVERY ====================
    "T1087": {
        "name": "Account Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may attempt to get a listing of accounts.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has enumerated domain accounts."]
    },
    "T1087.001": {
        "name": "Local Account",
        "tactics": ["Discovery"],
        "description": "Adversaries may attempt to get a listing of local accounts.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": [],
        "procedure_examples": ["APT28 has enumerated local accounts."]
    },
    "T1087.002": {
        "name": "Domain Account",
        "tactics": ["Discovery"],
        "description": "Adversaries may attempt to get a listing of domain accounts.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT29 has enumerated domain accounts."]
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may gather detailed information about the operating system.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 collects system information.", "FIN7 gathers OS version information."]
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate files and directories.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla", "OilRig"],
        "software": [],
        "procedure_examples": ["APT28 searches for sensitive files.", "Turla enumerates files."]
    },
    "T1057": {
        "name": "Process Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate running processes.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 enumerates running processes."]
    },
    "T1012": {
        "name": "Query Registry",
        "tactics": ["Discovery"],
        "description": "Adversaries may query the Registry for information.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 queries registry for software information."]
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may scan for remote systems.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Wizard Spider"],
        "software": [],
        "procedure_examples": ["APT28 has used net view for network discovery."]
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may look for network configuration and settings.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 uses ipconfig for network discovery."]
    },
    "T1016.001": {
        "name": "Internet Connection Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may check for Internet connectivity.",
        "groups": ["APT28", "APT29", "Lazarus Group"],
        "software": [],
        "procedure_examples": ["APT28 checks Internet connectivity before execution."]
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may attempt to get a listing of network connections.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has used netstat to list connections."]
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may identify the primary user or owner of a system.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 uses whoami to identify the current user."]
    },
    "T1007": {
        "name": "System Service Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate services running on a system.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 enumerates services."]
    },
    "T1124": {
        "name": "System Time Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may gather the system time on a victim.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla"],
        "software": [],
        "procedure_examples": ["Turla gathers system time."]
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate groups and permission settings.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has enumerated domain groups."]
    },
    "T1069.001": {
        "name": "Local Groups",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate local groups.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "software": [],
        "procedure_examples": ["APT28 has enumerated local groups."]
    },
    "T1069.002": {
        "name": "Domain Groups",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate domain groups.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT29 has enumerated domain groups."]
    },
    "T1135": {
        "name": "Network Share Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate network shares.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider"],
        "software": [],
        "procedure_examples": ["APT28 has enumerated network shares."]
    },
    "T1201": {
        "name": "Password Policy Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate password policy.",
        "groups": ["APT28", "APT29", "FIN7"],
        "software": [],
        "procedure_examples": ["APT28 has queried domain password policy."]
    },
    "T1518": {
        "name": "Software Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate software and applications.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 enumerates installed software."]
    },
    "T1518.001": {
        "name": "Security Software Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate security software.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 checks for security products."]
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate information about domain trusts.",
        "groups": ["APT28", "APT29", "FIN7", "Wizard Spider"],
        "software": [],
        "procedure_examples": ["APT29 has enumerated domain trusts."]
    },
    "T1120": {
        "name": "Peripheral Device Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may enumerate connected peripheral devices.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has enumerated USB devices."]
    },

    # ==================== LATERAL MOVEMENT ====================
    "T1021": {
        "name": "Remote Services",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use remote services to move laterally.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Wizard Spider"],
        "software": ["Cobalt Strike", "Metasploit"],
        "procedure_examples": ["APT28 uses remote services for lateral movement."]
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use RDP to log into remote machines.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Wizard Spider"],
        "software": [],
        "procedure_examples": ["FIN7 has used RDP for lateral movement."]
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use SMB shares for lateral movement.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Wizard Spider"],
        "software": ["Cobalt Strike", "Impacket"],
        "procedure_examples": ["APT28 uses SMB for lateral movement."]
    },
    "T1021.004": {
        "name": "SSH",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use SSH to log into remote machines.",
        "groups": ["APT28", "APT29", "Lazarus Group", "TeamTNT"],
        "software": [],
        "procedure_examples": ["TeamTNT uses stolen SSH keys for lateral movement."]
    },
    "T1021.005": {
        "name": "VNC",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use VNC to log into remote machines.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has used VNC for remote access."]
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use WinRM for lateral movement.",
        "groups": ["APT28", "APT29", "FIN7", "Wizard Spider"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT29 has used WinRM for lateral movement."]
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may transfer tools between systems during operations.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 has transferred tools via SMB."]
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may exploit remote services to gain access.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Sandworm Team"],
        "software": [],
        "procedure_examples": ["APT28 has exploited vulnerable services."]
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may hijack existing remote service sessions.",
        "groups": ["APT28", "APT29"],
        "software": [],
        "procedure_examples": ["APT28 has hijacked RDP sessions."]
    },
    "T1563.002": {
        "name": "RDP Hijacking",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may hijack RDP sessions.",
        "groups": ["APT28", "APT29"],
        "software": [],
        "procedure_examples": ["APT28 has used tscon.exe for RDP hijacking."]
    },

    # ==================== COLLECTION ====================
    "T1560": {
        "name": "Archive Collected Data",
        "tactics": ["Collection"],
        "description": "Adversaries may compress collected data before exfiltration.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 uses RAR for data compression."]
    },
    "T1560.001": {
        "name": "Archive via Utility",
        "tactics": ["Collection"],
        "description": "Adversaries may use utilities to compress files.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["WinRAR", "7-Zip"],
        "procedure_examples": ["APT28 uses RAR to compress data.", "Turla uses 7-Zip for archiving."]
    },
    "T1005": {
        "name": "Data from Local System",
        "tactics": ["Collection"],
        "description": "Adversaries may search local system sources for data.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 searches for sensitive documents."]
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactics": ["Collection"],
        "description": "Adversaries may search network shares for data.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 searches network shares for data."]
    },
    "T1025": {
        "name": "Data from Removable Media",
        "tactics": ["Collection"],
        "description": "Adversaries may search removable media for data.",
        "groups": ["APT28", "Turla", "Equation Group"],
        "software": [],
        "procedure_examples": ["Turla has targeted removable media."]
    },
    "T1114": {
        "name": "Email Collection",
        "tactics": ["Collection"],
        "description": "Adversaries may target user email to collect sensitive information.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "OilRig", "Kimsuky"],
        "software": [],
        "procedure_examples": ["APT28 has collected email from OWA."]
    },
    "T1114.001": {
        "name": "Local Email Collection",
        "tactics": ["Collection"],
        "description": "Adversaries may target user email on local systems.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "OilRig", "Kimsuky", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has collected PST files.", "Turla has stolen email from Outlook."]
    },
    "T1114.003": {
        "name": "Email Forwarding Rule",
        "tactics": ["Collection"],
        "description": "Adversaries may setup email forwarding rules.",
        "groups": ["APT28", "APT29", "Kimsuky"],
        "software": [],
        "procedure_examples": ["APT28 has created email forwarding rules."]
    },
    "T1113": {
        "name": "Screen Capture",
        "tactics": ["Collection"],
        "description": "Adversaries may capture screenshots.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "Turla", "APT41"],
        "software": [],
        "procedure_examples": ["APT28 captures screenshots.", "Turla has screen capture capabilities."]
    },
    "T1115": {
        "name": "Clipboard Data",
        "tactics": ["Collection"],
        "description": "Adversaries may collect data stored in the clipboard.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has captured clipboard data."]
    },
    "T1123": {
        "name": "Audio Capture",
        "tactics": ["Collection"],
        "description": "Adversaries may capture audio recordings.",
        "groups": ["APT28", "Turla", "APT32"],
        "software": [],
        "procedure_examples": ["Turla has recorded audio."]
    },
    "T1125": {
        "name": "Video Capture",
        "tactics": ["Collection"],
        "description": "Adversaries may capture video recordings.",
        "groups": ["APT28", "Turla", "APT32"],
        "software": [],
        "procedure_examples": ["Turla has captured webcam video."]
    },

    # ==================== COMMAND AND CONTROL ====================
    "T1071": {
        "name": "Application Layer Protocol",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using application layer protocols.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 uses HTTPS for C2."]
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using web protocols.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla", "OilRig", "Kimsuky"],
        "software": ["Cobalt Strike", "Empire"],
        "procedure_examples": ["APT28 uses HTTPS for C2.", "Cobalt Strike uses HTTP/HTTPS."]
    },
    "T1071.002": {
        "name": "File Transfer Protocols",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using file transfer protocols.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has used FTP for data transfer."]
    },
    "T1071.003": {
        "name": "Mail Protocols",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using mail protocols.",
        "groups": ["APT28", "Turla"],
        "software": [],
        "procedure_examples": ["Turla has used email for C2."]
    },
    "T1071.004": {
        "name": "DNS",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using DNS.",
        "groups": ["APT28", "APT29", "Turla", "OilRig"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 has used DNS for C2.", "OilRig extensively uses DNS tunneling."]
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "description": "Adversaries may transfer tools from an external system.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla", "OilRig", "Scattered Spider"],
        "software": ["Cobalt Strike", "Metasploit"],
        "procedure_examples": ["APT28 downloads additional tools.", "FIN7 downloads Cobalt Strike."]
    },
    "T1132": {
        "name": "Data Encoding",
        "tactics": ["Command and Control"],
        "description": "Adversaries may encode data to make C2 traffic harder to detect.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 uses base64 encoding for C2."]
    },
    "T1132.001": {
        "name": "Standard Encoding",
        "tactics": ["Command and Control"],
        "description": "Adversaries may encode data with standard data encoding schemes.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 uses base64 encoding."]
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactics": ["Command and Control"],
        "description": "Adversaries may encrypt C2 communications.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 uses encrypted C2 channels."]
    },
    "T1573.001": {
        "name": "Symmetric Cryptography",
        "tactics": ["Command and Control"],
        "description": "Adversaries may use symmetric encryption for C2.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT41"],
        "software": [],
        "procedure_examples": ["Lazarus Group uses symmetric encryption."]
    },
    "T1573.002": {
        "name": "Asymmetric Cryptography",
        "tactics": ["Command and Control"],
        "description": "Adversaries may use asymmetric encryption for C2.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 uses RSA encryption for C2."]
    },
    "T1090": {
        "name": "Proxy",
        "tactics": ["Command and Control"],
        "description": "Adversaries may use proxies to direct C2 traffic.",
        "groups": ["APT28", "APT29", "Lazarus Group", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has used proxy servers for C2."]
    },
    "T1090.001": {
        "name": "Internal Proxy",
        "tactics": ["Command and Control"],
        "description": "Adversaries may use internal proxies to direct C2 traffic.",
        "groups": ["APT28", "APT29", "Turla"],
        "software": [],
        "procedure_examples": ["APT28 has used internal proxies."]
    },
    "T1219": {
        "name": "Remote Access Software",
        "tactics": ["Command and Control"],
        "description": "Adversaries may use legitimate remote access software for C2.",
        "groups": ["APT28", "Lazarus Group", "FIN7", "TA505"],
        "software": ["TeamViewer", "AnyDesk", "Ammyy Admin"],
        "procedure_examples": ["FIN7 has used remote access software."]
    },

    # ==================== EXFILTRATION ====================
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may steal data by exfiltrating it over the C2 channel.",
        "groups": ["APT28", "APT29", "Lazarus Group", "FIN7", "APT41", "Turla"],
        "software": ["Cobalt Strike"],
        "procedure_examples": ["APT28 exfiltrates data over C2.", "FIN7 exfiltrates over HTTPS."]
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may steal data by exfiltrating it over alternative protocols.",
        "groups": ["APT28", "APT29", "Turla", "OilRig"],
        "software": [],
        "procedure_examples": ["Turla has used FTP for exfiltration."]
    },
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may steal data over an unencrypted non-C2 protocol.",
        "groups": ["APT28", "APT29", "Turla", "OilRig"],
        "software": [],
        "procedure_examples": ["Turla has used FTP for exfiltration."]
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may use web services to exfiltrate data.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT41"],
        "software": [],
        "procedure_examples": ["APT29 has used cloud services for exfiltration."]
    },
    "T1567.002": {
        "name": "Exfiltration to Cloud Storage",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may exfiltrate data to cloud storage.",
        "groups": ["APT28", "APT29", "Lazarus Group", "APT41"],
        "software": [],
        "procedure_examples": ["APT29 has exfiltrated data to cloud storage."]
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may exfiltrate data to a cloud account they control.",
        "groups": ["APT29", "APT41"],
        "software": [],
        "procedure_examples": ["APT29 has transferred data to cloud accounts."]
    },

    # ==================== IMPACT ====================
    "T1485": {
        "name": "Data Destruction",
        "tactics": ["Impact"],
        "description": "Adversaries may destroy data to disrupt operations.",
        "groups": ["Lazarus Group", "Sandworm Team", "APT38"],
        "software": ["KillDisk", "WhisperGate"],
        "procedure_examples": ["Sandworm Team has used data wipers.", "Lazarus Group has destroyed data."]
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "description": "Adversaries may encrypt data to render it inaccessible.",
        "groups": ["Wizard Spider", "TA505", "Lazarus Group", "Sandworm Team"],
        "software": ["Ryuk", "Conti", "REvil", "WannaCry"],
        "procedure_examples": ["Wizard Spider deploys Ryuk ransomware.", "Sandworm deployed NotPetya."]
    },
    "T1489": {
        "name": "Service Stop",
        "tactics": ["Impact"],
        "description": "Adversaries may stop services to render systems or applications unavailable.",
        "groups": ["Lazarus Group", "Wizard Spider", "Sandworm Team"],
        "software": ["Ryuk"],
        "procedure_examples": ["Ryuk stops services before encryption."]
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactics": ["Impact"],
        "description": "Adversaries may delete or remove data recovery capabilities.",
        "groups": ["Lazarus Group", "Wizard Spider", "Sandworm Team"],
        "software": ["Ryuk", "Conti"],
        "procedure_examples": ["Ryuk deletes shadow copies.", "Conti deletes backups."]
    },
    "T1529": {
        "name": "System Shutdown/Reboot",
        "tactics": ["Impact"],
        "description": "Adversaries may shutdown or reboot systems to interrupt availability.",
        "groups": ["Lazarus Group", "Sandworm Team"],
        "software": [],
        "procedure_examples": ["Sandworm Team has caused system shutdowns."]
    },
    "T1531": {
        "name": "Account Access Removal",
        "tactics": ["Impact"],
        "description": "Adversaries may delete or modify accounts to remove access.",
        "groups": ["Sandworm Team", "Lazarus Group"],
        "software": [],
        "procedure_examples": ["Sandworm Team has deleted accounts during destructive attacks."]
    },
}


def get_technique_data(technique_id: str) -> Optional[Dict]:
    """
    Get full metadata for a MITRE ATT&CK technique.

    Args:
        technique_id: The technique ID (e.g., "T1059", "T1059.001")

    Returns:
        Dictionary with technique metadata, or None if not found
    """
    technique_id = attack_lookup.normalise(technique_id)
    published = attack_lookup.technique(technique_id)
    # Curated entries are keyed by the pinned release's IDs; an older case's revoked ID finds
    # its replacement's
    curated = ATTACK_TECHNIQUES.get(technique_id) or ATTACK_TECHNIQUES.get(attack_lookup.current_id(technique_id))
    if published is None:
        return curated
    # Name, tactics and domain from the pinned release (Enterprise or Mobile); groups,
    # software and procedures from the curated entries above, where there is one
    data = dict(curated or {})
    data.update({"name": attack_lookup.full_name(technique_id), "tactics": published.tactics,
                 "domain": published.domain, "platforms": published.platforms})
    data.setdefault("description", "")
    return data


def get_techniques_for_tactic(tactic: str) -> List[Dict]:
    """
    Get all techniques for a specific tactic.

    Args:
        tactic: The tactic name (e.g., "Execution", "Persistence")

    Returns:
        List of technique data dictionaries
    """
    tactic_lower = tactic.lower()
    results = []

    for tech_id, data in ATTACK_TECHNIQUES.items():
        tactics = [t.lower() for t in data.get("tactics", [])]
        if tactic_lower in tactics:
            results.append({"technique_id": tech_id, **data})

    return results


def enrich_technique(technique_id: str) -> Dict:
    """
    Get enriched data for a technique ID suitable for JSON embedding.

    Args:
        technique_id: The technique ID

    Returns:
        Dictionary with all technique metadata
    """
    data = get_technique_data(technique_id)
    if not data:
        # Return minimal data for unknown techniques
        return {
            "mitre_technique_id": technique_id,
            "mitre_technique_name": "Unknown Technique",
            "mitre_domain": "",
            "mitre_tactics": [],
            "mitre_description": "",
            "mitre_groups": [],
            "mitre_software": [],
            "mitre_procedure_examples": []
        }

    return {
        "mitre_technique_id": technique_id,
        "mitre_technique_name": data.get("name", ""),
        "mitre_domain": data.get("domain", ""),
        "mitre_tactics": data.get("tactics", []),
        "mitre_description": data.get("description", ""),
        "mitre_groups": data.get("groups", []),
        "mitre_software": data.get("software", []),
        "mitre_procedure_examples": data.get("procedure_examples", [])
    }

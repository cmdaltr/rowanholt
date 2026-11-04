#!/usr/bin/env python3
"""
MITRE ATT&CK CSV Generator for Splunk Elrond App

This module generates a mitre.csv lookup file from the MITRE ATT&CK
enterprise-attack.json STIX data file.

Usage:
    python mitre_csv_generator.py <input_json_path> <output_csv_path>
"""

import csv
import json
import os
import sys


def extract_techniques_from_stix(stix_data):
    """
    Extract technique information from STIX 2.1 bundle.

    Args:
        stix_data: Parsed STIX bundle dictionary

    Returns:
        List of technique dictionaries
    """
    techniques = []
    tactics_map = {}  # id -> name
    groups_map = {}   # id -> name
    software_map = {} # id -> name
    relationships = []

    # First pass: collect all objects
    for obj in stix_data.get("objects", []):
        obj_type = obj.get("type", "")

        if obj_type == "x-mitre-tactic":
            # Map tactic short names to display names
            tactics_map[obj.get("x_mitre_shortname", "")] = obj.get("name", "")

        elif obj_type == "intrusion-set":
            # Threat groups
            groups_map[obj.get("id", "")] = obj.get("name", "")

        elif obj_type == "malware" or obj_type == "tool":
            # Software
            software_map[obj.get("id", "")] = obj.get("name", "")

        elif obj_type == "relationship":
            # Relationships (e.g., group uses technique)
            if obj.get("relationship_type") == "uses":
                relationships.append({
                    "source": obj.get("source_ref", ""),
                    "target": obj.get("target_ref", ""),
                })

        elif obj_type == "attack-pattern":
            # Techniques and sub-techniques
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            technique = {
                "name": obj.get("name", ""),
                "id": "",
                "tactic": "",
                "platform": "",
                "procedure_example": "-",
                "description": obj.get("description", "").replace("\n", " ").replace('"', '""')[:500] if obj.get("description") else "-",
                "technique_description": obj.get("description", "").replace("\n", " ").replace('"', '""')[:2000] if obj.get("description") else "-",
                "detection": "-",
            }

            # Extract MITRE ID from external references
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique["id"] = ref.get("external_id", "")
                    break

            # Extract tactics (kill chain phases)
            tactics = []
            for kc in obj.get("kill_chain_phases", []):
                if kc.get("kill_chain_name") == "mitre-attack":
                    phase_name = kc.get("phase_name", "")
                    # Convert phase_name to display format
                    display_name = tactics_map.get(phase_name, phase_name.replace("-", " ").title())
                    tactics.append(display_name)
            technique["tactic"] = "; ".join(tactics) if tactics else "-"

            # Extract platforms
            platforms = obj.get("x_mitre_platforms", [])
            technique["platform"] = "; ".join(platforms) if platforms else "-"

            # Extract detection info (from data sources or detection field)
            detection_parts = []
            if obj.get("x_mitre_data_sources"):
                detection_parts.extend(obj.get("x_mitre_data_sources", []))
            technique["detection"] = "; ".join(detection_parts)[:500] if detection_parts else "-"

            techniques.append(technique)

    # Second pass: add procedure examples from relationships
    technique_id_map = {t["id"]: idx for idx, t in enumerate(techniques)}

    for rel in relationships:
        source_id = rel["source"]
        target_id = rel["target"]

        # Get the technique ID from the target
        for t in techniques:
            if target_id.startswith("attack-pattern"):
                # Check if this relationship's target matches a technique
                for obj in stix_data.get("objects", []):
                    if obj.get("id") == target_id:
                        for ref in obj.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                technique_id = ref.get("external_id", "")
                                if technique_id in technique_id_map:
                                    idx = technique_id_map[technique_id]
                                    # Add the group or software name
                                    example_name = groups_map.get(source_id) or software_map.get(source_id)
                                    if example_name:
                                        current = techniques[idx]["procedure_example"]
                                        if current == "-":
                                            techniques[idx]["procedure_example"] = example_name
                                        elif example_name not in current:
                                            techniques[idx]["procedure_example"] += f"; {example_name}"
                                break
                break

    return techniques


def generate_mitre_csv(input_json_path, output_csv_path):
    """
    Generate mitre.csv from MITRE ATT&CK STIX JSON.

    Args:
        input_json_path: Path to enterprise-attack.json
        output_csv_path: Path to output mitre.csv
    """
    # Load STIX data
    with open(input_json_path, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)

    # Extract techniques
    techniques = extract_techniques_from_stix(stix_data)

    # Sort by ID
    techniques.sort(key=lambda t: t["id"])

    # Write CSV
    fieldnames = ["name", "id", "tactic", "platform", "procedure_example", "description", "technique_description", "detection"]

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for technique in techniques:
            writer.writerow(technique)

    print(f"Generated {len(techniques)} techniques to {output_csv_path}")
    return len(techniques)


def generate_embedded_mitre_csv():
    """
    Generate a minimal embedded mitre.csv for the Splunk app.
    This creates a CSV with the essential MITRE ATT&CK v18 techniques.
    """
    # Hardcoded techniques for embedded use
    techniques = [
        {"name": "Drive-by Compromise", "id": "T1189", "tactic": "Initial Access", "platform": "Windows; Linux; macOS; SaaS", "procedure_example": "APT32; Lazarus Group", "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.", "technique_description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.", "detection": "Network Traffic; Process; File"},
        {"name": "Exploit Public-Facing Application", "id": "T1190", "tactic": "Initial Access", "platform": "Windows; Linux; macOS; Containers; Network; IaaS", "procedure_example": "APT28; APT41; Sandworm Team", "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.", "technique_description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.", "detection": "Application Log; Network Traffic"},
        {"name": "Phishing", "id": "T1566", "tactic": "Initial Access", "platform": "Windows; Linux; macOS; SaaS; Office 365; Google Workspace", "procedure_example": "APT29; Lazarus Group; Kimsuky", "description": "Adversaries may send phishing messages to gain access to victim systems.", "technique_description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing.", "detection": "Network Traffic; Application Log"},
        {"name": "Valid Accounts", "id": "T1078", "tactic": "Initial Access; Defense Evasion; Persistence; Privilege Escalation", "platform": "Windows; Linux; macOS; Containers; IaaS; SaaS; Network; Azure AD; Office 365; Google Workspace", "procedure_example": "APT28; APT29; FIN7", "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.", "technique_description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network.", "detection": "Logon Session; User Account"},
        {"name": "Command and Scripting Interpreter", "id": "T1059", "tactic": "Execution", "platform": "Windows; Linux; macOS; Network; IaaS; Containers", "procedure_example": "APT28; Cobalt Group; FIN7", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", "technique_description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.", "detection": "Command; Process; Script"},
        {"name": "Scheduled Task/Job", "id": "T1053", "tactic": "Execution; Persistence; Privilege Escalation", "platform": "Windows; Linux; macOS; Containers", "procedure_example": "APT29; Sandworm Team; Lazarus Group", "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.", "technique_description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time.", "detection": "Scheduled Job; Process; Command"},
        {"name": "User Execution", "id": "T1204", "tactic": "Execution", "platform": "Windows; Linux; macOS; IaaS; Containers", "procedure_example": "APT28; Lazarus Group; FIN7", "description": "An adversary may rely upon specific actions by a user in order to gain execution.", "technique_description": "An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link.", "detection": "Process; File; Network Traffic"},
        {"name": "Boot or Logon Autostart Execution", "id": "T1547", "tactic": "Persistence; Privilege Escalation", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence.", "technique_description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems.", "detection": "Windows Registry; File; Process"},
        {"name": "Create Account", "id": "T1136", "tactic": "Persistence", "platform": "Windows; Linux; macOS; IaaS; SaaS; Azure AD; Office 365; Google Workspace; Network", "procedure_example": "APT41; FIN7; Sandworm Team", "description": "Adversaries may create an account to maintain access to victim systems.", "technique_description": "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access.", "detection": "User Account; Process; Command"},
        {"name": "Process Injection", "id": "T1055", "tactic": "Defense Evasion; Privilege Escalation", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; Lazarus Group; Cobalt Group", "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.", "technique_description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.", "detection": "Process; OS API Execution"},
        {"name": "Masquerading", "id": "T1036", "tactic": "Defense Evasion", "platform": "Windows; Linux; macOS; Containers", "procedure_example": "APT29; Lazarus Group; FIN7", "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.", "technique_description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused.", "detection": "File; Process; Scheduled Job"},
        {"name": "Indicator Removal", "id": "T1070", "tactic": "Defense Evasion", "platform": "Windows; Linux; macOS; Containers; Network", "procedure_example": "APT28; APT29; Sandworm Team", "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.", "technique_description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary's actions.", "detection": "File; Process; Windows Registry; Command"},
        {"name": "Obfuscated Files or Information", "id": "T1027", "tactic": "Defense Evasion", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.", "technique_description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.", "detection": "File; Process"},
        {"name": "OS Credential Dumping", "id": "T1003", "tactic": "Credential Access", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.", "technique_description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.", "detection": "Process; Command; Windows Registry"},
        {"name": "Brute Force", "id": "T1110", "tactic": "Credential Access", "platform": "Windows; Linux; macOS; Azure AD; Office 365; SaaS; IaaS; Google Workspace; Containers; Network", "procedure_example": "APT28; APT29; Sandworm Team", "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.", "technique_description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password.", "detection": "User Account; Application Log"},
        {"name": "Account Discovery", "id": "T1087", "tactic": "Discovery", "platform": "Windows; Linux; macOS; Azure AD; Office 365; SaaS; IaaS; Google Workspace", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system.", "technique_description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist.", "detection": "Command; Process"},
        {"name": "System Information Discovery", "id": "T1082", "tactic": "Discovery", "platform": "Windows; Linux; macOS; IaaS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "An adversary may attempt to get detailed information about the operating system and hardware.", "technique_description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.", "detection": "Command; Process; OS API Execution"},
        {"name": "File and Directory Discovery", "id": "T1083", "tactic": "Discovery", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; FIN7", "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share.", "technique_description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.", "detection": "Command; Process"},
        {"name": "Remote Services", "id": "T1021", "tactic": "Lateral Movement", "platform": "Windows; Linux; macOS; IaaS", "procedure_example": "APT28; APT29; Sandworm Team", "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.", "technique_description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC.", "detection": "Logon Session; Network Traffic; Process"},
        {"name": "Lateral Tool Transfer", "id": "T1570", "tactic": "Lateral Movement", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; Sandworm Team; FIN7", "description": "Adversaries may transfer tools or other files between systems in a compromised environment.", "technique_description": "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment files may then be copied from one system to another to stage adversary tools.", "detection": "File; Network Traffic; Command"},
        {"name": "Data from Local System", "id": "T1005", "tactic": "Collection", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may search local system sources, such as file systems and configuration files or local databases.", "technique_description": "Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.", "detection": "File; Command"},
        {"name": "Archive Collected Data", "id": "T1560", "tactic": "Collection", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration.", "technique_description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.", "detection": "File; Process; Command"},
        {"name": "Application Layer Protocol", "id": "T1071", "tactic": "Command and Control", "platform": "Windows; Linux; macOS; Network", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.", "technique_description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic.", "detection": "Network Traffic"},
        {"name": "Encrypted Channel", "id": "T1573", "tactic": "Command and Control", "platform": "Windows; Linux; macOS; Network", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may employ a known encryption algorithm to conceal command and control traffic.", "technique_description": "Adversaries may employ a known encryption algorithm to conceal command and control traffic. The encryption algorithms used may include AES, DES, RC4, RC5, and TEA.", "detection": "Network Traffic"},
        {"name": "Ingress Tool Transfer", "id": "T1105", "tactic": "Command and Control", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.", "technique_description": "Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel.", "detection": "File; Network Traffic"},
        {"name": "Exfiltration Over C2 Channel", "id": "T1041", "tactic": "Exfiltration", "platform": "Windows; Linux; macOS", "procedure_example": "APT28; APT29; Lazarus Group", "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.", "technique_description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.", "detection": "Network Traffic; Command"},
        {"name": "Exfiltration Over Web Service", "id": "T1567", "tactic": "Exfiltration", "platform": "Windows; Linux; macOS; SaaS; Office 365; Google Workspace", "procedure_example": "APT28; APT29; FIN7", "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data.", "technique_description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover.", "detection": "Network Traffic; Command; Application Log"},
        {"name": "Data Encrypted for Impact", "id": "T1486", "tactic": "Impact", "platform": "Windows; Linux; macOS; IaaS", "procedure_example": "Sandworm Team; Lazarus Group", "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability.", "technique_description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives.", "detection": "File; Process; Command"},
        {"name": "Service Stop", "id": "T1489", "tactic": "Impact", "platform": "Windows; Linux; macOS", "procedure_example": "Sandworm Team; Lazarus Group", "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.", "technique_description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives.", "detection": "Process; Command; Service"},
        {"name": "Inhibit System Recovery", "id": "T1490", "tactic": "Impact", "platform": "Windows; Linux; macOS", "procedure_example": "Sandworm Team; Lazarus Group", "description": "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system.", "technique_description": "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options.", "detection": "Windows Registry; Process; Command; File"},
    ]

    return techniques


if __name__ == "__main__":
    if len(sys.argv) == 3:
        # Generate from JSON file
        input_path = sys.argv[1]
        output_path = sys.argv[2]
        generate_mitre_csv(input_path, output_path)
    elif len(sys.argv) == 2 and sys.argv[1] == "--embedded":
        # Generate embedded CSV to stdout
        techniques = generate_embedded_mitre_csv()
        fieldnames = ["name", "id", "tactic", "platform", "procedure_example", "description", "technique_description", "detection"]
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for t in techniques:
            writer.writerow(t)
    else:
        print("Usage:")
        print("  python mitre_csv_generator.py <input_json_path> <output_csv_path>")
        print("  python mitre_csv_generator.py --embedded")
        sys.exit(1)

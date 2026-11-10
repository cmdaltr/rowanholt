"""
MITRE ATT&CK Technique Mapper

Maps forensic artifacts to ATT&CK techniques dynamically.
Provides confidence scoring and context-aware mapping.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from .attck_updater import MitreAttackUpdater


class TechniqueMapper:
    """
    Map forensic artifacts to ATT&CK techniques dynamically.

    Features:
    - Automatic mapping based on artifact type
    - Custom mapping rules
    - Confidence scoring (0.0-1.0)
    - Multi-technique artifacts
    - Context-aware mapping
    """

    # Base artifact-to-technique mappings
    # Format: artifact_type -> [(technique_id, base_confidence), ...]
    ARTIFACT_MAPPINGS = {
        # ===== Windows Artifacts =====
        # Execution
        "prefetch": [
            ("T1059", 0.8),  # Command and Scripting Interpreter
            ("T1106", 0.7),  # Native API
        ],
        "powershell_history": [
            ("T1059.001", 0.95),  # PowerShell
            ("T1059", 0.9),  # Command and Scripting Interpreter
        ],
        "cmd_history": [
            ("T1059.003", 0.95),  # Windows Command Shell
            ("T1059", 0.9),  # Command and Scripting Interpreter
        ],
        "wmi_consumers": [
            ("T1546.003", 0.95),  # WMI Event Subscription
            ("T1047", 0.9),  # Windows Management Instrumentation
        ],
        "wmi_event_consumer": [
            ("T1546.003", 0.95),  # WMI Event Subscription
            ("T1047", 0.9),  # Windows Management Instrumentation
        ],
        "wmi_event_filter": [
            ("T1546.003", 0.95),  # WMI Event Subscription
            ("T1047", 0.9),  # Windows Management Instrumentation
        ],
        "wmi_binding": [
            ("T1546.003", 0.95),  # WMI Event Subscription
            ("T1047", 0.9),  # Windows Management Instrumentation
        ],
        "wmi_namespace": [
            ("T1047", 0.85),  # Windows Management Instrumentation
        ],
        "scheduled_tasks": [
            ("T1053.005", 0.95),  # Scheduled Task
            ("T1053", 0.9),  # Scheduled Task/Job
        ],
        # Persistence
        "registry_run_keys": [
            ("T1547.001", 0.95),  # Registry Run Keys / Startup Folder
            ("T1547", 0.9),  # Boot or Logon Autostart Execution
        ],
        "registry_persistence": [
            ("T1547", 0.85),  # Boot or Logon Autostart Execution
            ("T1112", 0.7),  # Modify Registry
        ],
        "services": [
            ("T1543.003", 0.9),  # Windows Service
            ("T1543", 0.85),  # Create or Modify System Process
        ],
        # Privilege Escalation
        "token_manipulation": [
            ("T1134", 0.9),  # Access Token Manipulation
        ],
        # Stealth and Defense Impairment (v20's split of Defense Evasion)
        "timestomp": [
            ("T1070.006", 0.95),  # Timestomp
            ("T1070", 0.9),  # Indicator Removal
        ],
        "file_deletion": [
            ("T1070.004", 0.8),  # File Deletion
            ("T1070", 0.75),  # Indicator Removal
        ],
        "clear_logs": [
            ("T1685.005", 0.95),  # Clear Windows Event Logs
            ("T1070", 0.9),  # Indicator Removal
        ],
        # Credential Access
        "lsass_dump": [
            ("T1003.001", 0.95),  # LSASS Memory
            ("T1003", 0.9),  # OS Credential Dumping
        ],
        "sam_dump": [
            ("T1003.002", 0.95),  # Security Account Manager
            ("T1003", 0.9),  # OS Credential Dumping
        ],
        "credentials_registry": [
            ("T1003.005", 0.9),  # Cached Domain Credentials
            ("T1003", 0.85),  # OS Credential Dumping
        ],
        # Discovery
        "network_connections": [
            ("T1049", 0.85),  # System Network Connections Discovery
            ("T1057", 0.7),  # Process Discovery
        ],
        "process_list": [
            ("T1057", 0.9),  # Process Discovery
        ],
        "file_directory_discovery": [
            ("T1083", 0.85),  # File and Directory Discovery
        ],
        # Collection
        "clipboard": [
            ("T1115", 0.95),  # Clipboard Data
        ],
        "screen_capture": [
            ("T1113", 0.95),  # Screen Capture
        ],
        "browser_data": [
            ("T1555.003", 0.9),  # Credentials from Web Browsers
            ("T1555", 0.85),  # Credentials from Password Stores
        ],
        # ===== Linux Artifacts =====
        "bash_history": [
            ("T1059.004", 0.95),  # Unix Shell
            ("T1059", 0.9),  # Command and Scripting Interpreter
        ],
        "cron_jobs": [
            ("T1053.003", 0.95),  # Cron
            ("T1053", 0.9),  # Scheduled Task/Job
        ],
        "systemd_services": [
            ("T1543.002", 0.95),  # Systemd Service
            ("T1543", 0.9),  # Create or Modify System Process
        ],
        "ssh_authorized_keys": [
            ("T1098.004", 0.9),  # SSH Authorized Keys
            ("T1098", 0.85),  # Account Manipulation
        ],
        # Linux Enhanced Artifacts (Feature 3)
        "systemd_journal": [
            ("T1685.006", 0.7),  # Clear Linux or Mac System Logs
        ],
        "audit_execve": [
            ("T1059", 0.9),  # Command and Scripting Interpreter
            ("T1059.004", 0.85),  # Unix Shell
        ],
        "audit_user": [
            ("T1136", 0.85),  # Create Account
            ("T1087", 0.8),  # Account Discovery
        ],
        "audit_auth": [
            ("T1078", 0.85),  # Valid Accounts
            ("T1110", 0.7),  # Brute Force
        ],
        "audit_file": [
            ("T1005", 0.7),  # Data from Local System
            ("T1083", 0.75),  # File and Directory Discovery
        ],
        "audit_network": [
            ("T1049", 0.75),  # System Network Connections Discovery
        ],
        "docker_container": [
            ("T1610", 0.9),  # Deploy Container
            ("T1613", 0.85),  # Container Discovery
            ("T1611", 0.7),  # Escape to Host
        ],
        "docker_image": [
            ("T1610", 0.85),  # Deploy Container
        ],
        "docker_volume": [
            ("T1610", 0.7),  # Deploy Container
        ],
        "zsh_history": [
            ("T1059.004", 0.95),  # Unix Shell
            ("T1059", 0.9),  # Command and Scripting Interpreter
        ],
        "python_history": [
            ("T1059.006", 0.9),  # Python
            ("T1059", 0.85),  # Command and Scripting Interpreter
        ],
        "package_install": [
            ("T1072", 0.85),  # Software Deployment
            ("T1105", 0.75),  # Ingress Tool Transfer
        ],
        # ===== macOS Artifacts =====
        "launch_agents": [
            ("T1543.001", 0.95),  # Launch Agent
            ("T1543", 0.9),  # Create or Modify System Process
        ],
        "launch_daemons": [
            ("T1543.004", 0.95),  # Launch Daemon
            ("T1543", 0.9),  # Create or Modify System Process
        ],
        "login_items": [
            ("T1547.015", 0.9),  # Login Items
            ("T1547", 0.85),  # Boot or Logon Autostart Execution
        ],
        "plist_files": [
            ("T1647", 0.75),  # Plist File Modification
        ],
        # macOS Enhanced Artifacts (Feature 3)
        "unified_log": [
            ("T1685.006", 0.7),  # Clear Linux or Mac System Logs
        ],
        "coreduet_app_usage": [
            ("T1083", 0.75),  # File and Directory Discovery
            ("T1087", 0.7),  # Account Discovery
        ],
        "coreduet_app_install": [
            ("T1105", 0.8),  # Ingress Tool Transfer
        ],
        "tcc_permission": [
            ("T1123", 0.9),  # Audio Capture
            ("T1125", 0.9),  # Video Capture
            ("T1005", 0.85),  # Data from Local System
        ],
        "fsevent": [
            ("T1083", 0.7),  # File and Directory Discovery
            ("T1070.004", 0.75),  # File Deletion
        ],
        "quarantine_event": [
            ("T1105", 0.85),  # Ingress Tool Transfer
            ("T1566", 0.6),  # Phishing
        ],
        # ===== Network Artifacts =====
        "network_traffic": [
            ("T1071", 0.7),  # Application Layer Protocol
            ("T1571", 0.6),  # Non-Standard Port
        ],
        "dns_queries": [
            ("T1071.004", 0.85),  # DNS
            ("T1071", 0.8),  # Application Layer Protocol
        ],
        # ===== Generic Artifacts =====
        "file_creation": [
            ("T1105", 0.6),  # Ingress Tool Transfer
        ],
        "registry_modification": [
            ("T1112", 0.8),  # Modify Registry
        ],
    }

    # Context-based bonus rules
    # These adjust confidence based on artifact content
    CONTEXT_RULES = {
        "powershell_obfuscation": {
            "patterns": [r"-enc", r"-encodedcommand", r"invoke-expression", r"iex"],
            "techniques": [("T1027", 0.2), ("T1140", 0.15)],  # Obfuscated Files, Deobfuscate/Decode
        },
        "powershell_download": {
            "patterns": [
                r"downloadstring",
                r"downloadfile",
                r"net.webclient",
                r"invoke-webrequest",
            ],
            "techniques": [("T1105", 0.25)],  # Ingress Tool Transfer
        },
        "powershell_execution_policy_bypass": {
            "patterns": [r"-executionpolicy bypass", r"-ep bypass"],
            "techniques": [("T1685", 0.2)],  # Disable or Modify Tools
        },
        "mimikatz": {
            "patterns": [r"mimikatz", r"sekurlsa", r"lsadump"],
            "techniques": [("T1003.001", 0.3)],  # LSASS Memory
        },
        "reconnaissance": {
            "patterns": [r"net user", r"net group", r"net localgroup", r"whoami /all"],
            "techniques": [
                ("T1087", 0.2),
                ("T1069", 0.2),
            ],  # Account Discovery, Permission Groups Discovery
        },
        "wmi_commands": {
            "patterns": [
                r"get-wmiobject",
                r"gwmi",
                r"invoke-wmimethod",
                r"register-wmievent",
                r"set-wmiinstance",
            ],
            "techniques": [("T1047", 0.25), ("T1546.003", 0.2)],  # WMI, WMI Event Subscription
        },
        "docker_commands": {
            "patterns": [r"docker run", r"docker exec", r"docker create", r"docker-compose"],
            "techniques": [("T1610", 0.2)],  # Deploy Container
        },
        "persistence_commands": {
            "patterns": [r"crontab", r"at\s+", r"systemctl enable", r"launchctl load"],
            "techniques": [("T1053", 0.2)],  # Scheduled Task/Job
        },
    }

    def __init__(self, updater: Optional[MitreAttackUpdater] = None):
        """
        Initialize technique mapper.

        Args:
            updater: MitreAttackUpdater instance (creates new if not provided)
        """
        self.updater = updater or MitreAttackUpdater()
        self.attck_data = self.updater.load_cached_data()

        if not self.attck_data:
            logging.warning("No ATT&CK data loaded, attempting to download...")
            if self.updater.update_local_cache(force=True):
                self.attck_data = self.updater.load_cached_data()

        self.logger = logging.getLogger(__name__)

    def map_artifact_to_techniques(
        self,
        artifact_type: str,
        artifact_data: Optional[dict] = None,
        context: Optional[str] = None,
    ) -> List[dict]:
        """
        Map artifact to ATT&CK techniques with confidence scoring.

        Args:
            artifact_type: Type of artifact (e.g., 'prefetch', 'powershell_history')
            artifact_data: Optional artifact data for context-aware mapping
            context: Optional text context (e.g., command line, file content)

        Returns:
            List of technique mappings with confidence scores
        """
        techniques = []

        # Get base mappings
        base_mappings = self.ARTIFACT_MAPPINGS.get(artifact_type, [])

        for technique_id, base_confidence in base_mappings:
            technique_details = self.get_technique_details(technique_id)

            if technique_details:
                mapping = {
                    "id": technique_id,
                    "name": technique_details.get("name"),
                    "tactics": technique_details.get("tactics", []),
                    "confidence": base_confidence,
                    "confidence_factors": {
                        "base": base_confidence,
                        "context": 0.0,
                    },
                    "evidence": {
                        "artifact_type": artifact_type,
                        "artifact_data": artifact_data,
                    },
                }

                techniques.append(mapping)

        # Apply context-based adjustments
        if context:
            context_techniques = self._apply_context_rules(context)
            techniques.extend(context_techniques)

        # Apply data-based adjustments
        if artifact_data:
            data_techniques = self._apply_data_rules(artifact_type, artifact_data)
            techniques.extend(data_techniques)

        # Merge duplicate techniques (take highest confidence)
        techniques = self._merge_techniques(techniques)

        # Sort by confidence (highest first)
        techniques.sort(key=lambda x: x["confidence"], reverse=True)

        return techniques

    def _apply_context_rules(self, context: str) -> List[dict]:
        """
        Apply context-based rules to detect additional techniques.

        Args:
            context: Text context to analyze

        Returns:
            List of additional technique mappings
        """
        techniques = []
        context_lower = context.lower()

        for rule_name, rule_data in self.CONTEXT_RULES.items():
            patterns = rule_data["patterns"]
            rule_techniques = rule_data["techniques"]

            # Check if any pattern matches
            for pattern in patterns:
                if re.search(pattern, context_lower, re.IGNORECASE):
                    # Add techniques from this rule
                    for technique_id, confidence_bonus in rule_techniques:
                        technique_details = self.get_technique_details(technique_id)

                        if technique_details:
                            techniques.append(
                                {
                                    "id": technique_id,
                                    "name": technique_details.get("name"),
                                    "tactics": technique_details.get("tactics", []),
                                    "confidence": confidence_bonus,
                                    "confidence_factors": {
                                        "base": 0.0,
                                        "context": confidence_bonus,
                                        "rule": rule_name,
                                    },
                                    "evidence": {
                                        "context_match": pattern,
                                    },
                                }
                            )
                    break  # Only match once per rule

        return techniques

    def _apply_data_rules(self, artifact_type: str, artifact_data: dict) -> List[dict]:
        """
        Apply data-based rules for specific artifact types.

        Args:
            artifact_type: Type of artifact
            artifact_data: Artifact data

        Returns:
            List of additional technique mappings
        """
        techniques = []

        # Example: Check for specific file names in prefetch
        if artifact_type == "prefetch":
            filename = artifact_data.get("filename", "").lower()

            # Known malicious tools
            if "mimikatz" in filename:
                techniques.append(
                    self._create_technique_mapping("T1003.001", 0.9, "mimikatz_detection")
                )
            elif "psexec" in filename:
                techniques.append(
                    self._create_technique_mapping("T1021.002", 0.85, "psexec_detection")
                )
            elif "procdump" in filename:
                techniques.append(
                    self._create_technique_mapping("T1003.001", 0.8, "procdump_detection")
                )

        # Example: Check for suspicious registry keys
        elif artifact_type == "registry_modification":
            key_path = artifact_data.get("key_path", "").lower()

            if "run" in key_path or "runonce" in key_path:
                techniques.append(
                    self._create_technique_mapping("T1547.001", 0.9, "run_key_detection")
                )
            elif "userinit" in key_path:
                techniques.append(
                    self._create_technique_mapping("T1547.001", 0.85, "userinit_detection")
                )

        return techniques

    def _create_technique_mapping(
        self, technique_id: str, confidence: float, rule_name: str
    ) -> dict:
        """Helper to create technique mapping dict."""
        technique_details = self.get_technique_details(technique_id)

        if technique_details:
            return {
                "id": technique_id,
                "name": technique_details.get("name"),
                "tactics": technique_details.get("tactics", []),
                "confidence": confidence,
                "confidence_factors": {
                    "base": 0.0,
                    "data_rule": confidence,
                    "rule": rule_name,
                },
                "evidence": {},
            }
        return {}

    def _merge_techniques(self, techniques: List[dict]) -> List[dict]:
        """
        Merge duplicate techniques, keeping highest confidence.

        Args:
            techniques: List of technique mappings

        Returns:
            Deduplicated list with merged confidences
        """
        merged = {}

        for tech in techniques:
            tech_id = tech["id"]

            if tech_id not in merged:
                merged[tech_id] = tech
            else:
                # Keep highest confidence
                if tech["confidence"] > merged[tech_id]["confidence"]:
                    merged[tech_id] = tech

        return list(merged.values())

    def get_technique_details(self, technique_id: str) -> Optional[dict]:
        """
        Get full technique details from ATT&CK data.

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            Technique details or None if not found
        """
        if not self.attck_data:
            return None

        return self.attck_data.get("techniques", {}).get(technique_id)

    def get_techniques_by_artifact_type(self, artifact_type: str) -> List[str]:
        """
        Get all technique IDs that can be mapped from an artifact type.

        Args:
            artifact_type: Artifact type

        Returns:
            List of technique IDs
        """
        mappings = self.ARTIFACT_MAPPINGS.get(artifact_type, [])
        return [tech_id for tech_id, _ in mappings]

    def get_confidence_threshold(self, artifact_type: str) -> float:
        """
        Get recommended confidence threshold for artifact type.

        Args:
            artifact_type: Artifact type

        Returns:
            Confidence threshold (0.0-1.0)
        """
        # High-fidelity artifacts
        if artifact_type in [
            "powershell_history",
            "scheduled_tasks",
            "wmi_consumers",
            "wmi_event_consumer",
            "wmi_event_filter",
            "wmi_binding",
            "audit_execve",
            "docker_container",
            "tcc_permission",
        ]:
            return 0.7

        # Medium-fidelity artifacts
        elif artifact_type in [
            "prefetch",
            "registry_modification",
            "coreduet_app_install",
            "quarantine_event",
            "package_install",
            "systemd_journal",
            "audit_user",
            "audit_auth",
        ]:
            return 0.6

        # Lower-fidelity artifacts
        else:
            return 0.5

    def add_custom_mapping(self, artifact_type: str, technique_id: str, confidence: float):
        """
        Add custom artifact-to-technique mapping.

        Args:
            artifact_type: Artifact type
            technique_id: ATT&CK technique ID
            confidence: Base confidence score
        """
        if artifact_type not in self.ARTIFACT_MAPPINGS:
            self.ARTIFACT_MAPPINGS[artifact_type] = []

        self.ARTIFACT_MAPPINGS[artifact_type].append((technique_id, confidence))
        self.logger.info(
            f"Added custom mapping: {artifact_type} -> {technique_id} (confidence: {confidence})"
        )

    def get_statistics(self) -> dict:
        """
        Get mapper statistics.

        Returns:
            Statistics dictionary
        """
        total_mappings = sum(len(mappings) for mappings in self.ARTIFACT_MAPPINGS.values())

        return {
            "artifact_types": len(self.ARTIFACT_MAPPINGS),
            "total_mappings": total_mappings,
            "context_rules": len(self.CONTEXT_RULES),
            "attck_version": self.attck_data.get("version") if self.attck_data else None,
        }


# Convenience function


def map_artifact(
    artifact_type: str, artifact_data: Optional[dict] = None, context: Optional[str] = None
) -> List[dict]:
    """
    Convenience function to map artifact to techniques.

    Args:
        artifact_type: Artifact type
        artifact_data: Optional artifact data
        context: Optional context

    Returns:
        List of technique mappings
    """
    mapper = TechniqueMapper()
    return mapper.map_artifact_to_techniques(artifact_type, artifact_data, context)

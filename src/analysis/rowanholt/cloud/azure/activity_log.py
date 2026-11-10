#!/usr/bin/env python3
"""
Azure Activity Log Analyzer

Analyze Azure Activity Logs for suspicious activity and MITRE ATT&CK mapping.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from collections import defaultdict

try:
    from azure.mgmt.monitor import MonitorManagementClient

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from ..base import CloudForensicsException


class ActivityLogAnalyzer:
    """
    Analyze Azure Activity Logs for suspicious activity.

    Detects:
    - Resource manipulation
    - Role assignment changes
    - Security configuration changes
    - Unusual administrative actions
    """

    # Suspicious operations mapped to MITRE ATT&CK
    SUSPICIOUS_OPERATIONS = {
        # Defense Impairment
        "Microsoft.Insights/DiagnosticSettings/Delete": ["T1685.002"],  # Disable or Modify Cloud Log
        "Microsoft.Security/securityContacts/delete": ["T1685"],  # Disable or Modify Tools
        # Privilege Escalation
        "Microsoft.Authorization/roleAssignments/write": ["T1098"],  # Account Manipulation
        "Microsoft.Authorization/roleDefinitions/write": ["T1098"],
        # Persistence
        "Microsoft.Compute/virtualMachines/write": ["T1578.002"],  # Create Cloud Instance
        "Microsoft.Web/sites/write": ["T1505.003"],  # Web Shell
        # Credential Access
        "Microsoft.KeyVault/vaults/secrets/read": ["T1555"],  # Credentials from Password Stores
        "Microsoft.Sql/servers/databases/read": ["T1552.001"],  # Unsecured Credentials
        # Discovery
        "Microsoft.Resources/subscriptions/resourceGroups/read": [
            "T1580"
        ],  # Cloud Infrastructure Discovery
        "Microsoft.Compute/virtualMachines/read": ["T1580"],
        "Microsoft.Storage/storageAccounts/read": ["T1619"],  # Cloud Storage Discovery
        # Impact
        "Microsoft.Compute/virtualMachines/delete": ["T1485"],  # Data Destruction
        "Microsoft.Storage/storageAccounts/delete": ["T1485"],
    }

    def __init__(self, credential: Any, subscription_id: str):
        """
        Initialize Activity Log analyzer.

        Args:
            credential: Azure credential object
            subscription_id: Azure subscription ID
        """
        if not AZURE_AVAILABLE:
            raise ImportError("Azure SDK required")

        self.credential = credential
        self.subscription_id = subscription_id
        self.monitor_client = MonitorManagementClient(credential, subscription_id)

    def acquire_logs(self, start_time: datetime, end_time: datetime, output_dir: str) -> List[str]:
        """
        Acquire Activity Logs for time range.

        Args:
            start_time: Start datetime
            end_time: End datetime
            output_dir: Output directory

        Returns:
            List of output file paths
        """
        try:
            filter_str = (
                f"eventTimestamp ge '{start_time.isoformat()}' and "
                f"eventTimestamp le '{end_time.isoformat()}'"
            )

            logs = []
            activity_logs = self.monitor_client.activity_logs.list(filter=filter_str)

            for log in activity_logs:
                logs.append(self._format_log(log))

            # Save logs
            output_file = os.path.join(
                output_dir,
                f"azure_activity_logs_{start_time.strftime('%Y%m%d')}_{end_time.strftime('%Y%m%d')}.json",
            )

            with open(output_file, "w") as f:
                json.dump(logs, f, indent=2, default=str)

            return [output_file]

        except Exception as e:
            raise CloudForensicsException(f"Failed to acquire Activity Logs: {e}", provider="Azure")

    def _format_log(self, log: Any) -> Dict[str, Any]:
        """Format Activity Log entry."""
        return {
            "timestamp": log.event_timestamp.isoformat() if log.event_timestamp else None,
            "operation_name": log.operation_name.value if log.operation_name else None,
            "operation_id": log.operation_id,
            "status": log.status.value if log.status else None,
            "caller": log.caller,
            "correlation_id": log.correlation_id,
            "resource_id": log.resource_id,
            "resource_group": log.resource_group_name,
            "resource_provider": (
                log.resource_provider_name.value if log.resource_provider_name else None
            ),
            "resource_type": log.resource_type.value if log.resource_type else None,
            "subscription_id": log.subscription_id,
            "level": log.level,
            "properties": log.properties,
        }

    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """
        Analyze Activity Logs for suspicious activity.

        Args:
            log_file: Path to Activity Log JSON file

        Returns:
            Dictionary with analysis findings
        """
        with open(log_file, "r") as f:
            logs = json.load(f)

        findings = {
            "suspicious_operations": [],
            "role_changes": [],
            "resource_deletions": [],
            "failed_operations": [],
            "unusual_callers": [],
            "statistics": {
                "total_events": len(logs),
                "unique_callers": set(),
                "operation_counts": defaultdict(int),
                "resource_types": defaultdict(int),
            },
        }

        for log in logs:
            # Update statistics
            findings["statistics"]["unique_callers"].add(log.get("caller", "N/A"))
            findings["statistics"]["operation_counts"][log.get("operation_name", "N/A")] += 1
            findings["statistics"]["resource_types"][log.get("resource_type", "N/A")] += 1

            operation_name = log.get("operation_name", "")

            # Check for suspicious operations
            if operation_name in self.SUSPICIOUS_OPERATIONS:
                findings["suspicious_operations"].append(
                    {
                        "log": log,
                        "attck_techniques": self.SUSPICIOUS_OPERATIONS[operation_name],
                        "severity": self._get_operation_severity(operation_name),
                    }
                )

            # Check for role changes
            if "roleAssignment" in operation_name or "roleDefinition" in operation_name:
                findings["role_changes"].append(log)

            # Check for resource deletions
            if log.get("operation_name", "").endswith("/delete"):
                findings["resource_deletions"].append(log)

            # Check for failed operations
            if log.get("status") == "Failed":
                findings["failed_operations"].append(log)

        # Convert sets to lists
        findings["statistics"]["unique_callers"] = list(findings["statistics"]["unique_callers"])
        findings["statistics"]["operation_counts"] = dict(
            findings["statistics"]["operation_counts"]
        )
        findings["statistics"]["resource_types"] = dict(findings["statistics"]["resource_types"])

        return findings

    def _get_operation_severity(self, operation_name: str) -> str:
        """Determine operation severity."""
        high_severity = [
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Insights/DiagnosticSettings/Delete",
            "Microsoft.KeyVault/vaults/secrets/read",
        ]

        if operation_name in high_severity:
            return "high"
        elif operation_name in self.SUSPICIOUS_OPERATIONS:
            return "medium"
        else:
            return "low"

    def map_to_mitre(self, findings: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """
        Map findings to MITRE ATT&CK techniques.

        Args:
            findings: Analysis findings

        Returns:
            Dictionary mapping technique IDs to events
        """
        technique_map = defaultdict(list)

        for finding in findings.get("suspicious_operations", []):
            for technique in finding["attck_techniques"]:
                technique_map[technique].append(
                    {
                        "operation_name": finding["log"]["operation_name"],
                        "timestamp": finding["log"]["timestamp"],
                        "caller": finding["log"]["caller"],
                        "resource_id": finding["log"]["resource_id"],
                        "severity": finding["severity"],
                    }
                )

        return dict(technique_map)

    def generate_report(self, findings: Dict[str, Any], output_file: str):
        """
        Generate analysis report.

        Args:
            findings: Analysis findings
            output_file: Output file path
        """
        report = {
            "report_generated": datetime.now().isoformat(),
            "summary": {
                "total_events": findings["statistics"]["total_events"],
                "suspicious_operations": len(findings["suspicious_operations"]),
                "role_changes": len(findings["role_changes"]),
                "resource_deletions": len(findings["resource_deletions"]),
                "failed_operations": len(findings["failed_operations"]),
                "unique_callers": len(findings["statistics"]["unique_callers"]),
            },
            "statistics": findings["statistics"],
            "findings": findings,
            "mitre_mapping": self.map_to_mitre(findings),
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

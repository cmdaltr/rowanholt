#!/usr/bin/env python3
"""
GCP Cloud Logging Analyzer

Analyze GCP Cloud Logging for suspicious activity and MITRE ATT&CK mapping.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from collections import defaultdict

try:
    from google.cloud import logging_v2

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from ..base import CloudForensicsException


class CloudLoggingAnalyzer:
    """
    Analyze GCP Cloud Logging for suspicious activity.

    Detects:
    - IAM policy changes
    - Resource modifications
    - Logging configuration changes
    - Unusual API calls
    """

    # Suspicious method names mapped to MITRE ATT&CK
    SUSPICIOUS_METHODS = {
        # Defense Evasion
        "google.logging.v2.ConfigServiceV2.DeleteSink": ["T1562.008"],  # Disable Cloud Logs
        "google.logging.v2.ConfigServiceV2.UpdateSink": ["T1562.008"],
        # Privilege Escalation
        "google.iam.admin.v1.SetIamPolicy": ["T1098"],  # Account Manipulation
        "google.iam.admin.v1.CreateRole": ["T1098"],
        "google.iam.admin.v1.CreateServiceAccount": ["T1136.003"],  # Create Cloud Account
        # Persistence
        "google.compute.v1.Instances.Insert": ["T1578.002"],  # Create Cloud Instance
        "google.compute.v1.Instances.Start": ["T1578.002"],
        # Credential Access
        "google.iam.admin.v1.CreateServiceAccountKey": ["T1552.001"],  # Unsecured Credentials
        # Discovery
        "google.compute.v1.Instances.List": ["T1580"],  # Cloud Infrastructure Discovery
        "google.storage.v1.Buckets.List": ["T1619"],  # Cloud Storage Discovery
        "google.iam.admin.v1.ListServiceAccounts": ["T1087.004"],  # Cloud Account Discovery
        # Impact
        "google.compute.v1.Instances.Delete": ["T1485"],  # Data Destruction
        "google.storage.v1.Buckets.Delete": ["T1485"],
    }

    def __init__(self, project_id: str):
        """
        Initialize Cloud Logging analyzer.

        Args:
            project_id: GCP project ID
        """
        if not GCP_AVAILABLE:
            raise ImportError("Google Cloud SDK required")

        self.project_id = project_id
        self.logging_client = logging_v2.Client(project=project_id)

    def acquire_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        output_dir: str,
        log_filter: Optional[str] = None,
    ) -> List[str]:
        """
        Acquire Cloud Logging entries for time range.

        Args:
            start_time: Start datetime
            end_time: End datetime
            output_dir: Output directory
            log_filter: Optional additional filter

        Returns:
            List of output file paths
        """
        try:
            # Build filter
            filter_parts = [
                f'timestamp>="{start_time.isoformat()}"',
                f'timestamp<="{end_time.isoformat()}"',
            ]

            if log_filter:
                filter_parts.append(log_filter)

            filter_str = " AND ".join(filter_parts)

            # Fetch logs
            logs = []
            for entry in self.logging_client.list_entries(filter_=filter_str):
                logs.append(self._format_log_entry(entry))

            # Save logs
            output_file = os.path.join(
                output_dir,
                f"gcp_cloud_logs_{start_time.strftime('%Y%m%d')}_{end_time.strftime('%Y%m%d')}.json",
            )

            with open(output_file, "w") as f:
                json.dump(logs, f, indent=2, default=str)

            return [output_file]

        except Exception as e:
            raise CloudForensicsException(f"Failed to acquire Cloud Logs: {e}", provider="GCP")

    def _format_log_entry(self, entry: Any) -> Dict[str, Any]:
        """Format log entry."""
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "severity": entry.severity,
            "log_name": entry.log_name,
            "resource": {
                "type": entry.resource.type if entry.resource else None,
                "labels": (
                    dict(entry.resource.labels) if entry.resource and entry.resource.labels else {}
                ),
            },
            "proto_payload": (
                self._format_proto_payload(entry.proto_payload)
                if hasattr(entry, "proto_payload") and entry.proto_payload
                else None
            ),
            "json_payload": entry.payload if entry.payload else None,
            "insert_id": entry.insert_id,
            "trace": entry.trace,
            "span_id": entry.span_id,
        }

    def _format_proto_payload(self, proto_payload: Any) -> Dict[str, Any]:
        """Format protocol buffer payload."""
        try:
            return {
                "method_name": proto_payload.get("methodName"),
                "service_name": proto_payload.get("serviceName"),
                "resource_name": proto_payload.get("resourceName"),
                "caller_ip": proto_payload.get("requestMetadata", {}).get("callerIp"),
                "caller_supplied_user_agent": proto_payload.get("requestMetadata", {}).get(
                    "callerSuppliedUserAgent"
                ),
                "status": proto_payload.get("status"),
                "request": proto_payload.get("request"),
                "response": proto_payload.get("response"),
            }
        except:
            return {}

    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """
        Analyze Cloud Logs for suspicious activity.

        Args:
            log_file: Path to Cloud Logs JSON file

        Returns:
            Dictionary with analysis findings
        """
        with open(log_file, "r") as f:
            logs = json.load(f)

        findings = {
            "suspicious_methods": [],
            "iam_changes": [],
            "resource_deletions": [],
            "failed_requests": [],
            "statistics": {
                "total_events": len(logs),
                "unique_callers": set(),
                "method_counts": defaultdict(int),
                "service_counts": defaultdict(int),
            },
        }

        for log in logs:
            proto_payload = log.get("proto_payload", {})
            if not proto_payload:
                continue

            method_name = proto_payload.get("method_name", "")
            service_name = proto_payload.get("service_name", "")
            caller_ip = proto_payload.get("caller_ip", "N/A")

            # Update statistics
            findings["statistics"]["unique_callers"].add(caller_ip)
            findings["statistics"]["method_counts"][method_name] += 1
            findings["statistics"]["service_counts"][service_name] += 1

            # Check for suspicious methods
            if method_name in self.SUSPICIOUS_METHODS:
                findings["suspicious_methods"].append(
                    {
                        "log": log,
                        "attck_techniques": self.SUSPICIOUS_METHODS[method_name],
                        "severity": self._get_method_severity(method_name),
                    }
                )

            # Check for IAM changes
            if (
                "iam" in method_name.lower()
                and "Set" in method_name
                or "Create" in method_name
                or "Update" in method_name
            ):
                findings["iam_changes"].append(log)

            # Check for resource deletions
            if "Delete" in method_name:
                findings["resource_deletions"].append(log)

            # Check for failed requests
            status = proto_payload.get("status", {})
            if status and status.get("code") != 0:
                findings["failed_requests"].append(log)

        # Convert sets to lists
        findings["statistics"]["unique_callers"] = list(findings["statistics"]["unique_callers"])
        findings["statistics"]["method_counts"] = dict(findings["statistics"]["method_counts"])
        findings["statistics"]["service_counts"] = dict(findings["statistics"]["service_counts"])

        return findings

    def _get_method_severity(self, method_name: str) -> str:
        """Determine method severity."""
        high_severity = [
            "google.iam.admin.v1.SetIamPolicy",
            "google.logging.v2.ConfigServiceV2.DeleteSink",
            "google.iam.admin.v1.CreateServiceAccountKey",
        ]

        if method_name in high_severity:
            return "high"
        elif method_name in self.SUSPICIOUS_METHODS:
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

        for finding in findings.get("suspicious_methods", []):
            for technique in finding["attck_techniques"]:
                proto_payload = finding["log"].get("proto_payload", {})
                technique_map[technique].append(
                    {
                        "method_name": proto_payload.get("method_name"),
                        "timestamp": finding["log"]["timestamp"],
                        "caller_ip": proto_payload.get("caller_ip"),
                        "resource_name": proto_payload.get("resource_name"),
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
            "project_id": self.project_id,
            "summary": {
                "total_events": findings["statistics"]["total_events"],
                "suspicious_methods": len(findings["suspicious_methods"]),
                "iam_changes": len(findings["iam_changes"]),
                "resource_deletions": len(findings["resource_deletions"]),
                "failed_requests": len(findings["failed_requests"]),
                "unique_callers": len(findings["statistics"]["unique_callers"]),
            },
            "statistics": findings["statistics"],
            "findings": findings,
            "mitre_mapping": self.map_to_mitre(findings),
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

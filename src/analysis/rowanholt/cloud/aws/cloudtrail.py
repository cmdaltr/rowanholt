#!/usr/bin/env python3
"""
AWS CloudTrail Analyzer

Analyze AWS CloudTrail logs for suspicious activity and MITRE ATT&CK mapping.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from ..base import CloudForensicsException


class CloudTrailAnalyzer:
    """
    Analyze CloudTrail logs for suspicious activity.

    Detects:
    - Stealth and defence impairment (log tampering)
    - Privilege escalation
    - Credential access
    - Discovery activities
    - Data exfiltration
    """

    # Suspicious event names mapped to MITRE ATT&CK
    SUSPICIOUS_EVENTS = {
        # Stealth (T1070.003) - Log Tampering
        "DeleteTrail": ["T1070.003"],  # Clear Cloud Logs
        "StopLogging": ["T1070.003"],
        "UpdateTrail": ["T1070.003"],
        "PutEventSelectors": ["T1070.003"],
        # Impact, Stealth and Defense Impairment - Policy Modification
        "DeleteBucket": ["T1485"],  # Data Destruction
        "PutBucketLogging": ["T1070.003"],
        "DeleteFlowLogs": ["T1070.003"],
        "DeleteDetector": ["T1685"],  # Disable or Modify Tools (GuardDuty)
        # Privilege Escalation
        "CreateAccessKey": ["T1098"],  # Account Manipulation
        "CreateUser": ["T1136.003"],  # Create Cloud Account
        "AttachUserPolicy": ["T1098"],
        "AttachRolePolicy": ["T1098"],
        "PutUserPolicy": ["T1098"],
        "PutRolePolicy": ["T1098"],
        "AssumeRole": ["T1078.004"],  # Valid Accounts: Cloud Accounts
        # Credential Access
        "GetSecretValue": ["T1552.001"],  # Unsecured Credentials
        "GetParameter": ["T1552.001"],
        "DescribeDBInstances": ["T1552.001"],  # Looking for DB credentials
        # Discovery
        "DescribeInstances": ["T1580"],  # Cloud Infrastructure Discovery
        "DescribeSecurityGroups": ["T1580"],
        "ListBuckets": ["T1619"],  # Cloud Storage Object Discovery
        "GetUser": ["T1087.004"],  # Cloud Account Discovery
        "ListUsers": ["T1087.004"],
        "GetRole": ["T1087.004"],
        # Execution
        "RunInstances": ["T1578.002"],  # Create Cloud Instance
        "CreateFunction": ["T1059"],  # Command and Scripting Interpreter
        # Persistence
        "CreateLoginProfile": ["T1136.003"],  # Create Cloud Account
        "UpdateLoginProfile": ["T1098"],
        "CreateKeyPair": ["T1098"],
        # Exfiltration
        "GetObject": ["T1530"],  # Data from Cloud Storage
        "CopyObject": ["T1537"],  # Transfer Data to Cloud Account
        "CreateSnapshot": ["T1537"],
        "CopySnapshot": ["T1537"],
    }

    # High-risk services for credential access
    CREDENTIAL_SERVICES = ["secretsmanager", "ssm", "rds", "redshift"]  # Parameter Store

    # Discovery service patterns
    DISCOVERY_SERVICES = ["ec2", "s3", "iam", "lambda", "ecs"]

    def __init__(self, session: Optional[Any] = None):
        """
        Initialize CloudTrail analyzer.

        Args:
            session: Optional boto3 session
        """
        self.session = session
        if session:
            self.cloudtrail = session.client("cloudtrail")
        else:
            self.cloudtrail = None

    def acquire_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        output_dir: str,
        region: Optional[str] = None,
    ) -> List[str]:
        """
        Acquire CloudTrail logs for time range.

        Args:
            start_time: Start datetime
            end_time: End datetime
            output_dir: Output directory
            region: AWS region

        Returns:
            List of output file paths
        """
        if not self.cloudtrail:
            raise CloudForensicsException("CloudTrail client not initialized", provider="AWS")

        output_files = []

        try:
            logs = []
            paginator = self.cloudtrail.get_paginator("lookup_events")

            for page in paginator.paginate(StartTime=start_time, EndTime=end_time):
                for event in page.get("Events", []):
                    logs.append(self._format_event(event))

            # Save raw logs
            output_file = os.path.join(
                output_dir,
                f"cloudtrail_{start_time.strftime('%Y%m%d')}_{end_time.strftime('%Y%m%d')}.json",
            )

            with open(output_file, "w") as f:
                json.dump(logs, f, indent=2, default=str)

            output_files.append(output_file)

            return output_files

        except ClientError as e:
            raise CloudForensicsException(f"Failed to acquire CloudTrail logs: {e}", provider="AWS")

    def _format_event(self, event: Dict) -> Dict[str, Any]:
        """Format CloudTrail event."""
        cloud_trail_event = json.loads(event.get("CloudTrailEvent", "{}"))

        return {
            "event_time": event.get("EventTime").isoformat() if event.get("EventTime") else None,
            "event_name": event.get("EventName"),
            "event_source": event.get("EventSource"),
            "username": event.get("Username"),
            "access_key_id": event.get("AccessKeyId"),
            "event_id": event.get("EventId"),
            "resources": event.get("Resources", []),
            "user_agent": cloud_trail_event.get("userAgent"),
            "source_ip": cloud_trail_event.get("sourceIPAddress"),
            "request_parameters": cloud_trail_event.get("requestParameters", {}),
            "response_elements": cloud_trail_event.get("responseElements", {}),
            "error_code": cloud_trail_event.get("errorCode"),
            "error_message": cloud_trail_event.get("errorMessage"),
        }

    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """
        Analyze CloudTrail logs for suspicious activity.

        Args:
            log_file: Path to CloudTrail JSON log file

        Returns:
            Dictionary with analysis findings
        """
        with open(log_file, "r") as f:
            logs = json.load(f)

        findings = {
            "suspicious_events": [],
            "unusual_sources": [],
            "privilege_escalations": [],
            "credential_access": [],
            "discovery_activity": [],
            "failed_attempts": [],
            "statistics": {
                "total_events": len(logs),
                "unique_users": set(),
                "unique_ips": set(),
                "event_counts": defaultdict(int),
                "service_counts": defaultdict(int),
            },
        }

        for event in logs:
            # Update statistics
            findings["statistics"]["unique_users"].add(event.get("username", "N/A"))
            findings["statistics"]["unique_ips"].add(event.get("source_ip", "N/A"))
            findings["statistics"]["event_counts"][event.get("event_name", "N/A")] += 1

            service = event.get("event_source", "").split(".")[0]
            findings["statistics"]["service_counts"][service] += 1

            # Analyze event
            event_name = event.get("event_name")

            # Check for suspicious events
            if event_name in self.SUSPICIOUS_EVENTS:
                findings["suspicious_events"].append(
                    {
                        "event": event,
                        "attck_techniques": self.SUSPICIOUS_EVENTS[event_name],
                        "severity": self._get_event_severity(event_name),
                    }
                )

            # Check for unusual source IPs
            if self._is_unusual_source(event):
                findings["unusual_sources"].append(event)

            # Check for privilege escalation
            if self._is_privilege_escalation(event):
                findings["privilege_escalations"].append(event)

            # Check for credential access
            if self._is_credential_access(event):
                findings["credential_access"].append(event)

            # Check for discovery activity
            if self._is_discovery_activity(event):
                findings["discovery_activity"].append(event)

            # Check for failed attempts
            if event.get("error_code"):
                findings["failed_attempts"].append(event)

        # Convert sets to lists for JSON serialization
        findings["statistics"]["unique_users"] = list(findings["statistics"]["unique_users"])
        findings["statistics"]["unique_ips"] = list(findings["statistics"]["unique_ips"])
        findings["statistics"]["event_counts"] = dict(findings["statistics"]["event_counts"])
        findings["statistics"]["service_counts"] = dict(findings["statistics"]["service_counts"])

        return findings

    def _get_event_severity(self, event_name: str) -> str:
        """Determine event severity."""
        high_severity = [
            "DeleteTrail",
            "StopLogging",
            "CreateAccessKey",
            "AttachUserPolicy",
            "PutUserPolicy",
            "CreateUser",
        ]

        if event_name in high_severity:
            return "high"
        elif event_name in self.SUSPICIOUS_EVENTS:
            return "medium"
        else:
            return "low"

    def _is_unusual_source(self, event: Dict) -> bool:
        """
        Check if event source IP is unusual.

        This is a simplified check. Production should use:
        - IP reputation services
        - Geographic analysis
        - Historical baseline
        """
        source_ip = event.get("source_ip", "")

        # Check for non-AWS IPs accessing sensitive services
        if not source_ip.startswith("AWS Internal"):
            event_name = event.get("event_name", "")
            if event_name in ["CreateAccessKey", "CreateUser", "DeleteTrail"]:
                return True

        return False

    def _is_privilege_escalation(self, event: Dict) -> bool:
        """Check if event indicates privilege escalation."""
        event_name = event.get("event_name", "")

        escalation_events = [
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "CreateAccessKey",
            "UpdateAssumeRolePolicy",
        ]

        if event_name in escalation_events:
            # Check if granting admin-like permissions
            request_params = event.get("request_parameters", {})
            policy_arn = request_params.get("policyArn", "")

            if "AdministratorAccess" in policy_arn or "FullAccess" in policy_arn:
                return True

            # Check inline policy content
            policy_doc = request_params.get("policyDocument", "")
            if 'Action":"*"' in str(policy_doc) or '"Resource":"*"' in str(policy_doc):
                return True

        return False

    def _is_credential_access(self, event: Dict) -> bool:
        """Check if event indicates credential access."""
        event_name = event.get("event_name", "")
        event_source = event.get("event_source", "")

        # Direct credential access
        credential_events = ["GetSecretValue", "GetParameter", "GetUser", "ListAccessKeys"]

        if event_name in credential_events:
            return True

        # Service-based credential hunting
        service = event_source.split(".")[0]
        if service in self.CREDENTIAL_SERVICES:
            if event_name.startswith("Describe") or event_name.startswith("List"):
                return True

        return False

    def _is_discovery_activity(self, event: Dict) -> bool:
        """Check if event indicates discovery activity."""
        event_name = event.get("event_name", "")
        event_source = event.get("event_source", "")

        # Discovery event patterns
        discovery_patterns = ["Describe", "List", "Get", "Lookup"]

        service = event_source.split(".")[0]
        if service in self.DISCOVERY_SERVICES:
            if any(event_name.startswith(pattern) for pattern in discovery_patterns):
                return True

        return False

    def map_to_mitre(self, findings: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """
        Map findings to MITRE ATT&CK techniques.

        Args:
            findings: Analysis findings from analyze_logs()

        Returns:
            Dictionary mapping technique IDs to events
        """
        technique_map = defaultdict(list)

        for finding in findings.get("suspicious_events", []):
            for technique in finding["attck_techniques"]:
                technique_map[technique].append(
                    {
                        "event_name": finding["event"]["event_name"],
                        "timestamp": finding["event"]["event_time"],
                        "username": finding["event"]["username"],
                        "source_ip": finding["event"]["source_ip"],
                        "severity": finding["severity"],
                    }
                )

        # Add privilege escalations
        for event in findings.get("privilege_escalations", []):
            technique_map["T1098"].append(
                {
                    "event_name": event["event_name"],
                    "timestamp": event["event_time"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "severity": "high",
                    "category": "privilege_escalation",
                }
            )

        # Add credential access
        for event in findings.get("credential_access", []):
            technique_map["T1552.001"].append(
                {
                    "event_name": event["event_name"],
                    "timestamp": event["event_time"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "severity": "high",
                    "category": "credential_access",
                }
            )

        # Add discovery
        for event in findings.get("discovery_activity", []):
            technique_map["T1580"].append(
                {
                    "event_name": event["event_name"],
                    "timestamp": event["event_time"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "severity": "low",
                    "category": "discovery",
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
                "suspicious_events": len(findings["suspicious_events"]),
                "unusual_sources": len(findings["unusual_sources"]),
                "privilege_escalations": len(findings["privilege_escalations"]),
                "credential_access": len(findings["credential_access"]),
                "discovery_activity": len(findings["discovery_activity"]),
                "failed_attempts": len(findings["failed_attempts"]),
                "unique_users": len(findings["statistics"]["unique_users"]),
                "unique_source_ips": len(findings["statistics"]["unique_ips"]),
            },
            "statistics": findings["statistics"],
            "findings": findings,
            "mitre_mapping": self.map_to_mitre(findings),
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

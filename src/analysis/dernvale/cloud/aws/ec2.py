#!/usr/bin/env python3
"""
AWS EC2 Forensics Module

Forensic acquisition and analysis of AWS EC2 instances and EBS volumes.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
import time
from datetime import datetime
from typing import List, Dict, Optional, Any

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from ..base import CloudProvider, CloudForensicsException, CloudArtifact


class AWSForensics(CloudProvider):
    """
    AWS forensics acquisition and analysis.

    Supports:
    - EC2 instance enumeration
    - EBS volume snapshot creation
    - Instance metadata collection
    - Security group analysis
    - IAM role analysis
    """

    def __init__(self, credentials: Dict[str, str], config: Optional[Dict] = None):
        """
        Initialize AWS forensics.

        Args:
            credentials: AWS credentials dict with keys:
                - access_key: AWS access key ID
                - secret_key: AWS secret access key
                - region: AWS region (default: us-east-1)
                - session_token: Optional session token
            config: Optional configuration
        """
        super().__init__(credentials, config)

        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 library not available. Install with: pip install boto3")

        self.session = None
        self.ec2_client = None
        self.region = credentials.get("region", "us-east-1")

    def get_required_credential_keys(self) -> List[str]:
        """Required AWS credential keys."""
        return ["access_key", "secret_key"]

    def authenticate(self) -> bool:
        """
        Authenticate with AWS using credentials.

        Returns:
            True if authentication successful

        Raises:
            CloudForensicsException: If authentication fails
        """
        if not self.validate_credentials():
            raise CloudForensicsException("Invalid credentials", provider="AWS")

        try:
            session_kwargs = {
                "aws_access_key_id": self.credentials["access_key"],
                "aws_secret_access_key": self.credentials["secret_key"],
                "region_name": self.region,
            }

            if "session_token" in self.credentials:
                session_kwargs["aws_session_token"] = self.credentials["session_token"]

            self.session = boto3.Session(**session_kwargs)

            # Test credentials with STS
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()

            self.ec2_client = self.session.client("ec2", region_name=self.region)
            self.authenticated = True

            self.logger.info(f"Authenticated as: {identity['Arn']}")
            return True

        except NoCredentialsError:
            raise CloudForensicsException("No valid AWS credentials found", provider="AWS")
        except ClientError as e:
            raise CloudForensicsException(f"Authentication failed: {e}", provider="AWS")
        except Exception as e:
            raise CloudForensicsException(f"Unexpected authentication error: {e}", provider="AWS")

    def list_instances(self, region: Optional[str] = None, **kwargs) -> List[Dict[str, Any]]:
        """
        List all EC2 instances in region.

        Args:
            region: AWS region (uses default if not specified)
            **kwargs: Additional filters
                - state: Instance state filter (e.g., 'running', 'stopped')
                - tags: Tag filters

        Returns:
            List of instance dictionaries
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="AWS")

        if region and region != self.region:
            ec2 = self.session.client("ec2", region_name=region)
        else:
            ec2 = self.ec2_client

        try:
            filters = []
            if "state" in kwargs:
                filters.append({"Name": "instance-state-name", "Values": [kwargs["state"]]})
            if "tags" in kwargs:
                for key, value in kwargs["tags"].items():
                    filters.append({"Name": f"tag:{key}", "Values": [value]})

            describe_kwargs = {}
            if filters:
                describe_kwargs["Filters"] = filters

            response = ec2.describe_instances(**describe_kwargs)

            instances = []
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    instances.append(self._format_instance(instance))

            self.logger.info(f"Found {len(instances)} instances in {region or self.region}")
            return instances

        except ClientError as e:
            raise CloudForensicsException(f"Failed to list instances: {e}", provider="AWS")

    def _format_instance(self, instance: Dict) -> Dict[str, Any]:
        """Format instance data for output."""
        tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}

        return {
            "id": instance["InstanceId"],
            "name": tags.get("Name", "N/A"),
            "type": instance["InstanceType"],
            "state": instance["State"]["Name"],
            "launch_time": self.format_timestamp(instance["LaunchTime"]),
            "private_ip": instance.get("PrivateIpAddress", "N/A"),
            "public_ip": instance.get("PublicIpAddress", "N/A"),
            "vpc_id": instance.get("VpcId", "N/A"),
            "subnet_id": instance.get("SubnetId", "N/A"),
            "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
            "iam_role": instance.get("IamInstanceProfile", {}).get("Arn", "N/A"),
            "volumes": [
                {
                    "device": mapping["DeviceName"],
                    "volume_id": mapping["Ebs"]["VolumeId"],
                    "delete_on_termination": mapping["Ebs"]["DeleteOnTermination"],
                }
                for mapping in instance.get("BlockDeviceMappings", [])
            ],
            "tags": tags,
            "provider": "AWS",
            "artifact_type": "ec2_instance",
        }

    def acquire_disk_image(self, instance_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire EBS volume snapshots from EC2 instance.

        Args:
            instance_id: EC2 instance ID
            output_dir: Output directory for metadata
            **kwargs: Additional options
                - volume_ids: Specific volume IDs to snapshot (default: all)
                - description: Snapshot description
                - no_reboot: Don't reboot instance (default: True)

        Returns:
            Dictionary with snapshot information
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="AWS")

        try:
            # Get instance details
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            if not response["Reservations"]:
                raise CloudForensicsException(f"Instance {instance_id} not found", provider="AWS")

            instance = response["Reservations"][0]["Instances"][0]

            # Get volumes
            volume_ids = kwargs.get("volume_ids")
            if volume_ids is None:
                volume_ids = [
                    mapping["Ebs"]["VolumeId"] for mapping in instance["BlockDeviceMappings"]
                ]

            description = kwargs.get("description", f"Forensic snapshot of {instance_id}")

            # Create snapshots
            snapshots = []
            for volume_id in volume_ids:
                self.logger.info(f"Creating snapshot for volume {volume_id}...")

                snapshot = self.ec2_client.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"{description} - {datetime.now().isoformat()}",
                    TagSpecifications=[
                        {
                            "ResourceType": "snapshot",
                            "Tags": [
                                {"Key": "ForensicSnapshot", "Value": "true"},
                                {"Key": "SourceInstance", "Value": instance_id},
                                {"Key": "SourceVolume", "Value": volume_id},
                                {"Key": "AcquisitionTime", "Value": datetime.now().isoformat()},
                            ],
                        }
                    ],
                )

                snapshot_id = snapshot["SnapshotId"]
                snapshots.append(
                    {
                        "snapshot_id": snapshot_id,
                        "volume_id": volume_id,
                        "start_time": self.format_timestamp(snapshot["StartTime"]),
                        "state": snapshot["State"],
                    }
                )

                self.logger.info(f"Snapshot {snapshot_id} created for volume {volume_id}")

            # Wait for snapshots to complete
            if kwargs.get("wait", True):
                self.logger.info("Waiting for snapshots to complete...")
                self._wait_for_snapshots([s["snapshot_id"] for s in snapshots])

            # Save metadata
            result = {
                "instance_id": instance_id,
                "acquisition_time": datetime.now().isoformat(),
                "snapshots": snapshots,
                "instance_metadata": self._format_instance(instance),
            }

            metadata_file = os.path.join(output_dir, f"{instance_id}_snapshots.json")
            self.save_json(result, metadata_file)

            return result

        except ClientError as e:
            raise CloudForensicsException(f"Failed to acquire disk image: {e}", provider="AWS")

    def _wait_for_snapshots(self, snapshot_ids: List[str], timeout: int = 3600):
        """
        Wait for snapshots to complete.

        Args:
            snapshot_ids: List of snapshot IDs
            timeout: Timeout in seconds
        """
        waiter = self.ec2_client.get_waiter("snapshot_completed")
        try:
            waiter.wait(
                SnapshotIds=snapshot_ids, WaiterConfig={"Delay": 15, "MaxAttempts": timeout // 15}
            )
            self.logger.info("All snapshots completed successfully")
        except Exception as e:
            self.logger.warning(f"Snapshot wait error: {e}")

    def acquire_logs(
        self, start_time: datetime, end_time: datetime, output_dir: str, **kwargs
    ) -> List[str]:
        """
        Acquire instance logs (from CloudWatch).

        Note: For CloudTrail logs, use cloudtrail.py module.

        Args:
            start_time: Start time
            end_time: End time
            output_dir: Output directory
            **kwargs: Additional options
                - instance_ids: Specific instances to get logs for
                - log_group: CloudWatch log group name

        Returns:
            List of output file paths
        """
        # This is a placeholder - CloudWatch Logs would be implemented here
        # For now, return empty list and log warning
        self.logger.warning("CloudWatch Logs acquisition not yet implemented")
        return []

    def acquire_storage(self, storage_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire S3 bucket metadata and artifacts.

        Note: For full S3 analysis, use s3.py module.

        Args:
            storage_id: S3 bucket name
            output_dir: Output directory
            **kwargs: Additional options

        Returns:
            Dictionary with S3 bucket analysis
        """
        # Placeholder - S3 functionality in separate module
        self.logger.warning("S3 acquisition not implemented in EC2 module. Use aws.s3 module.")
        return {}

    def get_instance_metadata(self, instance_id: str) -> Dict[str, Any]:
        """
        Get detailed instance metadata.

        Args:
            instance_id: EC2 instance ID

        Returns:
            Dictionary with instance metadata
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="AWS")

        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            if not response["Reservations"]:
                raise CloudForensicsException(f"Instance {instance_id} not found", provider="AWS")

            instance = response["Reservations"][0]["Instances"][0]
            return self._format_instance(instance)

        except ClientError as e:
            raise CloudForensicsException(f"Failed to get instance metadata: {e}", provider="AWS")

    def analyze_security_groups(self, instance_id: str) -> List[Dict[str, Any]]:
        """
        Analyze security groups attached to instance.

        Args:
            instance_id: EC2 instance ID

        Returns:
            List of security group analysis
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="AWS")

        try:
            # Get instance
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response["Reservations"][0]["Instances"][0]

            sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

            # Get security group details
            sg_response = self.ec2_client.describe_security_groups(GroupIds=sg_ids)

            results = []
            for sg in sg_response["SecurityGroups"]:
                results.append(
                    {
                        "group_id": sg["GroupId"],
                        "group_name": sg["GroupName"],
                        "description": sg["Description"],
                        "vpc_id": sg.get("VpcId", "N/A"),
                        "ingress_rules": self._format_sg_rules(sg.get("IpPermissions", [])),
                        "egress_rules": self._format_sg_rules(sg.get("IpPermissionsEgress", [])),
                        "attck_techniques": self._analyze_sg_threats(sg),
                    }
                )

            return results

        except ClientError as e:
            raise CloudForensicsException(f"Failed to analyze security groups: {e}", provider="AWS")

    def _format_sg_rules(self, rules: List[Dict]) -> List[Dict[str, Any]]:
        """Format security group rules."""
        formatted = []
        for rule in rules:
            formatted.append(
                {
                    "protocol": rule.get("IpProtocol", "all"),
                    "from_port": rule.get("FromPort", "all"),
                    "to_port": rule.get("ToPort", "all"),
                    "ip_ranges": [r["CidrIp"] for r in rule.get("IpRanges", [])],
                    "ipv6_ranges": [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])],
                }
            )
        return formatted

    def _analyze_sg_threats(self, sg: Dict) -> List[str]:
        """
        Analyze security group for threat indicators.

        Returns:
            List of MITRE ATT&CK technique IDs
        """
        techniques = []

        # Check for overly permissive ingress rules
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range["CidrIp"] == "0.0.0.0/0":
                    # Open to internet
                    if rule.get("FromPort") in [22, 3389, 1433, 3306]:
                        # Exposed management/database ports
                        techniques.append("T1190")  # Exploit Public-Facing Application
                        techniques.append("T1133")  # External Remote Services

        return list(set(techniques))

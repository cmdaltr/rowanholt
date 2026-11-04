#!/usr/bin/env python3
"""
AWS S3 Forensics Module

Forensic analysis of AWS S3 buckets and objects.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from ..base import CloudForensicsException


class S3Forensics:
    """
    S3 bucket forensics and analysis.

    Capabilities:
    - Bucket configuration analysis
    - Object metadata collection
    - Version history tracking
    - Access log analysis
    - Encryption status
    """

    def __init__(self, session: Any):
        """
        Initialize S3 forensics.

        Args:
            session: boto3 session
        """
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 required")

        self.session = session
        self.s3 = session.client("s3")

    def analyze_bucket(self, bucket_name: str, output_dir: str) -> Dict[str, Any]:
        """
        Comprehensive bucket analysis.

        Args:
            bucket_name: S3 bucket name
            output_dir: Output directory

        Returns:
            Dictionary with bucket analysis
        """
        try:
            analysis = {
                "bucket_name": bucket_name,
                "analysis_time": datetime.now().isoformat(),
                "configuration": self._get_bucket_config(bucket_name),
                "objects": self._list_objects(bucket_name),
                "security": self._analyze_security(bucket_name),
                "attck_techniques": [],
            }

            # Determine ATT&CK techniques based on findings
            if not analysis["configuration"]["logging_enabled"]:
                analysis["attck_techniques"].append("T1070.003")  # Clear Cloud Logs

            if analysis["configuration"].get("public_access", False):
                analysis["attck_techniques"].append("T1530")  # Data from Cloud Storage

            if not analysis["configuration"]["versioning_enabled"]:
                analysis["attck_techniques"].append("T1485")  # Data Destruction risk

            # Save analysis
            output_file = os.path.join(output_dir, f"{bucket_name}_analysis.json")
            with open(output_file, "w") as f:
                json.dump(analysis, f, indent=2, default=str)

            return analysis

        except ClientError as e:
            raise CloudForensicsException(f"Failed to analyze bucket: {e}", provider="AWS")

    def _get_bucket_config(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket configuration."""
        config = {}

        # Get logging
        try:
            logging = self.s3.get_bucket_logging(Bucket=bucket_name)
            config["logging_enabled"] = "LoggingEnabled" in logging
            config["logging"] = logging.get("LoggingEnabled", {})
        except ClientError:
            config["logging_enabled"] = False

        # Get versioning
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            config["versioning_enabled"] = versioning.get("Status") == "Enabled"
            config["versioning"] = versioning
        except ClientError:
            config["versioning_enabled"] = False

        # Get encryption
        try:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
            config["encryption_enabled"] = True
            config["encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
        except ClientError:
            config["encryption_enabled"] = False

        # Get lifecycle
        try:
            lifecycle = self.s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            config["lifecycle_rules"] = lifecycle.get("Rules", [])
        except ClientError:
            config["lifecycle_rules"] = []

        # Get replication
        try:
            replication = self.s3.get_bucket_replication(Bucket=bucket_name)
            config["replication_enabled"] = True
            config["replication"] = replication.get("ReplicationConfiguration", {})
        except ClientError:
            config["replication_enabled"] = False

        return config

    def _list_objects(self, bucket_name: str, max_objects: int = 1000) -> List[Dict[str, Any]]:
        """List bucket objects with metadata."""
        objects = []

        try:
            paginator = self.s3.get_paginator("list_object_versions")

            for page in paginator.paginate(Bucket=bucket_name):
                # Current versions
                for obj in page.get("Versions", []):
                    objects.append(
                        {
                            "key": obj["Key"],
                            "version_id": obj["VersionId"],
                            "is_latest": obj["IsLatest"],
                            "last_modified": obj["LastModified"].isoformat(),
                            "size": obj["Size"],
                            "etag": obj["ETag"],
                            "storage_class": obj.get("StorageClass", "STANDARD"),
                            "owner": obj.get("Owner", {}),
                        }
                    )

                    if len(objects) >= max_objects:
                        break

                # Delete markers
                for dm in page.get("DeleteMarkers", []):
                    objects.append(
                        {
                            "key": dm["Key"],
                            "version_id": dm["VersionId"],
                            "is_delete_marker": True,
                            "last_modified": dm["LastModified"].isoformat(),
                            "owner": dm.get("Owner", {}),
                        }
                    )

                if len(objects) >= max_objects:
                    break

        except ClientError as e:
            raise CloudForensicsException(f"Failed to list objects: {e}", provider="AWS")

        return objects

    def _analyze_security(self, bucket_name: str) -> Dict[str, Any]:
        """Analyze bucket security configuration."""
        security = {}

        # Get ACL
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            security["acl"] = acl.get("Grants", [])
            security["public_acl"] = any(
                grant.get("Grantee", {}).get("Type") == "Group"
                and "AllUsers" in grant.get("Grantee", {}).get("URI", "")
                for grant in security["acl"]
            )
        except ClientError:
            security["acl"] = []
            security["public_acl"] = False

        # Get policy
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            security["policy"] = json.loads(policy["Policy"])
            security["has_policy"] = True
        except ClientError:
            security["policy"] = None
            security["has_policy"] = False

        # Get public access block
        try:
            public_block = self.s3.get_public_access_block(Bucket=bucket_name)
            security["public_access_block"] = public_block["PublicAccessBlockConfiguration"]
        except ClientError:
            security["public_access_block"] = None

        # Determine if bucket is public
        security["is_public"] = security["public_acl"] or (
            not security.get("public_access_block")
            or not all(security.get("public_access_block", {}).values())
        )

        return security

    def acquire_bucket_logs(self, bucket_name: str, log_prefix: str, output_dir: str) -> List[str]:
        """
        Download S3 access logs.

        Args:
            bucket_name: Bucket containing logs
            log_prefix: Log file prefix
            output_dir: Output directory

        Returns:
            List of downloaded log file paths
        """
        downloaded = []

        try:
            paginator = self.s3.get_paginator("list_objects_v2")

            for page in paginator.paginate(Bucket=bucket_name, Prefix=log_prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith("/"):
                        continue

                    # Download log file
                    local_path = os.path.join(output_dir, os.path.basename(key))
                    self.s3.download_file(bucket_name, key, local_path)
                    downloaded.append(local_path)

            return downloaded

        except ClientError as e:
            raise CloudForensicsException(f"Failed to acquire logs: {e}", provider="AWS")

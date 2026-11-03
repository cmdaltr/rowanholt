#!/usr/bin/env python3
"""
GCP Compute Engine Forensics Module

Forensic acquisition and analysis of GCP Compute Engine instances and disks.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

try:
    from google.cloud import compute_v1
    from google.auth import default

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from ..base import CloudProvider, CloudForensicsException


class GCPForensics(CloudProvider):
    """
    GCP forensics acquisition and analysis.

    Supports:
    - Compute Engine instance enumeration
    - Persistent disk snapshot creation
    - Instance metadata collection
    - Firewall rule analysis
    """

    def __init__(self, credentials: Dict[str, str], config: Optional[Dict] = None):
        """
        Initialize GCP forensics.

        Args:
            credentials: GCP credentials dict with keys:
                - project_id: GCP project ID
                - service_account_file: Path to service account JSON file (optional)
            config: Optional configuration
        """
        super().__init__(credentials, config)

        if not GCP_AVAILABLE:
            raise ImportError(
                "Google Cloud SDK not available. Install with: "
                "pip install google-cloud-compute google-cloud-logging"
            )

        self.project_id = credentials.get("project_id")
        self.instances_client = None
        self.disks_client = None
        self.firewalls_client = None

    def get_required_credential_keys(self) -> List[str]:
        """Required GCP credential keys."""
        return ["project_id"]

    def authenticate(self) -> bool:
        """
        Authenticate with GCP using service account or application default credentials.

        Returns:
            True if authentication successful

        Raises:
            CloudForensicsException: If authentication fails
        """
        if not self.validate_credentials():
            raise CloudForensicsException("Invalid credentials", provider="GCP")

        try:
            # Set service account file if provided
            if "service_account_file" in self.credentials:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials[
                    "service_account_file"
                ]

            # Initialize clients
            self.instances_client = compute_v1.InstancesClient()
            self.disks_client = compute_v1.DisksClient()
            self.firewalls_client = compute_v1.FirewallsClient()

            # Test authentication by listing zones
            zones_client = compute_v1.ZonesClient()
            list(zones_client.list(project=self.project_id))

            self.authenticated = True
            self.logger.info(f"Authenticated with GCP project: {self.project_id}")
            return True

        except Exception as e:
            raise CloudForensicsException(f"GCP authentication failed: {e}", provider="GCP")

    def list_instances(self, region: Optional[str] = None, **kwargs) -> List[Dict[str, Any]]:
        """
        List all Compute Engine instances.

        Args:
            region: GCP zone filter (optional)
            **kwargs: Additional filters
                - zone: Specific zone

        Returns:
            List of instance dictionaries
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="GCP")

        try:
            zone = kwargs.get("zone") or region

            if zone:
                zones = [zone]
            else:
                # List all zones
                zones_client = compute_v1.ZonesClient()
                zones = [z.name for z in zones_client.list(project=self.project_id)]

            instances = []
            for zone_name in zones:
                try:
                    instance_list = self.instances_client.list(
                        project=self.project_id, zone=zone_name
                    )

                    for instance in instance_list:
                        instances.append(self._format_instance(instance, zone_name))

                except Exception as e:
                    self.logger.debug(f"Error listing instances in zone {zone_name}: {e}")

            self.logger.info(f"Found {len(instances)} instances")
            return instances

        except Exception as e:
            raise CloudForensicsException(f"Failed to list instances: {e}", provider="GCP")

    def _format_instance(self, instance: Any, zone: str) -> Dict[str, Any]:
        """Format instance data for output."""
        return {
            "id": instance.id,
            "name": instance.name,
            "zone": zone,
            "machine_type": instance.machine_type.split("/")[-1],
            "status": instance.status,
            "creation_timestamp": instance.creation_timestamp,
            "disks": [
                {
                    "device_name": disk.device_name,
                    "source": disk.source.split("/")[-1],
                    "boot": disk.boot,
                    "auto_delete": disk.auto_delete,
                }
                for disk in instance.disks
            ],
            "network_interfaces": [
                {
                    "network": ni.network.split("/")[-1],
                    "subnetwork": ni.subnetwork.split("/")[-1] if ni.subnetwork else None,
                    "network_ip": ni.network_i_p,
                }
                for ni in instance.network_interfaces
            ],
            "service_accounts": [
                {"email": sa.email, "scopes": list(sa.scopes)} for sa in instance.service_accounts
            ],
            "labels": dict(instance.labels) if instance.labels else {},
            "metadata": (
                {item.key: item.value for item in instance.metadata.items}
                if instance.metadata
                else {}
            ),
            "provider": "GCP",
            "artifact_type": "gcp_instance",
        }

    def acquire_disk_image(self, instance_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire persistent disk snapshots from Compute Engine instance.

        Args:
            instance_id: Instance name
            output_dir: Output directory for metadata
            **kwargs: Additional options
                - zone: Instance zone (required)
                - disk_names: Specific disk names to snapshot (default: all)

        Returns:
            Dictionary with snapshot information
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="GCP")

        zone = kwargs.get("zone")
        if not zone:
            raise CloudForensicsException("zone parameter required", provider="GCP")

        try:
            # Get instance
            instance = self.instances_client.get(
                project=self.project_id, zone=zone, instance=instance_id
            )

            # Get disks to snapshot
            disk_names = kwargs.get("disk_names")
            if disk_names is None:
                disk_names = [disk.source.split("/")[-1] for disk in instance.disks]

            # Create snapshots
            snapshots = []
            for disk_name in disk_names:
                self.logger.info(f"Creating snapshot for disk {disk_name}...")

                snapshot_name = (
                    f"{instance_id}-{disk_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                )

                snapshot_body = compute_v1.Snapshot(
                    name=snapshot_name,
                    labels={
                        "forensic_snapshot": "true",
                        "source_instance": instance_id,
                        "source_disk": disk_name,
                        "acquisition_time": datetime.now().strftime("%Y%m%d%H%M%S"),
                    },
                )

                operation = self.disks_client.create_snapshot(
                    project=self.project_id,
                    zone=zone,
                    disk=disk_name,
                    snapshot_resource=snapshot_body,
                )

                # Wait for operation
                operation.result()

                snapshots.append(
                    {"snapshot_name": snapshot_name, "source_disk": disk_name, "zone": zone}
                )

                self.logger.info(f"Snapshot {snapshot_name} created")

            # Save metadata
            result = {
                "instance_name": instance_id,
                "zone": zone,
                "acquisition_time": datetime.now().isoformat(),
                "snapshots": snapshots,
                "instance_metadata": self._format_instance(instance, zone),
            }

            metadata_file = os.path.join(output_dir, f"{instance_id}_snapshots.json")
            self.save_json(result, metadata_file)

            return result

        except Exception as e:
            raise CloudForensicsException(f"Failed to acquire disk image: {e}", provider="GCP")

    def acquire_logs(
        self, start_time: datetime, end_time: datetime, output_dir: str, **kwargs
    ) -> List[str]:
        """
        Acquire Cloud Logging entries.

        Note: For full Cloud Logging analysis, use logging.py module.

        Args:
            start_time: Start datetime
            end_time: End datetime
            output_dir: Output directory
            **kwargs: Additional options

        Returns:
            List of output file paths
        """
        # Placeholder - Cloud Logging functionality in separate module
        self.logger.warning(
            "Cloud Logging acquisition not implemented in compute module. Use gcp.logging module."
        )
        return []

    def acquire_storage(self, storage_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire Cloud Storage metadata.

        Note: For full Cloud Storage analysis, use storage.py module.

        Args:
            storage_id: Bucket name
            output_dir: Output directory
            **kwargs: Additional options

        Returns:
            Dictionary with storage analysis
        """
        # Placeholder - Cloud Storage functionality in separate module
        self.logger.warning(
            "Cloud Storage acquisition not implemented in compute module. Use gcp.storage module."
        )
        return {}

    def analyze_firewall_rules(self) -> List[Dict[str, Any]]:
        """
        Analyze VPC firewall rules for security issues.

        Returns:
            List of firewall rule analysis
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="GCP")

        try:
            firewall_rules = self.firewalls_client.list(project=self.project_id)

            analysis = []
            for rule in firewall_rules:
                analysis.append(
                    {
                        "name": rule.name,
                        "direction": rule.direction,
                        "priority": rule.priority,
                        "allowed": [
                            {
                                "ip_protocol": allowed.i_p_protocol,
                                "ports": list(allowed.ports) if allowed.ports else [],
                            }
                            for allowed in rule.allowed
                        ],
                        "denied": [
                            {
                                "ip_protocol": denied.i_p_protocol,
                                "ports": list(denied.ports) if denied.ports else [],
                            }
                            for denied in rule.denied
                        ],
                        "source_ranges": list(rule.source_ranges) if rule.source_ranges else [],
                        "destination_ranges": (
                            list(rule.destination_ranges) if rule.destination_ranges else []
                        ),
                        "target_tags": list(rule.target_tags) if rule.target_tags else [],
                        "attck_techniques": self._analyze_firewall_threats(rule),
                    }
                )

            return analysis

        except Exception as e:
            raise CloudForensicsException(f"Failed to analyze firewall rules: {e}", provider="GCP")

    def _analyze_firewall_threats(self, rule: Any) -> List[str]:
        """Analyze firewall rule for threat indicators."""
        techniques = []

        if rule.direction == "INGRESS":
            # Check for overly permissive rules
            source_ranges = list(rule.source_ranges) if rule.source_ranges else []

            if "0.0.0.0/0" in source_ranges:
                for allowed in rule.allowed:
                    ports = list(allowed.ports) if allowed.ports else []

                    # Check for exposed management/database ports
                    if any(port in ["22", "3389", "1433", "3306"] or "-" in port for port in ports):
                        techniques.append("T1190")  # Exploit Public-Facing Application
                        techniques.append("T1133")  # External Remote Services

        return list(set(techniques))

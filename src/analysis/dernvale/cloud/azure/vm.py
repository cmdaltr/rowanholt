#!/usr/bin/env python3
"""
Azure Virtual Machine Forensics Module

Forensic acquisition and analysis of Azure VMs and managed disks.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.models import Snapshot, CreationData, DiskCreateOption
    from azure.mgmt.network import NetworkManagementClient

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from ..base import CloudProvider, CloudForensicsException


class AzureForensics(CloudProvider):
    """
    Azure forensics acquisition and analysis.

    Supports:
    - VM enumeration
    - Managed disk snapshot creation
    - VM metadata collection
    - NSG (Network Security Group) analysis
    """

    def __init__(self, credentials: Dict[str, str], config: Optional[Dict] = None):
        """
        Initialize Azure forensics.

        Args:
            credentials: Azure credentials dict with keys:
                - tenant_id: Azure AD tenant ID
                - client_id: Service principal client ID
                - client_secret: Service principal secret
                - subscription_id: Azure subscription ID
            config: Optional configuration
        """
        super().__init__(credentials, config)

        if not AZURE_AVAILABLE:
            raise ImportError(
                "Azure SDK not available. Install with: "
                "pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-monitor"
            )

        self.credential = None
        self.compute_client = None
        self.network_client = None
        self.subscription_id = credentials.get("subscription_id")

    def get_required_credential_keys(self) -> List[str]:
        """Required Azure credential keys."""
        return ["tenant_id", "client_id", "client_secret", "subscription_id"]

    def authenticate(self) -> bool:
        """
        Authenticate with Azure using service principal.

        Returns:
            True if authentication successful

        Raises:
            CloudForensicsException: If authentication fails
        """
        if not self.validate_credentials():
            raise CloudForensicsException("Invalid credentials", provider="Azure")

        try:
            self.credential = ClientSecretCredential(
                tenant_id=self.credentials["tenant_id"],
                client_id=self.credentials["client_id"],
                client_secret=self.credentials["client_secret"],
            )

            self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)

            self.network_client = NetworkManagementClient(self.credential, self.subscription_id)

            # Test authentication
            list(self.compute_client.virtual_machines.list_all())

            self.authenticated = True
            self.logger.info(f"Authenticated with Azure subscription: {self.subscription_id}")
            return True

        except Exception as e:
            raise CloudForensicsException(f"Azure authentication failed: {e}", provider="Azure")

    def list_instances(self, region: Optional[str] = None, **kwargs) -> List[Dict[str, Any]]:
        """
        List all Azure VMs.

        Args:
            region: Azure location filter (optional)
            **kwargs: Additional filters
                - resource_group: Specific resource group

        Returns:
            List of VM dictionaries
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="Azure")

        try:
            resource_group = kwargs.get("resource_group")

            if resource_group:
                vm_list = self.compute_client.virtual_machines.list(resource_group)
            else:
                vm_list = self.compute_client.virtual_machines.list_all()

            vms = []
            for vm in vm_list:
                # Filter by location if specified
                if region and vm.location != region:
                    continue

                vms.append(self._format_vm(vm))

            self.logger.info(f"Found {len(vms)} VMs")
            return vms

        except Exception as e:
            raise CloudForensicsException(f"Failed to list VMs: {e}", provider="Azure")

    def _format_vm(self, vm: Any) -> Dict[str, Any]:
        """Format VM data for output."""
        return {
            "id": vm.id,
            "name": vm.name,
            "location": vm.location,
            "vm_size": vm.hardware_profile.vm_size,
            "os_type": vm.storage_profile.os_disk.os_type,
            "os_disk_name": vm.storage_profile.os_disk.name,
            "os_disk_id": (
                vm.storage_profile.os_disk.managed_disk.id
                if vm.storage_profile.os_disk.managed_disk
                else None
            ),
            "data_disks": [
                {
                    "name": disk.name,
                    "lun": disk.lun,
                    "disk_size_gb": disk.disk_size_gb,
                    "managed_disk_id": disk.managed_disk.id if disk.managed_disk else None,
                }
                for disk in vm.storage_profile.data_disks
            ],
            "network_interfaces": [nic.id for nic in vm.network_profile.network_interfaces],
            "provisioning_state": vm.provisioning_state,
            "tags": vm.tags or {},
            "provider": "Azure",
            "artifact_type": "azure_vm",
        }

    def acquire_disk_image(self, instance_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire managed disk snapshots from Azure VM.

        Args:
            instance_id: VM name or resource ID
            output_dir: Output directory for metadata
            **kwargs: Additional options
                - resource_group: Resource group name (required if using VM name)
                - disk_ids: Specific disk IDs to snapshot (default: all)

        Returns:
            Dictionary with snapshot information
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="Azure")

        resource_group = kwargs.get("resource_group")
        if not resource_group:
            # Extract from resource ID
            if "/resourceGroups/" in instance_id:
                resource_group = instance_id.split("/resourceGroups/")[1].split("/")[0]
                vm_name = instance_id.split("/")[-1]
            else:
                raise CloudForensicsException(
                    "resource_group required when using VM name", provider="Azure"
                )
        else:
            vm_name = instance_id

        try:
            # Get VM
            vm = self.compute_client.virtual_machines.get(resource_group, vm_name)

            # Get disks to snapshot
            disk_ids = kwargs.get("disk_ids")
            if disk_ids is None:
                disk_ids = []
                # OS disk
                if vm.storage_profile.os_disk.managed_disk:
                    disk_ids.append(vm.storage_profile.os_disk.managed_disk.id)
                # Data disks
                for disk in vm.storage_profile.data_disks:
                    if disk.managed_disk:
                        disk_ids.append(disk.managed_disk.id)

            # Create snapshots
            snapshots = []
            for disk_id in disk_ids:
                self.logger.info(f"Creating snapshot for disk {disk_id}...")

                disk_name = disk_id.split("/")[-1]
                snapshot_name = f"{vm_name}-{disk_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

                snapshot = Snapshot(
                    location=vm.location,
                    creation_data=CreationData(
                        create_option=DiskCreateOption.copy, source_uri=disk_id
                    ),
                    tags={
                        "ForensicSnapshot": "true",
                        "SourceVM": vm_name,
                        "SourceDisk": disk_name,
                        "AcquisitionTime": datetime.now().isoformat(),
                    },
                )

                async_snapshot = self.compute_client.snapshots.begin_create_or_update(
                    resource_group, snapshot_name, snapshot
                )

                snapshot_resource = async_snapshot.result()

                snapshots.append(
                    {
                        "snapshot_id": snapshot_resource.id,
                        "snapshot_name": snapshot_name,
                        "source_disk_id": disk_id,
                        "location": snapshot_resource.location,
                        "provisioning_state": snapshot_resource.provisioning_state,
                    }
                )

                self.logger.info(f"Snapshot {snapshot_name} created")

            # Save metadata
            result = {
                "vm_name": vm_name,
                "resource_group": resource_group,
                "acquisition_time": datetime.now().isoformat(),
                "snapshots": snapshots,
                "vm_metadata": self._format_vm(vm),
            }

            metadata_file = os.path.join(output_dir, f"{vm_name}_snapshots.json")
            self.save_json(result, metadata_file)

            return result

        except Exception as e:
            raise CloudForensicsException(f"Failed to acquire disk image: {e}", provider="Azure")

    def acquire_logs(
        self, start_time: datetime, end_time: datetime, output_dir: str, **kwargs
    ) -> List[str]:
        """
        Acquire Azure Activity Logs.

        Note: For full Activity Log analysis, use activity_log.py module.

        Args:
            start_time: Start datetime
            end_time: End datetime
            output_dir: Output directory
            **kwargs: Additional options

        Returns:
            List of output file paths
        """
        # Placeholder - Activity Log functionality in separate module
        self.logger.warning(
            "Activity Log acquisition not implemented in VM module. Use azure.activity_log module."
        )
        return []

    def acquire_storage(self, storage_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire Azure Blob Storage metadata.

        Note: For full Blob Storage analysis, use blob.py module.

        Args:
            storage_id: Storage account name
            output_dir: Output directory
            **kwargs: Additional options

        Returns:
            Dictionary with storage analysis
        """
        # Placeholder - Blob Storage functionality in separate module
        self.logger.warning(
            "Blob Storage acquisition not implemented in VM module. Use azure.blob module."
        )
        return {}

    def analyze_network_security(self, vm_name: str, resource_group: str) -> List[Dict[str, Any]]:
        """
        Analyze Network Security Groups attached to VM.

        Args:
            vm_name: VM name
            resource_group: Resource group

        Returns:
            List of NSG analysis
        """
        if not self.authenticated:
            raise CloudForensicsException("Not authenticated", provider="Azure")

        try:
            # Get VM
            vm = self.compute_client.virtual_machines.get(resource_group, vm_name)

            nsg_analysis = []

            # Get NICs
            for nic_ref in vm.network_profile.network_interfaces:
                nic_id = nic_ref.id
                nic_resource_group = nic_id.split("/resourceGroups/")[1].split("/")[0]
                nic_name = nic_id.split("/")[-1]

                nic = self.network_client.network_interfaces.get(nic_resource_group, nic_name)

                # Get NSG
                if nic.network_security_group:
                    nsg_id = nic.network_security_group.id
                    nsg_resource_group = nsg_id.split("/resourceGroups/")[1].split("/")[0]
                    nsg_name = nsg_id.split("/")[-1]

                    nsg = self.network_client.network_security_groups.get(
                        nsg_resource_group, nsg_name
                    )

                    nsg_analysis.append(
                        {
                            "nsg_name": nsg.name,
                            "nsg_id": nsg.id,
                            "location": nsg.location,
                            "security_rules": self._format_nsg_rules(nsg.security_rules),
                            "default_security_rules": self._format_nsg_rules(
                                nsg.default_security_rules
                            ),
                            "attck_techniques": self._analyze_nsg_threats(nsg),
                        }
                    )

            return nsg_analysis

        except Exception as e:
            raise CloudForensicsException(f"Failed to analyze NSGs: {e}", provider="Azure")

    def _format_nsg_rules(self, rules: List[Any]) -> List[Dict[str, Any]]:
        """Format NSG rules."""
        formatted = []
        for rule in rules:
            formatted.append(
                {
                    "name": rule.name,
                    "priority": rule.priority,
                    "direction": rule.direction,
                    "access": rule.access,
                    "protocol": rule.protocol,
                    "source_port_range": rule.source_port_range,
                    "destination_port_range": rule.destination_port_range,
                    "source_address_prefix": rule.source_address_prefix,
                    "destination_address_prefix": rule.destination_address_prefix,
                }
            )
        return formatted

    def _analyze_nsg_threats(self, nsg: Any) -> List[str]:
        """Analyze NSG for threat indicators."""
        techniques = []

        for rule in nsg.security_rules:
            if rule.access == "Allow" and rule.direction == "Inbound":
                # Check for open management ports
                if rule.source_address_prefix == "*" or rule.source_address_prefix == "Internet":
                    dest_port = rule.destination_port_range
                    if dest_port in ["22", "3389", "1433", "3306", "*"]:
                        techniques.append("T1190")  # Exploit Public-Facing Application
                        techniques.append("T1133")  # External Remote Services

        return list(set(techniques))

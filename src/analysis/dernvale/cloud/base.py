#!/usr/bin/env python3
"""
Base Cloud Provider Class

Abstract base class for cloud provider forensics implementations.
Defines common interface for AWS, Azure, and GCP forensics.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging
import json


class CloudProvider(ABC):
    """
    Abstract base class for cloud provider forensics.

    All cloud provider implementations (AWS, Azure, GCP) must inherit
    from this class and implement the required methods.
    """

    def __init__(self, credentials: Dict[str, str], config: Optional[Dict] = None):
        """
        Initialize cloud provider.

        Args:
            credentials: Provider-specific credentials
            config: Optional configuration parameters
        """
        self.credentials = credentials
        self.config = config or {}
        self.client = None
        self.authenticated = False
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def authenticate(self) -> bool:
        """
        Authenticate with cloud provider.

        Returns:
            True if authentication successful, False otherwise

        Raises:
            Exception: If authentication fails
        """
        pass

    @abstractmethod
    def list_instances(self, region: Optional[str] = None, **kwargs) -> List[Dict[str, Any]]:
        """
        List all compute instances.

        Args:
            region: Optional region/zone filter
            **kwargs: Provider-specific parameters

        Returns:
            List of instance dictionaries with metadata
        """
        pass

    @abstractmethod
    def acquire_disk_image(self, instance_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire disk image/snapshot from instance.

        Args:
            instance_id: Instance identifier
            output_dir: Output directory for acquired data
            **kwargs: Provider-specific parameters

        Returns:
            Dictionary with snapshot/image information
        """
        pass

    @abstractmethod
    def acquire_logs(
        self, start_time: datetime, end_time: datetime, output_dir: str, **kwargs
    ) -> List[str]:
        """
        Acquire cloud audit/activity logs.

        Args:
            start_time: Start of time range
            end_time: End of time range
            output_dir: Output directory
            **kwargs: Provider-specific parameters

        Returns:
            List of output file paths
        """
        pass

    @abstractmethod
    def acquire_storage(self, storage_id: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Acquire cloud storage artifacts.

        Args:
            storage_id: Storage bucket/container identifier
            output_dir: Output directory
            **kwargs: Provider-specific parameters

        Returns:
            Dictionary with storage analysis results
        """
        pass

    # Common utility methods

    def validate_credentials(self) -> bool:
        """
        Validate that required credentials are present.

        Returns:
            True if credentials appear valid
        """
        if not self.credentials:
            self.logger.error("No credentials provided")
            return False

        required_keys = self.get_required_credential_keys()
        missing_keys = [key for key in required_keys if key not in self.credentials]

        if missing_keys:
            self.logger.error(f"Missing required credentials: {missing_keys}")
            return False

        return True

    @abstractmethod
    def get_required_credential_keys(self) -> List[str]:
        """
        Get list of required credential keys for this provider.

        Returns:
            List of required credential key names
        """
        pass

    def save_json(self, data: Any, output_path: str):
        """
        Save data to JSON file.

        Args:
            data: Data to save
            output_path: Output file path
        """
        try:
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            self.logger.info(f"Saved data to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to save JSON to {output_path}: {e}")
            raise

    def format_timestamp(self, timestamp: Any) -> str:
        """
        Format timestamp to ISO format.

        Args:
            timestamp: Timestamp to format (datetime, string, or int)

        Returns:
            ISO format timestamp string
        """
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()
        elif isinstance(timestamp, str):
            return timestamp
        elif isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp).isoformat()
        else:
            return str(timestamp)

    def get_provider_name(self) -> str:
        """
        Get cloud provider name.

        Returns:
            Provider name (e.g., 'AWS', 'Azure', 'GCP')
        """
        return self.__class__.__name__.replace("Forensics", "")

    def __str__(self) -> str:
        """String representation."""
        return f"{self.get_provider_name()} Cloud Provider (authenticated: {self.authenticated})"

    def __repr__(self) -> str:
        """String representation."""
        return self.__str__()


class CloudArtifact:
    """
    Base class for cloud artifacts with MITRE ATT&CK mapping.
    """

    def __init__(
        self,
        artifact_type: str,
        provider: str,
        timestamp: datetime,
        data: Dict[str, Any],
        attck_techniques: Optional[List[str]] = None,
    ):
        """
        Initialize cloud artifact.

        Args:
            artifact_type: Type of artifact (e.g., 'instance', 'log_entry', 'storage')
            provider: Cloud provider name
            timestamp: Artifact timestamp
            data: Artifact data
            attck_techniques: Associated MITRE ATT&CK technique IDs
        """
        self.artifact_type = artifact_type
        self.provider = provider
        self.timestamp = timestamp
        self.data = data
        self.attck_techniques = attck_techniques or []

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert artifact to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "artifact_type": self.artifact_type,
            "provider": self.provider,
            "timestamp": (
                self.timestamp.isoformat()
                if isinstance(self.timestamp, datetime)
                else str(self.timestamp)
            ),
            "data": self.data,
            "attck_techniques": self.attck_techniques,
        }

    def __str__(self) -> str:
        """String representation."""
        return f"{self.provider} {self.artifact_type} artifact at {self.timestamp}"


class CloudForensicsException(Exception):
    """Custom exception for cloud forensics operations."""

    def __init__(
        self, message: str, provider: Optional[str] = None, details: Optional[Dict] = None
    ):
        """
        Initialize exception.

        Args:
            message: Error message
            provider: Cloud provider name
            details: Additional error details
        """
        self.message = message
        self.provider = provider
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        """String representation."""
        if self.provider:
            return f"[{self.provider}] {self.message}"
        return self.message

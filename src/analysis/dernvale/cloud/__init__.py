"""
Cloud Forensics Module

Support for forensic acquisition and analysis of cloud infrastructure
artifacts from AWS, Azure, and GCP.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

from .base import CloudProvider, CloudArtifact, CloudForensicsException

__all__ = [
    "CloudProvider",
    "CloudArtifact",
    "CloudForensicsException",
]

__version__ = "2.1.0"

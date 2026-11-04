"""
GCP Cloud Forensics Module

Forensic acquisition and analysis for Google Cloud Platform.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

from .compute import GCPForensics
from .logging import CloudLoggingAnalyzer

__all__ = [
    "GCPForensics",
    "CloudLoggingAnalyzer",
]

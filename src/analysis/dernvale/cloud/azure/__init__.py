"""
Azure Cloud Forensics Module

Forensic acquisition and analysis for Microsoft Azure.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

from .vm import AzureForensics
from .activity_log import ActivityLogAnalyzer

__all__ = [
    "AzureForensics",
    "ActivityLogAnalyzer",
]

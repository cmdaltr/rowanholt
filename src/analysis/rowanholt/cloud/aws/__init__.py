"""
AWS Cloud Forensics Module

Forensic acquisition and analysis for Amazon Web Services.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

from .ec2 import AWSForensics
from .cloudtrail import CloudTrailAnalyzer
from .s3 import S3Forensics

__all__ = [
    "AWSForensics",
    "CloudTrailAnalyzer",
    "S3Forensics",
]

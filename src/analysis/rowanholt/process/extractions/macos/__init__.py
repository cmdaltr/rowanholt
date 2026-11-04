"""
macOS Artifact Extraction Modules

Enhanced parsers for macOS-specific artifacts.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

from .unified_log import UnifiedLogParser
from .coreduet import CoreDuetParser
from .tcc import TCCParser
from .fseventsd import FSEventsParser
from .quarantine import QuarantineParser

__all__ = [
    "UnifiedLogParser",
    "CoreDuetParser",
    "TCCParser",
    "FSEventsParser",
    "QuarantineParser",
]

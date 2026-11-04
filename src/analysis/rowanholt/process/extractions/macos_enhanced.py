#!/usr/bin/env python3
"""
Enhanced macOS Artifact Parsers

Comprehensive parsers for macOS-specific artifacts including:
- Unified Logging (tracev3)
- CoreDuet (application usage)
- TCC (privacy permissions)
- FSEvents (file system events)
- Quarantine database

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import os
import sqlite3
import struct
import plistlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging


class UnifiedLogParser:
    """
    Parse macOS Unified Logging (tracev3 files).

    Unified logging replaced traditional syslog in macOS 10.12+.
    Log files are in /private/var/db/diagnostics/ and /private/var/db/uuidtext/.

    ATT&CK Mapping:
    - T1562.002: Disable Windows Event Logging (similar on macOS)
    - T1070.002: Clear Linux or Mac System Logs
    """

    def __init__(self):
        """Initialize Unified Log parser."""
        self.logger = logging.getLogger(__name__)

    def parse_unified_logs(self, diagnostics_dir: str) -> List[Dict[str, Any]]:
        """
        Parse unified log files from diagnostics directory.

        Args:
            diagnostics_dir: Path to /private/var/db/diagnostics/

        Returns:
            List of log entries
        """
        entries = []

        try:
            # Look for .tracev3 files
            for root, dirs, files in os.walk(diagnostics_dir):
                for file in files:
                    if file.endswith(".tracev3"):
                        file_path = os.path.join(root, file)
                        try:
                            file_entries = self._parse_tracev3_file(file_path)
                            entries.extend(file_entries)
                        except Exception as e:
                            self.logger.error(f"Error parsing {file_path}: {e}")

        except Exception as e:
            self.logger.error(f"Error parsing unified logs: {e}")

        return entries

    def _parse_tracev3_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse individual tracev3 file.

        Note: This is a simplified parser. For production, consider using
        Apple's 'log' command or pyunifiedlog library.

        Args:
            file_path: Path to tracev3 file

        Returns:
            List of log entries
        """
        entries = []

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Tracev3 has a header followed by log entries
            # This is a simplified extraction looking for text strings

            # Extract printable strings that look like log messages
            import re

            strings = re.findall(rb"[\x20-\x7E]{20,200}", data)

            for string in strings:
                try:
                    text = string.decode("utf-8")
                    entries.append(
                        {
                            "source_file": file_path,
                            "message": text,
                            "artifact_type": "unified_log",
                            "attck_techniques": ["T1070.002"],
                        }
                    )
                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Error parsing tracev3 file: {e}")

        return entries


class CoreDuetParser:
    """
    Parse CoreDuet application usage database.

    CoreDuet tracks application usage, focus time, and user interactions.
    Located at /private/var/db/CoreDuet/Knowledge/knowledgeC.db

    ATT&CK Mapping:
    - T1083: File and Directory Discovery
    - T1087: Account Discovery
    """

    def __init__(self):
        """Initialize CoreDuet parser."""
        self.logger = logging.getLogger(__name__)

    def parse_knowledge_db(self, db_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse knowledgeC.db for application usage.

        Args:
            db_path: Path to knowledgeC.db

        Returns:
            Dictionary with application usage data
        """
        results = {"app_usage": [], "app_installs": [], "focus_time": [], "errors": []}

        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get application usage
            try:
                cursor.execute(
                    """
                    SELECT
                        ZOBJECT.ZVALUESTRING as app_name,
                        datetime(ZOBJECT.ZCREATIONDATE + 978307200, 'unixepoch') as timestamp,
                        ZOBJECT.ZSTREAMNAME as stream_name
                    FROM ZOBJECT
                    WHERE ZSTREAMNAME LIKE '%app%'
                    ORDER BY ZCREATIONDATE DESC
                    LIMIT 1000
                """
                )

                for row in cursor.fetchall():
                    results["app_usage"].append(
                        {
                            "app_name": row[0],
                            "timestamp": row[1],
                            "stream_name": row[2],
                            "artifact_type": "coreduet_app_usage",
                            "attck_techniques": ["T1083", "T1087"],
                        }
                    )

            except sqlite3.Error as e:
                results["errors"].append(f"Error querying app usage: {e}")

            # Get application installs
            try:
                cursor.execute(
                    """
                    SELECT
                        ZOBJECT.ZVALUESTRING as app_name,
                        datetime(ZOBJECT.ZCREATIONDATE + 978307200, 'unixepoch') as install_time
                    FROM ZOBJECT
                    WHERE ZSTREAMNAME LIKE '%install%'
                    ORDER BY ZCREATIONDATE DESC
                    LIMIT 1000
                """
                )

                for row in cursor.fetchall():
                    results["app_installs"].append(
                        {
                            "app_name": row[0],
                            "install_time": row[1],
                            "artifact_type": "coreduet_app_install",
                            "attck_techniques": ["T1105"],  # Ingress Tool Transfer
                        }
                    )

            except sqlite3.Error as e:
                results["errors"].append(f"Error querying app installs: {e}")

            conn.close()

        except Exception as e:
            self.logger.error(f"Error parsing CoreDuet database: {e}")
            results["errors"].append(str(e))

        return results


class TCCParser:
    """
    Parse TCC.db (Transparency, Consent, and Control).

    TCC tracks which applications have been granted access to sensitive resources
    (camera, microphone, files, etc.).
    Located at /Library/Application Support/com.apple.TCC/TCC.db

    ATT&CK Mapping:
    - T1123: Audio Capture
    - T1125: Video Capture
    - T1005: Data from Local System
    """

    def __init__(self):
        """Initialize TCC parser."""
        self.logger = logging.getLogger(__name__)

    def parse_tcc_db(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Parse TCC.db for privacy permissions.

        Args:
            db_path: Path to TCC.db

        Returns:
            List of permission grants
        """
        permissions = []

        if not os.path.exists(db_path):
            return permissions

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Query access table
            cursor.execute(
                """
                SELECT
                    service,
                    client,
                    client_type,
                    allowed,
                    prompt_count,
                    last_modified
                FROM access
                ORDER BY last_modified DESC
            """
            )

            for row in cursor.fetchall():
                service = row[0]
                client = row[1]
                allowed = row[3]

                # Determine ATT&CK techniques based on service
                techniques = []
                if service == "kTCCServiceMicrophone":
                    techniques.append("T1123")  # Audio Capture
                elif service == "kTCCServiceCamera":
                    techniques.append("T1125")  # Video Capture
                elif service in [
                    "kTCCServiceSystemPolicyAllFiles",
                    "kTCCServiceSystemPolicyDesktopFolder",
                ]:
                    techniques.append("T1005")  # Data from Local System

                permissions.append(
                    {
                        "service": service,
                        "client": client,
                        "client_type": row[2],
                        "allowed": bool(allowed),
                        "prompt_count": row[4],
                        "last_modified": row[5],
                        "artifact_type": "tcc_permission",
                        "attck_techniques": techniques,
                        "severity": "high" if allowed and techniques else "low",
                    }
                )

            conn.close()

        except Exception as e:
            self.logger.error(f"Error parsing TCC database: {e}")

        return permissions


class FSEventsParser:
    """
    Parse FSEvents logs for file system activity.

    FSEvents tracks file system changes (creates, modifies, deletes).
    Located at /.fseventsd/

    ATT&CK Mapping:
    - T1083: File and Directory Discovery
    - T1070.004: File Deletion
    - T1105: Ingress Tool Transfer
    """

    def __init__(self):
        """Initialize FSEvents parser."""
        self.logger = logging.getLogger(__name__)

    def parse_fseventsd(self, fseventsd_dir: str) -> List[Dict[str, Any]]:
        """
        Parse FSEvents directory.

        Args:
            fseventsd_dir: Path to .fseventsd directory

        Returns:
            List of file system events
        """
        events = []

        if not os.path.exists(fseventsd_dir):
            return events

        try:
            # FSEvents are stored in numbered files
            for filename in os.listdir(fseventsd_dir):
                if filename.isdigit() or filename.endswith(".gzip"):
                    file_path = os.path.join(fseventsd_dir, filename)

                    try:
                        file_events = self._parse_fsevent_file(file_path)
                        events.extend(file_events)
                    except Exception as e:
                        self.logger.debug(f"Error parsing FSEvent file {filename}: {e}")

        except Exception as e:
            self.logger.error(f"Error parsing FSEvents directory: {e}")

        return events

    def _parse_fsevent_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse individual FSEvent file.

        Note: This is a simplified parser. For production, use fsevents-parser or similar.

        Args:
            file_path: Path to FSEvent file

        Returns:
            List of events
        """
        events = []

        try:
            # Check if gzipped
            if file_path.endswith(".gzip"):
                import gzip

                with gzip.open(file_path, "rb") as f:
                    data = f.read()
            else:
                with open(file_path, "rb") as f:
                    data = f.read()

            # Simplified extraction: look for file paths
            import re

            paths = re.findall(rb"/[\x20-\x7E/]{10,200}", data)

            for path in paths:
                try:
                    path_str = path.decode("utf-8")
                    events.append(
                        {
                            "path": path_str,
                            "source_file": file_path,
                            "artifact_type": "fsevent",
                            "attck_techniques": ["T1083", "T1070.004"],
                        }
                    )
                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Error parsing FSEvent file: {e}")

        return events


class QuarantineParser:
    """
    Parse macOS Quarantine database.

    Quarantine tracks downloaded files and their origin.
    Located at ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

    ATT&CK Mapping:
    - T1105: Ingress Tool Transfer
    - T1566: Phishing (if downloaded from email/web)
    """

    def __init__(self):
        """Initialize Quarantine parser."""
        self.logger = logging.getLogger(__name__)

    def parse_quarantine_db(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Parse QuarantineEventsV2 database.

        Args:
            db_path: Path to QuarantineEventsV2 database

        Returns:
            List of quarantine events
        """
        events = []

        if not os.path.exists(db_path):
            return events

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    LSQuarantineEventIdentifier,
                    LSQuarantineTimeStamp,
                    LSQuarantineAgentName,
                    LSQuarantineAgentBundleIdentifier,
                    LSQuarantineDataURLString,
                    LSQuarantineOriginURLString,
                    LSQuarantineOriginTitle
                FROM LSQuarantineEvent
                ORDER BY LSQuarantineTimeStamp DESC
            """
            )

            for row in cursor.fetchall():
                # Convert Core Data timestamp (seconds since 2001-01-01)
                timestamp = None
                if row[1]:
                    try:
                        timestamp = datetime(2001, 1, 1) + timedelta(seconds=row[1])
                        timestamp = timestamp.isoformat()
                    except:
                        pass

                events.append(
                    {
                        "event_id": row[0],
                        "timestamp": timestamp,
                        "agent_name": row[2],
                        "agent_bundle": row[3],
                        "data_url": row[4],
                        "origin_url": row[5],
                        "origin_title": row[6],
                        "artifact_type": "quarantine_event",
                        "attck_techniques": ["T1105"],
                        "severity": "medium",
                        "description": f"File downloaded from {row[5] or 'unknown source'}",
                    }
                )

            conn.close()

        except Exception as e:
            self.logger.error(f"Error parsing Quarantine database: {e}")

        return events


# macOS Artifact Collection Paths
MACOS_ARTIFACTS_EXTENDED = {
    # Unified Logging
    "/private/var/db/diagnostics/": "unified_logs",
    "/private/var/db/uuidtext/": "unified_logs",
    # Application Usage
    "/private/var/db/CoreDuet/Knowledge/knowledgeC.db": "coreduet",
    # Privacy Permissions
    "/Library/Application Support/com.apple.TCC/TCC.db": "tcc",
    "/Users/*/Library/Application Support/com.apple.TCC/TCC.db": "tcc",
    # File System Events
    "/.fseventsd/": "fseventsd",
    "/Users/*/.fseventsd/": "fseventsd",
    # Quarantine
    "/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2": "quarantine",
    # Network Configuration
    "/Library/Preferences/SystemConfiguration/": "network_config",
    "/private/var/db/dhcpclient/": "dhcp_leases",
    # Browser Extensions
    "/Users/*/Library/Safari/Extensions/": "safari_extensions",
    "/Users/*/Library/Application Support/Google/Chrome/Default/Extensions/": "chrome_extensions",
    # Spotlight
    "/.Spotlight-V100/": "spotlight",
    # Time Machine
    "/private/var/db/.TimeMachine/": "timemachine",
    # FileVault
    "/var/db/FileVaultKeys/": "filevault",
    # Keychain
    "/Users/*/Library/Keychains/": "keychains",
    "/Library/Keychains/": "keychains",
    # System Logs
    "/var/log/system.log": "system_log",
    "/var/log/install.log": "install_log",
    "/Library/Logs/DiagnosticReports/": "crash_reports",
}


# Convenience function


def parse_all_macos_artifacts(mount_point: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parse all enhanced macOS artifacts.

    Args:
        mount_point: Path to mounted macOS image

    Returns:
        Dictionary with all parsed artifacts
    """
    results = {
        "unified_logs": [],
        "coreduet": [],
        "tcc_permissions": [],
        "fse events": [],
        "quarantine": [],
        "errors": [],
    }

    # Unified Logs
    unified_parser = UnifiedLogParser()
    diagnostics_path = os.path.join(mount_point, "private/var/db/diagnostics")
    if os.path.exists(diagnostics_path):
        results["unified_logs"] = unified_parser.parse_unified_logs(diagnostics_path)

    # CoreDuet
    coreduet_parser = CoreDuetParser()
    coreduet_path = os.path.join(mount_point, "private/var/db/CoreDuet/Knowledge/knowledgeC.db")
    if os.path.exists(coreduet_path):
        coreduet_data = coreduet_parser.parse_knowledge_db(coreduet_path)
        results["coreduet"] = coreduet_data

    # TCC
    tcc_parser = TCCParser()
    tcc_paths = [
        os.path.join(mount_point, "Library/Application Support/com.apple.TCC/TCC.db"),
    ]
    for tcc_path in tcc_paths:
        if os.path.exists(tcc_path):
            results["tcc_permissions"].extend(tcc_parser.parse_tcc_db(tcc_path))

    # FSEvents
    fsevent_parser = FSEventsParser()
    fsevent_path = os.path.join(mount_point, ".fseventsd")
    if os.path.exists(fsevent_path):
        results["fsevents"] = fsevent_parser.parse_fseventsd(fsevent_path)

    # Quarantine
    quarantine_parser = QuarantineParser()
    # Would need to find user directories
    import glob

    quarantine_pattern = os.path.join(
        mount_point, "Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    )
    for quarantine_path in glob.glob(quarantine_pattern):
        results["quarantine"].extend(quarantine_parser.parse_quarantine_db(quarantine_path))

    return results

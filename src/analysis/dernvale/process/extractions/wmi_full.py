#!/usr/bin/env python3
"""
Comprehensive WMI Artifact Parser

Parses Windows Management Instrumentation (WMI) artifacts for forensic analysis.
Focuses on persistence mechanisms via WMI Event Subscriptions.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import os
import re
import struct
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging


class WmiArtifactParser:
    """
    Comprehensive WMI artifact parser.

    Parses:
    - Event Consumers (ActiveScriptEventConsumer, CommandLineEventConsumer, etc.)
    - Event Filters (WQL queries that trigger consumers)
    - Filter-to-Consumer Bindings (linking filters to consumers)
    - WMI Repository files (OBJECTS.DATA)
    - WMI Namespaces
    - MOF files

    ATT&CK Mapping:
    - T1546.003: WMI Event Subscription
    - T1047: Windows Management Instrumentation
    """

    # WMI Repository locations
    WMI_REPOSITORY_PATHS = [
        "Windows/System32/wbem/Repository/",
        "Windows/System32/wbem/Repository/FS/",
        "System32/wbem/Repository/",
        "System32/wbem/Repository/FS/",
    ]

    # Event Consumer types
    CONSUMER_TYPES = [
        "ActiveScriptEventConsumer",
        "CommandLineEventConsumer",
        "LogFileEventConsumer",
        "NTEventLogEventConsumer",
        "SMTPEventConsumer",
    ]

    def __init__(self):
        """Initialize WMI parser."""
        self.logger = logging.getLogger(__name__)

    def parse_wmi_repository(self, mount_point: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parse WMI repository files from mounted image.

        Args:
            mount_point: Path to mounted Windows image

        Returns:
            Dictionary with consumers, filters, and bindings
        """
        results = {"consumers": [], "filters": [], "bindings": [], "namespaces": [], "errors": []}

        # Try each repository path
        for repo_path in self.WMI_REPOSITORY_PATHS:
            full_path = os.path.join(mount_point, repo_path)

            if not os.path.exists(full_path):
                continue

            self.logger.info(f"Parsing WMI repository: {full_path}")

            try:
                # Parse OBJECTS.DATA
                objects_file = os.path.join(full_path, "OBJECTS.DATA")
                if os.path.exists(objects_file):
                    objects = self._parse_objects_data(objects_file)

                    # Extract different artifact types
                    results["consumers"].extend(self._extract_event_consumers(objects))
                    results["filters"].extend(self._extract_event_filters(objects))
                    results["bindings"].extend(self._extract_bindings(objects))

                # Parse INDEX.BTR for namespace info
                index_file = os.path.join(full_path, "INDEX.BTR")
                if os.path.exists(index_file):
                    namespaces = self._parse_index_btr(index_file)
                    results["namespaces"].extend(namespaces)

            except Exception as e:
                self.logger.error(f"Error parsing WMI repository {full_path}: {e}")
                results["errors"].append({"path": full_path, "error": str(e)})

        return results

    def parse_wmi_powershell(self, mount_point: str) -> List[Dict[str, Any]]:
        """
        Parse PowerShell logs for WMI-related commands.

        Args:
            mount_point: Path to mounted Windows image

        Returns:
            List of WMI-related PowerShell commands
        """
        wmi_commands = []

        # PowerShell history locations
        ps_history_paths = [
            "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            "Windows/System32/config/systemprofile/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        ]

        # WMI-related cmdlets and patterns
        wmi_patterns = [
            r"Get-WmiObject",
            r"Get-CimInstance",
            r"Set-WmiInstance",
            r"Invoke-WmiMethod",
            r"Register-WmiEvent",
            r"Remove-WmiObject",
            r"__EventConsumer",
            r"__EventFilter",
            r"__FilterToConsumerBinding",
        ]

        for pattern_path in ps_history_paths:
            full_pattern = os.path.join(mount_point, pattern_path)

            try:
                from glob import glob

                for file_path in glob(full_pattern):
                    if os.path.exists(file_path):
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line_num, line in enumerate(f, 1):
                                for pattern in wmi_patterns:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        wmi_commands.append(
                                            {
                                                "file": file_path,
                                                "line_number": line_num,
                                                "command": line.strip(),
                                                "pattern_matched": pattern,
                                                "attck_techniques": ["T1047", "T1059.001"],
                                            }
                                        )
                                        break

            except Exception as e:
                self.logger.error(f"Error parsing PowerShell history: {e}")

        return wmi_commands

    def _parse_objects_data(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse OBJECTS.DATA file for WMI objects.

        This is a simplified parser. For production, consider using
        python-cim library or other specialized WMI parsers.

        Args:
            file_path: Path to OBJECTS.DATA file

        Returns:
            List of WMI objects
        """
        objects = []

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Simple string extraction for WMI classes
            # Look for common WMI class names and their data

            # Event Consumers
            for consumer_type in self.CONSUMER_TYPES:
                pattern = consumer_type.encode("utf-16-le")
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    # Try to extract nearby strings (simplified)
                    obj = self._extract_wmi_object(data, offset, consumer_type)
                    if obj:
                        objects.append(obj)

                    offset += len(pattern)

            # Event Filters
            filter_pattern = b"__EventFilter"
            offset = 0
            while True:
                offset = data.find(filter_pattern, offset)
                if offset == -1:
                    break

                obj = self._extract_wmi_object(data, offset, "__EventFilter")
                if obj:
                    objects.append(obj)

                offset += len(filter_pattern)

            # Filter-to-Consumer Bindings
            binding_pattern = b"__FilterToConsumerBinding"
            offset = 0
            while True:
                offset = data.find(binding_pattern, offset)
                if offset == -1:
                    break

                obj = self._extract_wmi_object(data, offset, "__FilterToConsumerBinding")
                if obj:
                    objects.append(obj)

                offset += len(binding_pattern)

        except Exception as e:
            self.logger.error(f"Error parsing OBJECTS.DATA: {e}")

        return objects

    def _extract_wmi_object(
        self, data: bytes, offset: int, class_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Extract WMI object properties from binary data.

        This is a simplified extraction. For production, use proper WMI parser.

        Args:
            data: Binary data from OBJECTS.DATA
            offset: Offset where class name was found
            class_name: WMI class name

        Returns:
            Dictionary with extracted properties or None
        """
        try:
            # Extract a window of data around the offset
            window_start = max(0, offset - 2000)
            window_end = min(len(data), offset + 2000)
            window = data[window_start:window_end]

            # Try to find common property names
            obj = {
                "__CLASS": class_name,
                "_offset": offset,
                "_extracted": datetime.utcnow().isoformat(),
            }

            # Extract Name property
            name_match = re.search(rb"Name.{1,200}?([\x20-\x7E]{3,100})", window)
            if name_match:
                try:
                    obj["Name"] = name_match.group(1).decode("utf-8", errors="ignore").strip()
                except:
                    pass

            # For CommandLineEventConsumer: CommandLineTemplate
            if "CommandLine" in class_name:
                cmdline_match = re.search(
                    rb"CommandLineTemplate.{1,200}?([\x20-\x7E]{3,500})", window
                )
                if cmdline_match:
                    try:
                        obj["CommandLineTemplate"] = (
                            cmdline_match.group(1).decode("utf-8", errors="ignore").strip()
                        )
                    except:
                        pass

            # For ActiveScriptEventConsumer: ScriptText
            if "ActiveScript" in class_name:
                script_match = re.search(rb"ScriptText.{1,200}?([\x20-\x7E]{10,1000})", window)
                if script_match:
                    try:
                        obj["ScriptText"] = (
                            script_match.group(1).decode("utf-8", errors="ignore").strip()
                        )
                    except:
                        pass

            # For EventFilter: Query
            if "__EventFilter" in class_name:
                query_match = re.search(rb"Query.{1,200}?(SELECT.{10,500})", window, re.IGNORECASE)
                if query_match:
                    try:
                        obj["Query"] = query_match.group(1).decode("utf-8", errors="ignore").strip()
                    except:
                        pass

            return obj if len(obj) > 3 else None  # Return if we found more than just metadata

        except Exception as e:
            self.logger.debug(f"Error extracting WMI object: {e}")
            return None

    def _parse_index_btr(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse INDEX.BTR for namespace information.

        Args:
            file_path: Path to INDEX.BTR file

        Returns:
            List of namespace information
        """
        namespaces = []

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Look for common namespace patterns
            namespace_patterns = [
                b"root\\subscription",
                b"root\\cimv2",
                b"root\\default",
                b"root\\security",
            ]

            for pattern in namespace_patterns:
                if pattern in data:
                    try:
                        namespace_name = pattern.decode("utf-8")
                        namespaces.append({"namespace": namespace_name, "file": file_path})
                    except:
                        pass

        except Exception as e:
            self.logger.debug(f"Error parsing INDEX.BTR: {e}")

        return namespaces

    def _extract_event_consumers(self, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract and format Event Consumers.

        Args:
            objects: List of WMI objects

        Returns:
            List of formatted consumer artifacts
        """
        consumers = []

        for obj in objects:
            if obj.get("__CLASS") in self.CONSUMER_TYPES:
                consumer = {
                    "artifact_type": "wmi_event_consumer",
                    "consumer_type": obj["__CLASS"],
                    "name": obj.get("Name", "Unknown"),
                    "command_line": obj.get("CommandLineTemplate", ""),
                    "script_text": obj.get("ScriptText", ""),
                    "extracted_time": obj.get("_extracted"),
                    "offset": obj.get("_offset"),
                    "attck_techniques": ["T1546.003", "T1047"],
                    "severity": "high",  # WMI persistence is suspicious
                    "description": f"{obj['__CLASS']} found in WMI repository",
                }

                # Add context based on consumer type
                if "CommandLine" in obj["__CLASS"] and consumer["command_line"]:
                    consumer["context"] = consumer["command_line"]
                elif "ActiveScript" in obj["__CLASS"] and consumer["script_text"]:
                    consumer["context"] = consumer["script_text"]

                consumers.append(consumer)

        return consumers

    def _extract_event_filters(self, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract and format Event Filters.

        Args:
            objects: List of WMI objects

        Returns:
            List of formatted filter artifacts
        """
        filters = []

        for obj in objects:
            if obj.get("__CLASS") == "__EventFilter":
                filter_obj = {
                    "artifact_type": "wmi_event_filter",
                    "name": obj.get("Name", "Unknown"),
                    "query": obj.get("Query", ""),
                    "query_language": obj.get("QueryLanguage", "WQL"),
                    "event_namespace": obj.get("EventNamespace", "root\\cimv2"),
                    "extracted_time": obj.get("_extracted"),
                    "offset": obj.get("_offset"),
                    "attck_techniques": ["T1546.003", "T1047"],
                    "severity": "high",
                    "description": "WMI Event Filter found in repository",
                }

                if filter_obj["query"]:
                    filter_obj["context"] = filter_obj["query"]

                filters.append(filter_obj)

        return filters

    def _extract_bindings(self, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract and format Filter-to-Consumer Bindings.

        Args:
            objects: List of WMI objects

        Returns:
            List of formatted binding artifacts
        """
        bindings = []

        for obj in objects:
            if obj.get("__CLASS") == "__FilterToConsumerBinding":
                binding = {
                    "artifact_type": "wmi_binding",
                    "filter": obj.get("Filter", ""),
                    "consumer": obj.get("Consumer", ""),
                    "extracted_time": obj.get("_extracted"),
                    "offset": obj.get("_offset"),
                    "attck_techniques": ["T1546.003", "T1047"],
                    "severity": "critical",  # Binding completes the persistence
                    "description": "WMI Filter-to-Consumer binding (active persistence)",
                }

                bindings.append(binding)

        return bindings

    def parse_wmi_from_registry(self, mount_point: str) -> List[Dict[str, Any]]:
        """
        Parse WMI-related registry keys.

        Args:
            mount_point: Path to mounted Windows image

        Returns:
            List of WMI registry artifacts
        """
        artifacts = []

        # WMI-related registry paths
        registry_paths = [
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/SYSTEM",
        ]

        wmi_keys = [
            r"SOFTWARE\Microsoft\Wbem",
            r"SYSTEM\CurrentControlSet\Services\Winmgmt",
        ]

        # This is a placeholder - actual registry parsing would require
        # python-registry or similar library
        self.logger.info("WMI registry parsing requires python-registry library")

        return artifacts

    def generate_report(self, results: Dict[str, List[Dict[str, Any]]]) -> str:
        """
        Generate human-readable report from WMI artifacts.

        Args:
            results: Dictionary with parsed WMI artifacts

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("WMI ARTIFACT ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")

        # Summary
        consumer_count = len(results.get("consumers", []))
        filter_count = len(results.get("filters", []))
        binding_count = len(results.get("bindings", []))

        report.append(f"SUMMARY:")
        report.append(f"  Event Consumers: {consumer_count}")
        report.append(f"  Event Filters: {filter_count}")
        report.append(f"  Bindings: {binding_count}")
        report.append(f"  Namespaces: {len(results.get('namespaces', []))}")
        report.append("")

        if binding_count > 0:
            report.append("⚠️  WARNING: Active WMI persistence detected!")
            report.append("")

        # Consumers
        if consumer_count > 0:
            report.append("EVENT CONSUMERS:")
            report.append("-" * 80)
            for consumer in results["consumers"]:
                report.append(f"  Name: {consumer['name']}")
                report.append(f"  Type: {consumer['consumer_type']}")
                if consumer.get("command_line"):
                    report.append(f"  Command: {consumer['command_line']}")
                if consumer.get("script_text"):
                    report.append(f"  Script: {consumer['script_text'][:200]}...")
                report.append(f"  ATT&CK: {', '.join(consumer['attck_techniques'])}")
                report.append("")

        # Filters
        if filter_count > 0:
            report.append("EVENT FILTERS:")
            report.append("-" * 80)
            for filter_obj in results["filters"]:
                report.append(f"  Name: {filter_obj['name']}")
                if filter_obj.get("query"):
                    report.append(f"  Query: {filter_obj['query']}")
                report.append(f"  ATT&CK: {', '.join(filter_obj['attck_techniques'])}")
                report.append("")

        # Bindings
        if binding_count > 0:
            report.append("FILTER-TO-CONSUMER BINDINGS (Active Persistence):")
            report.append("-" * 80)
            for binding in results["bindings"]:
                report.append(f"  Filter: {binding['filter']}")
                report.append(f"  Consumer: {binding['consumer']}")
                report.append(f"  Severity: {binding['severity'].upper()}")
                report.append("")

        return "\n".join(report)


# Convenience functions


def parse_wmi_artifacts(mount_point: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convenience function to parse all WMI artifacts.

    Args:
        mount_point: Path to mounted Windows image

    Returns:
        Dictionary with all WMI artifacts
    """
    parser = WmiArtifactParser()
    results = parser.parse_wmi_repository(mount_point)

    # Also parse PowerShell logs for WMI usage
    ps_wmi = parser.parse_wmi_powershell(mount_point)
    results["powershell_wmi"] = ps_wmi

    return results


def export_wmi_to_json(results: Dict[str, List[Dict[str, Any]]], output_file: str):
    """
    Export WMI artifacts to JSON.

    Args:
        results: Dictionary with WMI artifacts
        output_file: Output JSON file path
    """
    import json

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)


def export_wmi_to_csv(results: Dict[str, List[Dict[str, Any]]], output_dir: str):
    """
    Export WMI artifacts to CSV files.

    Args:
        results: Dictionary with WMI artifacts
        output_dir: Output directory for CSV files
    """
    import csv
    from pathlib import Path

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Export consumers
    if results.get("consumers"):
        with open(output_path / "wmi_consumers.csv", "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "name",
                    "consumer_type",
                    "command_line",
                    "script_text",
                    "severity",
                    "attck_techniques",
                ],
            )
            writer.writeheader()
            for consumer in results["consumers"]:
                writer.writerow(
                    {
                        "name": consumer["name"],
                        "consumer_type": consumer["consumer_type"],
                        "command_line": consumer.get("command_line", ""),
                        "script_text": consumer.get("script_text", "")[:200],
                        "severity": consumer["severity"],
                        "attck_techniques": ", ".join(consumer["attck_techniques"]),
                    }
                )

    # Export filters
    if results.get("filters"):
        with open(output_path / "wmi_filters.csv", "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "name",
                    "query",
                    "query_language",
                    "event_namespace",
                    "severity",
                    "attck_techniques",
                ],
            )
            writer.writeheader()
            for filter_obj in results["filters"]:
                writer.writerow(
                    {
                        "name": filter_obj["name"],
                        "query": filter_obj.get("query", ""),
                        "query_language": filter_obj.get("query_language", ""),
                        "event_namespace": filter_obj.get("event_namespace", ""),
                        "severity": filter_obj["severity"],
                        "attck_techniques": ", ".join(filter_obj["attck_techniques"]),
                    }
                )

    # Export bindings
    if results.get("bindings"):
        with open(output_path / "wmi_bindings.csv", "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["filter", "consumer", "severity", "attck_techniques"]
            )
            writer.writeheader()
            for binding in results["bindings"]:
                writer.writerow(
                    {
                        "filter": binding.get("filter", ""),
                        "consumer": binding.get("consumer", ""),
                        "severity": binding["severity"],
                        "attck_techniques": ", ".join(binding["attck_techniques"]),
                    }
                )

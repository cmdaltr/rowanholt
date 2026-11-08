#!/usr/bin/env python3
"""
MITRE ATT&CK Enrichment for JSON Artefacts

Adds MITRE ATT&CK technique metadata to processed JSON artefact files.
This enables Navigator layer generation without SIEM dependencies.

Uses content-based pattern matching (from patterns.py) to identify techniques
based on the actual content of artefacts, ensuring consistent results
regardless of SIEM platform.

Author: Rowanholt DF Acceleration Suite
Version: 3.0.0
"""

import bisect
import json
import os
import logging
import gc
from pathlib import Path
from typing import Dict, List, Optional, Set, TextIO
from datetime import datetime

try:
    from rowanholt.core.records import ENVELOPE, read_records
except ImportError:
    ENVELOPE = ("host", "artefact", "source_path", "timestamp", "techniques")
    read_records = None

# Techniques file name - written incrementally during enrichment
TECHNIQUES_FILE = "mitre_techniques.txt"
# Tables over this size are matched a megabyte of text at a time before any line is decoded
LARGE_FILE_BYTES = 10 * 1024 * 1024
TABLE_SUFFIXES = (".jsonl", ".json")
_TECHNIQUES_MARK = '"techniques": ['


def scannable(record: Dict) -> Dict:
    """The part of a record its techniques are read from: not the envelope, whose source path and
    artefact name are the same on every record, nor ATT&CK fields an earlier run added."""
    enveloped = all(key in record for key in ENVELOPE)
    return {k: v for k, v in record.items()
            if not (enveloped and k in ENVELOPE) and not str(k).startswith("mitre_")}


def _technique_ids(values) -> List[str]:
    """Technique IDs from a list of IDs, or of the dicts enrichment writes."""
    out = []
    for value in values if isinstance(values, list) else []:
        if isinstance(value, dict):
            value = value.get("mitre_technique_id") or value.get("technique_id")
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return out


def record_technique_ids(record: Dict) -> Set[str]:
    """Every technique a record names: the envelope's techniques, mitre_technique_id and
    mitre_techniques."""
    found = set(_technique_ids(record.get("techniques")))
    found.update(_technique_ids(record.get("mitre_techniques")))
    primary = record.get("mitre_technique_id")
    found.update(_technique_ids(primary if isinstance(primary, list) else [primary]))
    return found


def _split_envelope(line: str):
    """(the envelope's techniques, the rest of the line) for a JSON Lines record as write_records
    writes it, without decoding it; None when the line isn't one."""
    start = line.find(_TECHNIQUES_MARK)
    if start < 0 or not line.startswith('{"host": '):
        return None
    end = line.find("]", start)
    if end < 0:
        return None
    try:
        techniques = json.loads(line[start + len(_TECHNIQUES_MARK) - 1:end + 1])
    except ValueError:
        return None
    return _technique_ids(techniques), line[end + 1:]

# Import the content-based pattern matcher
try:
    from rowanholt.post.mitre.patterns import get_pattern_matcher, scan_json_record
    PATTERNS_AVAILABLE = True
except ImportError:
    try:
        from .patterns import get_pattern_matcher, scan_json_record
        PATTERNS_AVAILABLE = True
    except ImportError:
        PATTERNS_AVAILABLE = False
        get_pattern_matcher = None
        scan_json_record = None

# Import the comprehensive ATT&CK data
try:
    from rowanholt.post.mitre.attack_data import get_technique_data, enrich_technique, ATTACK_TECHNIQUES
    ATTACK_DATA_AVAILABLE = True
except ImportError:
    try:
        from .attack_data import get_technique_data, enrich_technique, ATTACK_TECHNIQUES
        ATTACK_DATA_AVAILABLE = True
    except ImportError:
        ATTACK_DATA_AVAILABLE = False
        get_technique_data = None
        enrich_technique = None
        ATTACK_TECHNIQUES = {}

# Try to import the MITRE modules (legacy)
try:
    from analysis.mitre import MitreAttackUpdater, TechniqueMapper
    MITRE_AVAILABLE = True
except ImportError:
    MITRE_AVAILABLE = False


class MitreEnrichment:
    """
    Enrich JSON artefacts with MITRE ATT&CK technique metadata.

    Adds fields like:
    - mitre_technique_id: "T1105"
    - mitre_technique_name: "Ingress Tool Transfer"
    - mitre_tactics: ["Command and Control"]
    - mitre_groups: ["APT1", "APT28", "Scattered Spider", "OilRig"]
    """

    # Artefact type to technique mappings
    ARTEFACT_TECHNIQUES = {
        # Prefetch - execution evidence
        "prefetch": [
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
            {"technique_id": "T1106", "technique_name": "Native API", "tactics": ["Execution"]},
        ],
        # Browser artefacts
        "browser_history": [
            {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactics": ["Command and Control"]},
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactics": ["Command and Control"]},
        ],
        "browser_download": [
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactics": ["Command and Control"]},
        ],
        # Registry artefacts
        "registry": [
            {"technique_id": "T1112", "technique_name": "Modify Registry", "tactics": ["Defense Evasion"]},
            {"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactics": ["Persistence", "Privilege Escalation"]},
        ],
        "shellbags": [
            {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactics": ["Discovery"]},
        ],
        "userassist": [
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
        ],
        # Scheduled tasks
        "tasks": [
            {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactics": ["Execution", "Persistence", "Privilege Escalation"]},
        ],
        # Services
        "services": [
            {"technique_id": "T1543.003", "technique_name": "Windows Service", "tactics": ["Persistence", "Privilege Escalation"]},
            {"technique_id": "T1569.002", "technique_name": "Service Execution", "tactics": ["Execution"]},
        ],
        # WMI
        "wbem": [
            {"technique_id": "T1047", "technique_name": "Windows Management Instrumentation", "tactics": ["Execution"]},
            {"technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "tactics": ["Persistence", "Privilege Escalation"]},
        ],
        # Shimcache
        "shimcache": [
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactics": ["Command and Control"]},
        ],
        # Amcache
        "amcache": [
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactics": ["Command and Control"]},
        ],
        # BITS
        "bits": [
            {"technique_id": "T1197", "technique_name": "BITS Jobs", "tactics": ["Defense Evasion", "Persistence"]},
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactics": ["Command and Control"]},
        ],
        # Event logs
        "eventlogs": [
            {"technique_id": "T1070.001", "technique_name": "Clear Windows Event Logs", "tactics": ["Defense Evasion"]},
        ],
        # SRUM
        "srum": [
            {"technique_id": "T1049", "technique_name": "System Network Connections Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1057", "technique_name": "Process Discovery", "tactics": ["Discovery"]},
        ],
        # Jumplists
        "jumplists": [
            {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactics": ["Discovery"]},
        ],
        # Recycle Bin
        "recyclebin": [
            {"technique_id": "T1070.004", "technique_name": "File Deletion", "tactics": ["Defense Evasion"]},
        ],
        # Shortcuts (LNK)
        "shortcuts": [
            {"technique_id": "T1547.009", "technique_name": "Shortcut Modification", "tactics": ["Persistence", "Privilege Escalation"]},
            {"technique_id": "T1204.001", "technique_name": "Malicious Link", "tactics": ["Execution"]},
        ],
        # MFT
        "mft": [
            {"technique_id": "T1070.006", "technique_name": "Timestomp", "tactics": ["Defense Evasion"]},
            {"technique_id": "T1564.004", "technique_name": "NTFS File Attributes", "tactics": ["Defense Evasion"]},
        ],
        # USN Journal
        "usnjrnl": [
            {"technique_id": "T1070.004", "technique_name": "File Deletion", "tactics": ["Defense Evasion"]},
            {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactics": ["Discovery"]},
        ],
        # Outlook
        "outlook": [
            {"technique_id": "T1114.001", "technique_name": "Local Email Collection", "tactics": ["Collection"]},
            {"technique_id": "T1566", "technique_name": "Phishing", "tactics": ["Initial Access"]},
        ],
        # Memory artefacts - Volatility outputs
        "memory_pslist": [
            {"technique_id": "T1057", "technique_name": "Process Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
        ],
        "memory_pstree": [
            {"technique_id": "T1057", "technique_name": "Process Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1055", "technique_name": "Process Injection", "tactics": ["Defense Evasion", "Privilege Escalation"]},
        ],
        "memory_cmdline": [
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactics": ["Execution"]},
            {"technique_id": "T1059.003", "technique_name": "Windows Command Shell", "tactics": ["Execution"]},
        ],
        "memory_netscan": [
            {"technique_id": "T1049", "technique_name": "System Network Connections Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactics": ["Command and Control"]},
            {"technique_id": "T1095", "technique_name": "Non-Application Layer Protocol", "tactics": ["Command and Control"]},
        ],
        "memory_netstat": [
            {"technique_id": "T1049", "technique_name": "System Network Connections Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactics": ["Command and Control"]},
        ],
        "memory_malfind": [
            {"technique_id": "T1055", "technique_name": "Process Injection", "tactics": ["Defense Evasion", "Privilege Escalation"]},
            {"technique_id": "T1055.001", "technique_name": "Dynamic-link Library Injection", "tactics": ["Defense Evasion", "Privilege Escalation"]},
            {"technique_id": "T1620", "technique_name": "Reflective Code Loading", "tactics": ["Defense Evasion"]},
        ],
        "memory_dlllist": [
            {"technique_id": "T1055.001", "technique_name": "Dynamic-link Library Injection", "tactics": ["Defense Evasion", "Privilege Escalation"]},
            {"technique_id": "T1574.001", "technique_name": "DLL Search Order Hijacking", "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"]},
            {"technique_id": "T1129", "technique_name": "Shared Modules", "tactics": ["Execution"]},
        ],
        "memory_handles": [
            {"technique_id": "T1057", "technique_name": "Process Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1106", "technique_name": "Native API", "tactics": ["Execution"]},
        ],
        "memory_filescan": [
            {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1005", "technique_name": "Data from Local System", "tactics": ["Collection"]},
        ],
        "memory_driverscan": [
            {"technique_id": "T1014", "technique_name": "Rootkit", "tactics": ["Defense Evasion"]},
            {"technique_id": "T1543.003", "technique_name": "Windows Service", "tactics": ["Persistence", "Privilege Escalation"]},
        ],
        "memory_modules": [
            {"technique_id": "T1014", "technique_name": "Rootkit", "tactics": ["Defense Evasion"]},
            {"technique_id": "T1547.006", "technique_name": "Kernel Modules and Extensions", "tactics": ["Persistence", "Privilege Escalation"]},
        ],
        "memory_svcscan": [
            {"technique_id": "T1543.003", "technique_name": "Windows Service", "tactics": ["Persistence", "Privilege Escalation"]},
            {"technique_id": "T1569.002", "technique_name": "Service Execution", "tactics": ["Execution"]},
        ],
        "memory_getsids": [
            {"technique_id": "T1087", "technique_name": "Account Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]},
        ],
        "memory_envars": [
            {"technique_id": "T1082", "technique_name": "System Information Discovery", "tactics": ["Discovery"]},
            {"technique_id": "T1574.007", "technique_name": "Path Interception by PATH Environment Variable", "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"]},
        ],
        "memory_privileges": [
            {"technique_id": "T1134", "technique_name": "Access Token Manipulation", "tactics": ["Defense Evasion", "Privilege Escalation"]},
            {"technique_id": "T1134.001", "technique_name": "Token Impersonation/Theft", "tactics": ["Defense Evasion", "Privilege Escalation"]},
        ],
        "memory_mutantscan": [
            {"technique_id": "T1480", "technique_name": "Execution Guardrails", "tactics": ["Defense Evasion"]},
        ],
        "memory_registry": [
            {"technique_id": "T1112", "technique_name": "Modify Registry", "tactics": ["Defense Evasion"]},
            {"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactics": ["Persistence", "Privilege Escalation"]},
        ],
    }

    # Technique to threat groups mapping (commonly observed)
    TECHNIQUE_GROUPS = {
        "T1059": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider"],
        "T1059.001": ["APT28", "APT29", "Turla", "FIN7", "Cobalt Group"],
        "T1059.003": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "T1105": ["APT1", "APT28", "APT29", "OilRig", "Scattered Spider", "Lazarus Group"],
        "T1071.001": ["APT28", "APT29", "Turla", "OilRig", "Kimsuky"],
        "T1112": ["APT28", "APT29", "Turla", "Lazarus Group"],
        "T1547.001": ["APT28", "APT29", "Turla", "Lazarus Group", "FIN7"],
        "T1053.005": ["APT28", "APT29", "Lazarus Group", "FIN7", "Wizard Spider"],
        "T1543.003": ["APT28", "Turla", "Lazarus Group", "FIN7"],
        "T1047": ["APT29", "Lazarus Group", "FIN7", "Wizard Spider"],
        "T1546.003": ["APT29", "Turla", "Leviathan"],
        "T1197": ["APT41", "Leviathan", "Turla"],
        "T1070.001": ["APT28", "APT29", "APT41", "Lazarus Group"],
        "T1070.004": ["APT28", "APT29", "Turla", "Lazarus Group"],
        "T1070.006": ["APT28", "APT29", "APT41", "Lazarus Group"],
        "T1083": ["APT28", "APT29", "Turla", "Lazarus Group", "OilRig"],
        "T1049": ["APT28", "APT29", "Turla", "Lazarus Group"],
        "T1057": ["APT28", "APT29", "Turla", "Lazarus Group", "FIN7"],
        "T1547.009": ["APT28", "APT29", "Turla"],
        "T1204.001": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "T1564.004": ["APT28", "APT29", "Turla"],
        "T1114.001": ["APT28", "APT29", "Turla", "OilRig", "Kimsuky"],
        "T1566": ["APT28", "APT29", "Lazarus Group", "FIN7", "Kimsuky"],
        "T1569.002": ["APT28", "APT29", "Lazarus Group", "FIN7"],
        "T1106": ["APT28", "APT29", "Turla", "Lazarus Group"],
    }

    def __init__(self, cache_dir: Optional[str] = None):
        """Initialize MITRE enrichment."""
        self.logger = logging.getLogger(__name__)
        self.updater = None
        self.mapper = None
        self.attck_data = None
        self.groups_by_technique = {}

        # Try to load ATT&CK data if modules are available
        if MITRE_AVAILABLE:
            try:
                self.updater = MitreAttackUpdater(cache_dir)
                self.mapper = TechniqueMapper(self.updater)
                self.attck_data = self.updater.load_cached_data()
                if self.attck_data:
                    self._build_groups_by_technique()
            except Exception as e:
                self.logger.warning(f"Could not load ATT&CK data: {e}")

    def _build_groups_by_technique(self):
        """Build mapping of technique IDs to threat groups from relationships."""
        if not self.attck_data:
            return

        relationships = self.attck_data.get("relationships", [])
        groups = self.attck_data.get("groups", {})
        techniques = self.attck_data.get("techniques", {})

        # Build STIX ID to technique ID mapping
        stix_to_tech = {}
        for tech_id, tech_data in techniques.items():
            stix_id = tech_data.get("stix_id")
            if stix_id:
                stix_to_tech[stix_id] = tech_id

        # Build STIX ID to group name mapping
        stix_to_group = {}
        for group_id, group_data in groups.items():
            stix_id = group_data.get("stix_id")
            if stix_id:
                stix_to_group[stix_id] = group_data.get("name", group_id)

        # Parse relationships to find group->technique "uses" relationships
        for rel in relationships:
            if rel.get("type") == "uses":
                source = rel.get("source")
                target = rel.get("target")

                # Check if source is a group and target is a technique
                if source in stix_to_group and target in stix_to_tech:
                    tech_id = stix_to_tech[target]
                    group_name = stix_to_group[source]

                    if tech_id not in self.groups_by_technique:
                        self.groups_by_technique[tech_id] = []

                    if group_name not in self.groups_by_technique[tech_id]:
                        self.groups_by_technique[tech_id].append(group_name)

        self.logger.info(f"Built groups mapping for {len(self.groups_by_technique)} techniques")

    def get_groups_for_technique(self, technique_id: str) -> List[str]:
        """Get threat groups known to use a technique."""
        # First try dynamic data from ATT&CK
        if technique_id in self.groups_by_technique:
            return self.groups_by_technique[technique_id]

        # Fall back to static mapping
        return self.TECHNIQUE_GROUPS.get(technique_id, [])

    def get_techniques_for_artefact(self, artefact_type: str) -> List[Dict]:
        """Get MITRE techniques associated with an artefact type."""
        # Normalize artefact type
        artefact_type = artefact_type.lower().replace(" ", "_")

        techniques = self.ARTEFACT_TECHNIQUES.get(artefact_type, [])

        # Enrich with groups
        enriched = []
        for tech in techniques:
            tech_copy = tech.copy()
            tech_copy["groups"] = self.get_groups_for_technique(tech["technique_id"])
            enriched.append(tech_copy)

        return enriched

    def enrich_json_record(self, record: Dict, artefact_type: str) -> Dict:
        """
        Add MITRE ATT&CK metadata to a JSON record.

        Uses content-based pattern matching to identify techniques, then embeds
        full ATT&CK metadata including:
        - Technique ID and Name
        - Tactics
        - CTI (Threat Groups and Software)
        - Procedure Examples

        Args:
            record: The JSON record to enrich
            artefact_type: Type of artefact (e.g., 'prefetch', 'browser_history')

        Returns:
            Enriched record with full MITRE metadata
        """
        # Not the artefact type's techniques: every memory image has a DLL list and a module
        # list, which isn't DLL hijacking or a rootkit. A record's techniques are what it shows
        all_technique_ids = set()
        if PATTERNS_AVAILABLE and scan_json_record:
            all_technique_ids.update(scan_json_record(scannable(record)))
        return self.apply_techniques(record, all_technique_ids)

    def apply_techniques(self, record: Dict, all_technique_ids: Set[str]) -> Dict:
        """``record`` with the ATT&CK fields for the techniques its content matched, which also
        join the envelope's ``techniques`` list when the record has one."""
        base_techniques = []
        if not all_technique_ids:
            return record

        if isinstance(record.get("techniques"), list):
            record["techniques"] = record["techniques"] + sorted(
                t for t in all_technique_ids if t not in record["techniques"])

        # 3. Build full enrichment data for all techniques
        if ATTACK_DATA_AVAILABLE and enrich_technique:
            # Get full metadata for primary technique (first from base or content)
            technique_ids = sorted(all_technique_ids)
            primary_id = technique_ids[0]
            primary_data = enrich_technique(primary_id)

            # Add primary technique fields
            record["mitre_technique_id"] = primary_data["mitre_technique_id"]
            record["mitre_technique_name"] = primary_data["mitre_technique_name"]
            record["mitre_tactics"] = primary_data["mitre_tactics"]
            record["mitre_description"] = primary_data["mitre_description"]
            record["mitre_groups"] = primary_data["mitre_groups"]
            record["mitre_software"] = primary_data["mitre_software"]
            record["mitre_procedure_examples"] = primary_data["mitre_procedure_examples"]

            # Add all techniques if more than one
            if len(technique_ids) > 1:
                record["mitre_techniques"] = [
                    enrich_technique(tid) for tid in technique_ids
                ]
        else:
            # Fallback to basic enrichment without full ATT&CK data
            if base_techniques:
                primary = base_techniques[0]
                record["mitre_technique_id"] = primary["technique_id"]
                record["mitre_technique_name"] = primary["technique_name"]
                record["mitre_tactics"] = primary["tactics"]
                record["mitre_groups"] = primary.get("groups", [])

                if len(base_techniques) > 1:
                    record["mitre_techniques"] = base_techniques

        return record

    def enrich_json_file_streaming(self, filepath: str, techniques_file: TextIO, artefact_type: Optional[str] = None) -> bool:
        """
        Enrich a JSON artefact file with MITRE metadata using streaming approach.

        Uses content-based pattern matching to identify techniques from the actual
        artefact content, ensuring consistent results independent of SIEM platform.

        Writes discovered techniques directly to the techniques file to avoid
        keeping them in memory. Processes files line-by-line for large files.

        Args:
            filepath: Path to JSON file
            techniques_file: Open file handle to write techniques to
            artefact_type: Type of artefact (auto-detected if not provided)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check file size - skip empty files
            file_size = os.path.getsize(filepath)
            if file_size == 0:
                return True

            # Auto-detect artefact type from filename if not provided
            if not artefact_type:
                artefact_type = self._detect_artefact_type(filepath)

            if filepath.lower().endswith(".jsonl"):
                return self._enrich_jsonl(filepath, techniques_file, artefact_type, file_size)

            # The artefact type's own techniques aren't recorded: its being there shows nothing
            # (see enrich_json_record); only what the content matches is
            base_techniques = set()

            # For large files (>10MB), use streaming content scanning
            if file_size > LARGE_FILE_BYTES:
                # Write base techniques
                for tech_id in base_techniques:
                    techniques_file.write(f"{tech_id}\n")

                # Stream through file to find patterns without loading all into memory
                if PATTERNS_AVAILABLE:
                    try:
                        with open(filepath, 'r') as f:
                            # Read in chunks and scan for patterns
                            chunk_size = 1024 * 1024  # 1MB chunks
                            while True:
                                chunk = f.read(chunk_size)
                                if not chunk:
                                    break
                                chunk_techniques = get_pattern_matcher().match_content(chunk)
                                for tech_id in chunk_techniques:
                                    techniques_file.write(f"{tech_id}\n")
                    except Exception as e:
                        self.logger.warning(f"Error streaming large file {filepath}: {e}")

                techniques_file.flush()
                return self._enrich_large_file(filepath, artefact_type)

            # For smaller files, use content-based pattern matching
            with open(filepath, 'r') as f:
                content = f.read().strip()

            if not content:
                return True

            # Parse JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Try to scan raw content even if JSON is invalid
                if PATTERNS_AVAILABLE:
                    content_techniques = get_pattern_matcher().match_content(content)
                    for tech_id in content_techniques:
                        techniques_file.write(f"{tech_id}\n")
                    techniques_file.flush()
                return True

            del content
            gc.collect()

            if isinstance(data, list) and len(data) == 0:
                return True

            # Collect all techniques from content-based scanning
            all_techniques = set(base_techniques)

            # Use content-based pattern matching if available
            if PATTERNS_AVAILABLE:
                if isinstance(data, list):
                    # Scan ALL records for comprehensive technique detection
                    # This is critical for consistent Navigator results
                    for record in data:
                        if isinstance(record, dict):
                            record_techniques = scan_json_record(record)
                            all_techniques.update(record_techniques)
                elif isinstance(data, dict):
                    record_techniques = scan_json_record(data)
                    all_techniques.update(record_techniques)

            # Write all discovered techniques to file
            for tech_id in all_techniques:
                techniques_file.write(f"{tech_id}\n")
            techniques_file.flush()

            # Enrich records with MITRE metadata (using artefact type for primary technique)
            if artefact_type:
                if isinstance(data, list):
                    enriched = []
                    for record in data:
                        if isinstance(record, dict):
                            enriched.append(self.enrich_json_record(record, artefact_type))
                    del data
                    gc.collect()
                else:
                    enriched = self.enrich_json_record(data, artefact_type)
                    del data
                    gc.collect()

                # Write back
                with open(filepath, 'w') as f:
                    json.dump(enriched, f, indent=2)

                del enriched
                gc.collect()

            return True

        except json.JSONDecodeError:
            return True  # Skip invalid JSON
        except MemoryError:
            self.logger.warning(f"Memory error processing {filepath}, techniques still recorded")
            gc.collect()
            return True  # Techniques were already written
        except Exception as e:
            self.logger.error(f"Error enriching {filepath}: {e}")
            return False

    def _enrich_jsonl(self, filepath: str, techniques_file: TextIO, artefact_type: Optional[str],
                      file_size: int) -> bool:
        """Record a JSON Lines table's techniques (the envelope's and what each record's content
        matches) and, with an artefact type, rewrite it line by line with each matching record's
        ATT&CK fields, through a temporary file so a failure leaves the table as it was. A large
        table's lines are matched as text first and only the candidates decoded."""
        if file_size > LARGE_FILE_BYTES:
            found = self._enrich_large_jsonl(filepath, artefact_type)
            for tech_id in sorted(found):
                techniques_file.write(f"{tech_id}\n")
            techniques_file.flush()
            return True

        found: Set[str] = set()
        building = f"{filepath}.enriching"
        out = open(building, "w", encoding="utf-8") if artefact_type else None
        changed = False
        try:
            with open(filepath, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        record = json.loads(line) if line.strip() else None
                    except ValueError:
                        record = None
                    if not isinstance(record, dict):
                        if out is not None:
                            out.write(line)  # blank or broken lines are kept as they are
                        continue
                    found.update(record_technique_ids(record))
                    matched = set()
                    if PATTERNS_AVAILABLE and scan_json_record:
                        matched = scan_json_record(scannable(record))
                    found.update(matched)
                    if out is None:
                        continue
                    if matched:
                        record = self.apply_techniques(record, matched)
                        out.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                        changed = True
                    else:
                        out.write(line if line.endswith("\n") else line + "\n")
        except BaseException:
            if out is not None:
                out.close()
                os.remove(building)
            raise
        if out is not None:
            out.close()
            if changed:
                os.replace(building, filepath)
            else:
                os.remove(building)

        for tech_id in sorted(found):
            techniques_file.write(f"{tech_id}\n")
        techniques_file.flush()
        return True

    def _enrich_large_jsonl(self, filepath: str, artefact_type: Optional[str],
                            chunk: int = 1 << 20) -> Set[str]:
        """A large JSON Lines table's techniques, each from a record it tags: the envelope's, and
        what the records' own fields match. Every pattern runs once over a megabyte of lines as
        text (decoding an MFT's millions of lines would take longer than the run); only the lines
        a match falls in are decoded and scanned as records. Those that match are rewritten with
        their ATT&CK fields when there's an artefact type; a table nothing matched isn't
        rewritten at all."""
        found: Set[str] = set()
        tags: Dict[int, Set[str]] = {}
        matcher = get_pattern_matcher() if PATTERNS_AVAILABLE else None
        lines: List[str] = []
        texts: List[str] = []
        first = size = 0

        def flush() -> None:
            if matcher is None or not lines:
                return
            starts, offset = [], 0
            for text in texts:
                starts.append(offset)
                offset += len(text)
            for index in sorted({bisect.bisect_right(starts, pos) - 1
                                 for pos in matcher.match_positions("".join(texts))}):
                try:
                    record = json.loads(lines[index])
                except ValueError:
                    continue
                if isinstance(record, dict):
                    matched = scan_json_record(scannable(record))
                    if matched:
                        tags[first + index] = matched
                        found.update(matched)

        with open(filepath, encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh):
                split = _split_envelope(line)
                text = line
                if split is not None:
                    techniques, text = split
                    found.update(techniques)
                # Matched as the decoded values would be: JSON doubles backslashes and escapes quotes
                lines.append(line)
                texts.append(text.replace("\\\\", "\\").replace('\\"', '"'))
                size += len(texts[-1])
                if size >= chunk:
                    flush()
                    first, size, lines, texts = number + 1, 0, [], []
        flush()

        if tags and artefact_type:
            self._tag_lines(filepath, tags)
        return found

    def _tag_lines(self, filepath: str, tags: Dict[int, Set[str]]) -> None:
        """Rewrite ``filepath`` with the ATT&CK fields on the lines ``tags`` names (by number),
        every other line byte for byte, through a temporary file."""
        building = f"{filepath}.enriching"
        try:
            with open(filepath, encoding="utf-8", errors="replace") as fh, \
                    open(building, "w", encoding="utf-8") as out:
                for number, line in enumerate(fh):
                    matched = tags.get(number)
                    if matched:
                        record = self.apply_techniques(json.loads(line), matched)
                        out.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                    else:
                        out.write(line if line.endswith("\n") else line + "\n")
        except BaseException:
            if os.path.exists(building):
                os.remove(building)
            raise
        os.replace(building, filepath)

    def _enrich_large_file(self, filepath: str, artefact_type: str) -> bool:
        """
        Enrich a large JSON file - for large files, skip JSON modification
        to avoid memory issues. Techniques are already recorded to the
        techniques file before this method is called.

        For very large files (like MFT, USNJrnl, event logs), we skip
        in-place enrichment to avoid memory/performance issues. The
        Navigator layer will still work because techniques were already
        written to the techniques file.
        """
        # For large files, just skip the JSON modification
        # The techniques have already been recorded to the techniques file
        # in enrich_json_file_streaming() before this method is called
        self.logger.info(f"Skipping in-place enrichment for large file: {filepath}")
        return True

    def _detect_artefact_type(self, filepath: str) -> Optional[str]:
        """Detect artefact type from file path."""
        path_lower = filepath.lower()

        # Check directory names and file names
        if "prefetch" in path_lower:
            return "prefetch"
        elif "browser" in path_lower:
            if "download" in path_lower:
                return "browser_download"
            return "browser_history"
        elif "shellbags" in path_lower:
            return "shellbags"
        elif "userassist" in path_lower:
            return "userassist"
        elif "tasks" in path_lower or "scheduled" in path_lower:
            return "tasks"
        elif "services" in path_lower:
            return "services"
        elif "wbem" in path_lower or "wmi" in path_lower:
            return "wbem"
        elif "shimcache" in path_lower:
            return "shimcache"
        elif "amcache" in path_lower:
            return "amcache"
        elif "bits" in path_lower:
            return "bits"
        elif "evtx" in path_lower or "eventlog" in path_lower:
            return "eventlogs"
        elif "srum" in path_lower:
            return "srum"
        elif "jumplist" in path_lower:
            return "jumplists"
        elif "recycle" in path_lower:
            return "recyclebin"
        elif "shortcut" in path_lower or ".lnk" in path_lower:
            return "shortcuts"
        elif "mft" in path_lower or "$mft" in path_lower:
            return "mft"
        elif "usnjrnl" in path_lower or "$usn" in path_lower:
            return "usnjrnl"
        elif "outlook" in path_lower or ".pst" in path_lower or ".ost" in path_lower:
            return "outlook"
        elif "registry" in path_lower:
            return "registry"

        return None

    def collect_techniques_from_directory(self, directory: str) -> Set[str]:
        """
        Scan a directory of JSON files and collect all MITRE technique IDs found.

        Args:
            directory: Path to directory containing JSON files

        Returns:
            Set of technique IDs found
        """
        techniques = set()

        for root, dirs, files in os.walk(directory):
            for filename in files:
                if filename.endswith('.jsonl') and read_records is not None:
                    try:
                        for _, record in read_records(os.path.join(root, filename)):
                            techniques.update(record_technique_ids(record))
                    except (OSError, ValueError):
                        pass
                elif filename.endswith('.json'):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)

                        for record in data if isinstance(data, list) else [data]:
                            if isinstance(record, dict):
                                techniques.update(record_technique_ids(record))
                    except:
                        pass

        return techniques


def enrich_artefacts_directory(directory: str) -> Dict:
    """
    Enrich all JSON artefact files in a directory with MITRE metadata.

    This function is memory-optimized:
    - Writes techniques to a file as they're discovered (no memory accumulation)
    - Uses streaming for large files (>10MB) to avoid loading into memory
    - Processes ALL files regardless of size
    - Uses gc.collect() to free memory between files

    The techniques file (mitre_techniques.txt) is created in the parent directory
    of the cooked folder and can be used to construct the Navigator layer.

    Args:
        directory: Path to directory containing JSON files

    Returns:
        Statistics dictionary
    """
    enrichment = MitreEnrichment()

    stats = {
        "total_files": 0,
        "enriched_files": 0,
        "failed_files": 0,
        "techniques_file": None,
    }

    # Count total files first for progress reporting
    json_files = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(TABLE_SUFFIXES) and not filename.startswith("._"):
                json_files.append(os.path.join(root, filename))

    total_json_files = len(json_files)
    if total_json_files > 0:
        print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> MITRE tagging: found {total_json_files} JSON and JSON Lines files to process (this may take several minutes)...")

    # Determine where to write the techniques file
    # Go up from 'cooked' to the image directory
    parent_dir = os.path.dirname(directory.rstrip('/'))
    techniques_filepath = os.path.join(parent_dir, TECHNIQUES_FILE)
    stats["techniques_file"] = techniques_filepath

    # Open techniques file for writing (append mode in case of retries)
    with open(techniques_filepath, 'w') as techniques_file:
        # Process all JSON files
        for filepath in json_files:
            filename = os.path.basename(filepath)
            stats["total_files"] += 1

            # Use streaming method that writes techniques directly to file
            if enrichment.enrich_json_file_streaming(filepath, techniques_file):
                stats["enriched_files"] += 1
            else:
                stats["failed_files"] += 1

            # Progress reporting every 100 files or at milestones
            processed = stats["total_files"]
            if processed % 100 == 0 or processed == total_json_files:
                pct = int((processed / total_json_files) * 100) if total_json_files > 0 else 100
                print(f" -> {datetime.now().isoformat().replace('T', ' ')} -> MITRE tagging progress: {processed}/{total_json_files} files ({pct}%)")

            # Periodic garbage collection every 50 files
            if stats["total_files"] % 50 == 0:
                gc.collect()

    # Read techniques file to get unique count
    try:
        with open(techniques_filepath, 'r') as f:
            techniques = set(line.strip() for line in f if line.strip())
        stats["technique_count"] = len(techniques)
        stats["techniques_found"] = techniques

        # Rewrite file with unique techniques only
        with open(techniques_filepath, 'w') as f:
            for tech_id in sorted(techniques):
                f.write(f"{tech_id}\n")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading techniques file: {e}")
        stats["technique_count"] = 0
        stats["techniques_found"] = set()

    # Final garbage collection
    gc.collect()

    return stats


def get_techniques_from_file(directory: str) -> Set[str]:
    """
    Read techniques from the techniques file created during enrichment.

    Args:
        directory: Path to the cooked directory or its parent

    Returns:
        Set of technique IDs
    """
    # Try different possible locations
    possible_paths = [
        os.path.join(directory, TECHNIQUES_FILE),
        os.path.join(os.path.dirname(directory.rstrip('/')), TECHNIQUES_FILE),
        os.path.join(directory, 'artefacts', TECHNIQUES_FILE),
    ]

    for filepath in possible_paths:
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    return set(line.strip() for line in f if line.strip())
            except Exception:
                pass

    return set()

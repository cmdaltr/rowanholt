#!/usr/bin/env python3
"""
MITRE ATT&CK Integration for Elrond Analysis Pipeline

Bridges the new MITRE module with the existing Elrond analysis pipeline.
Provides automatic technique mapping and dashboard generation.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict

# Import new MITRE modules
from analysis.mitre import MitreAttackUpdater, TechniqueMapper, MitreDashboardGenerator


class ElrondMitreIntegration:
    """
    Integration layer between Elrond analysis and MITRE ATT&CK module.

    Features:
    - Automatic artifact-to-technique mapping during analysis
    - MITRE coverage dashboard generation
    - Legacy compatibility with existing Elrond pipeline
    - Export to Splunk, Elastic, and Navigator formats
    """

    def __init__(self, output_dir: str = "/tmp/dernvale/mitre", auto_update: bool = True):
        """
        Initialize MITRE integration.

        Args:
            output_dir: Output directory for dashboards and exports
            auto_update: Auto-update ATT&CK data on startup
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(__name__)

        # Initialize MITRE components
        self.updater = MitreAttackUpdater()
        self.mapper = TechniqueMapper(self.updater)
        self.generator = MitreDashboardGenerator(self.updater)

        # Update ATT&CK data if needed
        if auto_update:
            self.updater.update_local_cache()

        # Track mapped techniques during analysis
        self.technique_mappings: List[dict] = []

    def map_artifact(
        self,
        artifact_type: str,
        artifact_data: Optional[dict] = None,
        context: Optional[str] = None,
    ) -> List[dict]:
        """
        Map a single artifact to MITRE ATT&CK techniques.

        Args:
            artifact_type: Type of artifact (e.g., 'prefetch', 'powershell_history')
            artifact_data: Optional artifact metadata
            context: Optional context (command line, file content, etc.)

        Returns:
            List of technique mappings with confidence scores
        """
        techniques = self.mapper.map_artifact_to_techniques(
            artifact_type=artifact_type, artifact_data=artifact_data, context=context
        )

        # Store for dashboard generation
        self.technique_mappings.extend(techniques)

        return techniques

    def map_artifacts_batch(self, artifacts: List[Dict[str, any]]) -> List[dict]:
        """
        Map multiple artifacts to techniques in batch.

        Args:
            artifacts: List of artifact dictionaries with keys:
                - type: Artifact type
                - data: Optional artifact data
                - context: Optional context

        Returns:
            List of all technique mappings
        """
        all_techniques = []

        for artifact in artifacts:
            techniques = self.map_artifact(
                artifact_type=artifact.get("type"),
                artifact_data=artifact.get("data"),
                context=artifact.get("context"),
            )
            all_techniques.extend(techniques)

        return all_techniques

    def generate_dashboards(self, case_name: str, formats: List[str] = None) -> dict:
        """
        Generate MITRE coverage dashboards for current analysis.

        Args:
            case_name: Case/investigation name
            formats: List of formats to generate (default: all)

        Returns:
            Dictionary with dashboard file paths
        """
        if not self.technique_mappings:
            self.logger.warning("No technique mappings available for dashboard generation")
            return {}

        # Create case-specific output directory
        case_output = self.output_dir / case_name
        case_output.mkdir(parents=True, exist_ok=True)

        # Generate dashboards
        result = self.generator.save_dashboards(
            technique_mappings=self.technique_mappings, output_dir=str(case_output), formats=formats
        )

        self.logger.info(f"Dashboards generated for case '{case_name}' in {case_output}")

        return result

    def export_to_legacy_format(self, case_name: str, output_file: Optional[str] = None) -> str:
        """
        Export technique mappings in legacy Elrond format.

        This ensures backward compatibility with existing Elrond output formats.

        Args:
            case_name: Case/investigation name
            output_file: Optional output file path

        Returns:
            Path to exported file
        """
        if not output_file:
            output_file = str(self.output_dir / f"{case_name}_mitre_mappings.json")

        # Convert to legacy format
        legacy_data = {
            "case": case_name,
            "timestamp": self.updater.load_cached_data().get("last_updated", "unknown"),
            "attck_version": self.updater.load_cached_data().get("version", "unknown"),
            "techniques": [],
        }

        # Deduplicate techniques
        unique_techniques = {}
        for mapping in self.technique_mappings:
            tech_id = mapping["id"]
            if (
                tech_id not in unique_techniques
                or mapping["confidence"] > unique_techniques[tech_id]["confidence"]
            ):
                unique_techniques[tech_id] = mapping

        # Convert to legacy format
        for tech_id, mapping in unique_techniques.items():
            legacy_data["techniques"].append(
                {
                    "id": tech_id,
                    "name": mapping.get("name", "Unknown"),
                    "tactics": mapping.get("tactics", []),
                    "confidence": mapping.get("confidence", 0.0),
                    "evidence": mapping.get("evidence", {}),
                }
            )

        # Sort by confidence
        legacy_data["techniques"].sort(key=lambda x: x["confidence"], reverse=True)

        # Write to file
        with open(output_file, "w") as f:
            json.dump(legacy_data, f, indent=2)

        self.logger.info(f"Legacy format export saved to {output_file}")

        return output_file

    def get_techniques_for_splunk(self) -> List[str]:
        """
        Get list of technique IDs for Splunk indexing.

        Returns:
            List of unique technique IDs
        """
        techniques = set()
        for mapping in self.technique_mappings:
            techniques.add(mapping["id"])

        return sorted(list(techniques))

    def get_techniques_for_elastic(self) -> List[dict]:
        """
        Get technique data formatted for Elasticsearch.

        Returns:
            List of technique documents for ES indexing
        """
        documents = []

        # Deduplicate and prepare for ES
        unique_techniques = {}
        for mapping in self.technique_mappings:
            tech_id = mapping["id"]
            if (
                tech_id not in unique_techniques
                or mapping["confidence"] > unique_techniques[tech_id]["confidence"]
            ):
                unique_techniques[tech_id] = mapping

        for tech_id, mapping in unique_techniques.items():
            documents.append(
                {
                    "mitre_technique_id": tech_id,
                    "mitre_technique_name": mapping.get("name", "Unknown"),
                    "mitre_tactics": mapping.get("tactics", []),
                    "mitre_confidence": mapping.get("confidence", 0.0),
                    "mitre_evidence": mapping.get("evidence", {}),
                    "@timestamp": self.updater.load_cached_data().get("last_updated", "unknown"),
                }
            )

        return documents

    def get_coverage_statistics(self) -> dict:
        """
        Get MITRE coverage statistics.

        Returns:
            Dictionary with coverage statistics
        """
        if not self.technique_mappings:
            return {
                "total_techniques": 0,
                "detected_techniques": 0,
                "coverage_percentage": 0.0,
                "confidence_distribution": {"high": 0, "medium": 0, "low": 0},
            }

        # Calculate coverage
        coverage = self.generator._calculate_coverage(self.technique_mappings)

        return coverage["statistics"]

    def reset(self):
        """Reset technique mappings for new analysis."""
        self.technique_mappings = []

    def update_attck_data(self, force: bool = False) -> bool:
        """
        Update ATT&CK framework data.

        Args:
            force: Force update even if cache is fresh

        Returns:
            True if update was successful
        """
        return self.updater.update_local_cache(force=force)


# Convenience functions for backward compatibility with existing Elrond code


def configure_navigator_v2(
    case_name: str, technique_mappings: List[dict], output_dir: str = "/tmp/dernvale/mitre"
) -> str:
    """
    Replacement for the legacy configure_navigator function.

    This provides the same functionality as the old function but uses
    the new MITRE module internally.

    Args:
        case_name: Case/investigation name
        technique_mappings: List of technique mappings
        output_dir: Output directory for dashboards

    Returns:
        Status string ("-" if successful, "" if no techniques)
    """
    if not technique_mappings:
        print("     No evidence of MITRE ATT&CK® techniques could be identified.")
        return ""

    integration = ElrondMitreIntegration(output_dir=output_dir)
    integration.technique_mappings = technique_mappings

    # Generate dashboards
    result = integration.generate_dashboards(case_name, formats=["navigator"])

    if "navigator" in result:
        print(f"     ATT&CK Navigator built for '{case_name}'")
        print(f"     Navigator file: {result['navigator']}")
        return "-"
    else:
        print("     Failed to generate ATT&CK Navigator")
        return ""


def extract_techniques_from_artifacts(
    artifacts: List[Dict[str, any]], output_dir: str = "/tmp/dernvale/mitre"
) -> List[dict]:
    """
    Extract MITRE techniques from collected artifacts.

    This is a convenience function for the Elrond pipeline to automatically
    map artifacts to techniques during analysis.

    Args:
        artifacts: List of artifact dictionaries with keys:
            - type: Artifact type (e.g., 'prefetch', 'powershell_history')
            - path: File path
            - data: Optional artifact metadata
            - context: Optional context (command line, etc.)
        output_dir: Output directory

    Returns:
        List of technique mappings
    """
    integration = ElrondMitreIntegration(output_dir=output_dir)

    return integration.map_artifacts_batch(artifacts)


# Example artifact type mappings for Elrond collectors
ELROND_ARTIFACT_TYPE_MAP = {
    # Windows artifacts
    "Prefetch": "prefetch",
    "PowerShell_History": "powershell_history",
    "CMD_History": "cmd_history",
    "WMI_Consumers": "wmi_consumers",
    "Scheduled_Tasks": "scheduled_tasks",
    "Registry_Run_Keys": "registry_run_keys",
    "Services": "services",
    "LSASS_Dump": "lsass_dump",
    "SAM_Dump": "sam_dump",
    "Browser_Data": "browser_data",
    # Linux artifacts
    "Bash_History": "bash_history",
    "Cron_Jobs": "cron_jobs",
    "Systemd_Services": "systemd_services",
    "SSH_Keys": "ssh_authorized_keys",
    # macOS artifacts
    "Launch_Agents": "launch_agents",
    "Launch_Daemons": "launch_daemons",
    "Login_Items": "login_items",
    "Plist_Files": "plist_files",
    # Network artifacts
    "Network_Connections": "network_connections",
    "DNS_Queries": "dns_queries",
    # Generic
    "File_Creation": "file_creation",
    "Registry_Modification": "registry_modification",
}


def normalize_artifact_type(elrond_type: str) -> str:
    """
    Convert Elrond artifact type to MITRE mapper artifact type.

    Args:
        elrond_type: Artifact type from Elrond collector

    Returns:
        Normalized artifact type for MITRE mapper
    """
    return ELROND_ARTIFACT_TYPE_MAP.get(elrond_type, elrond_type.lower())

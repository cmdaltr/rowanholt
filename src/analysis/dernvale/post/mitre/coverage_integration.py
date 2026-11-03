#!/usr/bin/env python3
"""
Elrond Pipeline Integration for MITRE Coverage Analysis

Provides hooks for real-time coverage analysis during artifact processing.
Integrates seamlessly with existing Elrond workflow.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import logging
from pathlib import Path
from typing import Optional, Dict, List, Any

from analysis.mitre.coverage_analyzer import MitreCoverageAnalyzer
from analysis.mitre.standalone_dashboard import generate_standalone_dashboard


class ElrondCoverageHook:
    """
    Coverage analysis hook for Elrond processing pipeline.

    Usage in Elrond processors:
        # Initialize at start of processing
        coverage_hook = ElrondCoverageHook(case_id, output_dir)

        # Call for each processed artifact
        coverage_hook.process_artifact(artifact_type, artifact_path, data, context)

        # Finalize at end of processing
        coverage_hook.finalize()
    """

    def __init__(
        self,
        case_id: str,
        output_dir: str,
        enabled: bool = True,
        auto_dashboard: bool = True,
        auto_export: bool = True,
    ):
        """
        Initialize coverage hook.

        Args:
            case_id: Case/investigation identifier
            output_dir: Output directory for reports
            enabled: Enable coverage analysis
            auto_dashboard: Auto-generate dashboard on finalize
            auto_export: Auto-export all formats on finalize
        """
        self.case_id = case_id
        self.output_dir = output_dir
        self.enabled = enabled
        self.auto_dashboard = auto_dashboard
        self.auto_export = auto_export

        self.logger = logging.getLogger(__name__)

        # Initialize analyzer if enabled
        self.analyzer = None
        if self.enabled:
            try:
                self.analyzer = MitreCoverageAnalyzer(case_id, output_dir, auto_update=True)
                self.logger.info(f"Coverage analysis enabled for case: {case_id}")
            except Exception as e:
                self.logger.error(f"Failed to initialize coverage analyzer: {e}")
                self.enabled = False

    def process_artifact(
        self,
        artifact_type: str,
        artifact_path: str,
        artifact_data: Optional[Dict[str, Any]] = None,
        context: Optional[str] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Process artifact for MITRE coverage.

        Call this from Elrond artifact processors after parsing.

        Args:
            artifact_type: Type of artifact
            artifact_path: Path to artifact
            artifact_data: Optional parsed data
            context: Optional context (command line, etc.)

        Returns:
            List of detected techniques (or None if disabled/error)
        """
        if not self.enabled or not self.analyzer:
            return None

        try:
            detections = self.analyzer.analyze_artifact(
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                artifact_data=artifact_data,
                context=context,
            )

            if detections:
                self.logger.debug(
                    f"Detected {len(detections)} technique(s) in {artifact_type}: {artifact_path}"
                )

            return [d.to_dict() for d in detections]

        except Exception as e:
            self.logger.error(f"Error analyzing artifact {artifact_path}: {e}")
            return None

    def finalize(self) -> Optional[Dict[str, Any]]:
        """
        Finalize coverage analysis and generate reports.

        Call this at end of Elrond processing pipeline.

        Returns:
            Coverage report summary (or None if disabled/error)
        """
        if not self.enabled or not self.analyzer:
            return None

        try:
            self.logger.info("Finalizing MITRE coverage analysis...")

            # Generate coverage report
            report = self.analyzer.generate_coverage_report()

            stats = report["statistics"]
            self.logger.info(
                f"Coverage: {stats['coverage_percentage']:.1f}% "
                f"({stats['detected_techniques']}/{stats['total_techniques']} techniques)"
            )

            # Auto-export if enabled
            if self.auto_export:
                self._auto_export()

            # Auto-generate dashboard if enabled
            if self.auto_dashboard:
                self._auto_dashboard(report)

            # Close analyzer
            self.analyzer.close()

            return {
                "case_id": self.case_id,
                "coverage_percentage": stats["coverage_percentage"],
                "detected_techniques": stats["detected_techniques"],
                "total_artifacts": stats["total_artifacts"],
                "high_confidence": stats["confidence_distribution"]["high"],
                "reports_generated": True,
            }

        except Exception as e:
            self.logger.error(f"Error finalizing coverage analysis: {e}")
            return None

    def _auto_export(self):
        """Auto-export coverage data in all formats."""
        try:
            # Export JSON
            json_path = self.analyzer.export_json()
            self.logger.info(f"Exported JSON: {json_path}")

            # Export CSV
            csv_paths = self.analyzer.export_csv()
            self.logger.info(f"Exported CSV: {len(csv_paths)} files")

            # Export SIEM formats
            splunk_events = self.analyzer.export_for_siem("splunk")
            splunk_path = Path(self.analyzer.mitre_dir) / "splunk_events.json"
            with open(splunk_path, "w") as f:
                import json

                json.dump(splunk_events, f, indent=2)
            self.logger.info(f"Exported Splunk HEC events: {splunk_path}")

            elastic_docs = self.analyzer.export_for_siem("elastic")
            elastic_path = Path(self.analyzer.mitre_dir) / "elastic_docs.json"
            with open(elastic_path, "w") as f:
                import json

                json.dump(elastic_docs, f, indent=2)
            self.logger.info(f"Exported Elasticsearch docs: {elastic_path}")

        except Exception as e:
            self.logger.error(f"Error auto-exporting: {e}")

    def _auto_dashboard(self, report: Dict[str, Any]):
        """Auto-generate standalone dashboard."""
        try:
            dashboard_path = str(Path(self.analyzer.mitre_dir) / "coverage.html")
            generate_standalone_dashboard(report, dashboard_path)
            self.logger.info(f"Generated dashboard: {dashboard_path}")
            self.logger.info(f"Open in browser: file://{Path(dashboard_path).absolute()}")

        except Exception as e:
            self.logger.error(f"Error generating dashboard: {e}")

    def get_statistics(self) -> Optional[Dict[str, Any]]:
        """
        Get current coverage statistics.

        Returns:
            Statistics dictionary (or None if disabled/error)
        """
        if not self.enabled or not self.analyzer:
            return None

        try:
            return self.analyzer.db.get_statistics()
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return None


# Artifact type mapping (Elrond artifact names -> MITRE mapper names)
ELROND_TO_MITRE_TYPES = {
    # Windows
    "Prefetch": "prefetch",
    "PowerShell History": "powershell_history",
    "PowerShell_History": "powershell_history",
    "CMD History": "cmd_history",
    "CMD_History": "cmd_history",
    "WMI Consumers": "wmi_consumers",
    "WMI_Consumers": "wmi_consumers",
    "Scheduled Tasks": "scheduled_tasks",
    "Scheduled_Tasks": "scheduled_tasks",
    "Registry Run Keys": "registry_run_keys",
    "Registry_Run_Keys": "registry_run_keys",
    "Services": "services",
    "LSASS Dump": "lsass_dump",
    "LSASS_Dump": "lsass_dump",
    "SAM Dump": "sam_dump",
    "SAM_Dump": "sam_dump",
    "Browser Data": "browser_data",
    "Browser_Data": "browser_data",
    "Registry Modification": "registry_modification",
    "Registry_Modification": "registry_modification",
    # Linux
    "Bash History": "bash_history",
    "Bash_History": "bash_history",
    "Cron Jobs": "cron_jobs",
    "Cron_Jobs": "cron_jobs",
    "Systemd Services": "systemd_services",
    "Systemd_Services": "systemd_services",
    "SSH Keys": "ssh_authorized_keys",
    "SSH_Keys": "ssh_authorized_keys",
    # macOS
    "Launch Agents": "launch_agents",
    "Launch_Agents": "launch_agents",
    "Launch Daemons": "launch_daemons",
    "Launch_Daemons": "launch_daemons",
    "Login Items": "login_items",
    "Login_Items": "login_items",
    "Plist Files": "plist_files",
    "Plist_Files": "plist_files",
    # Network
    "Network Connections": "network_connections",
    "Network_Connections": "network_connections",
    "DNS Queries": "dns_queries",
    "DNS_Queries": "dns_queries",
}


def normalize_artifact_type(elrond_type: str) -> str:
    """
    Convert Elrond artifact type to MITRE mapper type.

    Args:
        elrond_type: Artifact type from Elrond

    Returns:
        Normalized MITRE artifact type
    """
    return ELROND_TO_MITRE_TYPES.get(elrond_type, elrond_type.lower().replace(" ", "_"))


# Integration example for Elrond processors


def example_processor_integration():
    """
    Example of how to integrate coverage hook into Elrond processor.

    This shows the recommended pattern for adding coverage analysis
    to existing Elrond artifact processors.
    """

    # In processor __init__:
    class ExampleProcessor:
        def __init__(self, case_id, output_dir, enable_coverage=True):
            self.case_id = case_id
            self.output_dir = output_dir

            # Initialize coverage hook
            self.coverage = ElrondCoverageHook(
                case_id=case_id,
                output_dir=output_dir,
                enabled=enable_coverage,
                auto_dashboard=True,
                auto_export=True,
            )

        def process_artifact(self, artifact_type, artifact_path):
            """Process a single artifact."""
            # Existing artifact processing logic
            data = self.parse_artifact(artifact_type, artifact_path)

            # Extract any relevant context
            context = self.extract_context(data)

            # NEW: Coverage analysis hook
            self.coverage.process_artifact(
                artifact_type=normalize_artifact_type(artifact_type),
                artifact_path=artifact_path,
                artifact_data=data,
                context=context,
            )

            # Continue with existing processing
            self.save_processed_data(data)

        def parse_artifact(self, artifact_type, artifact_path):
            """Parse artifact (existing logic)."""
            # ... existing parsing code ...
            return {}

        def extract_context(self, data):
            """Extract context from parsed data."""
            # For PowerShell: command line
            # For Prefetch: executable name
            # For Registry: key path
            # etc.
            return data.get("context", None)

        def save_processed_data(self, data):
            """Save processed data (existing logic)."""
            pass

        def finalize(self):
            """Finalize processing."""
            # Existing finalization logic
            # ...

            # NEW: Finalize coverage analysis
            coverage_summary = self.coverage.finalize()

            if coverage_summary:
                print(f"MITRE Coverage: {coverage_summary['coverage_percentage']:.1f}%")
                print(f"Techniques detected: {coverage_summary['detected_techniques']}")


# Convenience function for quick integration


def analyze_with_coverage(
    case_id: str, output_dir: str, artifacts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function for batch coverage analysis.

    Args:
        case_id: Case identifier
        output_dir: Output directory
        artifacts: List of artifacts with keys:
            - type: Artifact type
            - path: Artifact path
            - data: Optional parsed data
            - context: Optional context

    Returns:
        Coverage summary
    """
    hook = ElrondCoverageHook(case_id, output_dir)

    for artifact in artifacts:
        hook.process_artifact(
            artifact_type=normalize_artifact_type(artifact["type"]),
            artifact_path=artifact["path"],
            artifact_data=artifact.get("data"),
            context=artifact.get("context"),
        )

    return hook.finalize()

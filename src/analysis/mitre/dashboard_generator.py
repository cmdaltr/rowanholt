"""
MITRE ATT&CK Dashboard Generator

Generates dashboards and visualizations for MITRE ATT&CK coverage.
Supports Splunk, Elasticsearch/Kibana, and ATT&CK Navigator formats.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import json
import logging
from typing import Dict, List, Optional, Set
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from .attck_updater import MitreAttackUpdater
from .technique_mapper import TechniqueMapper


class MitreDashboardGenerator:
    """
    Generate MITRE ATT&CK coverage dashboards.

    Features:
    - Splunk dashboard XML generation
    - Elasticsearch/Kibana dashboard JSON
    - ATT&CK Navigator layer generation
    - Coverage heatmaps
    - Technique-to-evidence mapping
    - Tactic coverage statistics
    """

    def __init__(self, updater: Optional[MitreAttackUpdater] = None):
        """
        Initialize dashboard generator.

        Args:
            updater: MitreAttackUpdater instance (creates new if not provided)
        """
        self.updater = updater or MitreAttackUpdater()
        self.attck_data = self.updater.load_cached_data()

        if not self.attck_data:
            logging.warning("No ATT&CK data loaded, attempting to download...")
            if self.updater.update_local_cache(force=True):
                self.attck_data = self.updater.load_cached_data()

        self.logger = logging.getLogger(__name__)

    def generate_coverage_report(
        self, technique_mappings: List[dict], output_format: str = "all"
    ) -> dict:
        """
        Generate comprehensive coverage report.

        Args:
            technique_mappings: List of technique mappings from TechniqueMapper
            output_format: 'splunk', 'elastic', 'navigator', or 'all'

        Returns:
            Dictionary with generated dashboards and statistics
        """
        # Calculate coverage statistics
        coverage = self._calculate_coverage(technique_mappings)

        result = {
            "statistics": coverage["statistics"],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "attck_version": self.attck_data.get("version", "unknown"),
        }

        # Generate requested formats
        if output_format in ["splunk", "all"]:
            result["splunk_xml"] = self.generate_splunk_dashboard(technique_mappings, coverage)

        if output_format in ["elastic", "all"]:
            result["elastic_json"] = self.generate_elastic_dashboard(technique_mappings, coverage)

        if output_format in ["navigator", "all"]:
            result["navigator_json"] = self.generate_navigator_layer(technique_mappings, coverage)

        return result

    def _calculate_coverage(self, technique_mappings: List[dict]) -> dict:
        """
        Calculate ATT&CK coverage statistics.

        Args:
            technique_mappings: List of technique mappings

        Returns:
            Coverage statistics and metadata
        """
        # Get all technique IDs and their confidence scores
        techniques_detected = {}
        tactics_detected = defaultdict(set)

        for mapping in technique_mappings:
            tech_id = mapping["id"]
            confidence = mapping.get("confidence", 0.0)

            # Store highest confidence for each technique
            if tech_id not in techniques_detected or confidence > techniques_detected[tech_id]:
                techniques_detected[tech_id] = confidence

            # Track tactics
            for tactic in mapping.get("tactics", []):
                tactics_detected[tactic].add(tech_id)

        # Get total techniques from ATT&CK data
        all_techniques = self.attck_data.get("techniques", {})
        total_techniques = len(all_techniques)
        detected_techniques = len(techniques_detected)

        # Calculate tactic-level coverage
        all_tactics = self.attck_data.get("tactics", {})
        tactic_coverage = {}

        for tactic_id, tactic_data in all_tactics.items():
            tactic_name = tactic_data.get("name", tactic_id)
            # Count techniques for this tactic in ATT&CK data
            tactic_total = sum(
                1 for t in all_techniques.values() if tactic_name in t.get("tactics", [])
            )
            tactic_detected = len(tactics_detected.get(tactic_name, set()))

            if tactic_total > 0:
                tactic_coverage[tactic_name] = {
                    "detected": tactic_detected,
                    "total": tactic_total,
                    "percentage": (tactic_detected / tactic_total) * 100,
                    "techniques": list(tactics_detected.get(tactic_name, set())),
                }

        # Calculate confidence distribution
        confidence_ranges = {
            "high": sum(1 for c in techniques_detected.values() if c >= 0.8),
            "medium": sum(1 for c in techniques_detected.values() if 0.5 <= c < 0.8),
            "low": sum(1 for c in techniques_detected.values() if c < 0.5),
        }

        return {
            "statistics": {
                "total_techniques": total_techniques,
                "detected_techniques": detected_techniques,
                "coverage_percentage": (
                    (detected_techniques / total_techniques * 100) if total_techniques > 0 else 0
                ),
                "total_tactics": len(all_tactics),
                "tactics_with_coverage": len(
                    [t for t in tactic_coverage.values() if t["detected"] > 0]
                ),
                "confidence_distribution": confidence_ranges,
                "tactic_coverage": tactic_coverage,
            },
            "techniques": techniques_detected,
            "tactics": dict(tactics_detected),
        }

    def generate_splunk_dashboard(
        self, technique_mappings: List[dict], coverage: Optional[dict] = None
    ) -> str:
        """
        Generate Splunk dashboard XML.

        Args:
            technique_mappings: List of technique mappings
            coverage: Pre-calculated coverage (optional)

        Returns:
            Splunk dashboard XML as string
        """
        if coverage is None:
            coverage = self._calculate_coverage(technique_mappings)

        stats = coverage["statistics"]

        # Build Splunk XML dashboard
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<form version="1.1">
  <label>MITRE ATT&amp;CK Coverage - Dernvale</label>
  <description>ATT&amp;CK Framework Coverage Analysis (v{self.attck_data.get('version', 'unknown')})</description>

  <!-- Overall Coverage Statistics -->
  <row>
    <panel>
      <single>
        <title>Overall Coverage</title>
        <search>
          <query>| makeresults | eval coverage="{stats['coverage_percentage']:.1f}%", detected={stats['detected_techniques']}, total={stats['total_techniques']} | fields coverage</query>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xDC4E41","0xF1813F","0x53A051"]</option>
        <option name="rangeValues">[30,70]</option>
        <option name="underLabel">Techniques Detected: {stats['detected_techniques']}/{stats['total_techniques']}</option>
        <option name="useThousandSeparators">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>High Confidence Detections</title>
        <search>
          <query>| makeresults | eval count={stats['confidence_distribution']['high']} | fields count</query>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xDC4E41","0xF1813F","0x53A051"]</option>
        <option name="underLabel">Confidence ≥ 0.8</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Medium Confidence Detections</title>
        <search>
          <query>| makeresults | eval count={stats['confidence_distribution']['medium']} | fields count</query>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xDC4E41","0xF1813F","0x53A051"]</option>
        <option name="underLabel">0.5 ≤ Confidence &lt; 0.8</option>
      </single>
    </panel>
  </row>

  <!-- Tactic Coverage Chart -->
  <row>
    <panel>
      <chart>
        <title>Coverage by Tactic</title>
        <search>
          <query>| makeresults
"""

        # Add tactic coverage data
        for tactic, data in stats["tactic_coverage"].items():
            percentage = data["percentage"]
            xml += f"""| eval tactic="{tactic}", coverage={percentage:.1f}
| append [| makeresults | eval tactic="{tactic}", coverage={percentage:.1f}]
"""

        xml += """| stats first(coverage) as coverage by tactic
| sort - coverage</query>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisTitleX.text">Tactic</option>
        <option name="charting.axisTitleY.text">Coverage %</option>
        <option name="charting.chart.showDataLabels">all</option>
        <option name="charting.legend.placement">none</option>
      </chart>
    </panel>
  </row>

  <!-- Technique Details Table -->
  <row>
    <panel>
      <table>
        <title>Detected Techniques</title>
        <search>
          <query>| makeresults
"""

        # Add technique details
        for mapping in technique_mappings[:50]:  # Limit to top 50
            tech_id = mapping["id"]
            tech_name = mapping.get("name", "Unknown").replace('"', "'")
            confidence = mapping.get("confidence", 0.0)
            tactics = ", ".join(mapping.get("tactics", []))

            xml += f"""| eval technique_id="{tech_id}", technique_name="{tech_name}", confidence={confidence:.2f}, tactics="{tactics}"
| append [| makeresults | eval technique_id="{tech_id}", technique_name="{tech_name}", confidence={confidence:.2f}, tactics="{tactics}"]
"""

        xml += """| stats first(*) as * by technique_id
| sort - confidence
| fields technique_id, technique_name, confidence, tactics</query>
        </search>
        <option name="drilldown">row</option>
        <option name="count">20</option>
      </table>
    </panel>
  </row>

  <!-- Confidence Distribution -->
  <row>
    <panel>
      <chart>
        <title>Confidence Distribution</title>
        <search>
          <query>| makeresults
| eval high={stats['confidence_distribution']['high']}, medium={stats['confidence_distribution']['medium']}, low={stats['confidence_distribution']['low']}
| eval "High (≥0.8)"=high, "Medium (0.5-0.8)"=medium, "Low (&lt;0.5)"=low
| fields "High (≥0.8)", "Medium (0.5-0.8)", "Low (&lt;0.5)"</query>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.showPercent">1</option>
      </chart>
    </panel>
  </row>

</form>"""

        return xml

    def generate_elastic_dashboard(
        self, technique_mappings: List[dict], coverage: Optional[dict] = None
    ) -> str:
        """
        Generate Elasticsearch/Kibana dashboard JSON.

        Args:
            technique_mappings: List of technique mappings
            coverage: Pre-calculated coverage (optional)

        Returns:
            Kibana dashboard JSON as string
        """
        if coverage is None:
            coverage = self._calculate_coverage(technique_mappings)

        stats = coverage["statistics"]

        # Build Kibana dashboard
        dashboard = {
            "version": "8.0.0",
            "objects": [
                {
                    "id": "mitre-attck-coverage",
                    "type": "dashboard",
                    "attributes": {
                        "title": f"MITRE ATT&CK Coverage - Dernvale (v{self.attck_data.get('version', 'unknown')})",
                        "description": "ATT&CK Framework Coverage Analysis",
                        "panelsJSON": json.dumps(
                            [
                                # Overall coverage metric
                                {
                                    "panelIndex": "1",
                                    "gridData": {"x": 0, "y": 0, "w": 12, "h": 4},
                                    "type": "metric",
                                    "id": "coverage-overall",
                                    "version": "8.0.0",
                                    "embeddableConfig": {
                                        "title": "Overall Coverage",
                                        "metric": {
                                            "value": f"{stats['coverage_percentage']:.1f}%",
                                            "label": f"Techniques Detected: {stats['detected_techniques']}/{stats['total_techniques']}",
                                        },
                                    },
                                },
                                # Confidence distribution
                                {
                                    "panelIndex": "2",
                                    "gridData": {"x": 12, "y": 0, "w": 12, "h": 8},
                                    "type": "pie",
                                    "id": "confidence-distribution",
                                    "embeddableConfig": {
                                        "title": "Confidence Distribution",
                                        "data": [
                                            {
                                                "label": "High (≥0.8)",
                                                "value": stats["confidence_distribution"]["high"],
                                            },
                                            {
                                                "label": "Medium (0.5-0.8)",
                                                "value": stats["confidence_distribution"]["medium"],
                                            },
                                            {
                                                "label": "Low (<0.5)",
                                                "value": stats["confidence_distribution"]["low"],
                                            },
                                        ],
                                    },
                                },
                                # Tactic coverage
                                {
                                    "panelIndex": "3",
                                    "gridData": {"x": 0, "y": 8, "w": 24, "h": 8},
                                    "type": "horizontal_bar",
                                    "id": "tactic-coverage",
                                    "embeddableConfig": {
                                        "title": "Coverage by Tactic",
                                        "data": [
                                            {"tactic": tactic, "coverage": data["percentage"]}
                                            for tactic, data in stats["tactic_coverage"].items()
                                        ],
                                    },
                                },
                                # Technique table
                                {
                                    "panelIndex": "4",
                                    "gridData": {"x": 0, "y": 16, "w": 24, "h": 12},
                                    "type": "data_table",
                                    "id": "technique-table",
                                    "embeddableConfig": {
                                        "title": "Detected Techniques",
                                        "columns": [
                                            "technique_id",
                                            "technique_name",
                                            "confidence",
                                            "tactics",
                                        ],
                                        "data": [
                                            {
                                                "technique_id": m["id"],
                                                "technique_name": m.get("name", "Unknown"),
                                                "confidence": m.get("confidence", 0.0),
                                                "tactics": ", ".join(m.get("tactics", [])),
                                            }
                                            for m in sorted(
                                                technique_mappings,
                                                key=lambda x: x.get("confidence", 0),
                                                reverse=True,
                                            )[:50]
                                        ],
                                    },
                                },
                            ]
                        ),
                    },
                }
            ],
        }

        return json.dumps(dashboard, indent=2)

    def generate_navigator_layer(
        self, technique_mappings: List[dict], coverage: Optional[dict] = None
    ) -> str:
        """
        Generate ATT&CK Navigator layer JSON.

        Args:
            technique_mappings: List of technique mappings
            coverage: Pre-calculated coverage (optional)

        Returns:
            Navigator layer JSON as string
        """
        if coverage is None:
            coverage = self._calculate_coverage(technique_mappings)

        # Build technique list with scores
        techniques = []
        for tech_id, confidence in coverage["techniques"].items():
            # Get technique details
            tech_details = self.attck_data.get("techniques", {}).get(tech_id, {})

            # Map confidence to color gradient (red = low, yellow = medium, green = high)
            if confidence >= 0.8:
                color = "#2ecc71"  # Green
            elif confidence >= 0.5:
                color = "#f39c12"  # Yellow/Orange
            else:
                color = "#e74c3c"  # Red

            techniques.append(
                {
                    "techniqueID": tech_id,
                    "score": int(confidence * 100),
                    "color": color,
                    "comment": f"Confidence: {confidence:.2f}",
                    "enabled": True,
                    "metadata": [],
                    "showSubtechniques": True,
                }
            )

        # Create Navigator layer
        layer = {
            "name": "Dernvale Coverage",
            "versions": {
                "attack": str(self.attck_data.get("version", "unknown")),
                "navigator": "4.8.0",
                "layer": "4.3",
            },
            "domain": "enterprise-attack",
            "description": f"MITRE ATT&CK coverage from Dernvale analysis. "
            f"Coverage: {coverage['statistics']['coverage_percentage']:.1f}% "
            f"({coverage['statistics']['detected_techniques']}/{coverage['statistics']['total_techniques']} techniques)",
            "filters": {"platforms": ["windows", "linux", "macos"]},
            "sorting": 3,  # Sort by score descending
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#e74c3c", "#f39c12", "#2ecc71"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "High Confidence (≥0.8)", "color": "#2ecc71"},
                {"label": "Medium Confidence (0.5-0.8)", "color": "#f39c12"},
                {"label": "Low Confidence (<0.5)", "color": "#e74c3c"},
            ],
            "metadata": [
                {"name": "Generated", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")},
                {"name": "ATT&CK Version", "value": str(self.attck_data.get("version", "unknown"))},
                {
                    "name": "Total Techniques",
                    "value": str(coverage["statistics"]["detected_techniques"]),
                },
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
        }

        return json.dumps(layer, indent=2)

    def save_dashboards(
        self, technique_mappings: List[dict], output_dir: str, formats: List[str] = None
    ) -> dict:
        """
        Generate and save dashboards to files.

        Args:
            technique_mappings: List of technique mappings
            output_dir: Output directory for dashboard files
            formats: List of formats to generate (default: all)

        Returns:
            Dictionary with file paths for generated dashboards
        """
        if formats is None:
            formats = ["splunk", "elastic", "navigator"]

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        coverage = self._calculate_coverage(technique_mappings)
        result = {"output_dir": str(output_path)}

        # Generate Splunk dashboard
        if "splunk" in formats:
            splunk_xml = self.generate_splunk_dashboard(technique_mappings, coverage)
            splunk_file = output_path / "mitre_coverage_splunk.xml"
            splunk_file.write_text(splunk_xml, encoding="utf-8")
            result["splunk"] = str(splunk_file)
            self.logger.info(f"Splunk dashboard saved to {splunk_file}")

        # Generate Elastic dashboard
        if "elastic" in formats:
            elastic_json = self.generate_elastic_dashboard(technique_mappings, coverage)
            elastic_file = output_path / "mitre_coverage_kibana.json"
            elastic_file.write_text(elastic_json, encoding="utf-8")
            result["elastic"] = str(elastic_file)
            self.logger.info(f"Kibana dashboard saved to {elastic_file}")

        # Generate Navigator layer
        if "navigator" in formats:
            navigator_json = self.generate_navigator_layer(technique_mappings, coverage)
            navigator_file = output_path / "mitre_coverage_navigator.json"
            navigator_file.write_text(navigator_json, encoding="utf-8")
            result["navigator"] = str(navigator_file)
            self.logger.info(f"Navigator layer saved to {navigator_file}")

        # Save coverage statistics
        stats_file = output_path / "coverage_statistics.json"
        stats_file.write_text(
            json.dumps(
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "attck_version": self.attck_data.get("version", "unknown"),
                    "statistics": coverage["statistics"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        result["statistics"] = str(stats_file)
        self.logger.info(f"Coverage statistics saved to {stats_file}")

        return result


# Convenience function


def generate_dashboards(
    technique_mappings: List[dict], output_dir: str, formats: List[str] = None
) -> dict:
    """
    Convenience function to generate dashboards.

    Args:
        technique_mappings: List of technique mappings from TechniqueMapper
        output_dir: Output directory for dashboard files
        formats: List of formats to generate (default: all)

    Returns:
        Dictionary with file paths for generated dashboards
    """
    generator = MitreDashboardGenerator()
    return generator.save_dashboards(technique_mappings, output_dir, formats)
